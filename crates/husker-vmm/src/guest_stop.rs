//! The stop contract every backend's `stop_vm` fulfils.
//!
//! A successful stop must mean the guest no longer runs: callers delete the
//! rootfs clone, release the TAP device and reuse the vsock CID the moment the
//! call returns. Merely accepting a shutdown request is not enough, so every
//! backend follows the same shape: ask the guest to shut down, poll until it has
//! ended, and force it off when the grace period runs out.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::VmmError;

/// How long a guest gets to act on a shutdown request before it is forced off.
/// Public so that the host-side stop budgets built on top of a backend stop
/// can account for it.
pub const GUEST_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Interval between liveness checks while a guest shuts down. A backend's probe
/// takes its instance lock only for the check itself, so every other VM's
/// operations keep flowing during a grace period.
pub(crate) const GUEST_EXIT_POLL: Duration = Duration::from_millis(25);

/// How a `stop_vm` wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestExit {
    /// The guest ended on its own within the grace period.
    Clean,
    /// The grace period elapsed, or the guest's state could not be read, and
    /// the guest was forced off.
    Forced,
    /// The instance left the backend's map during the wait; a concurrent
    /// destroy owns the guest now.
    Gone,
}

/// Poll `probe` every [`GUEST_EXIT_POLL`] until it reports an exit or `grace`
/// elapses, then run `force` once and report its outcome. `probe` runs before
/// the first deadline check, so a zero grace still observes a guest that has
/// already ended instead of forcing it.
pub(crate) async fn wait_for_guest_exit<P, PF, F, FF>(
    grace: Duration,
    mut probe: P,
    force: F,
) -> Result<GuestExit, VmmError>
where
    P: FnMut() -> PF,
    PF: Future<Output = Result<Option<GuestExit>, VmmError>>,
    F: FnOnce() -> FF,
    FF: Future<Output = Result<GuestExit, VmmError>>,
{
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        if let Some(exit) = probe().await? {
            return Ok(exit);
        }
        if tokio::time::Instant::now() >= deadline {
            return force().await;
        }
        tokio::time::sleep(GUEST_EXIT_POLL).await;
    }
}

/// Wait for a hypervisor child process to exit and kill it when the guest does
/// not shut down within `grace`. Shared by the backends that run the guest as
/// a child process; `process` selects the child inside an instance.
///
/// The instance map is locked per check, never across the whole grace, because
/// the map guards every VM: a stop that held it for the full grace would stall
/// creates, execs and stops of unrelated VMs.
pub(crate) async fn wait_for_process_exit_or_kill<I>(
    instances: &Mutex<HashMap<Uuid, I>>,
    id: Uuid,
    grace: Duration,
    hypervisor: &str,
    process: impl Fn(&mut I) -> Option<&mut tokio::process::Child>,
) -> Result<GuestExit, VmmError> {
    let process = &process;
    wait_for_guest_exit(
        grace,
        || async move {
            let mut instances = instances.lock().await;
            match instances.get_mut(&id) {
                Some(instance) => {
                    let process = process(instance).ok_or_else(|| VmmError::ProcessError(format!("{hypervisor} allocation has no confirmed child handle")))?;
                    probe_process(process, hypervisor).await
                },
                None => Ok(Some(GuestExit::Gone)),
            }
        },
        || async move {
            let mut instances = instances.lock().await;
            match instances.get_mut(&id) {
                Some(instance) => {
                    process(instance).ok_or_else(|| VmmError::ProcessError(format!("{hypervisor} allocation has no confirmed child handle")))?.kill().await.map_err(|error| {
                        VmmError::ProcessError(format!(
                            "{hypervisor} did not exit within {}s and force kill failed: {error}",
                            grace.as_secs_f64()
                        ))
                    })?;
                    Ok(GuestExit::Forced)
                }
                None => Ok(GuestExit::Gone),
            }
        },
    )
    .await
}

/// One liveness check of a hypervisor child: exited is `Clean`, alive is
/// `None`, and an unreadable process state is resolved by killing the child
/// (`Forced`), because the wait cannot otherwise tell whether the guest is gone.
async fn probe_process(
    process: &mut tokio::process::Child,
    hypervisor: &str,
) -> Result<Option<GuestExit>, VmmError> {
    match process.try_wait() {
        Ok(Some(_)) => Ok(Some(GuestExit::Clean)),
        Ok(None) => Ok(None),
        Err(wait_error) => {
            process.kill().await.map_err(|kill_error| {
                VmmError::ProcessError(format!(
                    "wait for {hypervisor} exit: {wait_error}; force kill also failed: {kill_error}"
                ))
            })?;
            Ok(Some(GuestExit::Forced))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::Duration;

    use super::{GUEST_EXIT_POLL, GuestExit, wait_for_guest_exit};
    use crate::VmmError;

    /// A probe that reports the guest alive forever.
    fn never_ends(
        probes: &Cell<u32>,
    ) -> impl FnMut() -> std::future::Ready<Result<Option<GuestExit>, VmmError>> {
        move || {
            probes.set(probes.get() + 1);
            std::future::ready(Ok(None))
        }
    }

    /// A force that records it ran and reports a forced exit.
    fn forcing(
        forced: &Cell<u32>,
    ) -> impl FnOnce() -> std::future::Ready<Result<GuestExit, VmmError>> {
        move || {
            forced.set(forced.get() + 1);
            std::future::ready(Ok(GuestExit::Forced))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn forces_a_guest_that_never_ends_once_the_grace_elapses() {
        let probes = Cell::new(0);
        let forced = Cell::new(0);
        let grace = Duration::from_secs(5);
        let started = tokio::time::Instant::now();

        let exit = wait_for_guest_exit(grace, never_ends(&probes), forcing(&forced))
            .await
            .unwrap();

        assert_eq!(exit, GuestExit::Forced);
        assert_eq!(forced.get(), 1, "force runs exactly once");
        assert!(
            started.elapsed() >= grace,
            "the force must not precede the grace period"
        );
        assert!(
            started.elapsed() < grace + GUEST_EXIT_POLL,
            "the force must follow the grace period by at most one poll"
        );
        assert!(probes.get() > 1, "the guest is probed throughout the grace");
    }

    #[tokio::test(start_paused = true)]
    async fn a_guest_that_ends_in_time_is_not_forced() {
        let probes = Cell::new(0);
        let forced = Cell::new(0);
        let started = tokio::time::Instant::now();

        let exit = wait_for_guest_exit(
            Duration::from_secs(5),
            || {
                probes.set(probes.get() + 1);
                let ended = probes.get() == 3;
                std::future::ready(Ok(ended.then_some(GuestExit::Clean)))
            },
            forcing(&forced),
        )
        .await
        .unwrap();

        assert_eq!(exit, GuestExit::Clean);
        assert_eq!(forced.get(), 0, "a clean exit is never forced");
        assert_eq!(probes.get(), 3);
        assert_eq!(started.elapsed(), GUEST_EXIT_POLL * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_grace_still_observes_a_guest_that_already_ended() {
        let forced = Cell::new(0);

        let exit = wait_for_guest_exit(
            Duration::ZERO,
            || std::future::ready(Ok(Some(GuestExit::Clean))),
            forcing(&forced),
        )
        .await
        .unwrap();

        assert_eq!(exit, GuestExit::Clean);
        assert_eq!(forced.get(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_grace_forces_a_live_guest_after_a_single_probe() {
        let probes = Cell::new(0);
        let forced = Cell::new(0);

        let exit = wait_for_guest_exit(Duration::ZERO, never_ends(&probes), forcing(&forced))
            .await
            .unwrap();

        assert_eq!(exit, GuestExit::Forced);
        assert_eq!(probes.get(), 1);
        assert_eq!(forced.get(), 1);
    }

    /// The probe decides the outcome it reports: a backend whose instance was
    /// removed by a concurrent destroy reports `Gone`, and the force is skipped.
    #[tokio::test(start_paused = true)]
    async fn the_probe_outcome_is_reported_without_forcing() {
        let forced = Cell::new(0);

        let exit = wait_for_guest_exit(
            Duration::from_secs(5),
            || std::future::ready(Ok(Some(GuestExit::Gone))),
            forcing(&forced),
        )
        .await
        .unwrap();

        assert_eq!(exit, GuestExit::Gone);
        assert_eq!(forced.get(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_probe_aborts_the_wait_without_forcing() {
        let forced = Cell::new(0);

        let result = wait_for_guest_exit(
            Duration::from_secs(5),
            || std::future::ready(Err(VmmError::ProcessError("state unreadable".into()))),
            forcing(&forced),
        )
        .await;

        assert!(matches!(result, Err(VmmError::ProcessError(_))));
        assert_eq!(forced.get(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_force_is_reported() {
        let probes = Cell::new(0);

        let result = wait_for_guest_exit(Duration::ZERO, never_ends(&probes), || {
            std::future::ready(Err(VmmError::ProcessError("kill failed".into())))
        })
        .await;

        assert!(matches!(result, Err(VmmError::ProcessError(_))));
    }
}
