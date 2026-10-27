//! Ask a live guest to end itself before the backend stops it.
//!
//! No VMM can shut a microVM guest down from outside on its own: Firecracker's
//! Ctrl-Alt-Del never reaches a guest booted without an i8042 controller, and
//! a `requestStop` on Apple VZ depends on the guest handling ACPI. The guest
//! agent can. It makes the guest's storage durable, acknowledges, and once the
//! host closes the connection carries out the power action that makes this
//! backend's VM process exit ([`guest_power_action`]). The backend stop that
//! follows finds an exited process and settles it without a grace period.
//!
//! Every failure here is tolerated. A guest without an agent, a guest whose
//! agent predates power control (it flushes and stays up), and a guest that
//! acknowledges and then hangs are all stopped by the backend exactly as
//! before, so the request can only make a stop cleaner, never fail it.

use std::time::Duration;

use husker_agent_proto::{AGENT_VSOCK_PORT, GuestPowerAction};
use husker_vmm::{GUEST_SHUTDOWN_GRACE, VmState, guest_power_action};

use super::*;

/// Bound on reaching the guest agent. A guest without an agent, or one whose
/// agent is not listening, is stopped by the backend after this.
pub const GUEST_SHUTDOWN_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Bound on the guest's acknowledgement once its agent is reached. The agent
/// acknowledges only after its `sync`, so this is the time a guest gets to
/// make its storage durable; a guest still inside a longer flush is stopped
/// by the backend regardless and loses what it had not written back yet.
pub const GUEST_FLUSH_TIMEOUT: Duration = Duration::from_secs(15);

/// Longest to wait for the VM process to exit once the guest acknowledged a
/// reboot or power-off. A guest reboot exits Firecracker within milliseconds;
/// a power-off exits QEMU or Apple VZ within a second or two.
pub const GUEST_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

const GUEST_EXIT_POLL: Duration = Duration::from_millis(25);

// A stop that runs every budget here to its end, followed by the backend's own
// grace for a guest that acknowledged and then stayed up, must still finish
// within the per-VM drain bound: a stop the drain cuts off leaves the guest to
// be swept by the service manager instead of stopped by the backend.
const _: () = assert!(
    GUEST_SHUTDOWN_CONNECT_TIMEOUT.as_secs()
        + GUEST_FLUSH_TIMEOUT.as_secs()
        + GUEST_EXIT_TIMEOUT.as_secs()
        + GUEST_SHUTDOWN_GRACE.as_secs()
        <= DRAIN_STOP_TIMEOUT.as_secs(),
    "the guest shutdown budgets plus the backend grace exceed the per-VM drain bound"
);

impl<B: VmmBackend> HuskerCore<B> {
    /// Ask `record`'s guest to flush its storage and end itself, then wait for
    /// the VM process to exit. The caller's backend stop or destroy follows
    /// whatever happened here.
    ///
    /// A paused guest cannot run its agent, so it is resumed for the request;
    /// the backend stop that follows handles a running guest either way.
    pub(crate) async fn shut_down_guest(&self, record: &VmRecord) {
        let name = record.name.as_str();
        if record.state == VmLifecycleState::Paused
            && let Err(error) = self.vmm.resume_vm(record.id).await
        {
            debug!(%name, %error, "could not resume the paused guest for its shutdown");
            return;
        }

        let connected = tokio::time::timeout(
            GUEST_SHUTDOWN_CONNECT_TIMEOUT,
            self.vmm.vsock_connect(record.id, AGENT_VSOCK_PORT),
        )
        .await;
        let stream = match connected {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                debug!(%name, %error, "guest agent is unreachable; stopping from the host");
                return;
            }
            Err(_) => {
                debug!(
                    %name,
                    timeout_secs = GUEST_SHUTDOWN_CONNECT_TIMEOUT.as_secs(),
                    "guest agent did not accept a connection in time; stopping from the host"
                );
                return;
            }
        };

        let requested = guest_power_action(record.vmm);
        let asked = tokio::time::timeout(GUEST_FLUSH_TIMEOUT, async {
            let mut connection = AgentConnection::new(stream);
            let planned = connection.shutdown(requested).await?;
            // Closing the connection tells the agent its acknowledgement was
            // delivered, so it may now end the guest.
            drop(connection);
            Ok::<_, CoreError>(planned)
        })
        .await;
        let planned = match asked {
            Ok(Ok(planned)) => planned,
            Ok(Err(error)) => {
                debug!(%name, %error, "guest agent did not take the shutdown request; stopping from the host");
                return;
            }
            Err(_) => {
                warn!(
                    %name,
                    timeout_secs = GUEST_FLUSH_TIMEOUT.as_secs(),
                    "guest did not finish flushing its storage in time; stopping from the host"
                );
                return;
            }
        };
        if planned == GuestPowerAction::Flush {
            info!(%name, "guest flushed its storage but its agent predates power control; stopping from the host");
            return;
        }

        let deadline = tokio::time::Instant::now() + GUEST_EXIT_TIMEOUT;
        loop {
            match self.vmm.vm_info(record.id).await {
                Ok(info) if matches!(info.state, VmState::Running | VmState::Paused) => {}
                Ok(_) | Err(husker_vmm::VmmError::VmNotFound(_)) => {
                    info!(%name, action = ?planned, "guest ended itself");
                    return;
                }
                Err(error) => {
                    warn!(%name, %error, "cannot observe the guest after its shutdown; stopping from the host");
                    return;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    %name,
                    action = ?planned,
                    timeout_secs = GUEST_EXIT_TIMEOUT.as_secs(),
                    "guest acknowledged the shutdown but is still running; stopping from the host"
                );
                return;
            }
            tokio::time::sleep(GUEST_EXIT_POLL).await;
        }
    }
}
