//! Guest restoration hooks. These run only inside the VM, never on the host.
use husker_agent_proto::RestoreGuestRequest;

fn validate(request: &RestoreGuestRequest) -> Result<(), String> {
    if request.unix_time_secs < 0 || request.unix_time_nanos >= 1_000_000_000 {
        return Err("invalid restore wall clock".into());
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn bound_vmgenid(driver: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(driver) else {
        return false;
    };
    let Ok(expected) = driver.canonicalize() else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .path()
            .join("driver")
            .canonicalize()
            .is_ok_and(|bound| bound == expected)
    })
}

pub(crate) fn reconcile(request: &RestoreGuestRequest) -> Result<(), String> {
    validate(request)?;
    #[cfg(target_os = "linux")]
    {
        if request.require_vmgenid
            && !bound_vmgenid(std::path::Path::new("/sys/bus/platform/drivers/vmgenid"))
        {
            return Err("fork requires a bound VMGenID guest driver; rebuild the guest kernel with CONFIG_VMGENID=y".into());
        }
        let time = libc::timespec {
            tv_sec: request.unix_time_secs,
            tv_nsec: request.unix_time_nanos.into(),
        };
        // SAFETY: time is a live, validated timespec; only this guest's realtime
        // clock changes. Monotonic deadlines and guest timers are untouched.
        if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) } != 0 {
            return Err(format!(
                "reconcile guest wall clock: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    Err("restore hooks are only supported in Linux guests".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_clocks_without_mutating_the_host() {
        for (unix_time_secs, unix_time_nanos) in [(-1, 0), (1, 1_000_000_000)] {
            assert!(
                validate(&RestoreGuestRequest {
                    unix_time_secs,
                    unix_time_nanos,
                    require_vmgenid: false
                })
                .is_err()
            );
        }
    }
    #[test]
    fn registered_driver_without_a_bound_device_is_insufficient() {
        let temp = tempfile::tempdir().unwrap();
        let driver = temp.path().join("driver");
        let device = temp.path().join("device");
        std::fs::create_dir(&driver).unwrap();
        std::fs::create_dir(&device).unwrap();
        assert!(!bound_vmgenid(&driver));
        std::os::unix::fs::symlink(&device, driver.join("vmgenid.0")).unwrap();
        assert!(!bound_vmgenid(&driver));
        std::os::unix::fs::symlink(&driver, device.join("driver")).unwrap();
        assert!(bound_vmgenid(&driver));
    }
}
