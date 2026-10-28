//! A daemon restart is not a termination receipt. A kernel boot change on the
//! same host proves that allocations observed in the earlier boot cannot live.
use rusqlite::OptionalExtension;
use uuid::Uuid;

use crate::{StateError, StateStore};

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS creation_lease_boot_epochs (
    lease_id TEXT PRIMARY KEY REFERENCES host_resource_leases(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0 CHECK(confirmed IN (0,1))
);
CREATE TRIGGER IF NOT EXISTS creation_lease_boot_epoch_is_immutable
BEFORE UPDATE ON creation_lease_boot_epochs
WHEN NEW.lease_id<>OLD.lease_id OR NEW.host_id<>OLD.host_id OR NEW.boot_id<>OLD.boot_id
    OR (OLD.confirmed=1 AND NEW.confirmed<>1)
BEGIN SELECT RAISE(ABORT, 'invalid creation lease boot proof transition'); END;
CREATE TRIGGER IF NOT EXISTS creation_lease_boot_epoch_cannot_be_replaced
BEFORE INSERT ON creation_lease_boot_epochs
WHEN EXISTS(SELECT 1 FROM creation_lease_boot_epochs AS epochs
    JOIN host_resource_leases AS leases ON leases.id=epochs.lease_id
    WHERE epochs.lease_id=NEW.lease_id AND (leases.backend_entered=1 OR epochs.confirmed=1))
BEGIN SELECT RAISE(ABORT, 'entered creation lease boot evidence cannot be replaced'); END;
CREATE TRIGGER IF NOT EXISTS creation_lease_boot_epoch_cannot_be_forgotten
BEFORE DELETE ON creation_lease_boot_epochs
WHEN EXISTS(SELECT 1 FROM host_resource_leases WHERE id=OLD.lease_id AND (backend_entered=1 OR OLD.confirmed=1))
BEGIN SELECT RAISE(ABORT, 'entered creation lease boot evidence cannot be forgotten'); END;
CREATE TRIGGER IF NOT EXISTS creation_lease_cannot_reenter_after_reboot
BEFORE UPDATE OF backend_entered ON host_resource_leases
WHEN NEW.backend_entered=1 AND OLD.backend_entered=0
    AND EXISTS(SELECT 1 FROM creation_lease_boot_epochs WHERE lease_id=OLD.id AND confirmed=1)
BEGIN SELECT RAISE(ABORT, 'creation lease already has a host reboot receipt'); END;
DROP TRIGGER creation_lease_release_requires_proof;
CREATE TRIGGER creation_lease_release_requires_proof
BEFORE DELETE ON host_resource_leases
WHEN OLD.backend_entered=1 AND OLD.vm_destroyed=0
    AND NOT EXISTS(SELECT 1 FROM vms WHERE id=OLD.vm_id AND name=OLD.vm_name AND vsock_cid=OLD.vsock_cid)
    AND NOT EXISTS(SELECT 1 FROM creation_lease_boot_epochs WHERE lease_id=OLD.id AND confirmed=1)
BEGIN SELECT RAISE(ABORT, 'creation lease destruction is unconfirmed'); END;
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostBoot {
    pub host: Uuid,
    pub boot: Uuid,
}

#[cfg(target_os = "linux")]
pub(crate) fn current() -> Option<HostBoot> {
    use std::io::Read;
    let read_uuid = |path: &str| {
        let mut bytes = vec![];
        std::fs::File::open(path)
            .ok()?
            .take(65)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 64 {
            return None;
        }
        Uuid::parse_str(std::str::from_utf8(&bytes).ok()?.trim())
            .ok()
            .filter(|id| !id.is_nil())
    };
    Some(HostBoot {
        host: read_uuid("/etc/machine-id")?,
        boot: read_uuid("/proc/sys/kernel/random/boot_id")?,
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn current() -> Option<HostBoot> {
    let mut host = [0u8; 16];
    let timeout = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    // These are read-only OS identities; never use daemon PID or wall time.
    if unsafe { libc::gethostuuid(host.as_mut_ptr(), &timeout) } != 0 {
        return None;
    }
    let mut bytes = [0u8; 64];
    let mut size = bytes.len();
    if unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size == 0
        || size > bytes.len()
    {
        return None;
    }
    let boot = Uuid::parse_str(
        std::str::from_utf8(&bytes[..size])
            .ok()?
            .trim_end_matches('\0'),
    )
    .ok()?;
    let host = Uuid::from_bytes(host);
    (!host.is_nil() && !boot.is_nil()).then_some(HostBoot { host, boot })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn current() -> Option<HostBoot> {
    None
}

pub(crate) fn observe_on(conn: &rusqlite::Connection, lease: Uuid) -> Result<(), StateError> {
    if let Some(identity) = current() {
        conn.execute("INSERT OR IGNORE INTO creation_lease_boot_epochs(lease_id,host_id,boot_id) VALUES (?1,?2,?3)",
            rusqlite::params![lease.to_string(), identity.host.to_string(), identity.boot.to_string()])?;
    }
    Ok(())
}

/// Bind evidence to backend entry in the same transaction. A lease from an
/// earlier boot must be retired and replaced, never resumed against its old
/// termination evidence. If identity cannot be read, revoke the *unentered*
/// baseline rather than let a later boot comparison describe the wrong VM.
pub(crate) fn prepare_entry_on(
    conn: &rusqlite::Connection,
    lease: Uuid,
    identity: Option<HostBoot>,
) -> Result<(), StateError> {
    let baseline: Option<(String, String, bool)> = conn
        .query_row(
            "SELECT host_id,boot_id,confirmed FROM creation_lease_boot_epochs WHERE lease_id=?1",
            [lease.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((host, boot, confirmed)) = &baseline {
        if *confirmed {
            return Err(StateError::HostResourceLeaseMismatch(lease));
        }
        if let Some(identity) = identity
            && (Uuid::parse_str(host).ok() != Some(identity.host)
                || Uuid::parse_str(boot).ok() != Some(identity.boot))
        {
            return Err(StateError::HostResourceLeaseMismatch(lease));
        }
    }
    match (identity, baseline) {
        (None, Some(_)) => {
            conn.execute(
                "DELETE FROM creation_lease_boot_epochs WHERE lease_id=?1",
                [lease.to_string()],
            )?;
        }
        (Some(identity), None) => {
            conn.execute("INSERT INTO creation_lease_boot_epochs(lease_id,host_id,boot_id) VALUES (?1,?2,?3)",
                rusqlite::params![lease.to_string(),identity.host.to_string(),identity.boot.to_string()])?;
        }
        _ => (),
    }
    Ok(())
}

impl StateStore {
    /// Legacy allocations have no historical boot evidence. Observe them now;
    /// only a subsequent host reboot can authorize their automatic recovery.
    pub(crate) fn observe_legacy_lease_boots(&self) -> Result<(), StateError> {
        let Some(identity) = current() else {
            return Ok(());
        };
        let missing: bool = self.lock()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM host_resource_leases AS leases
                WHERE NOT EXISTS(SELECT 1 FROM creation_lease_boot_epochs WHERE lease_id=leases.id))",
            [], |row| row.get(0),
        )?;
        if !missing {
            return Ok(());
        }
        let conn = self.lock_durable()?;
        conn.execute(
            "INSERT OR IGNORE INTO creation_lease_boot_epochs(lease_id,host_id,boot_id)
            SELECT id,?1,?2 FROM host_resource_leases AS leases
            WHERE NOT EXISTS(SELECT 1 FROM creation_lease_boot_epochs WHERE lease_id=leases.id)",
            rusqlite::params![identity.host.to_string(), identity.boot.to_string()],
        )?;
        Ok(())
    }

    /// Persist positive host-reboot evidence. Missing identity, another host,
    /// and a daemon restart in the same boot never authorize resource release.
    pub fn confirm_host_resource_lease_reboot(&self, lease: Uuid) -> Result<bool, StateError> {
        self.confirm_lease_reboot_on(lease, current())
    }

    pub(crate) fn confirm_lease_reboot_on(
        &self,
        lease: Uuid,
        identity: Option<HostBoot>,
    ) -> Result<bool, StateError> {
        let conn = self.lock_durable()?;
        let baseline: Option<(String, String, bool)> = conn
            .query_row(
                "SELECT host_id,boot_id,confirmed FROM creation_lease_boot_epochs AS epochs
                JOIN host_resource_leases AS leases ON leases.id=epochs.lease_id
                WHERE lease_id=?1 AND leases.backend_entered=1",
                [lease.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((host, boot, confirmed)) = baseline else {
            return Ok(false);
        };
        let parse = |value: &str| {
            Uuid::parse_str(value)
                .ok()
                .filter(|id| !id.is_nil())
                .ok_or_else(|| StateError::CorruptData {
                    column: "creation_lease_boot_epochs",
                    message: "invalid host or boot UUID".into(),
                })
        };
        let baseline = HostBoot {
            host: parse(&host)?,
            boot: parse(&boot)?,
        };
        if confirmed {
            return Ok(true);
        }
        let Some(identity) = identity else {
            return Ok(false);
        };
        if identity.host != baseline.host
            || identity.boot == baseline.boot
            || identity.boot.is_nil()
        {
            return Ok(false);
        }
        Ok(conn.execute(
            "UPDATE creation_lease_boot_epochs SET confirmed=1
            WHERE lease_id=?1 AND host_id=?2 AND boot_id=?3
                AND EXISTS(SELECT 1 FROM host_resource_leases WHERE id=?1 AND backend_entered=1)",
            rusqlite::params![lease.to_string(), host, boot],
        )? == 1)
    }
}

pub(crate) fn confirmed_on(conn: &rusqlite::Connection, lease: Uuid) -> Result<bool, StateError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM creation_lease_boot_epochs WHERE lease_id=?1 AND confirmed=1)",
        [lease.to_string()],
        |row| row.get(0),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn identity() -> HostBoot {
        HostBoot {
            host: Uuid::new_v4(),
            boot: Uuid::new_v4(),
        }
    }
    fn entered(
        store: &StateStore,
        epoch: Option<HostBoot>,
        legacy: bool,
    ) -> crate::HostResourceLease {
        let lease = store.begin_host_resource_lease("interrupted").unwrap();
        let conn = store.lock().unwrap();
        conn.execute(
            "DELETE FROM creation_lease_boot_epochs WHERE lease_id=?1",
            [lease.id.to_string()],
        )
        .unwrap();
        if let Some(epoch) = epoch {
            conn.execute("INSERT INTO creation_lease_boot_epochs(lease_id,host_id,boot_id) VALUES (?1,?2,?3)", params![lease.id.to_string(),epoch.host.to_string(),epoch.boot.to_string()]).unwrap();
        }
        conn.execute(
            "UPDATE host_resource_leases SET backend_entered=1,vm_id=?2 WHERE id=?1",
            params![
                lease.id.to_string(),
                if legacy {
                    None
                } else {
                    Some(Uuid::new_v4().to_string())
                }
            ],
        )
        .unwrap();
        lease
    }

    #[test]
    fn missing_identity_same_boot_and_another_host_cannot_authorize_reuse() {
        let epoch = identity();
        for current in [None, Some(epoch), Some(identity())] {
            let store = StateStore::open_memory().unwrap();
            let lease = entered(&store, Some(epoch), false);
            assert!(!store.confirm_lease_reboot_on(lease.id, current).unwrap());
            assert!(store.release_host_resource_lease(lease.id).is_err());
            assert_ne!(store.allocate_cid().unwrap(), lease.vsock_cid);
        }
        let store = StateStore::open_memory().unwrap();
        let lease = entered(&store, None, true);
        assert!(
            !store
                .confirm_lease_reboot_on(lease.id, Some(epoch))
                .unwrap()
        );
        assert!(store.release_host_resource_lease(lease.id).is_err());
    }

    #[test]
    fn host_reboot_proof_survives_reopen_and_recovers_a_legacy_unknown_generation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let epoch = identity();
        let store = StateStore::open(&path).unwrap();
        let lease = entered(&store, Some(epoch), true);
        assert!(
            store
                .confirm_lease_reboot_on(
                    lease.id,
                    Some(HostBoot {
                        boot: Uuid::new_v4(),
                        ..epoch
                    })
                )
                .unwrap()
        );
        assert!(
            store
                .get_host_resource_lease(lease.id)
                .unwrap()
                .vm_id
                .is_none()
        );
        drop(store);
        let store = StateStore::open(&path).unwrap();
        assert!(store.confirm_lease_reboot_on(lease.id, None).unwrap());
        store.release_host_resource_lease(lease.id).unwrap();
        assert_eq!(store.allocate_cid().unwrap(), lease.vsock_cid);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM creation_lease_boot_epochs",
                    [],
                    |row| row.get::<_, u32>(0)
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn reboot_evidence_cannot_rewrite_its_baseline_or_revoke_a_receipt() {
        let store = StateStore::open_memory().unwrap();
        let epoch = identity();
        let lease = entered(&store, Some(epoch), false);
        let conn = store.lock().unwrap();
        for column in ["host_id", "boot_id", "lease_id"] {
            assert!(
                conn.execute(
                    &format!("UPDATE creation_lease_boot_epochs SET {column}=?1 WHERE lease_id=?2"),
                    params![Uuid::new_v4().to_string(), lease.id.to_string()]
                )
                .is_err()
            );
        }
        drop(conn);
        store
            .confirm_lease_reboot_on(
                lease.id,
                Some(HostBoot {
                    boot: Uuid::new_v4(),
                    ..epoch
                }),
            )
            .unwrap();
        assert!(
            store
                .lock()
                .unwrap()
                .execute(
                    "UPDATE creation_lease_boot_epochs SET confirmed=0 WHERE lease_id=?1",
                    [lease.id.to_string()]
                )
                .is_err()
        );
    }
    #[test]
    fn malformed_boot_evidence_never_becomes_a_termination_receipt() {
        let store = StateStore::open_memory().unwrap();
        let epoch = identity();
        let lease = store.begin_host_resource_lease("malformed").unwrap();
        let conn = store.lock().unwrap();
        conn.execute(
            "DELETE FROM creation_lease_boot_epochs WHERE lease_id=?1",
            [lease.id.to_string()],
        )
        .unwrap();
        conn.execute("INSERT INTO creation_lease_boot_epochs(lease_id,host_id,boot_id) VALUES (?1,?2,'malformed')",params![lease.id.to_string(),epoch.host.to_string()]).unwrap();
        conn.execute(
            "UPDATE host_resource_leases SET backend_entered=1 WHERE id=?1",
            [lease.id.to_string()],
        )
        .unwrap();
        drop(conn);
        assert!(
            store
                .confirm_lease_reboot_on(lease.id, Some(epoch))
                .is_err()
        );
        assert!(store.release_host_resource_lease(lease.id).is_err());
    }

    #[test]
    fn version_22_upgrade_observes_legacy_leases_without_inventing_a_prior_boot() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("old.db");
        let store = StateStore::open(&path).unwrap();
        let lease = store.begin_host_resource_lease("legacy-upgrade").unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE host_resource_leases SET backend_entered=1 WHERE id=?1",
                [lease.id.to_string()],
            )
            .unwrap();
        drop(store);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("DROP TRIGGER creation_lease_release_requires_proof;
            DROP TRIGGER creation_lease_cannot_reenter_after_reboot;
            DROP TABLE creation_lease_boot_epochs;
            CREATE TRIGGER creation_lease_release_requires_proof BEFORE DELETE ON host_resource_leases
            WHEN OLD.backend_entered=1 AND OLD.vm_destroyed=0
            BEGIN SELECT RAISE(ABORT,'unconfirmed'); END;
            PRAGMA user_version=22;").unwrap();
        drop(conn);
        for _ in 0..2 {
            let store = StateStore::open(&path).unwrap();
            assert!(!store.confirm_host_resource_lease_reboot(lease.id).unwrap());
            assert!(store.release_host_resource_lease(lease.id).is_err());
            assert!(
                store
                    .get_host_resource_lease(lease.id)
                    .unwrap()
                    .vm_id
                    .is_none()
            );
        }
    }
    #[test]
    fn backend_entry_refuses_an_older_boot_and_missing_identity_revokes_unentered_evidence() {
        let store = StateStore::open_memory().unwrap();
        let lease = store.begin_host_resource_lease("entry-boot").unwrap();
        let epoch = identity();
        let conn = store.lock().unwrap();
        conn.execute(
            "DELETE FROM creation_lease_boot_epochs WHERE lease_id=?1",
            [lease.id.to_string()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO creation_lease_boot_epochs(lease_id,host_id,boot_id) VALUES (?1,?2,?3)",
            params![
                lease.id.to_string(),
                epoch.host.to_string(),
                epoch.boot.to_string()
            ],
        )
        .unwrap();
        assert!(
            prepare_entry_on(
                &conn,
                lease.id,
                Some(HostBoot {
                    boot: Uuid::new_v4(),
                    ..epoch
                })
            )
            .is_err()
        );
        assert!(prepare_entry_on(&conn, lease.id, Some(identity())).is_err());
        prepare_entry_on(&conn, lease.id, None).unwrap();
        assert!(!confirmed_on(&conn, lease.id).unwrap());
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM creation_lease_boot_epochs WHERE lease_id=?1",
                [lease.id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        prepare_entry_on(&conn, lease.id, Some(epoch)).unwrap();
        conn.execute(
            "UPDATE creation_lease_boot_epochs SET confirmed=1 WHERE lease_id=?1",
            [lease.id.to_string()],
        )
        .unwrap();
        drop(conn);
        assert!(
            !store
                .get_host_resource_lease(lease.id)
                .unwrap()
                .backend_entered
        );
        assert!(
            store
                .enter_host_resource_lease_backend(lease.id, Uuid::new_v4())
                .is_err()
        );
    }

    #[test]
    fn entered_boot_evidence_cannot_be_deleted_or_replaced() {
        let store = StateStore::open_memory().unwrap();
        let lease = entered(&store, Some(identity()), true);
        let conn = store.lock().unwrap();
        assert!(
            conn.execute(
                "DELETE FROM creation_lease_boot_epochs WHERE lease_id=?1",
                [lease.id.to_string()]
            )
            .is_err()
        );
        assert!(conn.execute("INSERT OR REPLACE INTO creation_lease_boot_epochs(lease_id,host_id,boot_id) VALUES (?1,?2,?3)",params![lease.id.to_string(),Uuid::new_v4().to_string(),Uuid::new_v4().to_string()]).is_err());
    }
}
