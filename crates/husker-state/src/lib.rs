//! SQLite-backed persistent state store for VM records, CID allocation, port
//! forwards, host groups, and services.

use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("VM not found: {0}")]
    VmNotFound(Uuid),
    #[error("VM not found by name: {0}")]
    VmNotFoundByName(String),
    #[error("VM already exists: {0}")]
    VmAlreadyExists(String),
    #[error("host group not found: {0}")]
    HostGroupNotFound(Uuid),
    #[error("host group not found by name: {0}")]
    HostGroupNotFoundByName(String),
    #[error("host group already exists: {0}")]
    HostGroupAlreadyExists(String),
    #[error("service not found: {0}")]
    ServiceNotFound(Uuid),
    #[error("service not found by name: {0}")]
    ServiceNotFoundByName(String),
    #[error("service already exists: {0}")]
    ServiceAlreadyExists(String),
    #[error("snapshot not found: {0}")]
    SnapshotNotFound(Uuid),
    #[error("snapshot not found by name: {0}")]
    SnapshotNotFoundByName(String),
    #[error("snapshot already exists: {0}")]
    SnapshotAlreadyExists(String),
    #[error("image not found: {0}")]
    ImageNotFound(Uuid),
    #[error("image not found by name: {0}")]
    ImageNotFoundByName(String),
    #[error("image already exists: {0}")]
    ImageAlreadyExists(String),
    #[error("secret not found: {0}")]
    SecretNotFound(Uuid),
    #[error("secret not found by name: {0}")]
    SecretNotFoundByName(String),
    #[error("secret already exists: {0}")]
    SecretAlreadyExists(String),
    #[error("port already forwarded: {0}")]
    PortAlreadyForwarded(u16),
    #[error("lock poisoned")]
    LockPoisoned,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt data in column {column}: {message}")]
    CorruptData {
        column: &'static str,
        message: String,
    },
}

/// Persistent VM record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmRecord {
    pub id: Uuid,
    pub name: String,
    pub state: String,
    pub pid: Option<u32>,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub vsock_cid: u32,
    pub tap_device: Option<String>,
    pub host_ip: Option<String>,
    pub guest_ip: Option<String>,
    pub kernel_path: String,
    pub rootfs_path: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub userdata: Option<String>,
    pub userdata_status: Option<String>,
    /// JSON-serialized environment variables for userdata script.
    pub userdata_env: Option<String>,
    /// UUID of the owning service, or None for a standalone VM.
    pub service_id: Option<Uuid>,
    /// Stable instance ordinal within the owning service (0..desired-1).
    pub service_ordinal: Option<u32>,
    /// VMM backend that created this VM ("firecracker" or "qemu").
    pub vmm: String,
    /// How the VM boots: "direct" (host kernel) or "uefi" (OVMF + cloud image).
    pub boot_mode: String,
}

/// Persistent port forward record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardRecord {
    pub id: i64,
    pub vm_id: Uuid,
    pub host_port: u16,
    pub guest_port: u16,
    pub protocol: String,
    pub created_at: DateTime<Utc>,
}

/// Persistent host group record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostGroupRecord {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Persistent service record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub id: Uuid,
    pub name: String,
    pub host_group_id: Option<Uuid>,
    pub desired_instances: u32,
    pub image: Option<String>,
    /// Concrete kernel path, resolved at create time (empty until set).
    pub kernel_path: String,
    /// Concrete rootfs path; authoritative boot source (empty until set).
    pub rootfs_path: String,
    pub initrd_path: Option<String>,
    pub vcpu_count: Option<u32>,
    pub mem_size_mib: Option<u32>,
    pub userdata: Option<String>,
    /// JSON-encoded Vec<(String,String)>.
    pub userdata_env: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Persistent snapshot record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub id: Uuid,
    pub name: String,
    pub source_vm_name: String,
    pub file_path: String,
    pub created_at: DateTime<Utc>,
}

/// Persistent image catalog record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRecord {
    pub id: Uuid,
    pub name: String,
    pub source_path: String,
    pub file_path: String,
    pub format: String,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
}

/// Persistent secret record (ciphertext only; plaintext never stored).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub id: Uuid,
    pub name: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// SQLite-backed state store. Thread-safe via internal Mutex.
pub struct StateStore {
    conn: Mutex<Connection>,
}

impl StateStore {
    /// Open or create the state database.
    pub fn open(path: &Path) -> Result<Self, StateError> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> Result<Self, StateError> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StateError> {
        self.conn.lock().map_err(|_| StateError::LockPoisoned)
    }

    fn migrate(&self) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vms (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL DEFAULT 'creating',
                pid INTEGER,
                vcpu_count INTEGER NOT NULL,
                mem_size_mib INTEGER NOT NULL,
                vsock_cid INTEGER NOT NULL,
                tap_device TEXT,
                host_ip TEXT,
                guest_ip TEXT,
                kernel_path TEXT NOT NULL,
                rootfs_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cid_allocator (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                next_cid INTEGER NOT NULL DEFAULT 3
            );

            INSERT OR IGNORE INTO cid_allocator (id, next_cid) VALUES (1, 3);

            CREATE TABLE IF NOT EXISTS freed_cids (
                cid INTEGER PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS port_forwards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vm_id TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
                host_port INTEGER NOT NULL UNIQUE,
                guest_port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS host_groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS services (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                host_group_id TEXT REFERENCES host_groups(id) ON DELETE SET NULL,
                desired_instances INTEGER NOT NULL DEFAULT 1,
                image TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                source_vm_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS images (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                source_path TEXT NOT NULL,
                file_path TEXT NOT NULL,
                format TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )?;

        // Migration: add userdata columns (idempotent via suppressed errors)
        let _ = conn.execute("ALTER TABLE vms ADD COLUMN userdata TEXT", []);
        let _ = conn.execute("ALTER TABLE vms ADD COLUMN userdata_status TEXT", []);
        let _ = conn.execute("ALTER TABLE vms ADD COLUMN userdata_env TEXT", []);

        // Migration: tag VMs with their owning service (idempotent).
        let _ = conn.execute("ALTER TABLE vms ADD COLUMN service_id TEXT", []);
        let _ = conn.execute("ALTER TABLE vms ADD COLUMN service_ordinal INTEGER", []);

        // Migration: record which VMM backend created each VM (idempotent).
        let _ = conn.execute(
            "ALTER TABLE vms ADD COLUMN vmm TEXT NOT NULL DEFAULT 'firecracker'",
            [],
        );

        // Migration: record the boot mode (idempotent). NOT NULL DEFAULT keeps
        // ADD COLUMN working on populated tables and back-fills legacy rows.
        let _ = conn.execute(
            "ALTER TABLE vms ADD COLUMN boot_mode TEXT NOT NULL DEFAULT 'direct'",
            [],
        );

        // Migration: service VM template columns (idempotent).
        // NOT NULL with DEFAULT '' so ADD COLUMN succeeds on tables with rows.
        let _ = conn.execute(
            "ALTER TABLE services ADD COLUMN kernel_path TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE services ADD COLUMN rootfs_path TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute("ALTER TABLE services ADD COLUMN initrd_path TEXT", []);
        let _ = conn.execute("ALTER TABLE services ADD COLUMN vcpu_count INTEGER", []);
        let _ = conn.execute("ALTER TABLE services ADD COLUMN mem_size_mib INTEGER", []);
        let _ = conn.execute("ALTER TABLE services ADD COLUMN userdata TEXT", []);
        let _ = conn.execute("ALTER TABLE services ADD COLUMN userdata_env TEXT", []);

        Ok(())
    }

    /// Insert a new VM record.
    ///
    /// Returns `StateError::VmAlreadyExists` if a VM with the same name exists.
    pub fn insert_vm(&self, record: &VmRecord) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO vms (id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                              tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                              created_at, updated_at, userdata, userdata_status, userdata_env,
                              service_id, service_ordinal, vmm, boot_mode)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
            params![
                record.id.to_string(),
                record.name,
                record.state,
                record.pid,
                record.vcpu_count,
                record.mem_size_mib,
                record.vsock_cid,
                record.tap_device,
                record.host_ip,
                record.guest_ip,
                record.kernel_path,
                record.rootfs_path,
                record.created_at.to_rfc3339(),
                record.updated_at.to_rfc3339(),
                record.userdata,
                record.userdata_status,
                record.userdata_env,
                record.service_id.map(|id| id.to_string()),
                record.service_ordinal,
                record.vmm,
                record.boot_mode,
            ],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(err, Some(msg))
                if err.code == rusqlite::ErrorCode::ConstraintViolation
                    && msg.contains("vms.name") =>
            {
                StateError::VmAlreadyExists(record.name.clone())
            }
            _ => StateError::Database(e),
        })?;
        Ok(())
    }

    /// Get a VM by its ID.
    pub fn get_vm(&self, id: Uuid) -> Result<VmRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                    tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                    created_at, updated_at, userdata, userdata_status, userdata_env,
                    service_id, service_ordinal, vmm, boot_mode
             FROM vms WHERE id = ?1",
            params![id.to_string()],
            row_to_vm_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::VmNotFound(id),
            other => StateError::Database(other),
        })
    }

    /// Get a VM by name.
    pub fn get_vm_by_name(&self, name: &str) -> Result<VmRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                    tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                    created_at, updated_at, userdata, userdata_status, userdata_env,
                    service_id, service_ordinal, vmm, boot_mode
             FROM vms WHERE name = ?1",
            params![name],
            row_to_vm_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::VmNotFoundByName(name.to_string()),
            other => StateError::Database(other),
        })
    }

    /// List all VMs.
    pub fn list_vms(&self) -> Result<Vec<VmRecord>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                    tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                    created_at, updated_at, userdata, userdata_status, userdata_env,
                    service_id, service_ordinal, vmm, boot_mode
             FROM vms ORDER BY created_at",
        )?;

        let records = stmt
            .query_map([], row_to_vm_record)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// List all VMs owned by a given service, ordered by ordinal.
    pub fn list_vms_for_service(&self, service_id: Uuid) -> Result<Vec<VmRecord>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                    tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                    created_at, updated_at, userdata, userdata_status, userdata_env,
                    service_id, service_ordinal, vmm, boot_mode
             FROM vms WHERE service_id = ?1 ORDER BY service_ordinal",
        )?;
        let records = stmt
            .query_map(params![service_id.to_string()], row_to_vm_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Update a VM's state.
    pub fn update_vm_state(&self, id: Uuid, state: &str) -> Result<(), StateError> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE vms SET state = ?1, updated_at = ?2 WHERE id = ?3",
            params![state, Utc::now().to_rfc3339(), id.to_string()],
        )?;
        if updated == 0 {
            return Err(StateError::VmNotFound(id));
        }
        Ok(())
    }

    /// Delete a VM record.
    pub fn delete_vm(&self, id: Uuid) -> Result<(), StateError> {
        let conn = self.lock()?;
        let deleted = conn.execute("DELETE FROM vms WHERE id = ?1", params![id.to_string()])?;
        if deleted == 0 {
            return Err(StateError::VmNotFound(id));
        }
        Ok(())
    }

    // ── Host Groups ───────────────────────────────────────────────────

    /// Insert a new host group record.
    pub fn insert_host_group(&self, record: &HostGroupRecord) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO host_groups (id, name, description, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.id.to_string(),
                record.name,
                record.description,
                record.created_at.to_rfc3339(),
                record.updated_at.to_rfc3339(),
            ],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                StateError::HostGroupAlreadyExists(record.name.clone())
            }
            _ => StateError::Database(e),
        })?;
        Ok(())
    }

    /// Get a host group by ID.
    pub fn get_host_group(&self, id: Uuid) -> Result<HostGroupRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, description, created_at, updated_at
             FROM host_groups WHERE id = ?1",
            params![id.to_string()],
            row_to_host_group_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::HostGroupNotFound(id),
            other => StateError::Database(other),
        })
    }

    /// Get a host group by name.
    pub fn get_host_group_by_name(&self, name: &str) -> Result<HostGroupRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, description, created_at, updated_at
             FROM host_groups WHERE name = ?1",
            params![name],
            row_to_host_group_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                StateError::HostGroupNotFoundByName(name.to_string())
            }
            other => StateError::Database(other),
        })
    }

    /// List all host groups.
    pub fn list_host_groups(&self) -> Result<Vec<HostGroupRecord>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, description, created_at, updated_at
             FROM host_groups ORDER BY created_at",
        )?;

        let records = stmt
            .query_map([], row_to_host_group_record)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// Delete a host group record.
    pub fn delete_host_group(&self, id: Uuid) -> Result<(), StateError> {
        let conn = self.lock()?;
        let deleted = conn.execute(
            "DELETE FROM host_groups WHERE id = ?1",
            params![id.to_string()],
        )?;
        if deleted == 0 {
            return Err(StateError::HostGroupNotFound(id));
        }
        Ok(())
    }

    // ── Services ──────────────────────────────────────────────────────

    /// Insert a new service record.
    pub fn insert_service(&self, record: &ServiceRecord) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO services (id, name, host_group_id, desired_instances, image,
                                   kernel_path, rootfs_path, initrd_path, vcpu_count,
                                   mem_size_mib, userdata, userdata_env, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                record.id.to_string(),
                record.name,
                record.host_group_id.map(|id| id.to_string()),
                record.desired_instances,
                record.image,
                record.kernel_path,
                record.rootfs_path,
                record.initrd_path,
                record.vcpu_count,
                record.mem_size_mib,
                record.userdata,
                record.userdata_env,
                record.created_at.to_rfc3339(),
                record.updated_at.to_rfc3339(),
            ],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                StateError::ServiceAlreadyExists(record.name.clone())
            }
            _ => StateError::Database(e),
        })?;
        Ok(())
    }

    /// Get a service by ID.
    pub fn get_service(&self, id: Uuid) -> Result<ServiceRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, host_group_id, desired_instances, image, kernel_path, rootfs_path,
                    initrd_path, vcpu_count, mem_size_mib, userdata, userdata_env,
                    created_at, updated_at
             FROM services WHERE id = ?1",
            params![id.to_string()],
            row_to_service_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::ServiceNotFound(id),
            other => StateError::Database(other),
        })
    }

    /// Get a service by name.
    pub fn get_service_by_name(&self, name: &str) -> Result<ServiceRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, host_group_id, desired_instances, image, kernel_path, rootfs_path,
                    initrd_path, vcpu_count, mem_size_mib, userdata, userdata_env,
                    created_at, updated_at
             FROM services WHERE name = ?1",
            params![name],
            row_to_service_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::ServiceNotFoundByName(name.into()),
            other => StateError::Database(other),
        })
    }

    /// List all services.
    pub fn list_services(&self) -> Result<Vec<ServiceRecord>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, host_group_id, desired_instances, image, kernel_path, rootfs_path,
                    initrd_path, vcpu_count, mem_size_mib, userdata, userdata_env,
                    created_at, updated_at
             FROM services ORDER BY created_at",
        )?;

        let records = stmt
            .query_map([], row_to_service_record)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// Update desired instance count for a service.
    pub fn update_service_desired_instances(
        &self,
        id: Uuid,
        desired_instances: u32,
    ) -> Result<(), StateError> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE services
             SET desired_instances = ?2, updated_at = ?3
             WHERE id = ?1",
            params![id.to_string(), desired_instances, Utc::now().to_rfc3339()],
        )?;
        if updated == 0 {
            return Err(StateError::ServiceNotFound(id));
        }
        Ok(())
    }

    /// Delete a service record.
    pub fn delete_service(&self, id: Uuid) -> Result<(), StateError> {
        let conn = self.lock()?;
        let deleted = conn.execute(
            "DELETE FROM services WHERE id = ?1",
            params![id.to_string()],
        )?;
        if deleted == 0 {
            return Err(StateError::ServiceNotFound(id));
        }
        Ok(())
    }

    // ── Snapshots ─────────────────────────────────────────────────────

    /// Insert a new snapshot record.
    pub fn insert_snapshot(&self, record: &SnapshotRecord) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO snapshots (id, name, source_vm_name, file_path, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.id.to_string(),
                record.name,
                record.source_vm_name,
                record.file_path,
                record.created_at.to_rfc3339(),
            ],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                StateError::SnapshotAlreadyExists(record.name.clone())
            }
            _ => StateError::Database(e),
        })?;
        Ok(())
    }

    /// Get a snapshot by ID.
    pub fn get_snapshot(&self, id: Uuid) -> Result<SnapshotRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, source_vm_name, file_path, created_at
             FROM snapshots WHERE id = ?1",
            params![id.to_string()],
            row_to_snapshot_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::SnapshotNotFound(id),
            other => StateError::Database(other),
        })
    }

    /// Get a snapshot by name.
    pub fn get_snapshot_by_name(&self, name: &str) -> Result<SnapshotRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, source_vm_name, file_path, created_at
             FROM snapshots WHERE name = ?1",
            params![name],
            row_to_snapshot_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::SnapshotNotFoundByName(name.into()),
            other => StateError::Database(other),
        })
    }

    /// List all snapshots.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotRecord>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, source_vm_name, file_path, created_at
             FROM snapshots ORDER BY created_at",
        )?;
        let records = stmt
            .query_map([], row_to_snapshot_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Delete a snapshot record.
    pub fn delete_snapshot(&self, id: Uuid) -> Result<(), StateError> {
        let conn = self.lock()?;
        let deleted = conn.execute(
            "DELETE FROM snapshots WHERE id = ?1",
            params![id.to_string()],
        )?;
        if deleted == 0 {
            return Err(StateError::SnapshotNotFound(id));
        }
        Ok(())
    }

    // ── Images ───────────────────────────────────────────────────────

    /// Insert a new image record.
    pub fn insert_image(&self, record: &ImageRecord) -> Result<(), StateError> {
        let size_bytes_i64 =
            i64::try_from(record.size_bytes).map_err(|_| StateError::CorruptData {
                column: "size_bytes",
                message: format!("value {} exceeds SQLite INTEGER range", record.size_bytes),
            })?;

        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO images (id, name, source_path, file_path, format, size_bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.id.to_string(),
                record.name,
                record.source_path,
                record.file_path,
                record.format,
                size_bytes_i64,
                record.created_at.to_rfc3339(),
            ],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                StateError::ImageAlreadyExists(record.name.clone())
            }
            _ => StateError::Database(e),
        })?;
        Ok(())
    }

    /// Get an image by ID.
    pub fn get_image(&self, id: Uuid) -> Result<ImageRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, source_path, file_path, format, size_bytes, created_at
             FROM images WHERE id = ?1",
            params![id.to_string()],
            row_to_image_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::ImageNotFound(id),
            other => StateError::Database(other),
        })
    }

    /// Get an image by name.
    pub fn get_image_by_name(&self, name: &str) -> Result<ImageRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, source_path, file_path, format, size_bytes, created_at
             FROM images WHERE name = ?1",
            params![name],
            row_to_image_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::ImageNotFoundByName(name.into()),
            other => StateError::Database(other),
        })
    }

    /// List all images.
    pub fn list_images(&self) -> Result<Vec<ImageRecord>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, source_path, file_path, format, size_bytes, created_at
             FROM images ORDER BY created_at",
        )?;
        let records = stmt
            .query_map([], row_to_image_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Delete an image record.
    pub fn delete_image(&self, id: Uuid) -> Result<(), StateError> {
        let conn = self.lock()?;
        let deleted = conn.execute("DELETE FROM images WHERE id = ?1", params![id.to_string()])?;
        if deleted == 0 {
            return Err(StateError::ImageNotFound(id));
        }
        Ok(())
    }

    // ── Secrets ──────────────────────────────────────────────────────

    /// Insert a new secret record.
    pub fn insert_secret(&self, record: &SecretRecord) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO secrets (id, name, ciphertext, nonce, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.id.to_string(),
                record.name,
                record.ciphertext,
                record.nonce,
                record.created_at.to_rfc3339(),
                record.updated_at.to_rfc3339(),
            ],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                StateError::SecretAlreadyExists(record.name.clone())
            }
            _ => StateError::Database(e),
        })?;
        Ok(())
    }

    /// Get a secret by ID.
    pub fn get_secret(&self, id: Uuid) -> Result<SecretRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, ciphertext, nonce, created_at, updated_at
             FROM secrets WHERE id = ?1",
            params![id.to_string()],
            row_to_secret_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::SecretNotFound(id),
            other => StateError::Database(other),
        })
    }

    /// Get a secret by name.
    pub fn get_secret_by_name(&self, name: &str) -> Result<SecretRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, ciphertext, nonce, created_at, updated_at
             FROM secrets WHERE name = ?1",
            params![name],
            row_to_secret_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::SecretNotFoundByName(name.into()),
            other => StateError::Database(other),
        })
    }

    /// List all secrets.
    pub fn list_secrets(&self) -> Result<Vec<SecretRecord>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, ciphertext, nonce, created_at, updated_at
             FROM secrets ORDER BY created_at",
        )?;
        let records = stmt
            .query_map([], row_to_secret_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Update encrypted payload and nonce for a secret by ID.
    pub fn update_secret_payload(
        &self,
        id: Uuid,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<(), StateError> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE secrets
             SET ciphertext = ?2, nonce = ?3, updated_at = ?4
             WHERE id = ?1",
            params![id.to_string(), ciphertext, nonce, Utc::now().to_rfc3339()],
        )?;
        if updated == 0 {
            return Err(StateError::SecretNotFound(id));
        }
        Ok(())
    }

    /// Delete a secret record.
    pub fn delete_secret(&self, id: Uuid) -> Result<(), StateError> {
        let conn = self.lock()?;
        let deleted = conn.execute("DELETE FROM secrets WHERE id = ?1", params![id.to_string()])?;
        if deleted == 0 {
            return Err(StateError::SecretNotFound(id));
        }
        Ok(())
    }

    /// Allocate the next vsock CID.
    ///
    /// Reuses previously released CIDs (lowest first) before incrementing.
    /// CIDs start at 3 (0=hypervisor, 1=reserved, 2=host).
    pub fn allocate_cid(&self) -> Result<u32, StateError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;

        // Try freed CIDs first (lowest available)
        let freed: Option<u32> = tx
            .query_row(
                "SELECT cid FROM freed_cids ORDER BY cid LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();

        let cid = if let Some(cid) = freed {
            tx.execute("DELETE FROM freed_cids WHERE cid = ?1", params![cid])?;
            debug!(cid, "reusing freed CID");
            cid
        } else {
            let cid: u32 = tx.query_row(
                "SELECT next_cid FROM cid_allocator WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            tx.execute(
                "UPDATE cid_allocator SET next_cid = next_cid + 1 WHERE id = 1",
                [],
            )?;
            debug!(cid, "allocated new CID");
            cid
        };

        tx.commit()?;
        Ok(cid)
    }

    /// Raise the CID allocator's floor to `base` (never lowers it), so a second
    /// daemon configured with a distinct base hands out a disjoint CID range
    /// (and thus disjoint `husker<cid>` TAP names and vsock CIDs). CIDs 0-2 are
    /// reserved by vsock, so `base` is clamped to >= 3.
    pub fn ensure_cid_base(&self, base: u32) -> Result<(), StateError> {
        let base = base.max(3);
        let conn = self.lock()?;
        // Purge freed CIDs below the new floor so allocate_cid (which returns
        // the lowest freed entry first) cannot hand out a CID outside the
        // intended range, breaking the disjoint-range guarantee.
        conn.execute("DELETE FROM freed_cids WHERE cid < ?1", params![base])?;
        conn.execute(
            "UPDATE cid_allocator SET next_cid = MAX(next_cid, ?1) WHERE id = 1",
            params![base],
        )?;
        Ok(())
    }

    /// Release a vsock CID back to the pool.
    ///
    /// Idempotent — releasing an already-freed CID is a no-op.
    pub fn release_cid(&self, cid: u32) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO freed_cids (cid) VALUES (?1)",
            params![cid],
        )?;
        debug!(cid, "released CID");
        Ok(())
    }

    // ── Port Forwards ─────────────────────────────────────────────────

    /// Insert a new port forward record.
    ///
    /// Returns `StateError::PortAlreadyForwarded` if the host port is already in use.
    pub fn insert_port_forward(&self, record: &PortForwardRecord) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO port_forwards (vm_id, host_port, guest_port, protocol, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.vm_id.to_string(),
                record.host_port,
                record.guest_port,
                record.protocol,
                record.created_at.to_rfc3339(),
            ],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                StateError::PortAlreadyForwarded(record.host_port)
            }
            _ => StateError::Database(e),
        })?;
        Ok(())
    }

    /// Delete a port forward by host port.
    pub fn delete_port_forward(&self, host_port: u16) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM port_forwards WHERE host_port = ?1",
            params![host_port],
        )?;
        Ok(())
    }

    /// List all port forwards for a VM, ordered by host port.
    pub fn list_port_forwards_for_vm(
        &self,
        vm_id: Uuid,
    ) -> Result<Vec<PortForwardRecord>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, vm_id, host_port, guest_port, protocol, created_at
             FROM port_forwards WHERE vm_id = ?1 ORDER BY host_port",
        )?;
        let records = stmt
            .query_map(params![vm_id.to_string()], |row| {
                let vm_id_str: String = row.get(1)?;
                let created_str: String = row.get(5)?;
                Ok(PortForwardRecord {
                    id: row.get(0)?,
                    vm_id: parse_uuid(&vm_id_str)?,
                    host_port: row.get::<_, u32>(2)? as u16,
                    guest_port: row.get::<_, u32>(3)? as u16,
                    protocol: row.get(4)?,
                    created_at: parse_datetime(&created_str)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Update the userdata execution status for a VM.
    pub fn update_userdata_status(&self, id: Uuid, status: &str) -> Result<(), StateError> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE vms SET userdata_status = ?1, updated_at = ?2 WHERE id = ?3",
            params![status, Utc::now().to_rfc3339(), id.to_string()],
        )?;
        if updated == 0 {
            return Err(StateError::VmNotFound(id));
        }
        Ok(())
    }

    /// Mark all VMs in transient states (`running`, `creating`, `paused`) as `stopped`.
    ///
    /// Called on daemon startup to reconcile persisted state with reality —
    /// VMs cannot survive a daemon restart, so any that claim to be running
    /// or paused are stale. Returns the number of VMs that were transitioned.
    ///
    /// Also resets any `userdata_status = 'running'` to `'pending'` so that
    /// userdata interrupted by a daemon crash will be retried.
    pub fn mark_stale_vms_stopped(&self) -> Result<usize, StateError> {
        let conn = self.lock()?;
        let now = Utc::now().to_rfc3339();
        let count = conn.execute(
            "UPDATE vms SET state = 'stopped', updated_at = ?1
             WHERE state IN ('running', 'creating', 'paused')",
            params![now],
        )?;
        conn.execute(
            "UPDATE vms SET userdata_status = 'pending', updated_at = ?1
             WHERE userdata_status = 'running'",
            params![now],
        )?;
        Ok(count)
    }

    /// Create the partial unique index that prevents two VMs from claiming the
    /// same (service_id, service_ordinal). Idempotent. Must be called only after
    /// a core-level dedupe pass has removed any existing duplicates, since the
    /// index creation fails if duplicates already exist.
    pub fn create_service_ordinal_index(&self) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_vms_service_ordinal
               ON vms(service_id, service_ordinal)
               WHERE service_id IS NOT NULL AND service_ordinal IS NOT NULL;",
        )?;
        Ok(())
    }

    /// Delete all port forwards for a VM.
    pub fn delete_port_forwards_for_vm(&self, vm_id: Uuid) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM port_forwards WHERE vm_id = ?1",
            params![vm_id.to_string()],
        )?;
        Ok(())
    }
}

fn parse_uuid(s: &str) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn parse_datetime(s: &str) -> rusqlite::Result<DateTime<Utc>> {
    s.parse::<DateTime<Utc>>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn row_to_vm_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<VmRecord> {
    let id_str: String = row.get(0)?;
    let created_str: String = row.get(12)?;
    let updated_str: String = row.get(13)?;

    Ok(VmRecord {
        id: parse_uuid(&id_str)?,
        name: row.get(1)?,
        state: row.get(2)?,
        pid: row.get(3)?,
        vcpu_count: row.get(4)?,
        mem_size_mib: row.get(5)?,
        vsock_cid: row.get(6)?,
        tap_device: row.get(7)?,
        host_ip: row.get(8)?,
        guest_ip: row.get(9)?,
        kernel_path: row.get(10)?,
        rootfs_path: row.get(11)?,
        created_at: parse_datetime(&created_str)?,
        updated_at: parse_datetime(&updated_str)?,
        userdata: row.get(14)?,
        userdata_status: row.get(15)?,
        userdata_env: row.get(16)?,
        service_id: {
            let s: Option<String> = row.get(17)?;
            s.as_deref().map(parse_uuid).transpose()?
        },
        service_ordinal: {
            let raw: Option<i64> = row.get(18)?;
            match raw {
                None => None,
                Some(v) => Some(u32::try_from(v).map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        18,
                        rusqlite::types::Type::Integer,
                        format!("service_ordinal {v} out of u32 range").into(),
                    )
                })?),
            }
        },
        vmm: row.get(19)?,
        boot_mode: row.get(20)?,
    })
}

fn row_to_host_group_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<HostGroupRecord> {
    let id_str: String = row.get(0)?;
    let created_str: String = row.get(3)?;
    let updated_str: String = row.get(4)?;

    Ok(HostGroupRecord {
        id: parse_uuid(&id_str)?,
        name: row.get(1)?,
        description: row.get(2)?,
        created_at: parse_datetime(&created_str)?,
        updated_at: parse_datetime(&updated_str)?,
    })
}

fn row_to_service_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServiceRecord> {
    let id_str: String = row.get(0)?;
    let host_group_id_str: Option<String> = row.get(2)?;
    let created_str: String = row.get(12)?;
    let updated_str: String = row.get(13)?;

    Ok(ServiceRecord {
        id: parse_uuid(&id_str)?,
        name: row.get(1)?,
        host_group_id: host_group_id_str.as_deref().map(parse_uuid).transpose()?,
        desired_instances: row.get(3)?,
        image: row.get(4)?,
        kernel_path: row.get(5)?,
        rootfs_path: row.get(6)?,
        initrd_path: row.get(7)?,
        vcpu_count: row.get(8)?,
        mem_size_mib: row.get(9)?,
        userdata: row.get(10)?,
        userdata_env: row.get(11)?,
        created_at: parse_datetime(&created_str)?,
        updated_at: parse_datetime(&updated_str)?,
    })
}

fn row_to_snapshot_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<SnapshotRecord> {
    let id_str: String = row.get(0)?;
    let created_str: String = row.get(4)?;

    Ok(SnapshotRecord {
        id: parse_uuid(&id_str)?,
        name: row.get(1)?,
        source_vm_name: row.get(2)?,
        file_path: row.get(3)?,
        created_at: parse_datetime(&created_str)?,
    })
}

fn row_to_image_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ImageRecord> {
    let id_str: String = row.get(0)?;
    let created_str: String = row.get(6)?;
    let size_bytes: i64 = row.get(5)?;
    let size_bytes = u64::try_from(size_bytes)
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, size_bytes))?;

    Ok(ImageRecord {
        id: parse_uuid(&id_str)?,
        name: row.get(1)?,
        source_path: row.get(2)?,
        file_path: row.get(3)?,
        format: row.get(4)?,
        size_bytes,
        created_at: parse_datetime(&created_str)?,
    })
}

fn row_to_secret_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRecord> {
    let id_str: String = row.get(0)?;
    let created_str: String = row.get(4)?;
    let updated_str: String = row.get(5)?;

    Ok(SecretRecord {
        id: parse_uuid(&id_str)?,
        name: row.get(1)?,
        ciphertext: row.get(2)?,
        nonce: row.get(3)?,
        created_at: parse_datetime(&created_str)?,
        updated_at: parse_datetime(&updated_str)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(name: &str) -> VmRecord {
        VmRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            state: "running".into(),
            pid: Some(1234),
            vcpu_count: 2,
            mem_size_mib: 256,
            vsock_cid: 3,
            tap_device: Some("tap0".into()),
            host_ip: Some("172.20.0.1".into()),
            guest_ip: Some("172.20.0.2".into()),
            kernel_path: "/boot/vmlinux".into(),
            rootfs_path: "/images/rootfs.ext4".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            userdata: None,
            userdata_status: None,
            userdata_env: None,
            service_id: None,
            service_ordinal: None,
            vmm: "firecracker".into(),
            boot_mode: "direct".into(),
        }
    }

    fn make_host_group(name: &str) -> HostGroupRecord {
        HostGroupRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            description: Some(format!("{name} group")),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_service(name: &str, host_group_id: Option<Uuid>) -> ServiceRecord {
        ServiceRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            host_group_id,
            desired_instances: 1,
            image: Some("ghcr.io/example/service:latest".into()),
            kernel_path: String::new(),
            rootfs_path: String::new(),
            initrd_path: None,
            vcpu_count: None,
            mem_size_mib: None,
            userdata: None,
            userdata_env: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_snapshot(name: &str, source_vm_name: &str) -> SnapshotRecord {
        SnapshotRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            source_vm_name: source_vm_name.into(),
            file_path: format!("/tmp/husker-snapshots/{name}.ext4"),
            created_at: Utc::now(),
        }
    }

    fn make_image(name: &str) -> ImageRecord {
        ImageRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            source_path: format!("/tmp/source/{name}.ext4"),
            file_path: format!("/tmp/husker-images/{name}.ext4"),
            format: "ext4".into(),
            size_bytes: 1024,
            created_at: Utc::now(),
        }
    }

    fn make_secret(name: &str, payload: &[u8]) -> SecretRecord {
        SecretRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            ciphertext: payload.to_vec(),
            nonce: vec![7; 12],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn vmm_field_round_trips() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_record("qemu-vm");
        rec.vmm = "qemu".into();
        store.insert_vm(&rec).unwrap();
        let fetched = store.get_vm_by_name("qemu-vm").unwrap();
        assert_eq!(fetched.vmm, "qemu");
    }

    #[test]
    fn vmm_migration_default_applied() {
        // Simulate an older database that lacks the vmm column and verify
        // that after StateStore::open_memory() runs migrations, a VM inserted
        // via raw SQL (without vmm) gets the default "firecracker" value.
        let store = StateStore::open_memory().unwrap();

        // Insert a pre-vmm row by omitting the vmm column. The DEFAULT
        // 'firecracker' set by the migration must fill it.
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO vms (id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                                  tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                                  created_at, updated_at, userdata, userdata_status, userdata_env,
                                  service_id, service_ordinal)
                 VALUES ('11111111-1111-1111-1111-111111111111', 'legacy-vm', 'stopped',
                         NULL, 1, 128, 5, NULL, NULL, NULL, '/kernel', '/rootfs',
                         '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z',
                         NULL, NULL, NULL, NULL, NULL)",
                [],
            )
            .unwrap();
        }

        let fetched = store.get_vm_by_name("legacy-vm").unwrap();
        assert_eq!(
            fetched.vmm, "firecracker",
            "legacy row should default to firecracker"
        );
    }

    #[test]
    fn insert_and_get() {
        let store = StateStore::open_memory().unwrap();
        let rec = make_record("test-vm");
        store.insert_vm(&rec).unwrap();

        let fetched = store.get_vm(rec.id).unwrap();
        assert_eq!(fetched.name, "test-vm");
        assert_eq!(fetched.vcpu_count, 2);
    }

    #[test]
    fn get_by_name() {
        let store = StateStore::open_memory().unwrap();
        let rec = make_record("my-vm");
        store.insert_vm(&rec).unwrap();

        let fetched = store.get_vm_by_name("my-vm").unwrap();
        assert_eq!(fetched.id, rec.id);
    }

    #[test]
    fn list_vms() {
        let store = StateStore::open_memory().unwrap();
        store.insert_vm(&make_record("vm-a")).unwrap();
        store.insert_vm(&make_record("vm-b")).unwrap();

        let list = store.list_vms().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn update_state() {
        let store = StateStore::open_memory().unwrap();
        let rec = make_record("state-test");
        store.insert_vm(&rec).unwrap();

        store.update_vm_state(rec.id, "stopped").unwrap();
        let fetched = store.get_vm(rec.id).unwrap();
        assert_eq!(fetched.state, "stopped");
    }

    #[test]
    fn delete_vm() {
        let store = StateStore::open_memory().unwrap();
        let rec = make_record("delete-me");
        store.insert_vm(&rec).unwrap();
        store.delete_vm(rec.id).unwrap();
        assert!(store.get_vm(rec.id).is_err());
    }

    #[test]
    fn cid_allocation() {
        let store = StateStore::open_memory().unwrap();
        assert_eq!(store.allocate_cid().unwrap(), 3);
        assert_eq!(store.allocate_cid().unwrap(), 4);
        assert_eq!(store.allocate_cid().unwrap(), 5);
    }

    #[test]
    fn ensure_cid_base_raises_floor_only() {
        let store = StateStore::open_memory().unwrap();
        store.ensure_cid_base(1000).unwrap();
        assert_eq!(store.allocate_cid().unwrap(), 1000);
        assert_eq!(store.allocate_cid().unwrap(), 1001);
        // A lower base never rewinds the allocator.
        store.ensure_cid_base(5).unwrap();
        assert_eq!(store.allocate_cid().unwrap(), 1002);
        // Below the reserved floor is clamped to >= 3.
        let store2 = StateStore::open_memory().unwrap();
        store2.ensure_cid_base(0).unwrap();
        assert_eq!(store2.allocate_cid().unwrap(), 3);
        // A freed CID below the new base must not be handed out.
        let store3 = StateStore::open_memory().unwrap();
        let _ = store3.allocate_cid().unwrap(); // 3
        store3.release_cid(3).unwrap(); // freed: {3}
        store3.ensure_cid_base(1000).unwrap();
        assert_eq!(
            store3.allocate_cid().unwrap(),
            1000,
            "freed CID below base must not be returned"
        );
    }

    #[test]
    fn vm_not_found() {
        let store = StateStore::open_memory().unwrap();
        let result = store.get_vm(Uuid::new_v4());
        assert!(matches!(result, Err(StateError::VmNotFound(_))));
    }

    #[test]
    fn roundtrip_preserves_timestamps() {
        let store = StateStore::open_memory().unwrap();
        let rec = make_record("ts-test");
        let original_created = rec.created_at;
        store.insert_vm(&rec).unwrap();

        let fetched = store.get_vm(rec.id).unwrap();
        // RFC3339 roundtrip loses sub-nanosecond precision, compare seconds
        assert_eq!(fetched.created_at.timestamp(), original_created.timestamp());
    }

    #[test]
    fn vm_not_found_by_name() {
        let store = StateStore::open_memory().unwrap();
        let result = store.get_vm_by_name("nonexistent");
        assert!(matches!(result, Err(StateError::VmNotFoundByName(_))));
    }

    // ── CID Recycling ──────────────────────────────────────────────────

    #[test]
    fn cid_release_and_reuse() {
        let store = StateStore::open_memory().unwrap();
        let cid1 = store.allocate_cid().unwrap(); // 3
        let cid2 = store.allocate_cid().unwrap(); // 4
        assert_eq!(cid1, 3);
        assert_eq!(cid2, 4);

        // Release CID 3
        store.release_cid(cid1).unwrap();

        // Next allocation reuses CID 3
        let reused = store.allocate_cid().unwrap();
        assert_eq!(reused, 3);

        // Then fresh CID 5
        let fresh = store.allocate_cid().unwrap();
        assert_eq!(fresh, 5);
    }

    #[test]
    fn cid_release_reuses_lowest() {
        let store = StateStore::open_memory().unwrap();
        let cid3 = store.allocate_cid().unwrap(); // 3
        let _cid4 = store.allocate_cid().unwrap(); // 4
        let cid5 = store.allocate_cid().unwrap(); // 5

        // Release 5 then 3
        store.release_cid(cid5).unwrap();
        store.release_cid(cid3).unwrap();

        // Lowest freed (3) is reused first
        assert_eq!(store.allocate_cid().unwrap(), 3);
        assert_eq!(store.allocate_cid().unwrap(), 5);
        // Then fresh
        assert_eq!(store.allocate_cid().unwrap(), 6);
    }

    #[test]
    fn cid_double_release_is_idempotent() {
        let store = StateStore::open_memory().unwrap();
        let cid = store.allocate_cid().unwrap();

        store.release_cid(cid).unwrap();
        // Double release should not error
        store.release_cid(cid).unwrap();

        // Only allocated once on reuse
        assert_eq!(store.allocate_cid().unwrap(), cid);
        // Next is fresh, not cid again
        assert_eq!(store.allocate_cid().unwrap(), 4);
    }

    // ── Duplicate Name ─────────────────────────────────────────────────

    #[test]
    fn duplicate_name_rejected() {
        let store = StateStore::open_memory().unwrap();
        store.insert_vm(&make_record("dup")).unwrap();

        let mut dup = make_record("dup");
        dup.id = Uuid::new_v4(); // different ID, same name
        let err = store.insert_vm(&dup).unwrap_err();
        assert!(
            matches!(err, StateError::VmAlreadyExists(ref name) if name == "dup"),
            "expected VmAlreadyExists, got: {err}"
        );
    }

    // ── Update / Delete Edge Cases ─────────────────────────────────────

    #[test]
    fn update_state_nonexistent_vm() {
        let store = StateStore::open_memory().unwrap();
        let result = store.update_vm_state(Uuid::new_v4(), "stopped");
        assert!(matches!(result, Err(StateError::VmNotFound(_))));
    }

    #[test]
    fn delete_nonexistent_vm() {
        let store = StateStore::open_memory().unwrap();
        let result = store.delete_vm(Uuid::new_v4());
        assert!(matches!(result, Err(StateError::VmNotFound(_))));
    }

    #[test]
    fn update_state_updates_timestamp() {
        let store = StateStore::open_memory().unwrap();
        let rec = make_record("ts-update");
        store.insert_vm(&rec).unwrap();

        let before = store.get_vm(rec.id).unwrap().updated_at;
        std::thread::sleep(std::time::Duration::from_millis(10));
        store.update_vm_state(rec.id, "stopped").unwrap();
        let after = store.get_vm(rec.id).unwrap().updated_at;

        assert!(after >= before);
    }

    // ── File-backed Store ──────────────────────────────────────────────

    #[test]
    fn file_backed_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let id;
        {
            let store = StateStore::open(&db_path).unwrap();
            let rec = make_record("persistent");
            id = rec.id;
            store.insert_vm(&rec).unwrap();
        }

        // Reopen and verify data persists
        let store = StateStore::open(&db_path).unwrap();
        let fetched = store.get_vm(id).unwrap();
        assert_eq!(fetched.name, "persistent");
    }

    // ── Port Forward CRUD ─────────────────────────────────────────────

    fn make_port_forward(vm_id: Uuid, host_port: u16, guest_port: u16) -> PortForwardRecord {
        PortForwardRecord {
            id: 0,
            vm_id,
            host_port,
            guest_port,
            protocol: "tcp".into(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn insert_and_list_port_forwards() {
        let store = StateStore::open_memory().unwrap();
        let vm = make_record("pf-vm");
        store.insert_vm(&vm).unwrap();

        store
            .insert_port_forward(&make_port_forward(vm.id, 8080, 80))
            .unwrap();
        store
            .insert_port_forward(&make_port_forward(vm.id, 8443, 443))
            .unwrap();

        let forwards = store.list_port_forwards_for_vm(vm.id).unwrap();
        assert_eq!(forwards.len(), 2);
        assert_eq!(forwards[0].host_port, 8080);
        assert_eq!(forwards[0].guest_port, 80);
        assert_eq!(forwards[1].host_port, 8443);
        assert_eq!(forwards[1].guest_port, 443);
    }

    #[test]
    fn duplicate_host_port_rejected() {
        let store = StateStore::open_memory().unwrap();
        let vm = make_record("pf-dup");
        store.insert_vm(&vm).unwrap();

        store
            .insert_port_forward(&make_port_forward(vm.id, 8080, 80))
            .unwrap();

        let err = store
            .insert_port_forward(&make_port_forward(vm.id, 8080, 8080))
            .unwrap_err();
        assert!(
            matches!(err, StateError::PortAlreadyForwarded(8080)),
            "expected PortAlreadyForwarded(8080), got: {err}"
        );
    }

    #[test]
    fn delete_port_forward() {
        let store = StateStore::open_memory().unwrap();
        let vm = make_record("pf-del");
        store.insert_vm(&vm).unwrap();

        store
            .insert_port_forward(&make_port_forward(vm.id, 8080, 80))
            .unwrap();
        store
            .insert_port_forward(&make_port_forward(vm.id, 9090, 90))
            .unwrap();

        store.delete_port_forward(8080).unwrap();

        let forwards = store.list_port_forwards_for_vm(vm.id).unwrap();
        assert_eq!(forwards.len(), 1);
        assert_eq!(forwards[0].host_port, 9090);
    }

    #[test]
    fn delete_port_forwards_for_vm() {
        let store = StateStore::open_memory().unwrap();
        let vm1 = make_record("pf-vm1");
        let vm2 = make_record("pf-vm2");
        store.insert_vm(&vm1).unwrap();
        store.insert_vm(&vm2).unwrap();

        store
            .insert_port_forward(&make_port_forward(vm1.id, 8080, 80))
            .unwrap();
        store
            .insert_port_forward(&make_port_forward(vm1.id, 8443, 443))
            .unwrap();
        store
            .insert_port_forward(&make_port_forward(vm2.id, 9090, 90))
            .unwrap();

        store.delete_port_forwards_for_vm(vm1.id).unwrap();

        assert!(store.list_port_forwards_for_vm(vm1.id).unwrap().is_empty());
        assert_eq!(store.list_port_forwards_for_vm(vm2.id).unwrap().len(), 1);
    }

    #[test]
    fn cascade_delete_removes_port_forwards() {
        let store = StateStore::open_memory().unwrap();
        let vm = make_record("pf-cascade");
        store.insert_vm(&vm).unwrap();

        store
            .insert_port_forward(&make_port_forward(vm.id, 8080, 80))
            .unwrap();
        store
            .insert_port_forward(&make_port_forward(vm.id, 8443, 443))
            .unwrap();

        // Deleting the VM should cascade to port_forwards
        store.delete_vm(vm.id).unwrap();

        let forwards = store.list_port_forwards_for_vm(vm.id).unwrap();
        assert!(forwards.is_empty());
    }

    #[test]
    fn list_port_forwards_empty() {
        let store = StateStore::open_memory().unwrap();
        let vm = make_record("pf-empty");
        store.insert_vm(&vm).unwrap();

        let forwards = store.list_port_forwards_for_vm(vm.id).unwrap();
        assert!(forwards.is_empty());
    }

    // ── Stale VM Reconciliation ───────────────────────────────────────

    #[test]
    fn mark_stale_vms_stopped() {
        let store = StateStore::open_memory().unwrap();

        let running = make_record("vm-running");
        store.insert_vm(&running).unwrap();
        // make_record defaults to "running" state

        let mut creating = make_record("vm-creating");
        creating.state = "creating".into();
        store.insert_vm(&creating).unwrap();

        let mut paused = make_record("vm-paused");
        paused.state = "paused".into();
        store.insert_vm(&paused).unwrap();

        let mut stopped = make_record("vm-stopped");
        stopped.state = "stopped".into();
        store.insert_vm(&stopped).unwrap();

        let mut failed = make_record("vm-failed");
        failed.state = "failed".into();
        store.insert_vm(&failed).unwrap();

        let count = store.mark_stale_vms_stopped().unwrap();
        assert_eq!(
            count, 3,
            "should mark running + creating + paused as stopped"
        );

        assert_eq!(store.get_vm(running.id).unwrap().state, "stopped");
        assert_eq!(store.get_vm(creating.id).unwrap().state, "stopped");
        assert_eq!(store.get_vm(paused.id).unwrap().state, "stopped");
        assert_eq!(store.get_vm(stopped.id).unwrap().state, "stopped");
        assert_eq!(store.get_vm(failed.id).unwrap().state, "failed");
    }

    #[test]
    fn mark_stale_vms_noop_when_none_running() {
        let store = StateStore::open_memory().unwrap();

        let mut stopped = make_record("vm-stopped");
        stopped.state = "stopped".into();
        store.insert_vm(&stopped).unwrap();

        let count = store.mark_stale_vms_stopped().unwrap();
        assert_eq!(count, 0);
    }

    // ── Userdata ──────────────────────────────────────────────────────

    #[test]
    fn insert_and_get_with_userdata() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_record("ud-vm");
        rec.userdata = Some("#!/bin/sh\necho hello".into());
        rec.userdata_status = Some("pending".into());
        store.insert_vm(&rec).unwrap();

        let fetched = store.get_vm(rec.id).unwrap();
        assert_eq!(fetched.userdata.as_deref(), Some("#!/bin/sh\necho hello"));
        assert_eq!(fetched.userdata_status.as_deref(), Some("pending"));
    }

    #[test]
    fn insert_without_userdata_returns_none() {
        let store = StateStore::open_memory().unwrap();
        let rec = make_record("no-ud-vm");
        store.insert_vm(&rec).unwrap();

        let fetched = store.get_vm(rec.id).unwrap();
        assert!(fetched.userdata.is_none());
        assert!(fetched.userdata_status.is_none());
    }

    #[test]
    fn update_userdata_status() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_record("ud-status");
        rec.userdata = Some("#!/bin/sh".into());
        rec.userdata_status = Some("pending".into());
        store.insert_vm(&rec).unwrap();

        store.update_userdata_status(rec.id, "running").unwrap();
        assert_eq!(
            store.get_vm(rec.id).unwrap().userdata_status.as_deref(),
            Some("running")
        );

        store.update_userdata_status(rec.id, "completed").unwrap();
        assert_eq!(
            store.get_vm(rec.id).unwrap().userdata_status.as_deref(),
            Some("completed")
        );
    }

    #[test]
    fn update_userdata_status_nonexistent_vm() {
        let store = StateStore::open_memory().unwrap();
        let result = store.update_userdata_status(Uuid::new_v4(), "running");
        assert!(matches!(result, Err(StateError::VmNotFound(_))));
    }

    #[test]
    fn mark_stale_resets_running_userdata() {
        let store = StateStore::open_memory().unwrap();

        let mut rec = make_record("ud-stale");
        rec.userdata = Some("#!/bin/sh".into());
        rec.userdata_status = Some("running".into());
        store.insert_vm(&rec).unwrap();

        store.mark_stale_vms_stopped().unwrap();

        let fetched = store.get_vm(rec.id).unwrap();
        assert_eq!(fetched.state, "stopped");
        assert_eq!(fetched.userdata_status.as_deref(), Some("pending"));
    }

    #[test]
    fn mark_stale_preserves_completed_userdata() {
        let store = StateStore::open_memory().unwrap();

        let mut rec = make_record("ud-complete");
        rec.userdata = Some("#!/bin/sh".into());
        rec.userdata_status = Some("completed".into());
        store.insert_vm(&rec).unwrap();

        store.mark_stale_vms_stopped().unwrap();

        let fetched = store.get_vm(rec.id).unwrap();
        assert_eq!(fetched.userdata_status.as_deref(), Some("completed"));
    }

    // ── Host Groups ───────────────────────────────────────────────────

    #[test]
    fn insert_and_get_host_group() {
        let store = StateStore::open_memory().unwrap();
        let group = make_host_group("platform");
        store.insert_host_group(&group).unwrap();

        let fetched = store.get_host_group(group.id).unwrap();
        assert_eq!(fetched.name, "platform");
        assert_eq!(fetched.description.as_deref(), Some("platform group"));
    }

    #[test]
    fn get_host_group_by_name() {
        let store = StateStore::open_memory().unwrap();
        let group = make_host_group("edge");
        store.insert_host_group(&group).unwrap();

        let fetched = store.get_host_group_by_name("edge").unwrap();
        assert_eq!(fetched.id, group.id);
    }

    #[test]
    fn duplicate_host_group_name_rejected() {
        let store = StateStore::open_memory().unwrap();
        store.insert_host_group(&make_host_group("core")).unwrap();

        let dup = make_host_group("core");
        let err = store.insert_host_group(&dup).unwrap_err();
        assert!(
            matches!(err, StateError::HostGroupAlreadyExists(ref name) if name == "core"),
            "expected HostGroupAlreadyExists, got: {err}"
        );
    }

    #[test]
    fn delete_nonexistent_host_group() {
        let store = StateStore::open_memory().unwrap();
        let err = store.delete_host_group(Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, StateError::HostGroupNotFound(_)));
    }

    // ── Services ──────────────────────────────────────────────────────

    #[test]
    fn insert_and_list_services() {
        let store = StateStore::open_memory().unwrap();
        let group = make_host_group("service-hosts");
        store.insert_host_group(&group).unwrap();

        store
            .insert_service(&make_service("api", Some(group.id)))
            .unwrap();
        store
            .insert_service(&make_service("worker", Some(group.id)))
            .unwrap();

        let services = store.list_services().unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].name, "api");
        assert_eq!(services[1].name, "worker");
        assert_eq!(services[0].host_group_id, Some(group.id));
    }

    #[test]
    fn get_service_by_name() {
        let store = StateStore::open_memory().unwrap();
        let service = make_service("queue", None);
        store.insert_service(&service).unwrap();

        let fetched = store.get_service_by_name("queue").unwrap();
        assert_eq!(fetched.id, service.id);
        assert_eq!(fetched.desired_instances, 1);
    }

    #[test]
    fn duplicate_service_name_rejected() {
        let store = StateStore::open_memory().unwrap();
        store.insert_service(&make_service("cache", None)).unwrap();

        let dup = make_service("cache", None);
        let err = store.insert_service(&dup).unwrap_err();
        assert!(
            matches!(err, StateError::ServiceAlreadyExists(ref name) if name == "cache"),
            "expected ServiceAlreadyExists, got: {err}"
        );
    }

    #[test]
    fn delete_nonexistent_service() {
        let store = StateStore::open_memory().unwrap();
        let err = store.delete_service(Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, StateError::ServiceNotFound(_)));
    }

    #[test]
    fn update_service_desired_instances_persists() {
        let store = StateStore::open_memory().unwrap();
        let service = make_service("api", None);
        store.insert_service(&service).unwrap();

        store
            .update_service_desired_instances(service.id, 5)
            .unwrap();

        let fetched = store.get_service(service.id).unwrap();
        assert_eq!(fetched.desired_instances, 5);
    }

    #[test]
    fn update_nonexistent_service_desired_instances_returns_not_found() {
        let store = StateStore::open_memory().unwrap();
        let err = store
            .update_service_desired_instances(Uuid::new_v4(), 3)
            .unwrap_err();
        assert!(matches!(err, StateError::ServiceNotFound(_)));
    }

    #[test]
    fn deleting_host_group_nulls_service_reference() {
        let store = StateStore::open_memory().unwrap();
        let group = make_host_group("batch");
        store.insert_host_group(&group).unwrap();

        let service = make_service("etl", Some(group.id));
        store.insert_service(&service).unwrap();

        store.delete_host_group(group.id).unwrap();
        let fetched = store.get_service(service.id).unwrap();
        assert_eq!(fetched.host_group_id, None);
    }

    // ── Snapshots ─────────────────────────────────────────────────────

    #[test]
    fn insert_and_get_snapshot() {
        let store = StateStore::open_memory().unwrap();
        let snapshot = make_snapshot("base", "vm-a");
        store.insert_snapshot(&snapshot).unwrap();

        let fetched = store.get_snapshot(snapshot.id).unwrap();
        assert_eq!(fetched.name, "base");
        assert_eq!(fetched.source_vm_name, "vm-a");
    }

    #[test]
    fn get_snapshot_by_name() {
        let store = StateStore::open_memory().unwrap();
        let snapshot = make_snapshot("nightly", "vm-b");
        store.insert_snapshot(&snapshot).unwrap();

        let fetched = store.get_snapshot_by_name("nightly").unwrap();
        assert_eq!(fetched.id, snapshot.id);
    }

    #[test]
    fn list_snapshots_returns_all() {
        let store = StateStore::open_memory().unwrap();
        store
            .insert_snapshot(&make_snapshot("snap-a", "vm-a"))
            .unwrap();
        store
            .insert_snapshot(&make_snapshot("snap-b", "vm-b"))
            .unwrap();

        let snapshots = store.list_snapshots().unwrap();
        assert_eq!(snapshots.len(), 2);
    }

    #[test]
    fn duplicate_snapshot_name_rejected() {
        let store = StateStore::open_memory().unwrap();
        store
            .insert_snapshot(&make_snapshot("dup", "vm-a"))
            .unwrap();

        let err = store
            .insert_snapshot(&make_snapshot("dup", "vm-b"))
            .unwrap_err();
        assert!(
            matches!(err, StateError::SnapshotAlreadyExists(ref name) if name == "dup"),
            "expected SnapshotAlreadyExists, got: {err}"
        );
    }

    #[test]
    fn delete_nonexistent_snapshot() {
        let store = StateStore::open_memory().unwrap();
        let err = store.delete_snapshot(Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, StateError::SnapshotNotFound(_)));
    }

    // ── Images ───────────────────────────────────────────────────────

    #[test]
    fn insert_and_get_image() {
        let store = StateStore::open_memory().unwrap();
        let image = make_image("ubuntu-base");
        store.insert_image(&image).unwrap();

        let fetched = store.get_image(image.id).unwrap();
        assert_eq!(fetched.name, "ubuntu-base");
        assert_eq!(fetched.format, "ext4");
    }

    #[test]
    fn get_image_by_name() {
        let store = StateStore::open_memory().unwrap();
        let image = make_image("debian-base");
        store.insert_image(&image).unwrap();

        let fetched = store.get_image_by_name("debian-base").unwrap();
        assert_eq!(fetched.id, image.id);
    }

    #[test]
    fn list_images_returns_all() {
        let store = StateStore::open_memory().unwrap();
        store.insert_image(&make_image("img-a")).unwrap();
        store.insert_image(&make_image("img-b")).unwrap();

        let images = store.list_images().unwrap();
        assert_eq!(images.len(), 2);
    }

    #[test]
    fn duplicate_image_name_rejected() {
        let store = StateStore::open_memory().unwrap();
        store.insert_image(&make_image("dup")).unwrap();

        let err = store.insert_image(&make_image("dup")).unwrap_err();
        assert!(
            matches!(err, StateError::ImageAlreadyExists(ref name) if name == "dup"),
            "expected ImageAlreadyExists, got: {err}"
        );
    }

    #[test]
    fn delete_nonexistent_image() {
        let store = StateStore::open_memory().unwrap();
        let err = store.delete_image(Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, StateError::ImageNotFound(_)));
    }

    // ── Secrets ──────────────────────────────────────────────────────

    #[test]
    fn insert_and_get_secret() {
        let store = StateStore::open_memory().unwrap();
        let secret = make_secret("db-password", b"ciphertext");
        store.insert_secret(&secret).unwrap();

        let fetched = store.get_secret(secret.id).unwrap();
        assert_eq!(fetched.name, "db-password");
        assert_eq!(fetched.ciphertext, b"ciphertext");
    }

    #[test]
    fn get_secret_by_name() {
        let store = StateStore::open_memory().unwrap();
        let secret = make_secret("api-token", b"abc");
        store.insert_secret(&secret).unwrap();

        let fetched = store.get_secret_by_name("api-token").unwrap();
        assert_eq!(fetched.id, secret.id);
    }

    #[test]
    fn list_secrets_returns_all() {
        let store = StateStore::open_memory().unwrap();
        store.insert_secret(&make_secret("sec-a", b"a")).unwrap();
        store.insert_secret(&make_secret("sec-b", b"b")).unwrap();

        let secrets = store.list_secrets().unwrap();
        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn update_secret_payload_persists() {
        let store = StateStore::open_memory().unwrap();
        let secret = make_secret("rotated", b"old");
        store.insert_secret(&secret).unwrap();

        store
            .update_secret_payload(secret.id, b"new", &[1, 2, 3, 4])
            .unwrap();

        let fetched = store.get_secret(secret.id).unwrap();
        assert_eq!(fetched.ciphertext, b"new");
        assert_eq!(fetched.nonce, vec![1, 2, 3, 4]);
    }

    #[test]
    fn duplicate_secret_name_rejected() {
        let store = StateStore::open_memory().unwrap();
        store.insert_secret(&make_secret("dup", b"a")).unwrap();

        let err = store.insert_secret(&make_secret("dup", b"b")).unwrap_err();
        assert!(
            matches!(err, StateError::SecretAlreadyExists(ref name) if name == "dup"),
            "expected SecretAlreadyExists, got: {err}"
        );
    }

    #[test]
    fn delete_nonexistent_secret() {
        let store = StateStore::open_memory().unwrap();
        let err = store.delete_secret(Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, StateError::SecretNotFound(_)));
    }

    // ── Service VM template ───────────────────────────────────────────

    #[test]
    fn service_template_roundtrip() {
        let store = StateStore::open_memory().unwrap();
        let mut svc = make_service("web", None);
        svc.kernel_path = "/boot/vmlinux".into();
        svc.rootfs_path = "/images/web.ext4".into();
        svc.vcpu_count = Some(2);
        svc.mem_size_mib = Some(512);
        svc.userdata = Some("echo hi".into());
        store.insert_service(&svc).unwrap();

        let got = store.get_service_by_name("web").unwrap();
        assert_eq!(got.kernel_path, "/boot/vmlinux");
        assert_eq!(got.rootfs_path, "/images/web.ext4");
        assert_eq!(got.vcpu_count, Some(2));
        assert_eq!(got.mem_size_mib, Some(512));
        assert_eq!(got.userdata.as_deref(), Some("echo hi"));
    }

    // ── Service Ordinal Index ─────────────────────────────────────────

    #[test]
    fn create_service_ordinal_index_rejects_duplicate_ordinal() {
        let store = StateStore::open_memory().unwrap();
        store.create_service_ordinal_index().unwrap();
        let sid = Uuid::new_v4();
        let mut a = make_record("web-0");
        a.service_id = Some(sid);
        a.service_ordinal = Some(0);
        store.insert_vm(&a).unwrap();

        let mut dup = make_record("web-0-dup");
        dup.service_id = Some(sid);
        dup.service_ordinal = Some(0); // same (service_id, ordinal)
        let err = store.insert_vm(&dup).unwrap_err();
        assert!(matches!(err, StateError::Database(_)));
    }

    #[test]
    fn create_service_ordinal_index_allows_null_ordinals() {
        let store = StateStore::open_memory().unwrap();
        store.create_service_ordinal_index().unwrap();
        // Two standalone VMs (NULL service_id/ordinal) must not collide under the partial index.
        store.insert_vm(&make_record("a")).unwrap();
        store.insert_vm(&make_record("b")).unwrap();
        assert_eq!(store.list_vms().unwrap().len(), 2);
    }

    // ── Service ownership tags ────────────────────────────────────────

    #[test]
    fn vm_service_tags_roundtrip() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_record("svc-inst");
        let sid = Uuid::new_v4();
        rec.service_id = Some(sid);
        rec.service_ordinal = Some(0);
        store.insert_vm(&rec).unwrap();

        let fetched = store.get_vm(rec.id).unwrap();
        assert_eq!(fetched.service_id, Some(sid));
        assert_eq!(fetched.service_ordinal, Some(0));
    }

    #[test]
    fn list_vms_for_service_filters_by_owner() {
        let store = StateStore::open_memory().unwrap();
        let sid = Uuid::new_v4();
        let mut a = make_record("web-0");
        a.service_id = Some(sid);
        a.service_ordinal = Some(0);
        let mut b = make_record("web-1");
        b.service_id = Some(sid);
        b.service_ordinal = Some(1);
        let standalone = make_record("other"); // no service_id
        store.insert_vm(&a).unwrap();
        store.insert_vm(&b).unwrap();
        store.insert_vm(&standalone).unwrap();

        let owned = store.list_vms_for_service(sid).unwrap();
        assert_eq!(owned.len(), 2);
        assert!(owned.iter().all(|v| v.service_id == Some(sid)));
        assert_eq!(owned[0].service_ordinal, Some(0));
        assert_eq!(owned[1].service_ordinal, Some(1));
    }

    // ── boot_mode field ───────────────────────────────────────────────

    #[test]
    fn boot_mode_migration_default_applied() {
        // A row inserted via the raw column set (no boot_mode) must read back "direct".
        let store = StateStore::open_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO vms (id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                                  tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                                  created_at, updated_at, userdata, userdata_status, userdata_env,
                                  service_id, service_ordinal, vmm)
                 VALUES ('22222222-2222-2222-2222-222222222222', 'legacy', 'stopped',
                         NULL, 1, 128, 5, NULL, NULL, NULL, '/kernel', '/rootfs',
                         '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z',
                         NULL, NULL, NULL, NULL, NULL, 'qemu')",
                [],
            )
            .unwrap();
        }
        let rec = store.get_vm_by_name("legacy").unwrap();
        assert_eq!(rec.boot_mode, "direct");
    }

    #[test]
    fn insert_and_read_uefi_boot_mode() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_record("uefi-vm");
        rec.boot_mode = "uefi".to_string();
        store.insert_vm(&rec).unwrap();
        assert_eq!(store.get_vm_by_name("uefi-vm").unwrap().boot_mode, "uefi");
    }
}
