//! SQLite-backed persistent state store for VM records, CID allocation, port
//! forwards, host groups, and services.

use std::path::Path;

use chrono::{DateTime, Utc};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

/// A connection checked out of the pool. Derefs to `rusqlite::Connection`, so
/// every call site that used the old `MutexGuard<Connection>` is unchanged.
type PooledConn = r2d2::PooledConnection<SqliteConnectionManager>;

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
    #[error("pool not found by name: {0}")]
    PoolNotFoundByName(String),
    #[error("pool already exists: {0}")]
    PoolAlreadyExists(String),
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
    #[error("volume not found: {0}")]
    VolumeNotFound(Uuid),
    #[error("volume not found by name: {0}")]
    VolumeNotFoundByName(String),
    #[error("volume already exists: {0}")]
    VolumeAlreadyExists(String),
    #[error("volume '{volume}' is attached to VM '{vm}'")]
    VolumeAttached { volume: String, vm: String },
    #[error("port already forwarded: {0}")]
    PortAlreadyForwarded(u16),
    #[error("host-resource lease not found: {0}")]
    HostResourceLeaseNotFound(Uuid),
    #[error("VM record does not match host-resource lease: {0}")]
    HostResourceLeaseMismatch(Uuid),
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
    /// Whether a virtio memory balloon device was installed at boot.
    pub balloon: bool,
    /// Name of the persistent volume attached to this VM, or None.
    pub volume: Option<String>,
    /// Network mode: "nat" (husker-managed NAT) or "bridged" (LAN bridge via DHCP).
    pub network: String,
    /// Last control-plane interaction, debounced observability mirror of the
    /// in-memory activity signal used by the idle policy.
    pub last_activity_at: DateTime<Utc>,
    /// When the VM entered `suspended` (drives the reap timer). None = never
    /// suspended or suspended without stamping; treated as not-reapable.
    pub suspended_at: Option<DateTime<Utc>>,
    /// Idle policy: seconds of idle before suspend. None = policy disabled.
    pub idle_timeout_secs: Option<u64>,
    /// Idle policy: seconds suspended before reap. None/0 = never reap.
    pub suspend_ttl_secs: Option<u64>,
    /// Idle policy: whether the VM auto-resumes on activity/connect (default true).
    pub auto_resume: bool,
    /// Source VM this VM was forked from, or None. Fences reap of fork sources.
    pub forked_from: Option<Uuid>,
}

/// Persistent port forward record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardRecord {
    pub id: i64,
    pub vm_id: Uuid,
    pub host_port: u16,
    pub guest_port: u16,
    pub protocol: String,
    /// Host bind address for the userspace proxy (macOS). `None` means the
    /// platform default (127.0.0.1 on macOS; all-interfaces on Linux nftables).
    pub bind_addr: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Durable ownership of Linux host resources allocated before a VM record can
/// take ownership. A lease survives daemon restart until creation commits or
/// cleanup releases it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostResourceLease {
    pub id: Uuid,
    pub vm_name: String,
    pub vsock_cid: u32,
    pub tap_device: Option<String>,
    pub guest_ip: Option<String>,
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
    /// Cloud image name for UEFI-booted services (mutually exclusive with
    /// rootfs+kernel direct-boot). None for direct-kernel services.
    pub cloud_image: Option<String>,
    /// Disk size in bytes for cloud-image services. None uses the image default.
    pub disk_size: Option<u64>,
    /// Whether replacement instances for this service include a virtio balloon.
    pub balloon: bool,
    /// Name of the persistent volume attached to instances of this service, or None.
    pub volume: Option<String>,
}

/// Persistent hot-pool record. A pool is a pre-warmed, suspended template VM
/// that `run`/`job` fork fresh, isolated VMs from in sub-second instead of cold
/// booting. Direct-kernel / Firecracker only (fork is Firecracker-only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolRecord {
    pub id: Uuid,
    pub name: String,
    /// The suspended template VM that members are forked from.
    pub template_vm_id: Uuid,
    /// Concrete rootfs path the template booted from (the base image).
    pub rootfs_path: String,
    /// Concrete kernel path the template booted from.
    pub kernel_path: String,
    pub initrd_path: Option<String>,
    pub vcpu_count: Option<u32>,
    pub mem_size_mib: Option<u32>,
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
    /// Image kind: "rootfs" (raw ext4 for direct-kernel boot, the default)
    /// or "cloud-image" (qcow2 booted via UEFI/OVMF).
    pub kind: String,
    /// Kernel `init=` to boot this image with. Set by `import-oci` to the guest
    /// agent (agent-supervisor mode); `None` uses the default boot path.
    pub boot_init: Option<String>,
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

/// Persistent volume catalog record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeRecord {
    pub id: Uuid,
    pub name: String,
    pub file_path: String,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
}

/// SQLite-backed state store. Thread-safe via an internal connection pool: a
/// file-backed store uses several connections so concurrent requests are not
/// serialized through one lock (WAL gives concurrent readers + a single writer),
/// while an in-memory store uses a single connection so its ephemeral database
/// persists across checkouts.
pub struct StateStore {
    pool: r2d2::Pool<SqliteConnectionManager>,
}

/// Apply an idempotent `ALTER TABLE ... ADD COLUMN` migration.
///
/// SQLite reports "duplicate column name" when the column already exists (the
/// common case on an up-to-date database); that is the expected idempotent
/// no-op and is ignored. Any other error (I/O, read-only filesystem,
/// corruption) is propagated so a genuine migration failure surfaces at startup
/// instead of resurfacing later as a cryptic "no such column" on the first query.
fn add_column(conn: &Connection, sql: &str) -> rusqlite::Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(_, Some(msg)))
            if msg.contains("duplicate column name") =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Baseline schema version established by the idempotent `CREATE TABLE` /
/// `ADD COLUMN` block in [`StateStore::migrate`]. Every database - fresh, or one
/// created before versioning existed (`user_version` 0) - reaches this version.
///
/// From here on, every schema change is a numbered entry in [`MIGRATIONS`] and
/// is recorded in `PRAGMA user_version`, so the version fully describes the
/// schema. Do NOT extend the idempotent baseline block for new schema - add a
/// migration instead. (The block stays only to bootstrap any database to the
/// baseline, including ones that predate this system.)
const BASELINE_SCHEMA_VERSION: u32 = 1;

/// Ordered, one-shot migrations applied after the baseline, each bringing the
/// database TO its version number. Unlike the idempotent baseline these may be
/// non-additive (column rename/drop, type change, data backfill) and each runs
/// exactly once, in its own transaction, when `user_version` is below its
/// number. Append-only: never edit, reorder, or renumber a migration that has
/// shipped; keep the numbers strictly ascending and greater than the baseline.
const MIGRATIONS: &[(u32, &str)] = &[
    (
        2,
        "CREATE TABLE host_resource_leases (
            id TEXT PRIMARY KEY,
            vm_name TEXT NOT NULL UNIQUE,
            vsock_cid INTEGER NOT NULL UNIQUE,
            tap_device TEXT,
            guest_ip TEXT,
            created_at TEXT NOT NULL
        );",
    ),
    (
        3,
        "UPDATE vms
             SET volume = NULL
             WHERE volume IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM volumes WHERE name = vms.volume);

         UPDATE vms
             SET volume = NULL
             WHERE volume IS NOT NULL
               AND EXISTS (
                   SELECT 1 FROM vms AS keeper
                   WHERE keeper.volume = vms.volume
                     AND (keeper.created_at < vms.created_at
                          OR (keeper.created_at = vms.created_at AND keeper.id < vms.id))
               );

         CREATE UNIQUE INDEX idx_vms_volume
             ON vms(volume) WHERE volume IS NOT NULL;

         CREATE TRIGGER vms_volume_must_exist_on_insert
         BEFORE INSERT ON vms
         WHEN NEW.volume IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM volumes WHERE name = NEW.volume)
         BEGIN
             SELECT RAISE(ABORT, 'attached volume does not exist');
         END;

         CREATE TRIGGER vms_volume_must_exist_on_update
         BEFORE UPDATE OF volume ON vms
         WHEN NEW.volume IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM volumes WHERE name = NEW.volume)
         BEGIN
             SELECT RAISE(ABORT, 'attached volume does not exist');
         END;

         CREATE TRIGGER attached_volume_cannot_be_deleted
         BEFORE DELETE ON volumes
         WHEN EXISTS (SELECT 1 FROM vms WHERE volume = OLD.name)
         BEGIN
             SELECT RAISE(ABORT, 'volume is attached');
         END;",
    ),
];

/// Bring a database's schema version up to date: stamp the baseline onto a
/// database that predates versioning, then apply every migration newer than the
/// recorded `user_version`, in order, each in its own transaction so a
/// mid-migration failure rolls back cleanly. Idempotent - re-running applies
/// nothing already recorded, so an already-applied migration is never re-run
/// (which for an additive one would fail with a duplicate column).
fn apply_migrations(
    conn: &Connection,
    baseline: u32,
    migrations: &[(u32, &str)],
) -> rusqlite::Result<()> {
    debug_assert!(
        migrations.windows(2).all(|w| w[0].0 < w[1].0)
            && migrations.first().is_none_or(|m| m.0 > baseline),
        "migrations must be strictly ascending and greater than the baseline"
    );

    let mut current = conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? as u32;
    // A fresh or pre-versioning database (user_version 0) was just brought to
    // the baseline schema by migrate()'s idempotent block; record that so the
    // baseline is never re-bootstrapped as if it were a migration.
    if current < baseline {
        conn.execute_batch(&format!("PRAGMA user_version = {baseline};"))?;
        current = baseline;
    }
    for &(target, sql) in migrations {
        if target > current {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(sql)?;
            tx.execute_batch(&format!("PRAGMA user_version = {target};"))?;
            tx.commit()?;
            current = target;
        }
    }
    Ok(())
}

fn insert_vm_on(conn: &Connection, record: &VmRecord) -> Result<(), StateError> {
    if let Some(volume) = record.volume.as_deref() {
        let exists = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM volumes WHERE name = ?1)",
            params![volume],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            return Err(StateError::VolumeNotFoundByName(volume.to_string()));
        }
        if let Some(vm) = conn
            .query_row(
                "SELECT name FROM vms WHERE volume = ?1 LIMIT 1",
                params![volume],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Err(StateError::VolumeAttached {
                volume: volume.to_string(),
                vm,
            });
        }
    }

    let insert_result = conn.execute(
        "INSERT INTO vms (id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                          tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                          created_at, updated_at, userdata, userdata_status, userdata_env,
                          service_id, service_ordinal, vmm, boot_mode, balloon, volume,
                          network, last_activity_at, suspended_at, idle_timeout_secs,
                          suspend_ttl_secs, auto_resume, forked_from)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30)",
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
            record.balloon as i64,
            record.volume,
            record.network,
            record.last_activity_at.to_rfc3339(),
            record.suspended_at.map(|d| d.to_rfc3339()),
            record.idle_timeout_secs.map(|v| v as i64),
            record.suspend_ttl_secs.map(|v| v as i64),
            record.auto_resume as i64,
            record.forked_from.map(|u| u.to_string()),
        ],
    );
    if let Err(error) = insert_result {
        match &error {
            rusqlite::Error::SqliteFailure(err, Some(message))
                if err.code == rusqlite::ErrorCode::ConstraintViolation
                    && message.contains("vms.name") =>
            {
                return Err(StateError::VmAlreadyExists(record.name.clone()));
            }
            rusqlite::Error::SqliteFailure(err, Some(message))
                if err.code == rusqlite::ErrorCode::ConstraintViolation
                    && message.contains("vms.volume") =>
            {
                let volume = record.volume.clone().unwrap_or_default();
                let vm = conn.query_row(
                    "SELECT name FROM vms WHERE volume = ?1 LIMIT 1",
                    params![&volume],
                    |row| row.get::<_, String>(0),
                )?;
                return Err(StateError::VolumeAttached { volume, vm });
            }
            rusqlite::Error::SqliteFailure(err, Some(message))
                if err.code == rusqlite::ErrorCode::ConstraintViolation
                    && message.contains("attached volume does not exist") =>
            {
                return Err(StateError::VolumeNotFoundByName(
                    record.volume.clone().unwrap_or_default(),
                ));
            }
            _ => return Err(StateError::Database(error)),
        }
    }
    Ok(())
}

impl StateStore {
    /// Open or create the state database (file-backed, pooled for concurrency).
    pub fn open(path: &Path) -> Result<Self, StateError> {
        // WAL enables concurrent readers alongside a single writer; busy_timeout
        // lets a writer wait for the write lock instead of failing under
        // contention. foreign_keys is enforced per-connection.
        let manager = SqliteConnectionManager::file(path).with_init(|c| {
            c.execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
            )
        });
        let pool = r2d2::Pool::builder()
            .max_size(8)
            // SQLite connections are local and don't go stale like a network DB,
            // so skip the per-checkout test query.
            .test_on_check_out(false)
            .build(manager)
            .map_err(|_| StateError::LockPoisoned)?;
        let store = Self { pool };
        store.migrate()?;
        Ok(store)
    }

    /// Open an in-memory database (for testing).
    ///
    /// Uses a single-connection pool: an in-memory SQLite database lives only as
    /// long as its connection, so pooling multiple `:memory:` connections would
    /// each be a separate empty database. One connection keeps the store's data
    /// visible across every checkout, matching the previous single-`Connection`
    /// behavior.
    pub fn open_memory() -> Result<Self, StateError> {
        let manager = SqliteConnectionManager::memory()
            .with_init(|c| c.execute_batch("PRAGMA foreign_keys=ON;"));
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .test_on_check_out(false)
            .build(manager)
            .map_err(|_| StateError::LockPoisoned)?;
        let store = Self { pool };
        store.migrate()?;
        Ok(store)
    }

    fn lock(&self) -> Result<PooledConn, StateError> {
        self.pool.get().map_err(|_| StateError::LockPoisoned)
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
                updated_at TEXT NOT NULL,
                balloon INTEGER NOT NULL DEFAULT 0
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
                updated_at TEXT NOT NULL,
                cloud_image TEXT,
                disk_size INTEGER,
                balloon INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS pools (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                template_vm_id TEXT NOT NULL,
                rootfs_path TEXT NOT NULL,
                kernel_path TEXT NOT NULL,
                initrd_path TEXT,
                vcpu_count INTEGER,
                mem_size_mib INTEGER,
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
                kind TEXT NOT NULL DEFAULT 'rootfs',
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
            );

            CREATE TABLE IF NOT EXISTS volumes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                file_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );",
        )?;

        // Idempotent `ADD COLUMN` migrations. `add_column` treats the
        // "duplicate column name" error (column already present on an
        // up-to-date database) as a no-op and propagates any other error, so a
        // real failure surfaces here at startup rather than as a cryptic
        // "no such column" on the first query. Columns whose CREATE TABLE above
        // already defines them are re-listed here so older databases that
        // predate the column still get it; the duplicate-name no-op covers the
        // fresh-database case.
        const ADD_COLUMNS: &[&str] = &[
            // userdata execution columns
            "ALTER TABLE vms ADD COLUMN userdata TEXT",
            "ALTER TABLE vms ADD COLUMN userdata_status TEXT",
            "ALTER TABLE vms ADD COLUMN userdata_env TEXT",
            // owning-service tag
            "ALTER TABLE vms ADD COLUMN service_id TEXT",
            "ALTER TABLE vms ADD COLUMN service_ordinal INTEGER",
            // VMM backend that created the VM
            "ALTER TABLE vms ADD COLUMN vmm TEXT NOT NULL DEFAULT 'firecracker'",
            // boot mode; NOT NULL DEFAULT back-fills legacy rows
            "ALTER TABLE vms ADD COLUMN boot_mode TEXT NOT NULL DEFAULT 'direct'",
            // image catalog: kind + agent-supervisor boot init=
            "ALTER TABLE images ADD COLUMN kind TEXT NOT NULL DEFAULT 'rootfs'",
            "ALTER TABLE images ADD COLUMN boot_init TEXT",
            // service VM template columns; NOT NULL DEFAULT '' for populated tables
            "ALTER TABLE services ADD COLUMN kernel_path TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE services ADD COLUMN rootfs_path TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE services ADD COLUMN initrd_path TEXT",
            "ALTER TABLE services ADD COLUMN vcpu_count INTEGER",
            "ALTER TABLE services ADD COLUMN mem_size_mib INTEGER",
            "ALTER TABLE services ADD COLUMN userdata TEXT",
            "ALTER TABLE services ADD COLUMN userdata_env TEXT",
            // cloud-image service columns
            "ALTER TABLE services ADD COLUMN cloud_image TEXT",
            "ALTER TABLE services ADD COLUMN disk_size INTEGER",
            "ALTER TABLE services ADD COLUMN balloon INTEGER NOT NULL DEFAULT 0",
            // balloon flag for VMs; DEFAULT 0 reads legacy rows as false
            "ALTER TABLE vms ADD COLUMN balloon INTEGER NOT NULL DEFAULT 0",
            // persistent volume attachment (NULL = none)
            "ALTER TABLE vms ADD COLUMN volume TEXT",
            "ALTER TABLE services ADD COLUMN volume TEXT",
            // network mode; NOT NULL DEFAULT back-fills legacy rows
            "ALTER TABLE vms ADD COLUMN network TEXT NOT NULL DEFAULT 'nat'",
            // userspace-proxy bind address for port forwards
            "ALTER TABLE port_forwards ADD COLUMN bind_addr TEXT",
            // idle policy columns (all nullable; auto_resume back-fills to 1 = enabled)
            "ALTER TABLE vms ADD COLUMN last_activity_at TEXT",
            "ALTER TABLE vms ADD COLUMN suspended_at TEXT",
            "ALTER TABLE vms ADD COLUMN idle_timeout_secs INTEGER",
            "ALTER TABLE vms ADD COLUMN suspend_ttl_secs INTEGER",
            "ALTER TABLE vms ADD COLUMN auto_resume INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE vms ADD COLUMN forked_from TEXT",
        ];
        for sql in ADD_COLUMNS {
            add_column(&conn, sql)?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vms_forked_from ON vms(forked_from)",
            [],
        )?;
        // Per-VM port-forward lookups/deletes (`list_port_forwards_for_vm`,
        // `DELETE ... WHERE vm_id = ?`) and per-service VM enumeration
        // (`list_vms_for_service`) run in hot loops (destroy, idle-policy tick,
        // reconciler); index their filter columns so they don't full-scan as the
        // fleet grows.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_port_forwards_vm_id ON port_forwards(vm_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vms_service_id ON vms(service_id)",
            [],
        )?;

        // The idempotent block above has brought the schema to the baseline;
        // stamp the version and apply any newer numbered migrations.
        apply_migrations(&conn, BASELINE_SCHEMA_VERSION, MIGRATIONS)?;

        Ok(())
    }

    /// Insert a new VM record.
    ///
    /// Returns `StateError::VmAlreadyExists` if a VM with the same name exists.
    pub fn insert_vm(&self, record: &VmRecord) -> Result<(), StateError> {
        let conn = self.lock()?;
        insert_vm_on(&conn, record)
    }

    /// Get a VM by its ID.
    pub fn get_vm(&self, id: Uuid) -> Result<VmRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                    tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                    created_at, updated_at, userdata, userdata_status, userdata_env,
                    service_id, service_ordinal, vmm, boot_mode, balloon, volume,
                    network, last_activity_at, suspended_at, idle_timeout_secs,
                    suspend_ttl_secs, auto_resume, forked_from
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
                    service_id, service_ordinal, vmm, boot_mode, balloon, volume,
                    network, last_activity_at, suspended_at, idle_timeout_secs,
                    suspend_ttl_secs, auto_resume, forked_from
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
                    service_id, service_ordinal, vmm, boot_mode, balloon, volume,
                    network, last_activity_at, suspended_at, idle_timeout_secs,
                    suspend_ttl_secs, auto_resume, forked_from
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
                    service_id, service_ordinal, vmm, boot_mode, balloon, volume,
                    network, last_activity_at, suspended_at, idle_timeout_secs,
                    suspend_ttl_secs, auto_resume, forked_from
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

    /// Atomically update the lifecycle state and the VMM process that owns it.
    ///
    /// Snapshot suspend destroys the old process and restore starts a new one;
    /// persisting only the state would leave clients and crash recovery pointing
    /// at the pre-suspend PID.
    pub fn update_vm_runtime(
        &self,
        id: Uuid,
        state: &str,
        pid: Option<u32>,
    ) -> Result<(), StateError> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE vms SET state = ?1, pid = ?2, updated_at = ?3 WHERE id = ?4",
            params![state, pid, Utc::now().to_rfc3339(), id.to_string()],
        )?;
        if updated == 0 {
            return Err(StateError::VmNotFound(id));
        }
        Ok(())
    }

    /// Retire a VM's live runtime identity when it reaches the stopped state.
    ///
    /// State, PID, and suspend ownership are one lifecycle invariant: a stopped
    /// VM has no VMM process and no resumable suspend slot. Keeping this update
    /// atomic prevents callers from persisting a terminal state that still
    /// points at an obsolete process or remains fenced as suspended.
    pub fn mark_vm_stopped(&self, id: Uuid) -> Result<(), StateError> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE vms
             SET state = 'stopped', pid = NULL, suspended_at = NULL, updated_at = ?1
             WHERE id = ?2",
            params![Utc::now().to_rfc3339(), id.to_string()],
        )?;
        if updated == 0 {
            return Err(StateError::VmNotFound(id));
        }
        Ok(())
    }

    /// Clear a VM's host network fields (`tap_device`, `host_ip`, `guest_ip`)
    /// after its leaked resources have been reclaimed, keeping the (stopped)
    /// record. The record no longer references a freed TAP/IP, so a later
    /// same-name re-create replaces it without double-releasing.
    pub fn clear_vm_network_resources(&self, id: Uuid) -> Result<(), StateError> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE vms SET tap_device = NULL, host_ip = NULL, guest_ip = NULL, updated_at = ?2 \
             WHERE id = ?1",
            params![id.to_string(), Utc::now().to_rfc3339()],
        )?;
        if updated == 0 {
            return Err(StateError::VmNotFound(id));
        }
        Ok(())
    }

    /// Update the debounced last-activity mirror.
    pub fn touch_last_activity(&self, id: Uuid, at: DateTime<Utc>) -> Result<(), StateError> {
        let conn = self.lock()?;
        let n = conn.execute(
            "UPDATE vms SET last_activity_at = ?1 WHERE id = ?2",
            params![at.to_rfc3339(), id.to_string()],
        )?;
        if n == 0 {
            return Err(StateError::VmNotFound(id));
        }
        Ok(())
    }

    /// Set or clear the reap timer anchor.
    pub fn set_suspended_at(&self, id: Uuid, at: Option<DateTime<Utc>>) -> Result<(), StateError> {
        let conn = self.lock()?;
        let n = conn.execute(
            "UPDATE vms SET suspended_at = ?1 WHERE id = ?2",
            params![at.map(|d| d.to_rfc3339()), id.to_string()],
        )?;
        if n == 0 {
            return Err(StateError::VmNotFound(id));
        }
        Ok(())
    }

    /// Set the idle policy fields.
    pub fn set_idle_policy(
        &self,
        id: Uuid,
        idle_timeout_secs: Option<u64>,
        suspend_ttl_secs: Option<u64>,
        auto_resume: bool,
    ) -> Result<(), StateError> {
        let conn = self.lock()?;
        let n = conn.execute(
            "UPDATE vms SET idle_timeout_secs = ?1, suspend_ttl_secs = ?2, auto_resume = ?3 WHERE id = ?4",
            params![
                idle_timeout_secs.map(|v| v as i64),
                suspend_ttl_secs.map(|v| v as i64),
                auto_resume as i64,
                id.to_string()
            ],
        )?;
        if n == 0 {
            return Err(StateError::VmNotFound(id));
        }
        Ok(())
    }

    /// Count children forked from `source_id` that are in a non-terminal state.
    pub fn count_live_forks_of(&self, source_id: Uuid) -> Result<usize, StateError> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM vms WHERE forked_from = ?1 \
             AND state IN ('creating','running','paused','suspending','suspended')",
            params![source_id.to_string()],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// Persist the DHCP-assigned guest IP for a VM.
    ///
    /// Used by the lazy guest-IP discovery path for cloud (EFI-boot) VMs whose
    /// IP is not known at creation time.
    pub fn update_vm_guest_ip(&self, id: Uuid, ip: &str) -> Result<(), StateError> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE vms SET guest_ip = ?1, updated_at = ?2 WHERE id = ?3",
            params![ip, Utc::now().to_rfc3339(), id.to_string()],
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

    /// Atomically delete a VM and return its CID to the allocator. Until the
    /// deletion commits, the VM record remains the durable CID owner.
    pub fn retire_vm(&self, id: Uuid) -> Result<(), StateError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let cid = tx
            .query_row(
                "SELECT vsock_cid FROM vms WHERE id = ?1",
                params![id.to_string()],
                |row| row.get::<_, u32>(0),
            )
            .optional()?
            .ok_or(StateError::VmNotFound(id))?;
        tx.execute(
            "INSERT OR IGNORE INTO freed_cids (cid) VALUES (?1)",
            params![cid],
        )?;
        tx.execute("DELETE FROM vms WHERE id = ?1", params![id.to_string()])?;
        tx.commit()?;
        debug!(%id, cid, "retired VM and released CID");
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
        let disk_size_i64 = record
            .disk_size
            .map(i64::try_from)
            .transpose()
            .map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Integer,
                    "disk_size exceeds SQLite INTEGER range".into(),
                )
            })?;
        conn.execute(
            "INSERT INTO services (id, name, host_group_id, desired_instances, image,
                                   kernel_path, rootfs_path, initrd_path, vcpu_count,
                                   mem_size_mib, userdata, userdata_env, created_at, updated_at,
                                   cloud_image, disk_size, balloon, volume)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
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
                record.cloud_image,
                disk_size_i64,
                record.balloon as i64,
                record.volume,
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
                    created_at, updated_at, cloud_image, disk_size, balloon, volume
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
                    created_at, updated_at, cloud_image, disk_size, balloon, volume
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
                    created_at, updated_at, cloud_image, disk_size, balloon, volume
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

    // ── Pools ─────────────────────────────────────────────────────────

    /// Insert a new pool record.
    pub fn insert_pool(&self, record: &PoolRecord) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO pools (id, name, template_vm_id, rootfs_path, kernel_path,
                                initrd_path, vcpu_count, mem_size_mib, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.id.to_string(),
                record.name,
                record.template_vm_id.to_string(),
                record.rootfs_path,
                record.kernel_path,
                record.initrd_path,
                record.vcpu_count,
                record.mem_size_mib,
                record.created_at.to_rfc3339(),
                record.updated_at.to_rfc3339(),
            ],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                StateError::PoolAlreadyExists(record.name.clone())
            }
            _ => StateError::Database(e),
        })?;
        Ok(())
    }

    /// Get a pool by name.
    pub fn get_pool_by_name(&self, name: &str) -> Result<PoolRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, template_vm_id, rootfs_path, kernel_path, initrd_path,
                    vcpu_count, mem_size_mib, created_at, updated_at
             FROM pools WHERE name = ?1",
            params![name],
            row_to_pool_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::PoolNotFoundByName(name.into()),
            other => StateError::Database(other),
        })
    }

    /// List all pools, oldest first.
    pub fn list_pools(&self) -> Result<Vec<PoolRecord>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, template_vm_id, rootfs_path, kernel_path, initrd_path,
                    vcpu_count, mem_size_mib, created_at, updated_at
             FROM pools ORDER BY created_at",
        )?;
        let records = stmt
            .query_map([], row_to_pool_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Delete a pool record by name.
    pub fn delete_pool_by_name(&self, name: &str) -> Result<(), StateError> {
        let conn = self.lock()?;
        let deleted = conn.execute("DELETE FROM pools WHERE name = ?1", params![name])?;
        if deleted == 0 {
            return Err(StateError::PoolNotFoundByName(name.into()));
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
            "INSERT INTO images (id, name, source_path, file_path, format, kind, size_bytes, created_at, boot_init)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record.id.to_string(),
                record.name,
                record.source_path,
                record.file_path,
                record.format,
                record.kind,
                size_bytes_i64,
                record.created_at.to_rfc3339(),
                record.boot_init,
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
            "SELECT id, name, source_path, file_path, format, kind, size_bytes, created_at, boot_init
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
            "SELECT id, name, source_path, file_path, format, kind, size_bytes, created_at, boot_init
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
            "SELECT id, name, source_path, file_path, format, kind, size_bytes, created_at, boot_init
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
        // BEGIN IMMEDIATE takes the write lock up front so two concurrent
        // allocations (now possible with the connection pool) serialize on the
        // lock instead of both reading the same next_cid and one failing with a
        // write conflict. busy_timeout makes the loser wait rather than error.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

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

    /// Atomically allocate a CID and persist its creation-attempt owner.
    pub fn begin_host_resource_lease(
        &self,
        vm_name: &str,
    ) -> Result<HostResourceLease, StateError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let freed: Option<u32> = tx
            .query_row(
                "SELECT cid FROM freed_cids ORDER BY cid LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let vsock_cid = if let Some(cid) = freed {
            tx.execute("DELETE FROM freed_cids WHERE cid = ?1", params![cid])?;
            cid
        } else {
            let cid = tx.query_row(
                "SELECT next_cid FROM cid_allocator WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            tx.execute(
                "UPDATE cid_allocator SET next_cid = next_cid + 1 WHERE id = 1",
                [],
            )?;
            cid
        };

        let lease = HostResourceLease {
            id: Uuid::new_v4(),
            vm_name: vm_name.to_string(),
            vsock_cid,
            tap_device: None,
            guest_ip: None,
            created_at: Utc::now(),
        };
        tx.execute(
            "INSERT INTO host_resource_leases
                (id, vm_name, vsock_cid, tap_device, guest_ip, created_at)
             VALUES (?1, ?2, ?3, NULL, NULL, ?4)",
            params![
                lease.id.to_string(),
                lease.vm_name,
                lease.vsock_cid,
                lease.created_at.to_rfc3339(),
            ],
        )?;
        tx.commit()?;
        debug!(
            cid = lease.vsock_cid,
            vm = vm_name,
            "leased CID for VM creation"
        );
        Ok(lease)
    }

    /// List creation-attempt leases that still own host resources.
    pub fn list_host_resource_leases(&self) -> Result<Vec<HostResourceLease>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, vm_name, vsock_cid, tap_device, guest_ip, created_at
             FROM host_resource_leases ORDER BY created_at, id",
        )?;
        let leases = stmt
            .query_map([], |row| {
                let id: String = row.get(0)?;
                let created_at: String = row.get(5)?;
                Ok(HostResourceLease {
                    id: parse_uuid(&id)?,
                    vm_name: row.get(1)?,
                    vsock_cid: row.get(2)?,
                    tap_device: row.get(3)?,
                    guest_ip: row.get(4)?,
                    created_at: parse_datetime(&created_at)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(leases)
    }

    /// Persist the network identity a lease will create before touching the
    /// host, so restart recovery knows the exact TAP and address to reclaim.
    pub fn set_host_resource_lease_network(
        &self,
        id: Uuid,
        tap_device: Option<&str>,
        guest_ip: Option<&str>,
    ) -> Result<(), StateError> {
        let conn = self.lock()?;
        let updated = conn.execute(
            "UPDATE host_resource_leases SET tap_device = ?2, guest_ip = ?3 WHERE id = ?1",
            params![id.to_string(), tap_device, guest_ip],
        )?;
        if updated == 0 {
            return Err(StateError::HostResourceLeaseNotFound(id));
        }
        Ok(())
    }

    /// Atomically transfer a creation lease to its final VM record. The
    /// identity check prevents a caller from adopting another attempt's CID or
    /// network resources.
    pub fn commit_vm_from_host_resource_lease(
        &self,
        record: &VmRecord,
        lease_id: Uuid,
    ) -> Result<(), StateError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let lease = tx
            .query_row(
                "SELECT id, vm_name, vsock_cid, tap_device, guest_ip, created_at
                 FROM host_resource_leases WHERE id = ?1",
                params![lease_id.to_string()],
                |row| {
                    let id: String = row.get(0)?;
                    let created_at: String = row.get(5)?;
                    Ok(HostResourceLease {
                        id: parse_uuid(&id)?,
                        vm_name: row.get(1)?,
                        vsock_cid: row.get(2)?,
                        tap_device: row.get(3)?,
                        guest_ip: row.get(4)?,
                        created_at: parse_datetime(&created_at)?,
                    })
                },
            )
            .optional()?
            .ok_or(StateError::HostResourceLeaseNotFound(lease_id))?;
        if lease.vm_name != record.name
            || lease.vsock_cid != record.vsock_cid
            || lease.tap_device != record.tap_device
            || lease.guest_ip != record.guest_ip
        {
            return Err(StateError::HostResourceLeaseMismatch(lease_id));
        }

        insert_vm_on(&tx, record)?;
        tx.execute(
            "DELETE FROM host_resource_leases WHERE id = ?1",
            params![lease_id.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Release a creation lease and return its CID to the allocator atomically.
    pub fn release_host_resource_lease(&self, id: Uuid) -> Result<(), StateError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let cid: Option<u32> = tx
            .query_row(
                "SELECT vsock_cid FROM host_resource_leases WHERE id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(cid) = cid {
            tx.execute(
                "INSERT OR IGNORE INTO freed_cids (cid) VALUES (?1)",
                params![cid],
            )?;
            tx.execute(
                "DELETE FROM host_resource_leases WHERE id = ?1",
                params![id.to_string()],
            )?;
            debug!(cid, %id, "released host-resource lease");
        }
        tx.commit()?;
        Ok(())
    }

    // ── Port Forwards ─────────────────────────────────────────────────

    /// Insert a new port forward record.
    ///
    /// Returns `StateError::PortAlreadyForwarded` if the host port is already in use.
    pub fn insert_port_forward(&self, record: &PortForwardRecord) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO port_forwards (vm_id, host_port, guest_port, protocol, bind_addr, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.vm_id.to_string(),
                record.host_port,
                record.guest_port,
                record.protocol,
                record.bind_addr,
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
            "SELECT id, vm_id, host_port, guest_port, protocol, bind_addr, created_at
             FROM port_forwards WHERE vm_id = ?1 ORDER BY host_port",
        )?;
        let records = stmt
            .query_map(params![vm_id.to_string()], |row| {
                let vm_id_str: String = row.get(1)?;
                let created_str: String = row.get(6)?;
                Ok(PortForwardRecord {
                    id: row.get(0)?,
                    vm_id: parse_uuid(&vm_id_str)?,
                    host_port: row.get::<_, u32>(2)? as u16,
                    guest_port: row.get::<_, u32>(3)? as u16,
                    protocol: row.get(4)?,
                    bind_addr: row.get(5)?,
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
            "UPDATE vms
             SET state = 'stopped', pid = NULL, suspended_at = NULL, updated_at = ?1
             WHERE state IN ('running', 'creating', 'paused')",
            params![now],
        )?;
        // Terminal and suspended rows are not counted as stale transitions, but
        // none has a live VMM process after daemon restart. Clear legacy or
        // partially-persisted identities while preserving suspended_at for the
        // resumable suspended lifecycle.
        conn.execute(
            "UPDATE vms SET pid = NULL WHERE state IN ('stopped', 'failed', 'suspended')",
            [],
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

    /// Delete every port forward row. Used on macOS daemon startup, where
    /// userspace proxies do not survive a restart, so all rows are stale.
    pub fn clear_all_port_forwards(&self) -> Result<(), StateError> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM port_forwards", [])?;
        Ok(())
    }

    // ── Volumes ───────────────────────────────────────────────────────

    /// Insert a new volume record.
    ///
    /// Returns `StateError::VolumeAlreadyExists` if a volume with the same name exists.
    pub fn insert_volume(&self, record: &VolumeRecord) -> Result<(), StateError> {
        let size_bytes_i64 =
            i64::try_from(record.size_bytes).map_err(|_| StateError::CorruptData {
                column: "size_bytes",
                message: format!("value {} exceeds SQLite INTEGER range", record.size_bytes),
            })?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO volumes (id, name, file_path, size_bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.id.to_string(),
                record.name,
                record.file_path,
                size_bytes_i64,
                record.created_at.to_rfc3339(),
            ],
        )
        .map_err(|e| match &e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                StateError::VolumeAlreadyExists(record.name.clone())
            }
            _ => StateError::Database(e),
        })?;
        Ok(())
    }

    /// Get a volume by name.
    pub fn get_volume_by_name(&self, name: &str) -> Result<VolumeRecord, StateError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, name, file_path, size_bytes, created_at
             FROM volumes WHERE name = ?1",
            params![name],
            row_to_volume_record,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StateError::VolumeNotFoundByName(name.into()),
            other => StateError::Database(other),
        })
    }

    /// List all volumes.
    pub fn list_volumes(&self) -> Result<Vec<VolumeRecord>, StateError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, file_path, size_bytes, created_at
             FROM volumes ORDER BY created_at",
        )?;
        let records = stmt
            .query_map([], row_to_volume_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Delete a volume record by ID.
    pub fn delete_volume(&self, id: Uuid) -> Result<(), StateError> {
        let conn = self.lock()?;
        let deleted = conn.execute("DELETE FROM volumes WHERE id = ?1", params![id.to_string()])?;
        if deleted == 0 {
            return Err(StateError::VolumeNotFound(id));
        }
        Ok(())
    }

    /// Atomically remove an unattached volume from the catalog and return the
    /// deleted record. The immediate transaction serializes the holder check
    /// with deletion, while schema triggers prevent callers from bypassing it.
    pub fn delete_unattached_volume_by_name(&self, name: &str) -> Result<VolumeRecord, StateError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let record = tx
            .query_row(
                "SELECT id, name, file_path, size_bytes, created_at
                 FROM volumes WHERE name = ?1",
                params![name],
                row_to_volume_record,
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    StateError::VolumeNotFoundByName(name.to_string())
                }
                other => StateError::Database(other),
            })?;
        if let Some(vm) = tx
            .query_row(
                "SELECT name FROM vms WHERE volume = ?1 LIMIT 1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Err(StateError::VolumeAttached {
                volume: name.to_string(),
                vm,
            });
        }
        tx.execute(
            "DELETE FROM volumes WHERE id = ?1",
            params![record.id.to_string()],
        )?;
        tx.commit()?;
        Ok(record)
    }

    /// Find the first VM that currently has the named volume attached.
    ///
    /// Used to enforce single-attach exclusivity: a volume may be attached to
    /// at most one VM at a time. Returns `None` when no VM references the volume.
    pub fn find_vm_by_volume(&self, volume_name: &str) -> Result<Option<VmRecord>, StateError> {
        let conn = self.lock()?;
        let result = conn.query_row(
            "SELECT id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                    tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                    created_at, updated_at, userdata, userdata_status, userdata_env,
                    service_id, service_ordinal, vmm, boot_mode, balloon, volume,
                    network, last_activity_at, suspended_at, idle_timeout_secs,
                    suspend_ttl_secs, auto_resume, forked_from
             FROM vms WHERE volume = ?1 LIMIT 1",
            params![volume_name],
            row_to_vm_record,
        );
        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(other) => Err(StateError::Database(other)),
        }
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
    let created = parse_datetime(&created_str)?;

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
        created_at: created,
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
        balloon: {
            let raw: i64 = row.get(21)?;
            raw != 0
        },
        volume: row.get(22)?,
        network: row.get(23)?,
        last_activity_at: {
            let s: Option<String> = row.get(24)?;
            match s {
                Some(s) => parse_datetime(&s)?,
                None => created, // legacy rows: fall back to created_at
            }
        },
        suspended_at: {
            let s: Option<String> = row.get(25)?;
            s.map(|s| parse_datetime(&s)).transpose()?
        },
        idle_timeout_secs: row.get::<_, Option<i64>>(26)?.map(|v| v as u64),
        suspend_ttl_secs: row.get::<_, Option<i64>>(27)?.map(|v| v as u64),
        auto_resume: row.get::<_, i64>(28)? != 0,
        forked_from: {
            let s: Option<String> = row.get(29)?;
            s.as_deref().map(parse_uuid).transpose()?
        },
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

    let disk_size: Option<u64> = {
        let raw: Option<i64> = row.get(15)?;
        match raw {
            None => None,
            Some(v) => Some(
                u64::try_from(v).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(15, v))?,
            ),
        }
    };

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
        cloud_image: row.get(14)?,
        disk_size,
        balloon: {
            let raw: i64 = row.get(16)?;
            raw != 0
        },
        volume: row.get(17)?,
    })
}

fn row_to_pool_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<PoolRecord> {
    let id_str: String = row.get(0)?;
    let template_vm_id_str: String = row.get(2)?;
    let created_str: String = row.get(8)?;
    let updated_str: String = row.get(9)?;
    Ok(PoolRecord {
        id: parse_uuid(&id_str)?,
        name: row.get(1)?,
        template_vm_id: parse_uuid(&template_vm_id_str)?,
        rootfs_path: row.get(3)?,
        kernel_path: row.get(4)?,
        initrd_path: row.get(5)?,
        vcpu_count: row.get(6)?,
        mem_size_mib: row.get(7)?,
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
    let created_str: String = row.get(7)?;
    let size_bytes: i64 = row.get(6)?;
    let size_bytes = u64::try_from(size_bytes)
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(6, size_bytes))?;

    Ok(ImageRecord {
        id: parse_uuid(&id_str)?,
        name: row.get(1)?,
        source_path: row.get(2)?,
        file_path: row.get(3)?,
        format: row.get(4)?,
        kind: row.get(5)?,
        boot_init: row.get(8)?,
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

fn row_to_volume_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<VolumeRecord> {
    let id_str: String = row.get(0)?;
    let created_str: String = row.get(4)?;
    let size_bytes: i64 = row.get(3)?;
    let size_bytes = u64::try_from(size_bytes)
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, size_bytes))?;

    Ok(VolumeRecord {
        id: parse_uuid(&id_str)?,
        name: row.get(1)?,
        file_path: row.get(2)?,
        size_bytes,
        created_at: parse_datetime(&created_str)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_column_ignores_duplicate_but_propagates_real_errors() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (id TEXT);").unwrap();
        // First add succeeds.
        add_column(&conn, "ALTER TABLE t ADD COLUMN extra TEXT").unwrap();
        // Re-adding the same column is the idempotent no-op (duplicate column).
        add_column(&conn, "ALTER TABLE t ADD COLUMN extra TEXT").unwrap();
        // A genuine error (the table does not exist) must propagate, not be
        // swallowed the way the old `let _ = conn.execute(...)` did.
        assert!(add_column(&conn, "ALTER TABLE missing ADD COLUMN x TEXT").is_err());
    }

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
            balloon: false,
            volume: None,
            network: "nat".into(),
            last_activity_at: Utc::now(),
            suspended_at: None,
            idle_timeout_secs: None,
            suspend_ttl_secs: None,
            auto_resume: true,
            forked_from: None,
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
            cloud_image: None,
            disk_size: None,
            balloon: false,
            volume: None,
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
            kind: "rootfs".into(),
            boot_init: None,
            size_bytes: 1024,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn image_boot_init_round_trips() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_image("rust-sandbox");
        rec.boot_init = Some("/usr/local/bin/husker-agent".into());
        store.insert_image(&rec).unwrap();
        let got = store.get_image_by_name("rust-sandbox").unwrap();
        assert_eq!(
            got.boot_init.as_deref(),
            Some("/usr/local/bin/husker-agent")
        );
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
    fn clear_vm_network_resources_nulls_fields_and_keeps_record() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_record("crashed-vm");
        rec.state = "stopped".into();
        rec.tap_device = Some("tap-crashed".into());
        rec.host_ip = Some("192.0.2.1".into());
        rec.guest_ip = Some("192.0.2.2".into());
        store.insert_vm(&rec).unwrap();

        store.clear_vm_network_resources(rec.id).unwrap();

        let fetched = store.get_vm(rec.id).unwrap();
        assert_eq!(fetched.name, "crashed-vm", "record is kept");
        assert_eq!(fetched.state, "stopped", "non-network state preserved");
        assert!(fetched.tap_device.is_none(), "tap_device cleared");
        assert!(fetched.host_ip.is_none(), "host_ip cleared");
        assert!(fetched.guest_ip.is_none(), "guest_ip cleared");
    }

    #[test]
    fn clear_vm_network_resources_unknown_id_is_not_found() {
        let store = StateStore::open_memory().unwrap();
        let err = store
            .clear_vm_network_resources(Uuid::new_v4())
            .unwrap_err();
        assert!(matches!(err, StateError::VmNotFound(_)));
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
    fn update_runtime_replaces_state_and_pid_atomically() {
        let store = StateStore::open_memory().unwrap();
        let rec = make_record("runtime-test");
        store.insert_vm(&rec).unwrap();

        store.update_vm_runtime(rec.id, "suspended", None).unwrap();
        let suspended = store.get_vm(rec.id).unwrap();
        assert_eq!(suspended.state, "suspended");
        assert_eq!(suspended.pid, None);

        store
            .update_vm_runtime(rec.id, "running", Some(5678))
            .unwrap();
        let resumed = store.get_vm(rec.id).unwrap();
        assert_eq!(resumed.state, "running");
        assert_eq!(resumed.pid, Some(5678));
    }

    #[test]
    fn mark_vm_stopped_retires_runtime_and_suspend_identity() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_record("retired-runtime");
        rec.state = "suspended".into();
        rec.pid = Some(4242);
        rec.suspended_at = Some(Utc::now());
        store.insert_vm(&rec).unwrap();

        store.mark_vm_stopped(rec.id).unwrap();

        let stopped = store.get_vm(rec.id).unwrap();
        assert_eq!(stopped.state, "stopped");
        assert_eq!(stopped.pid, None);
        assert_eq!(stopped.suspended_at, None);
    }

    #[test]
    fn update_vm_guest_ip_persists() {
        let store = StateStore::open_memory().unwrap();
        let rec = make_record("ip-test");
        store.insert_vm(&rec).unwrap();

        store.update_vm_guest_ip(rec.id, "192.0.2.9").unwrap();
        let fetched = store.get_vm(rec.id).unwrap();
        assert_eq!(fetched.guest_ip.as_deref(), Some("192.0.2.9"));
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
    fn retiring_a_vm_releases_its_cid_with_the_record_deletion() {
        let store = StateStore::open_memory().unwrap();
        let cid = store.allocate_cid().unwrap();
        let mut rec = make_record("retire-me");
        rec.vsock_cid = cid;
        store.insert_vm(&rec).unwrap();

        store.retire_vm(rec.id).unwrap();

        assert!(matches!(
            store.get_vm(rec.id),
            Err(StateError::VmNotFound(_))
        ));
        assert_eq!(store.allocate_cid().unwrap(), cid);
    }

    #[test]
    fn vm_record_roundtrips_idle_policy_fields() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_record("idle-vm");
        rec.idle_timeout_secs = Some(1800);
        rec.suspend_ttl_secs = Some(3600);
        rec.auto_resume = false;
        rec.forked_from = None;
        store.insert_vm(&rec).unwrap();

        let got = store.get_vm_by_name("idle-vm").unwrap();
        assert_eq!(got.idle_timeout_secs, Some(1800));
        assert_eq!(got.suspend_ttl_secs, Some(3600));
        assert!(!got.auto_resume);
        assert_eq!(got.last_activity_at, rec.last_activity_at);
        assert_eq!(got.suspended_at, None);
    }

    #[test]
    fn setters_update_activity_suspend_and_policy() {
        let store = StateStore::open_memory().unwrap();
        let rec = make_record("s1");
        store.insert_vm(&rec).unwrap();
        let t = Utc::now();
        store.touch_last_activity(rec.id, t).unwrap();
        store.set_suspended_at(rec.id, Some(t)).unwrap();
        store
            .set_idle_policy(rec.id, Some(60), Some(120), true)
            .unwrap();
        let got = store.get_vm(rec.id).unwrap();
        assert_eq!(got.suspended_at.map(|d| d.timestamp()), Some(t.timestamp()));
        assert_eq!(got.idle_timeout_secs, Some(60));
        store.set_suspended_at(rec.id, None).unwrap();
        assert_eq!(store.get_vm(rec.id).unwrap().suspended_at, None);
    }

    #[test]
    fn count_live_forks_counts_only_non_terminal_children() {
        let store = StateStore::open_memory().unwrap();
        let src = make_record("src");
        store.insert_vm(&src).unwrap();
        let mut child = make_record("child");
        child.forked_from = Some(src.id);
        child.state = "running".into();
        store.insert_vm(&child).unwrap();
        let mut dead = make_record("dead");
        dead.forked_from = Some(src.id);
        dead.state = "stopped".into();
        store.insert_vm(&dead).unwrap();
        assert_eq!(store.count_live_forks_of(src.id).unwrap(), 1);
    }

    #[test]
    fn cid_allocation() {
        let store = StateStore::open_memory().unwrap();
        assert_eq!(store.allocate_cid().unwrap(), 3);
        assert_eq!(store.allocate_cid().unwrap(), 4);
        assert_eq!(store.allocate_cid().unwrap(), 5);
    }

    #[test]
    fn host_resource_lease_survives_restart_until_cleanup_releases_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");

        let abandoned = {
            let store = StateStore::open(&path).unwrap();
            store
                .begin_host_resource_lease("interrupted-create")
                .unwrap()
        };

        let store = StateStore::open(&path).unwrap();
        assert_eq!(
            store.list_host_resource_leases().unwrap(),
            vec![abandoned.clone()]
        );
        let next = store.begin_host_resource_lease("next-create").unwrap();
        assert_eq!(abandoned.vsock_cid, 3);
        assert_eq!(next.vsock_cid, 4, "the abandoned lease still owns CID 3");

        store.release_host_resource_lease(abandoned.id).unwrap();
        let reused = store.begin_host_resource_lease("after-cleanup").unwrap();
        assert_eq!(reused.vsock_cid, 3);
    }

    #[test]
    fn host_resource_lease_records_network_identity_before_host_setup() {
        let store = StateStore::open_memory().unwrap();
        let lease = store.begin_host_resource_lease("network-owner").unwrap();

        store
            .set_host_resource_lease_network(lease.id, Some("husker3"), Some("172.20.0.2"))
            .unwrap();

        let recorded = store.list_host_resource_leases().unwrap().remove(0);
        assert_eq!(recorded.tap_device.as_deref(), Some("husker3"));
        assert_eq!(recorded.guest_ip.as_deref(), Some("172.20.0.2"));
    }

    #[test]
    fn committing_a_vm_atomically_transfers_its_host_resource_lease() {
        let store = StateStore::open_memory().unwrap();
        let lease = store.begin_host_resource_lease("committed-vm").unwrap();
        store
            .set_host_resource_lease_network(lease.id, Some("husker3"), Some("172.20.0.2"))
            .unwrap();
        let mut vm = make_record("committed-vm");
        vm.vsock_cid = lease.vsock_cid;
        vm.tap_device = Some("husker3".into());
        vm.guest_ip = Some("172.20.0.2".into());

        store
            .commit_vm_from_host_resource_lease(&vm, lease.id)
            .unwrap();

        assert_eq!(store.get_vm(vm.id).unwrap().name, "committed-vm");
        assert!(store.list_host_resource_leases().unwrap().is_empty());
        assert_eq!(
            store
                .begin_host_resource_lease("next-vm")
                .unwrap()
                .vsock_cid,
            4,
            "the committed VM, not the journal, still owns CID 3"
        );
    }

    #[test]
    fn concurrent_allocate_cid_never_duplicates() {
        // The connection pool lets allocate_cid run on multiple connections at
        // once. Its read-then-write must stay atomic (BEGIN IMMEDIATE + busy
        // timeout) so no two concurrent allocations hand out the same CID. Uses a
        // file-backed store (the 8-connection pool; open_memory is single-conn).
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(&dir.path().join("cids.db")).unwrap());
        let n = 200usize;
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || s.allocate_cid().unwrap())
            })
            .collect();
        let cids: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let unique: std::collections::HashSet<u32> = cids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            n,
            "concurrent allocate_cid produced duplicate CIDs (race)"
        );
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
            bind_addr: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn port_forward_persists_bind_addr() {
        let store = StateStore::open_memory().unwrap();
        let vm = make_record("pf-bind");
        store.insert_vm(&vm).unwrap();
        let mut rec = make_port_forward(vm.id, 8080, 80);
        rec.bind_addr = Some("127.0.0.1".to_string());
        store.insert_port_forward(&rec).unwrap();
        let listed = store.list_port_forwards_for_vm(vm.id).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].bind_addr.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn clear_all_port_forwards_empties_table() {
        let store = StateStore::open_memory().unwrap();
        let vm = make_record("pf-clear");
        store.insert_vm(&vm).unwrap();
        store
            .insert_port_forward(&make_port_forward(vm.id, 8080, 80))
            .unwrap();
        store.clear_all_port_forwards().unwrap();
        assert!(store.list_port_forwards_for_vm(vm.id).unwrap().is_empty());
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

    #[test]
    fn stale_reconcile_retires_non_live_runtime_identities() {
        let store = StateStore::open_memory().unwrap();

        for state in [
            "running",
            "creating",
            "paused",
            "stopped",
            "failed",
            "suspended",
        ] {
            let mut vm = make_record(&format!("vm-{state}"));
            vm.state = state.into();
            vm.pid = Some(4242);
            store.insert_vm(&vm).unwrap();
        }

        store.mark_stale_vms_stopped().unwrap();

        for vm in store.list_vms().unwrap() {
            assert_eq!(
                vm.pid, None,
                "non-live VM '{}' in state '{}' retained a stale PID",
                vm.name, vm.state
            );
        }
    }

    #[test]
    fn suspended_vms_survive_stale_reconcile() {
        let store = StateStore::open_memory().unwrap();

        let running = make_record("vm-run");
        store.insert_vm(&running).unwrap();

        let mut suspended = make_record("vm-susp");
        suspended.state = "suspended".into();
        store.insert_vm(&suspended).unwrap();

        let marked = store.mark_stale_vms_stopped().unwrap();
        assert_eq!(marked, 1, "only the running VM is marked stopped");

        assert_eq!(store.get_vm(running.id).unwrap().state, "stopped");
        assert_eq!(
            store.get_vm(suspended.id).unwrap().state,
            "suspended",
            "suspend slot must survive daemon restart"
        );
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

    // ── images.kind field ─────────────────────────────────────────────

    #[test]
    fn image_kind_migration_default_applied() {
        // A row inserted via the legacy column set (no kind column) must read
        // back "rootfs" because the migration DEFAULT backfills it.
        let store = StateStore::open_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO images (id, name, source_path, file_path, format, size_bytes, created_at)
                 VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'legacy',
                         '/tmp/source/legacy.ext4', '/tmp/husker-images/legacy.ext4',
                         'ext4', 1024, '2024-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }
        let fetched = store.get_image_by_name("legacy").unwrap();
        assert_eq!(fetched.kind, "rootfs");
    }

    #[test]
    fn insert_and_read_uefi_boot_mode() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_record("uefi-vm");
        rec.boot_mode = "uefi".to_string();
        store.insert_vm(&rec).unwrap();
        assert_eq!(store.get_vm_by_name("uefi-vm").unwrap().boot_mode, "uefi");
    }

    // ── cloud-image service columns ───────────────────────────────────

    #[test]
    fn service_cloud_fields_roundtrip_and_default_null() {
        let store = StateStore::open_memory().unwrap();

        // Roundtrip: Some values survive insert + fetch.
        let mut svc = make_service("cloudy", None);
        svc.cloud_image = Some("ubuntu-2404".into());
        svc.disk_size = Some(10 * 1024 * 1024 * 1024);
        svc.balloon = true;
        store.insert_service(&svc).unwrap();
        let got = store.get_service_by_name("cloudy").unwrap();
        assert_eq!(got.cloud_image.as_deref(), Some("ubuntu-2404"));
        assert_eq!(got.disk_size, Some(10 * 1024 * 1024 * 1024));
        assert!(got.balloon);

        // Legacy row: a raw insert omitting cloud_image/disk_size/balloon reads
        // back as None/None/false because of the migration DEFAULT values.
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO services
                     (id, name, desired_instances, kernel_path, rootfs_path,
                      created_at, updated_at)
                 VALUES
                     ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'legacy-svc', 1, '', '',
                      '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }
        let legacy = store.get_service_by_name("legacy-svc").unwrap();
        assert_eq!(
            legacy.cloud_image, None,
            "legacy row must have cloud_image = None"
        );
        assert_eq!(
            legacy.disk_size, None,
            "legacy row must have disk_size = None"
        );
        assert!(!legacy.balloon, "legacy row must have balloon = false");
    }

    // ── vms.balloon migration default ────────────────────────────────

    #[test]
    fn vm_balloon_migration_default_applied() {
        // A row inserted without the balloon column must read back as false
        // because the migration DEFAULT 0 backfills it.
        let store = StateStore::open_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO vms (id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                                  tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                                  created_at, updated_at, userdata, userdata_status, userdata_env,
                                  service_id, service_ordinal, vmm, boot_mode)
                 VALUES ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'legacy-balloon', 'stopped',
                         NULL, 1, 128, 5, NULL, NULL, NULL, '/kernel', '/rootfs',
                         '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z',
                         NULL, NULL, NULL, NULL, NULL, 'firecracker', 'direct')",
                [],
            )
            .unwrap();
        }
        let rec = store.get_vm_by_name("legacy-balloon").unwrap();
        assert!(
            !rec.balloon,
            "legacy VM row without balloon column must default to false"
        );
    }

    // ── Volumes ───────────────────────────────────────────────────────

    fn make_volume(name: &str, size_bytes: u64) -> VolumeRecord {
        VolumeRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            file_path: format!("/var/lib/husker/volumes/{name}.img"),
            size_bytes,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn insert_and_get_volume_by_name() {
        let store = StateStore::open_memory().unwrap();
        let vol = make_volume("data", 1024 * 1024 * 1024);
        store.insert_volume(&vol).unwrap();

        let fetched = store.get_volume_by_name("data").unwrap();
        assert_eq!(fetched.id, vol.id);
        assert_eq!(fetched.name, "data");
        assert_eq!(fetched.size_bytes, 1024 * 1024 * 1024);
        assert_eq!(fetched.file_path, "/var/lib/husker/volumes/data.img");
    }

    #[test]
    fn list_volumes_returns_all() {
        let store = StateStore::open_memory().unwrap();
        store.insert_volume(&make_volume("vol-a", 512)).unwrap();
        store.insert_volume(&make_volume("vol-b", 1024)).unwrap();

        let volumes = store.list_volumes().unwrap();
        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0].name, "vol-a");
        assert_eq!(volumes[1].name, "vol-b");
    }

    #[test]
    fn duplicate_volume_name_rejected() {
        let store = StateStore::open_memory().unwrap();
        store.insert_volume(&make_volume("dup", 1024)).unwrap();

        let err = store.insert_volume(&make_volume("dup", 2048)).unwrap_err();
        assert!(
            matches!(err, StateError::VolumeAlreadyExists(ref name) if name == "dup"),
            "expected VolumeAlreadyExists, got: {err}"
        );
    }

    #[test]
    fn delete_volume_by_id() {
        let store = StateStore::open_memory().unwrap();
        let vol = make_volume("todel", 512);
        store.insert_volume(&vol).unwrap();
        store.delete_volume(vol.id).unwrap();

        let err = store.get_volume_by_name("todel").unwrap_err();
        assert!(matches!(err, StateError::VolumeNotFoundByName(_)));
    }

    #[test]
    fn delete_nonexistent_volume() {
        let store = StateStore::open_memory().unwrap();
        let err = store.delete_volume(Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, StateError::VolumeNotFound(_)));
    }

    #[test]
    fn get_volume_by_name_not_found() {
        let store = StateStore::open_memory().unwrap();
        let err = store.get_volume_by_name("missing").unwrap_err();
        assert!(matches!(err, StateError::VolumeNotFoundByName(_)));
    }

    #[test]
    fn find_vm_by_volume_returns_attached_vm() {
        let store = StateStore::open_memory().unwrap();
        store.insert_volume(&make_volume("mydata", 512)).unwrap();

        let mut vm = make_record("vm-with-vol");
        vm.volume = Some("mydata".into());
        store.insert_vm(&vm).unwrap();

        // A standalone VM without the volume.
        store.insert_vm(&make_record("other-vm")).unwrap();

        let found = store.find_vm_by_volume("mydata").unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.name, "vm-with-vol");
        assert_eq!(found.volume.as_deref(), Some("mydata"));
    }

    #[test]
    fn find_vm_by_volume_returns_none_when_unattached() {
        let store = StateStore::open_memory().unwrap();
        store.insert_vm(&make_record("standalone")).unwrap();

        let found = store.find_vm_by_volume("nonexistent-volume").unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn vm_volume_field_roundtrips() {
        let store = StateStore::open_memory().unwrap();
        store
            .insert_volume(&make_volume("persistent-data", 512))
            .unwrap();
        let mut vm = make_record("vol-vm");
        vm.volume = Some("persistent-data".into());
        store.insert_vm(&vm).unwrap();

        let fetched = store.get_vm_by_name("vol-vm").unwrap();
        assert_eq!(fetched.volume.as_deref(), Some("persistent-data"));
    }

    #[test]
    fn vm_cannot_attach_a_missing_volume() {
        let store = StateStore::open_memory().unwrap();
        let mut vm = make_record("missing-volume-vm");
        vm.volume = Some("missing".into());

        let error = store.insert_vm(&vm).unwrap_err();

        assert!(matches!(
            error,
            StateError::VolumeNotFoundByName(ref name) if name == "missing"
        ));
    }

    #[test]
    fn two_vms_cannot_attach_the_same_volume() {
        let store = StateStore::open_memory().unwrap();
        store.insert_volume(&make_volume("exclusive", 512)).unwrap();
        let mut first = make_record("first-holder");
        first.volume = Some("exclusive".into());
        store.insert_vm(&first).unwrap();
        let mut second = make_record("second-holder");
        second.volume = Some("exclusive".into());

        let error = store.insert_vm(&second).unwrap_err();

        assert!(matches!(
            error,
            StateError::VolumeAttached { ref volume, ref vm }
                if volume == "exclusive" && vm == "first-holder"
        ));
    }

    #[test]
    fn concurrent_vm_inserts_have_exactly_one_volume_holder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let setup = StateStore::open(&path).unwrap();
        setup.insert_volume(&make_volume("contended", 512)).unwrap();
        drop(setup);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let spawn = |name: &'static str| {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = StateStore::open(&path).unwrap();
                let mut vm = make_record(name);
                vm.volume = Some("contended".into());
                barrier.wait();
                store.insert_vm(&vm)
            })
        };
        let first = spawn("concurrent-a");
        let second = spawn("concurrent-b");
        let results = [first.join().unwrap(), second.join().unwrap()];

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(StateError::VolumeAttached { .. })))
                .count(),
            1
        );
        let store = StateStore::open(&path).unwrap();
        let holder = store.find_vm_by_volume("contended").unwrap().unwrap();
        assert!(holder.name == "concurrent-a" || holder.name == "concurrent-b");
    }

    #[test]
    fn deleting_an_attached_volume_is_atomic_and_non_destructive() {
        let store = StateStore::open_memory().unwrap();
        let volume = make_volume("in-use", 512);
        store.insert_volume(&volume).unwrap();
        let mut vm = make_record("holder");
        vm.volume = Some(volume.name.clone());
        store.insert_vm(&vm).unwrap();

        let error = store
            .delete_unattached_volume_by_name(&volume.name)
            .unwrap_err();

        assert!(matches!(
            error,
            StateError::VolumeAttached { ref volume, ref vm }
                if volume == "in-use" && vm == "holder"
        ));
        assert!(
            store.delete_volume(volume.id).is_err(),
            "the schema guard must also reject callers that bypass the atomic helper"
        );
        assert_eq!(store.get_volume_by_name("in-use").unwrap().id, volume.id);
    }

    #[test]
    fn concurrent_attach_and_delete_never_leave_a_dangling_vm() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let setup = StateStore::open(&path).unwrap();
        setup.insert_volume(&make_volume("raced", 512)).unwrap();
        drop(setup);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let attach = {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = StateStore::open(&path).unwrap();
                let mut vm = make_record("raced-holder");
                vm.volume = Some("raced".into());
                barrier.wait();
                store.insert_vm(&vm)
            })
        };
        let delete = {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = StateStore::open(&path).unwrap();
                barrier.wait();
                store.delete_unattached_volume_by_name("raced")
            })
        };
        let attach_result = attach.join().unwrap();
        let delete_result = delete.join().unwrap();
        let store = StateStore::open(&path).unwrap();

        match (attach_result, delete_result) {
            (Ok(()), Err(StateError::VolumeAttached { volume, vm })) => {
                assert_eq!(volume, "raced");
                assert_eq!(vm, "raced-holder");
                assert!(store.get_volume_by_name("raced").is_ok());
                assert!(store.find_vm_by_volume("raced").unwrap().is_some());
            }
            (Err(StateError::VolumeNotFoundByName(volume)), Ok(deleted)) => {
                assert_eq!(volume, "raced");
                assert_eq!(deleted.name, "raced");
                assert!(matches!(
                    store.get_volume_by_name("raced"),
                    Err(StateError::VolumeNotFoundByName(_))
                ));
                assert!(store.find_vm_by_volume("raced").unwrap().is_none());
            }
            other => panic!("unexpected attach/delete outcome: {other:?}"),
        }
    }

    #[test]
    fn vm_volume_migration_default_applied() {
        // A row inserted without the volume column must read back as None
        // because the migration adds it as nullable.
        let store = StateStore::open_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO vms (id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                                  tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                                  created_at, updated_at, userdata, userdata_status, userdata_env,
                                  service_id, service_ordinal, vmm, boot_mode, balloon)
                 VALUES ('dddddddd-dddd-dddd-dddd-dddddddddddd', 'legacy-vol', 'stopped',
                         NULL, 1, 128, 5, NULL, NULL, NULL, '/kernel', '/rootfs',
                         '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z',
                         NULL, NULL, NULL, NULL, NULL, 'firecracker', 'direct', 0)",
                [],
            )
            .unwrap();
        }
        let rec = store.get_vm_by_name("legacy-vol").unwrap();
        assert!(
            rec.volume.is_none(),
            "legacy VM row without volume column must default to None"
        );
    }

    #[test]
    fn service_volume_field_roundtrips() {
        let store = StateStore::open_memory().unwrap();
        let mut svc = make_service("vol-svc", None);
        svc.volume = Some("svc-data".into());
        store.insert_service(&svc).unwrap();

        let fetched = store.get_service_by_name("vol-svc").unwrap();
        assert_eq!(fetched.volume.as_deref(), Some("svc-data"));
    }

    #[test]
    fn pool_crud_roundtrips() {
        let store = StateStore::open_memory().unwrap();
        let template = Uuid::new_v4();
        let rec = PoolRecord {
            id: Uuid::new_v4(),
            name: "web".into(),
            template_vm_id: template,
            rootfs_path: "/img/base.ext4".into(),
            kernel_path: "/img/vmlinux".into(),
            initrd_path: Some("/img/initrd.gz".into()),
            vcpu_count: Some(2),
            mem_size_mib: Some(512),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.insert_pool(&rec).unwrap();

        let got = store.get_pool_by_name("web").unwrap();
        assert_eq!(got.name, "web");
        assert_eq!(got.template_vm_id, template);
        assert_eq!(got.rootfs_path, "/img/base.ext4");
        assert_eq!(got.initrd_path.as_deref(), Some("/img/initrd.gz"));
        assert_eq!(got.vcpu_count, Some(2));
        assert_eq!(got.mem_size_mib, Some(512));
        assert_eq!(store.list_pools().unwrap().len(), 1);

        assert!(matches!(
            store.insert_pool(&rec),
            Err(StateError::PoolAlreadyExists(n)) if n == "web"
        ));

        store.delete_pool_by_name("web").unwrap();
        assert!(matches!(
            store.get_pool_by_name("web"),
            Err(StateError::PoolNotFoundByName(_))
        ));
        assert!(store.list_pools().unwrap().is_empty());
        assert!(matches!(
            store.delete_pool_by_name("web"),
            Err(StateError::PoolNotFoundByName(_))
        ));
    }

    #[test]
    fn service_volume_migration_default_null() {
        // A row inserted without the volume column must read back as None.
        let store = StateStore::open_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO services
                     (id, name, desired_instances, kernel_path, rootfs_path,
                      created_at, updated_at)
                 VALUES
                     ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee', 'legacy-vol-svc', 1, '', '',
                      '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }
        let fetched = store.get_service_by_name("legacy-vol-svc").unwrap();
        assert!(
            fetched.volume.is_none(),
            "legacy service row must have volume = None"
        );
    }

    // ── vms.network field ─────────────────────────────────────────────

    #[test]
    fn network_field_round_trips() {
        let store = StateStore::open_memory().unwrap();
        let mut rec = make_record("net-vm");
        rec.network = "nat".to_string();
        store.insert_vm(&rec).unwrap();
        let fetched = store.get_vm_by_name("net-vm").unwrap();
        assert_eq!(fetched.network, "nat");
    }

    #[test]
    fn network_migration_default_applied() {
        // A row inserted without the network column must read back as "nat"
        // because the migration NOT NULL DEFAULT 'nat' backfills it.
        let store = StateStore::open_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO vms (id, name, state, pid, vcpu_count, mem_size_mib, vsock_cid,
                                  tap_device, host_ip, guest_ip, kernel_path, rootfs_path,
                                  created_at, updated_at, userdata, userdata_status, userdata_env,
                                  service_id, service_ordinal, vmm, boot_mode, balloon, volume)
                 VALUES ('ffffffff-ffff-ffff-ffff-ffffffffffff', 'legacy-net', 'stopped',
                         NULL, 1, 128, 5, NULL, NULL, NULL, '/kernel', '/rootfs',
                         '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z',
                         NULL, NULL, NULL, NULL, NULL, 'firecracker', 'direct', 0, NULL)",
                [],
            )
            .unwrap();
        }
        let rec = store.get_vm_by_name("legacy-net").unwrap();
        assert_eq!(
            rec.network, "nat",
            "legacy VM row without network column must default to nat"
        );
    }

    #[test]
    fn migrates_a_genuinely_old_on_disk_schema() {
        // A v0.2-era DB file predates the vmm/boot_mode/network/idle columns.
        // Opening it must ALTER TABLE the new columns in, backfill their
        // schema-correct defaults, and preserve the existing row - the real
        // upgrade path a user hits, which the open_memory migration tests (built by
        // the current binary) never exercise against a genuinely old file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        let vm_id = Uuid::new_v4();

        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE vms (
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
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO vms (id, name, state, vcpu_count, mem_size_mib, vsock_cid,
                                  guest_ip, kernel_path, rootfs_path, created_at, updated_at)
                 VALUES (?1, 'legacy-vm', 'running', 2, 256, 7, '192.0.2.50', '/k', '/r', ?2, ?2)",
                params![vm_id.to_string(), Utc::now().to_rfc3339()],
            )
            .unwrap();
        } // drop the raw connection so StateStore can reopen the file

        // Opening via StateStore runs migrate() against the old file.
        let store = StateStore::open(&path).unwrap();
        let vms = store.list_vms().unwrap();
        assert_eq!(vms.len(), 1, "the legacy row must survive migration");
        let vm = &vms[0];
        // Original data intact.
        assert_eq!(vm.id, vm_id);
        assert_eq!(vm.name, "legacy-vm");
        assert_eq!(vm.state, "running");
        assert_eq!(vm.vcpu_count, 2);
        assert_eq!(vm.guest_ip.as_deref(), Some("192.0.2.50"));
        // New columns backfilled with their schema-correct defaults.
        assert_eq!(vm.vmm, "firecracker");
        assert_eq!(vm.boot_mode, "direct");
        assert_eq!(vm.network, "nat");
        assert!(vm.auto_resume, "auto_resume defaults to enabled");
        assert!(!vm.balloon, "balloon defaults to off");

        // The pre-versioning file (user_version 0) is stamped up to the baseline
        // without re-bootstrapping - the legacy row above survives, proving
        // baselining is safe on a real old database.
        let version: i64 = store
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version as u32, MIGRATIONS.last().unwrap().0);
        assert!(store.list_host_resource_leases().unwrap().is_empty());
    }

    #[test]
    fn fresh_db_reaches_the_latest_schema_version() {
        let store = StateStore::open_memory().unwrap();
        let version: i64 = store
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version as u32, MIGRATIONS.last().unwrap().0);
    }

    #[test]
    fn volume_invariant_migration_repairs_legacy_dangling_and_duplicate_attachments() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE volumes (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE);
             CREATE TABLE vms (
                 id TEXT PRIMARY KEY,
                 name TEXT NOT NULL UNIQUE,
                 volume TEXT,
                 created_at TEXT NOT NULL
             );
             INSERT INTO volumes (id, name) VALUES ('volume-id', 'shared');
             INSERT INTO vms (id, name, volume, created_at) VALUES
                 ('a', 'keeper', 'shared', '2024-01-01T00:00:00Z'),
                 ('b', 'duplicate', 'shared', '2024-01-02T00:00:00Z'),
                 ('c', 'dangling', 'missing', '2024-01-03T00:00:00Z');
             PRAGMA user_version = 2;",
        )
        .unwrap();

        apply_migrations(&conn, BASELINE_SCHEMA_VERSION, MIGRATIONS).unwrap();

        let attachments = conn
            .prepare("SELECT name, volume FROM vms ORDER BY name")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            attachments,
            vec![
                ("dangling".into(), None),
                ("duplicate".into(), None),
                ("keeper".into(), Some("shared".into())),
            ]
        );
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                .unwrap(),
            3
        );
    }

    #[test]
    fn apply_migrations_stamps_baseline_then_applies_in_order() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
        let migrations: &[(u32, &str)] = &[
            (2, "ALTER TABLE t ADD COLUMN a TEXT"),
            (3, "ALTER TABLE t ADD COLUMN b TEXT"),
        ];
        apply_migrations(&conn, 1, migrations).unwrap();

        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 3, "version advances to the last migration");
        // Both columns exist (the INSERT would fail otherwise).
        conn.execute("INSERT INTO t (id, a, b) VALUES (1, 'x', 'y')", [])
            .unwrap();
    }

    #[test]
    fn apply_migrations_never_reruns_a_recorded_migration() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
        let m1: &[(u32, &str)] = &[(2, "ALTER TABLE t ADD COLUMN a TEXT")];
        apply_migrations(&conn, 1, m1).unwrap();
        // Re-running the same set is a no-op: migration 2 is already recorded,
        // so it is NOT re-applied (which would fail with "duplicate column a").
        apply_migrations(&conn, 1, m1).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 2);

        // Extending the set resumes from where it left off: only migration 3
        // runs; migration 2 is still skipped.
        let m2: &[(u32, &str)] = &[
            (2, "ALTER TABLE t ADD COLUMN a TEXT"),
            (3, "ALTER TABLE t ADD COLUMN b TEXT"),
        ];
        apply_migrations(&conn, 1, m2).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 3);
    }

    #[test]
    fn apply_migrations_rolls_back_a_failing_migration() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
        // Migration 2 succeeds; migration 3 is invalid SQL and must fail.
        let migrations: &[(u32, &str)] = &[
            (2, "ALTER TABLE t ADD COLUMN a TEXT"),
            (3, "THIS IS NOT VALID SQL"),
        ];
        assert!(apply_migrations(&conn, 1, migrations).is_err());
        // Migration 2 committed and its version is recorded; the failed
        // migration 3 left the version at 2 (its transaction rolled back).
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            version, 2,
            "a failed migration does not advance the version"
        );
    }
}
