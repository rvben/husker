//! Per-checkout durability for ownership and job receipts. Ordinary state
//! writes retain NORMAL synchronization after the guard returns to the pool.
use std::ops::{Deref, DerefMut};

use rusqlite::Connection;

use crate::{PooledConn, StateError};

pub(crate) struct DurableConn {
    connection: Option<PooledConn>,
    previous: i64,
}

impl DurableConn {
    pub(crate) fn new(connection: PooledConn) -> Result<Self, StateError> {
        let previous = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        let guard = Self {
            connection: Some(connection),
            previous,
        };
        guard.pragma_update(None, "synchronous", 2)?;
        Ok(guard)
    }
}

impl Deref for DurableConn {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.connection.as_deref().expect("owned pooled connection")
    }
}

impl DerefMut for DurableConn {
    fn deref_mut(&mut self) -> &mut Connection {
        self.connection
            .as_deref_mut()
            .expect("owned pooled connection")
    }
}

impl Drop for DurableConn {
    fn drop(&mut self) {
        let Some(mut connection) = self.connection.take() else {
            return;
        };
        if let Err(error) = connection.pragma_update(None, "synchronous", self.previous) {
            tracing::warn!(%error, "discarding connection whose durability could not be restored");
            // Never return a connection with unknown configuration to the pool.
            connection.poisoned = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::StateStore;

    #[test]
    fn receipts_are_full_and_return_every_connection_to_normal() {
        let temp = tempfile::tempdir().unwrap();
        let store = StateStore::open(&temp.path().join("state.db")).unwrap();
        // Enforce durability from inside the actual receipt transaction.
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER require_durable_receipt BEFORE INSERT ON execution_jobs
            WHEN (SELECT synchronous FROM pragma_synchronous)<>2
            BEGIN SELECT RAISE(ABORT, 'receipt was not durable'); END;",
            )
            .unwrap();
        store
            .accept_job(
                "durable",
                "{}",
                chrono::Utc::now() + chrono::Duration::hours(1),
                chrono::Utc::now() + chrono::Duration::days(1),
            )
            .unwrap();
        let mut held = Vec::new();
        for _ in 0..8 {
            let connection = store.lock_durable().unwrap();
            assert_eq!(
                connection
                    .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                2
            );
            held.push(connection);
        }
        drop(held);
        let mut ordinary = Vec::new();
        for _ in 0..8 {
            let connection = store.lock().unwrap();
            assert_eq!(
                connection
                    .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            ordinary.push(connection);
        }
    }

    #[test]
    fn failed_receipt_restores_normal_and_failed_restoration_discards_connection() {
        let temp = tempfile::tempdir().unwrap();
        let store = StateStore::open(&temp.path().join("state.db")).unwrap();
        {
            let connection = store.lock_durable().unwrap();
            assert!(
                connection
                    .execute_batch("INSERT INTO nonexistent VALUES (1)")
                    .is_err()
            );
        }
        {
            let connection = store.lock_durable().unwrap();
            // A transaction escaping its owner prevents PRAGMA restoration.
            connection
                .execute_batch("BEGIN; CREATE TABLE abandoned (id INTEGER);")
                .unwrap();
        }
        let mut held = Vec::new();
        for _ in 0..8 {
            let connection = store.lock().unwrap();
            assert_eq!(
                connection
                    .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE name='abandoned'",
                        [],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                0
            );
            held.push(connection);
        }
    }
    #[test]
    fn poisoning_a_memory_connection_keeps_the_existing_database() {
        let store = StateStore::open_memory().unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch("CREATE TABLE retained(id INTEGER); INSERT INTO retained VALUES(7);")
            .unwrap();
        {
            let connection = store.lock_durable().unwrap();
            connection
                .execute_batch("BEGIN; INSERT INTO retained VALUES(8);")
                .unwrap();
        }
        // SqliteConnectionManager keeps a separate connection to its shared
        // memory URI, so retiring a pooled connection cannot erase the database.
        let connection = store.lock().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT SUM(id) FROM retained", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            7
        );
    }
}
