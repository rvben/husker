//! Track failed connection restoration without querying SQLite on every return.
use std::ops::{Deref, DerefMut};

use r2d2::ManageConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

pub(crate) struct ManagedConnection {
    database: Connection,
    pub(crate) poisoned: bool,
}

impl Deref for ManagedConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.database
    }
}

impl DerefMut for ManagedConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.database
    }
}

pub(crate) struct StateManager(pub(crate) SqliteConnectionManager);

impl ManageConnection for StateManager {
    type Connection = ManagedConnection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<ManagedConnection, Self::Error> {
        Ok(ManagedConnection {
            database: self.0.connect()?,
            poisoned: false,
        })
    }

    fn is_valid(&self, connection: &mut ManagedConnection) -> Result<(), Self::Error> {
        self.0.is_valid(&mut connection.database)
    }

    fn has_broken(&self, connection: &mut ManagedConnection) -> bool {
        connection.poisoned || self.0.has_broken(&mut connection.database)
    }
}
