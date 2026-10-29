//! Per-key async mutexes whose map entries live only as long as the lock is
//! in use.
//!
//! The map holds weak references, so a key's mutex exists while some caller
//! holds or awaits it and is dropped with the last of them. Requests for keys
//! that were only looked up once (a misspelled VM name, a VM that has since
//! been deleted) therefore leave nothing behind, and the map stays bounded by
//! the number of keys in use at the same moment, plus the most recently
//! released one, which stays until the next access prunes it.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Weak};

pub(crate) struct NamedLocks<K> {
    locks: parking_lot::Mutex<HashMap<K, Weak<tokio::sync::Mutex<()>>>>,
}

impl<K: Eq + Hash> NamedLocks<K> {
    pub(crate) fn new() -> Self {
        Self {
            locks: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// The mutex for `key`. Every caller asking for the same key while any
    /// earlier handle is still alive receives that same mutex, so holding
    /// the returned handle (an owned guard keeps it) is what keeps the key
    /// locked against others.
    pub(crate) fn get<Q>(&self, key: &Q) -> Arc<tokio::sync::Mutex<()>>
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + Hash + ToOwned<Owned = K> + ?Sized,
    {
        let mut locks = self.locks.lock();
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(key.to_owned(), Arc::downgrade(&lock));
        lock
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> usize {
        self.locks.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_key_yields_the_same_mutex() {
        let locks = NamedLocks::<String>::new();
        let first = locks.get("vm");
        let second = locks.get("vm");
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &locks.get("other")));
    }

    #[tokio::test]
    async fn a_held_guard_excludes_other_callers_of_the_same_key() {
        let locks = NamedLocks::<String>::new();
        let guard = locks.get("vm").lock_owned().await;
        assert!(locks.get("vm").try_lock().is_err());
        assert!(locks.get("other").try_lock().is_ok());
        drop(guard);
        assert!(locks.get("vm").try_lock().is_ok());
    }

    #[tokio::test]
    async fn released_keys_are_pruned_and_live_ones_kept() {
        let locks = NamedLocks::<String>::new();
        let held = locks.get("held").lock_owned().await;
        for i in 0..1000 {
            drop(locks.get(&format!("gone-{i}")).lock_owned().await);
        }
        // Pruning runs on access, so a held probe triggers it and leaves
        // exactly the two live keys behind.
        let _probe = locks.get("probe");
        assert_eq!(locks.entries(), 2, "only live keys survive a prune");
        assert!(locks.get("held").try_lock().is_err());
        drop(held);
    }
}
