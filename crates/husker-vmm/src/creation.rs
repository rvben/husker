//! Serialize one requested generation without serializing unrelated VM boots.
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, OwnedMutexGuard};
use uuid::Uuid;

#[derive(Default)]
pub(crate) struct CreationLocks {
    locks: Mutex<HashMap<Uuid, Weak<Mutex<()>>>>,
}
impl CreationLocks {
    pub async fn lock(&self, id: Uuid) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().await;
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(&id).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(Mutex::new(()));
                locks.insert(id, Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn one_generation_serializes_while_another_can_boot_and_finished_locks_are_pruned() {
        let locks = Arc::new(CreationLocks::default());
        let id = Uuid::new_v4();
        let first = locks.lock(id).await;
        let concurrent = locks.lock(Uuid::new_v4()).await;
        let other_locks = locks.clone();
        let blocked = tokio::spawn(async move { other_locks.lock(id).await });
        tokio::task::yield_now().await;
        assert!(!blocked.is_finished());
        drop(first);
        let next = blocked.await.unwrap();
        drop(next);
        drop(concurrent);
        let last = locks.lock(Uuid::new_v4()).await;
        assert_eq!(locks.locks.lock().await.len(), 1);
        drop(last);
    }
}
