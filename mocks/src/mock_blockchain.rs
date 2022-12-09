use std::{ops::Deref, sync::Mutex};

use lightning::chain::chaininterface::BroadcasterInterface;

pub struct MockBlockchain<T: Deref>
where
    T::Target: BroadcasterInterface,
{
    inner: T,
    discard: Mutex<bool>,
}

impl<T: Deref> MockBlockchain<T>
where
    T::Target: BroadcasterInterface,
{
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            discard: Mutex::new(false),
        }
    }

    pub fn start_discard(&self) {
        *self.discard.lock().unwrap() = true;
    }
}

impl<T: Deref> BroadcasterInterface for MockBlockchain<T>
where
    T::Target: BroadcasterInterface,
{
    fn broadcast_transaction(&self, tx: &bitcoin::Transaction) {
        if !*self.discard.lock().unwrap() {
            self.inner.broadcast_transaction(tx);
        }
    }
}
