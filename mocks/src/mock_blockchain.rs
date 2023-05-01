use std::{ops::Deref, sync::Mutex};

use bitcoin::{Transaction, Txid};
use dlc_manager::error::Error;
use lightning::chain::chaininterface::BroadcasterInterface;
use simple_wallet::WalletBlockchainProvider;

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

pub struct MockBroadcaster {}

impl BroadcasterInterface for MockBroadcaster {
    fn broadcast_transaction(&self, _tx: &bitcoin::Transaction) {
        unimplemented!();
    }
}

impl<T: Deref> WalletBlockchainProvider for MockBlockchain<T>
where
    T::Target: BroadcasterInterface,
{
    fn get_utxos_for_address(
        &self,
        _address: &bitcoin::Address,
    ) -> Result<Vec<dlc_manager::Utxo>, dlc_manager::error::Error> {
        unimplemented!()
    }

    fn is_output_spent(
        &self,
        _txid: &bitcoin::Txid,
        _vout: u32,
    ) -> Result<bool, dlc_manager::error::Error> {
        unimplemented!()
    }
}

impl<T: Deref> lightning::chain::chaininterface::FeeEstimator for MockBlockchain<T>
where
    T::Target: BroadcasterInterface,
{
    fn get_est_sat_per_1000_weight(
        &self,
        _confirmation_target: lightning::chain::chaininterface::ConfirmationTarget,
    ) -> u32 {
        unimplemented!()
    }
}

impl<T: Deref> dlc_manager::Blockchain for MockBlockchain<T>
where
    T::Target: BroadcasterInterface,
{
    fn send_transaction(
        &self,
        _transaction: &Transaction,
    ) -> Result<(), dlc_manager::error::Error> {
        Ok(())
    }
    fn get_network(
        &self,
    ) -> Result<bitcoin::network::constants::Network, dlc_manager::error::Error> {
        Ok(bitcoin::Network::Regtest)
    }
    fn get_blockchain_height(&self) -> Result<u64, Error> {
        Ok(10)
    }
    fn get_block_at_height(&self, _height: u64) -> Result<bitcoin::Block, Error> {
        unimplemented!();
    }
    fn get_transaction(&self, _tx_id: &Txid) -> Result<Transaction, Error> {
        unimplemented!();
    }
    fn get_transaction_confirmations(&self, _tx_id: &Txid) -> Result<u32, Error> {
        Ok(6)
    }
}

