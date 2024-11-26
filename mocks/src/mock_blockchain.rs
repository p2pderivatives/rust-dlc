use std::sync::Mutex;

use bitcoin::{Block, Transaction, Txid};
use ddk_manager::{error::Error, Blockchain, Utxo};
use lightning::chain::chaininterface::FeeEstimator;
use simple_wallet::WalletBlockchainProvider;

pub struct MockBlockchain {
    transactions: Mutex<Vec<Transaction>>,
}

impl MockBlockchain {
    pub fn new() -> Self {
        Self {
            transactions: Mutex::new(Vec::new()),
        }
    }
}

impl Default for MockBlockchain {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Blockchain for MockBlockchain {
    async fn send_transaction(&self, transaction: &Transaction) -> Result<(), Error> {
        self.transactions.lock().unwrap().push(transaction.clone());
        Ok(())
    }
    fn get_network(&self) -> Result<bitcoin::Network, Error> {
        Ok(bitcoin::Network::Regtest)
    }
    async fn get_blockchain_height(&self) -> Result<u64, Error> {
        Ok(10)
    }
    async fn get_block_at_height(&self, _height: u64) -> Result<Block, Error> {
        unimplemented!();
    }
    async fn get_transaction(&self, tx_id: &Txid) -> Result<Transaction, Error> {
        Ok(self
            .transactions
            .lock()
            .unwrap()
            .iter()
            .find(|x| &x.compute_txid() == tx_id)
            .unwrap()
            .clone())
    }
    async fn get_transaction_confirmations(&self, _tx_id: &Txid) -> Result<u32, Error> {
        Ok(6)
    }
}

#[async_trait::async_trait]
impl WalletBlockchainProvider for MockBlockchain {
    async fn get_utxos_for_address(&self, _address: &bitcoin::Address) -> Result<Vec<Utxo>, Error> {
        unimplemented!()
    }

    async fn is_output_spent(&self, _txid: &Txid, _vout: u32) -> Result<bool, Error> {
        unimplemented!()
    }
}

impl FeeEstimator for MockBlockchain {
    fn get_est_sat_per_1000_weight(
        &self,
        _confirmation_target: lightning::chain::chaininterface::ConfirmationTarget,
    ) -> u32 {
        unimplemented!()
    }
}
