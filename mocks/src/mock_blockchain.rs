use bitcoin::{Block, Transaction, Txid};
use dlc_manager::{error::Error, Blockchain, Utxo};
use lightning::chain::chaininterface::FeeEstimator;
use simple_wallet::WalletBlockchainProvider;

pub struct MockBlockchain {}

impl Blockchain for MockBlockchain {
    fn send_transaction(&self, _transaction: &Transaction) -> Result<(), Error> {
        Ok(())
    }
    fn get_network(&self) -> Result<bitcoin::network::constants::Network, Error> {
        Ok(bitcoin::Network::Regtest)
    }
    fn get_blockchain_height(&self) -> Result<u64, Error> {
        Ok(10)
    }
    fn get_block_at_height(&self, _height: u64) -> Result<Block, Error> {
        unimplemented!();
    }
    fn get_transaction(&self, _tx_id: &Txid) -> Result<Transaction, Error> {
        unimplemented!();
    }
    fn get_transaction_confirmations(&self, _tx_id: &Txid) -> Result<u32, Error> {
        Ok(6)
    }
}

impl WalletBlockchainProvider for MockBlockchain {
    fn get_utxos_for_address(&self, _address: &bitcoin::Address) -> Result<Vec<Utxo>, Error> {
        unimplemented!()
    }

    fn is_output_spent(&self, _txid: &Txid, _vout: u32) -> Result<bool, Error> {
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
