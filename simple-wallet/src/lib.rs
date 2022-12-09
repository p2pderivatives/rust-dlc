use std::ops::Deref;

use bitcoin::{
    Address, Network, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use dlc_manager::{error::Error, Blockchain, Signer, Utxo, Wallet};
use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator};
use rust_bitcoin_coin_selection::select_coins;
use secp256k1_zkp::{rand::thread_rng, All, PublicKey, Secp256k1, SecretKey};

type Result<T> = core::result::Result<T, Error>;

/// Trait providing blockchain information to the wallet.
pub trait WalletBlockchainProvider: Blockchain + FeeEstimator {
    fn get_utxos_for_address(&self, address: &Address) -> Result<Vec<Utxo>>;
    fn is_output_spent(&self, txid: &Txid, vout: u32) -> Result<bool>;
}

/// Trait enabling the wallet to persist data.
pub trait WalletStorage {
    fn upsert_address(&self, address: &Address, privkey: &SecretKey) -> Result<()>;
    fn delete_address(&self, address: &Address) -> Result<()>;
    fn get_addresses(&self) -> Result<Vec<Address>>;
    fn get_priv_key_for_address(&self, address: &Address) -> Result<Option<SecretKey>>;
    fn upsert_key_pair(&self, public_key: &PublicKey, privkey: &SecretKey) -> Result<()>;
    fn get_priv_key_for_pubkey(&self, public_key: &PublicKey) -> Result<Option<SecretKey>>;
    fn upsert_utxo(&self, utxo: &Utxo) -> Result<()>;
    fn has_utxo(&self, utxo: &Utxo) -> Result<bool>;
    fn delete_utxo(&self, utxo: &Utxo) -> Result<()>;
    fn get_utxos(&self) -> Result<Vec<Utxo>>;
    fn unreserve_utxo(&self, txid: &Txid, vout: u32) -> Result<()>;
}

/// Basic wallet mainly meant for testing purposes.
pub struct SimpleWallet<B: Deref, W: Deref>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    blockchain: B,
    storage: W,
    secp_ctx: Secp256k1<All>,
    network: Network,
}

impl<B: Deref, W: Deref> SimpleWallet<B, W>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    /// Create a new wallet instance.
    pub fn new(blockchain: B, storage: W, network: Network) -> Self {
        Self {
            blockchain,
            storage,
            secp_ctx: Secp256k1::new(),
            network,
        }
    }

    pub fn refresh(&self) -> Result<()> {
        let utxos = self.storage.get_utxos()?;

        for utxo in &utxos {
            let is_spent = self
                .blockchain
                .is_output_spent(&utxo.outpoint.txid, utxo.outpoint.vout)?;
            if is_spent {
                self.storage.delete_utxo(utxo)?;
            }
        }

        let addresses = self.storage.get_addresses()?;

        for address in &addresses {
            let utxos = self.blockchain.get_utxos_for_address(address)?;

            for utxo in &utxos {
                if !self.storage.has_utxo(utxo)? {
                    self.storage.upsert_utxo(utxo)?;
                }
            }
        }

        Ok(())
    }

    /// Returns the sum of all UTXOs value.
    pub fn get_balance(&self) -> u64 {
        self.storage
            .get_utxos()
            .unwrap()
            .iter()
            .map(|x| x.tx_out.value)
            .sum()
    }

    /// Mark all UTXOs as unreserved.
    pub fn unreserve_all_utxos(&self) {
        let utxos = self.storage.get_utxos().unwrap();
        for utxo in utxos {
            self.storage
                .unreserve_utxo(&utxo.outpoint.txid, utxo.outpoint.vout)
                .unwrap();
        }
    }

    /// Creates a transaction with all wallet UTXOs as inputs and a single output
    /// sending everything to the given address.
    pub fn empty_to_address(&self, address: &Address) -> Result<()> {
        let utxos = self
            .storage
            .get_utxos()
            .expect("to be able to retrieve all utxos");
        if utxos.is_empty() {
            return Err(Error::InvalidState("No utxo in wallet".to_string()));
        }

        let mut total_value = 0;
        let input = utxos
            .iter()
            .map(|x| {
                total_value += x.tx_out.value;
                TxIn {
                    previous_output: x.outpoint,
                    script_sig: Script::default(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                }
            })
            .collect::<Vec<_>>();
        let output = vec![TxOut {
            value: total_value,
            script_pubkey: address.script_pubkey(),
        }];
        let mut tx = Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input,
            output,
        };
        // Signature + pubkey size assuming P2WPKH.
        let weight = (tx.weight() + tx.input.len() * (74 + 33)) as u64;
        let fee_rate = self
            .blockchain
            .get_est_sat_per_1000_weight(ConfirmationTarget::Normal) as u64;
        let fee = (weight * fee_rate) / 1000;
        tx.output[0].value -= fee;

        for (i, utxo) in utxos.iter().enumerate().take(tx.input.len()) {
            self.sign_tx_input(&mut tx, i, &utxo.tx_out, None)?;
        }

        self.blockchain.send_transaction(&tx)
    }
}

impl<B: Deref, W: Deref> Signer for SimpleWallet<B, W>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    fn sign_tx_input(
        &self,
        tx: &mut bitcoin::Transaction,
        input_index: usize,
        tx_out: &bitcoin::TxOut,
        _: Option<bitcoin::Script>,
    ) -> Result<()> {
        let address = Address::from_script(&tx_out.script_pubkey, self.network)
            .expect("a valid scriptpubkey");
        let seckey = self
            .storage
            .get_priv_key_for_address(&address)?
            .expect("to have the requested private key");
        dlc::util::sign_p2wpkh_input(
            &self.secp_ctx,
            &seckey,
            tx,
            input_index,
            bitcoin::EcdsaSighashType::All,
            tx_out.value,
        )?;
        Ok(())
    }

    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey> {
        Ok(self
            .storage
            .get_priv_key_for_pubkey(pubkey)?
            .expect("to have the requested private key"))
    }
}

impl<B: Deref, W: Deref> Wallet for SimpleWallet<B, W>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    fn get_new_address(&self) -> Result<Address> {
        let seckey = SecretKey::new(&mut thread_rng());
        let pubkey = PublicKey::from_secret_key(&self.secp_ctx, &seckey);
        let address = Address::p2wpkh(
            &bitcoin::PublicKey {
                inner: pubkey,
                compressed: true,
            },
            self.network,
        )
        .map_err(|x| Error::WalletError(Box::new(x)))?;
        self.storage.upsert_address(&address, &seckey)?;
        Ok(address)
    }

    fn get_new_secret_key(&self) -> Result<SecretKey> {
        let seckey = SecretKey::new(&mut thread_rng());
        let pubkey = PublicKey::from_secret_key(&self.secp_ctx, &seckey);
        self.storage.upsert_key_pair(&pubkey, &seckey)?;
        Ok(seckey)
    }

    fn get_utxos_for_amount(
        &self,
        amount: u64,
        _: Option<u64>,
        lock_utxos: bool,
    ) -> Result<Vec<Utxo>> {
        let mut utxos = self
            .storage
            .get_utxos()?
            .into_iter()
            .filter(|x| !x.reserved)
            .map(|x| UtxoWrap { utxo: x })
            .collect::<Vec<_>>();
        let selection = select_coins(amount, 20, &mut utxos)
            .ok_or_else(|| Error::InvalidState("Not enough fund in utxos".to_string()))?;
        if lock_utxos {
            for utxo in selection.clone() {
                let updated = Utxo {
                    reserved: true,
                    ..utxo.utxo
                };
                self.storage.upsert_utxo(&updated)?;
            }
        }
        Ok(selection.into_iter().map(|x| x.utxo).collect::<Vec<_>>())
    }

    fn import_address(&self, _: &Address) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct UtxoWrap {
    utxo: Utxo,
}

impl rust_bitcoin_coin_selection::Utxo for UtxoWrap {
    fn get_value(&self) -> u64 {
        self.utxo.tx_out.value
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use dlc_manager::{Signer, Wallet};
    use mocks::simple_wallet::SimpleWallet;
    use mocks::{memory_storage_provider::MemoryStorage, mock_blockchain::TestBlockchain};
    use secp256k1_zkp::{PublicKey, SECP256K1};

    fn get_wallet() -> SimpleWallet<Rc<TestBlockchain>, Rc<MemoryStorage>> {
        let blockchain = Rc::new(MockBlockchain {});
        let storage = Rc::new(MemoryStorage::new());
        let wallet = SimpleWallet::new(blockchain, storage, bitcoin::Network::Regtest);
        wallet
    }

    #[test]
    fn get_new_secret_key_can_be_retrieved() {
        let wallet = get_wallet();
        let sk = wallet.get_new_secret_key().unwrap();
        let pk = PublicKey::from_secret_key(SECP256K1, &sk);

        let sk2 = wallet.get_secret_key_for_pubkey(&pk).unwrap();

        assert_eq!(sk, sk2);
    }
}
