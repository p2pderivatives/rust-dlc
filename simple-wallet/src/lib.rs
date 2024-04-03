use std::ops::Deref;

use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{
    Address, Network, OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
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

        // construct psbt
        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(tx.clone()).unwrap();
        for (i, utxo) in utxos.iter().enumerate().take(tx.input.len()) {
            psbt.inputs[i].witness_utxo = Some(utxo.tx_out.clone());
        }

        for (i, _) in utxos.iter().enumerate().take(tx.input.len()) {
            self.sign_psbt_input(&mut psbt, i)?;
        }

        let tx = psbt.extract_tx();

        self.blockchain.send_transaction(&tx)
    }
}

impl<B: Deref, W: Deref> Signer for SimpleWallet<B, W>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    fn sign_psbt_input(
        &self,
        psbt: &mut PartiallySignedTransaction,
        input_index: usize,
    ) -> std::result::Result<(), Error> {
        let tx_out = if let Some(input) = psbt.inputs.get(input_index) {
            if let Some(wit_utxo) = &input.witness_utxo {
                Ok(wit_utxo.clone())
            } else if let Some(in_tx) = &input.non_witness_utxo {
                Ok(
                    in_tx.output[psbt.unsigned_tx.input[input_index].previous_output.vout as usize]
                        .clone(),
                )
            } else {
                Err(Error::InvalidParameters(
                    "No TxOut for PSBT inout".to_string(),
                ))
            }
        } else {
            Err(Error::InvalidParameters(
                "No TxOut for PSBT inout".to_string(),
            ))
        }?;
        let address = Address::from_script(&tx_out.script_pubkey, self.network)
            .expect("a valid scriptpubkey");
        let seckey = self
            .storage
            .get_priv_key_for_address(&address)?
            .expect("to have the requested private key");

        let mut tx = psbt.unsigned_tx.clone();
        dlc::util::sign_p2wpkh_input(
            &self.secp_ctx,
            &seckey,
            &mut tx,
            input_index,
            bitcoin::EcdsaSighashType::All,
            tx_out.value,
        )?;

        let tx_input = tx.input[input_index].clone();
        psbt.inputs[input_index].final_script_sig = Some(tx_input.script_sig);
        psbt.inputs[input_index].final_script_witness = Some(tx_input.witness);
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
        // TODO: We should probably use this argument. Unfortunately, it also affects LN-DLC, which
        // we don't really want to touch at the moment.
        _base_weight_wu: u64,
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

    fn unreserve_utxos(&self, outpoints: &[OutPoint]) -> std::result::Result<(), Error> {
        for outpoint in outpoints {
            self.storage.unreserve_utxo(&outpoint.txid, outpoint.vout)?;
        }

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
    use mocks::{
        memory_storage_provider::MemoryStorage,
        mock_blockchain::{MockBlockchain, MockBroadcaster},
    };
    use secp256k1_zkp::{PublicKey, SECP256K1};

    fn get_wallet() -> mocks::simple_wallet::SimpleWallet<
        Rc<MockBlockchain<Rc<MockBroadcaster>>>,
        Rc<MemoryStorage>,
    > {
        let broadcaster = Rc::new(MockBroadcaster {});
        let blockchain = Rc::new(MockBlockchain::new(broadcaster));
        let storage = Rc::new(MemoryStorage::new());

        SimpleWallet::new(blockchain, storage, bitcoin::Network::Regtest)
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
