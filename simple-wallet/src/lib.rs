use std::ops::Deref;

use bdk_wallet::{
    chain::ConfirmationTime,
    coin_selection::{CoinSelectionAlgorithm, OldestFirstCoinSelection},
    KeychainKind, LocalOutput, Utxo as BdkUtxo, WeightedUtxo,
};
use bitcoin::{
    hashes::Hash, Address, Amount, CompressedPublicKey, FeeRate, Network, OutPoint, PrivateKey,
    Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness,
};
use bitcoin::{psbt::Psbt, ScriptBuf};
use dlc_manager::{
    error::Error, Blockchain, ContractSignerProvider, KeysId, SimpleSigner, Utxo, Wallet,
};
use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator};
use secp256k1_zkp::rand::RngCore;
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
    fn upsert_key(&self, identifier: &[u8], privkey: &SecretKey) -> Result<()>;
    fn get_priv_key(&self, identifier: &[u8]) -> Result<Option<SecretKey>>;
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

    /// Refresh the wallet checking and updating the UTXO states.
    pub fn refresh(&self) -> Result<()> {
        let utxos: Vec<Utxo> = self.storage.get_utxos()?;

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
    pub fn get_balance(&self) -> Amount {
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

        let mut total_value = Amount::ZERO;
        let input = utxos
            .iter()
            .map(|x| {
                total_value += x.tx_out.value;
                TxIn {
                    previous_output: x.outpoint,
                    script_sig: ScriptBuf::default(),
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
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input,
            output,
        };
        // Signature + pubkey size assuming P2WPKH.
        let weight = tx.weight().to_wu() + tx.input.len() as u64 * (74 + 33);
        let fee_rate = self
            .blockchain
            .get_est_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee)
            as u64;
        let fee = Amount::from_sat((weight * fee_rate) / 1000);
        tx.output[0].value -= fee;

        // construct psbt
        let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        for (i, utxo) in utxos.iter().enumerate().take(tx.input.len()) {
            psbt.inputs[i].witness_utxo = Some(utxo.tx_out.clone());
        }

        for (i, _) in utxos.iter().enumerate().take(tx.input.len()) {
            self.sign_psbt_input(&mut psbt, i)?;
        }

        let tx = psbt
            .extract_tx()
            .expect("could not extract transaction from psbt");

        self.blockchain.send_transaction(&tx)
    }
}

impl<B: Deref, W: Deref> ContractSignerProvider for SimpleWallet<B, W>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    type Signer = SimpleSigner;

    fn derive_signer_key_id(&self, _is_offer_party: bool, _temp_id: [u8; 32]) -> [u8; 32] {
        let mut ret = [0u8; 32];
        thread_rng().fill_bytes(&mut ret);
        ret
    }

    fn derive_contract_signer(&self, keys_id: KeysId) -> Result<Self::Signer> {
        match self.storage.get_priv_key(&keys_id)? {
            None => {
                let seckey = SecretKey::new(&mut thread_rng());
                let pubkey = PublicKey::from_secret_key(&self.secp_ctx, &seckey);
                self.storage.upsert_key(&pubkey.serialize(), &seckey)?;
                self.storage.upsert_key(&keys_id, &seckey)?;
                Ok(SimpleSigner::new(seckey))
            }
            Some(seckey) => Ok(SimpleSigner::new(seckey)),
        }
    }

    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey> {
        Ok(self
            .storage
            .get_priv_key(&pubkey.serialize())?
            .expect("to have the requested private key"))
    }

    fn get_new_secret_key(&self) -> Result<SecretKey> {
        let seckey = SecretKey::new(&mut thread_rng());
        let pubkey = PublicKey::from_secret_key(&self.secp_ctx, &seckey);
        self.storage.upsert_key(&pubkey.serialize(), &seckey)?;
        Ok(seckey)
    }
}

impl<B: Deref, W: Deref> Wallet for SimpleWallet<B, W>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    fn get_new_address(&self) -> Result<Address> {
        let seckey = SecretKey::new(&mut thread_rng());
        let privkey = PrivateKey::new(seckey, self.network);
        let pubkey = CompressedPublicKey::from_private_key(&self.secp_ctx, &privkey).unwrap();
        let address = Address::p2wpkh(&pubkey, self.network);
        self.storage.upsert_address(&address, &seckey)?;
        Ok(address)
    }

    fn get_new_change_address(&self) -> Result<Address> {
        self.get_new_address()
    }

    fn get_utxos_for_amount(
        &self,
        amount: Amount,
        fee_rate: u64,
        lock_utxos: bool,
    ) -> Result<Vec<Utxo>> {
        let org_utxos = self.storage.get_utxos()?;
        let utxos = org_utxos
            .iter()
            .filter(|x| !x.reserved)
            .map(|x| WeightedUtxo {
                utxo: BdkUtxo::Local(LocalOutput {
                    outpoint: x.outpoint,
                    txout: x.tx_out.clone(),
                    keychain: KeychainKind::External,
                    is_spent: false,
                    confirmation_time: ConfirmationTime::unconfirmed(1),
                    derivation_index: 1,
                }),
                satisfaction_weight: Weight::from_wu(107),
            })
            .collect::<Vec<_>>();
        let coin_selection = OldestFirstCoinSelection;
        let dummy_pubkey: PublicKey =
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap();
        let dummy_drain =
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(&dummy_pubkey.serialize()));
        let fee_rate = FeeRate::from_sat_per_vb(fee_rate).unwrap_or(FeeRate::BROADCAST_MIN);
        let selection = coin_selection
            .coin_select(
                Vec::new(),
                utxos,
                fee_rate,
                amount.to_sat(),
                &dummy_drain,
                &mut bitcoin::key::rand::thread_rng(),
            )
            .map_err(|e| Error::WalletError(Box::new(e)))?;
        let mut res = Vec::new();
        for utxo in selection.selected {
            let local_utxo = if let BdkUtxo::Local(l) = utxo {
                l
            } else {
                panic!();
            };
            let org = org_utxos
                .iter()
                .find(|x| x.tx_out == local_utxo.txout && x.outpoint == local_utxo.outpoint)
                .unwrap();
            if lock_utxos {
                let updated = Utxo {
                    reserved: true,
                    ..org.clone()
                };
                self.storage.upsert_utxo(&updated)?;
            }
            res.push(org.clone());
        }
        Ok(res)
    }

    fn import_address(&self, _: &Address) -> Result<()> {
        Ok(())
    }

    fn unreserve_utxos(&self, outputs: &[OutPoint]) -> std::result::Result<(), Error> {
        for outpoint in outputs {
            self.storage.unreserve_utxo(&outpoint.txid, outpoint.vout)?;
        }

        Ok(())
    }

    fn sign_psbt_input(
        &self,
        psbt: &mut Psbt,
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
            bitcoin::sighash::EcdsaSighashType::All,
            tx_out.value,
        )?;

        let tx_input = tx.input[input_index].clone();
        psbt.inputs[input_index].final_script_sig = Some(tx_input.script_sig);
        psbt.inputs[input_index].final_script_witness = Some(tx_input.witness);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use dlc_manager::ContractSignerProvider;
    use mocks::simple_wallet::SimpleWallet;
    use mocks::{memory_storage_provider::MemoryStorage, mock_blockchain::MockBlockchain};
    use secp256k1_zkp::{PublicKey, SECP256K1};

    fn get_wallet() -> SimpleWallet<Rc<MockBlockchain>, Rc<MemoryStorage>> {
        let blockchain = Rc::new(MockBlockchain::new());
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
