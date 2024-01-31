use std::rc::Rc;

use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{absolute::LockTime, Address, OutPoint, ScriptBuf, Transaction, TxOut};
use dlc_manager::{error::Error, Blockchain, ContractSignerProvider, SimpleSigner, Utxo, Wallet};
use secp256k1_zkp::{rand::seq::SliceRandom, PublicKey, SecretKey};

use crate::mock_blockchain::MockBlockchain;

pub struct MockWallet {
    utxos: Vec<Utxo>,
}

impl MockWallet {
    pub fn new(blockchain: &Rc<MockBlockchain>, utxo_values: &[u64]) -> Self {
        let mut utxos = Vec::with_capacity(utxo_values.len());

        for utxo_value in utxo_values {
            let tx_out = TxOut {
                value: *utxo_value,
                script_pubkey: ScriptBuf::default(),
            };
            let tx = Transaction {
                version: 2,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![tx_out.clone()],
            };
            blockchain.send_transaction(&tx).unwrap();
            let utxo = Utxo {
                tx_out,
                outpoint: bitcoin::OutPoint {
                    txid: tx.txid(),
                    vout: 0,
                },
                address: get_address(),
                redeem_script: ScriptBuf::default(),
                reserved: false,
            };

            utxos.push(utxo);
        }

        Self { utxos }
    }
}

impl ContractSignerProvider for MockWallet {
    type Signer = SimpleSigner;

    fn derive_signer_key_id(&self, _: bool, temp_id: [u8; 32]) -> [u8; 32] {
        temp_id
    }

    fn derive_contract_signer(&self, _: [u8; 32]) -> Result<Self::Signer, Error> {
        Ok(SimpleSigner::new(get_secret_key()))
    }

    fn get_secret_key_for_pubkey(&self, _: &PublicKey) -> Result<SecretKey, Error> {
        Ok(get_secret_key())
    }

    fn get_new_secret_key(&self) -> Result<SecretKey, Error> {
        Ok(get_secret_key())
    }
}

impl Wallet for MockWallet {
    fn get_new_address(&self) -> Result<Address, dlc_manager::error::Error> {
        Ok(get_address())
    }

    fn get_new_change_address(&self) -> Result<Address, dlc_manager::error::Error> {
        Ok(get_address())
    }

    fn get_utxos_for_amount(
        &self,
        amount: u64,
        _fee_rate: u64,
        _lock_utxos: bool,
    ) -> Result<Vec<dlc_manager::Utxo>, Error> {
        let mut utxo_pool = self.utxos.clone();
        let seed = 1;
        utxo_pool.shuffle(&mut secp256k1_zkp::rand::rngs::mock::StepRng::new(
            seed, seed,
        ));

        let mut sum = 0;

        let res = utxo_pool
            .iter()
            .take_while(|x| {
                if sum >= amount {
                    return false;
                }
                sum += x.tx_out.value;
                true
            })
            .cloned()
            .collect();

        if sum >= amount {
            return Ok(res);
        }

        Err(Error::InvalidParameters("Not enought UTXOs".to_string()))
    }

    fn import_address(&self, _address: &Address) -> Result<(), dlc_manager::error::Error> {
        Ok(())
    }

    fn sign_psbt_input(&self, _: &mut PartiallySignedTransaction, _: usize) -> Result<(), Error> {
        Ok(())
    }

    fn unreserve_utxos(&self, _outpoints: &[OutPoint]) -> Result<(), Error> {
        Ok(())
    }
}

fn get_address() -> Address {
    Address::p2wpkh(
        &bitcoin::PublicKey::from_private_key(
            secp256k1_zkp::SECP256K1,
            &bitcoin::PrivateKey::new(get_secret_key(), bitcoin::Network::Regtest),
        ),
        bitcoin::Network::Regtest,
    )
    .unwrap()
}

pub fn get_secret_key() -> SecretKey {
    SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .unwrap()
}
