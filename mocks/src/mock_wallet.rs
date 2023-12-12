use std::rc::Rc;

use bitcoin::{Address, PackedLockTime, Script, Transaction, TxOut};
use dlc_manager::{error::Error, Blockchain, Signer, Utxo, Wallet};
use secp256k1_zkp::{rand::seq::SliceRandom, SecretKey};

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
                script_pubkey: Script::default(),
            };
            let tx = Transaction {
                version: 2,
                lock_time: PackedLockTime::ZERO,
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
                redeem_script: Script::default(),
                reserved: false,
            };

            utxos.push(utxo);
        }

        Self { utxos }
    }
}

impl Signer for MockWallet {
    fn sign_tx_input(
        &self,
        _tx: &mut bitcoin::Transaction,
        _input_index: usize,
        _tx_out: &bitcoin::TxOut,
        _redeem_script: Option<bitcoin::Script>,
    ) -> Result<(), dlc_manager::error::Error> {
        Ok(())
    }

    fn get_secret_key_for_pubkey(
        &self,
        _pubkey: &secp256k1_zkp::PublicKey,
    ) -> Result<SecretKey, dlc_manager::error::Error> {
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

    fn get_new_secret_key(&self) -> Result<SecretKey, dlc_manager::error::Error> {
        Ok(get_secret_key())
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
