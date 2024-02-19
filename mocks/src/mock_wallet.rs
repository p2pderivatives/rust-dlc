use std::{ops::Deref, rc::Rc};

use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{Address, OutPoint, PackedLockTime, Script, Transaction, TxOut};
use dlc_manager::{error::Error, Blockchain, Signer, Utxo, Wallet};
use lightning::chain::chaininterface::BroadcasterInterface;
use secp256k1_zkp::{rand::seq::SliceRandom, SecretKey};

use crate::mock_blockchain::MockBlockchain;

pub struct MockWallet {
    utxos: Vec<Utxo>,
}

impl MockWallet {
    pub fn new<T: Deref>(blockchain: &Rc<MockBlockchain<T>>, nb_utxo: u16) -> Self
    where
        T::Target: BroadcasterInterface,
    {
        let mut utxos = Vec::with_capacity(nb_utxo as usize);

        for i in 0..nb_utxo {
            let tx_out = TxOut {
                value: 1000000 * i as u64,
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
    fn sign_psbt_input(
        &self,
        _psbt: &mut PartiallySignedTransaction,
        _idx: usize,
    ) -> Result<(), Error> {
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

    fn get_new_secret_key(&self) -> Result<SecretKey, dlc_manager::error::Error> {
        Ok(get_secret_key())
    }

    fn get_utxos_for_amount(
        &self,
        amount: u64,
        _fee_rate: Option<u64>,
        _base_weight_wu: u64,
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

        Err(Error::InvalidParameters("".to_string()))
    }

    fn import_address(&self, _address: &Address) -> Result<(), dlc_manager::error::Error> {
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
