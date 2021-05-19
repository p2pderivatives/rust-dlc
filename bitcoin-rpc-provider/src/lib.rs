//! # Bitcoin rpc provider

extern crate bitcoin;
extern crate bitcoincore_rpc;
extern crate bitcoincore_rpc_json;
extern crate dlc_daemon;
extern crate rust_bitcoin_coin_selection;

use bitcoin::secp256k1::rand::thread_rng;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{
    consensus::Decodable, network::constants::Network, PrivateKey, Script, Transaction, Txid,
};
use bitcoin::{Address, OutPoint, TxOut};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc_json::AddressType;
use dlc_daemon::daemon::{Blockchain, Error as DaemonError, Utxo, Wallet};
use rust_bitcoin_coin_selection::select_coins;
use std::error::Error as StdError;

pub struct BitcoinCoreProvider {
    pub client: Client,
    pub network: Network,
}

#[derive(Debug)]
pub enum Error {
    RpcError(bitcoincore_rpc::Error),
    NotEnoughCoins,
    BitcoinError,
    InvalidState,
}

impl From<bitcoincore_rpc::Error> for Error {
    fn from(e: bitcoincore_rpc::Error) -> Error {
        Error::RpcError(e)
    }
}

impl From<Error> for dlc_daemon::daemon::Error {
    fn from(e: Error) -> dlc_daemon::daemon::Error {
        dlc_daemon::daemon::Error::WalletError(Box::new(e))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::RpcError(e) => write!(f, "Bitcoin Rpc Error {}", e),
            Error::NotEnoughCoins => {
                write!(f, "Utxo pool did not contain enough coins to reach target.")
            }
            Error::BitcoinError => write!(f, "Bitcoin related error"),
            Error::InvalidState => write!(f, "Unexpected state was encountered"),
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        "bitcoincore-rpc-provider error"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            Error::RpcError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl BitcoinCoreProvider {
    pub fn new(url: String, auth: Auth, network: Network) -> Result<Self, Error> {
        let client = Client::new(url, auth)?;
        Ok(BitcoinCoreProvider { client, network })
    }
}

#[derive(Clone)]
struct UtxoWrap(Utxo);

impl rust_bitcoin_coin_selection::Utxo for UtxoWrap {
    fn get_value(&self) -> u64 {
        self.0.tx_out.value
    }
}

fn rpc_err_to_daemon_err<T>(e: bitcoincore_rpc::Error) -> Result<T, DaemonError> {
    Err(Error::RpcError(e).into())
}

impl Wallet for BitcoinCoreProvider {
    fn get_new_address(&self) -> Result<Address, DaemonError> {
        self.client
            .get_new_address(None, Some(AddressType::Bech32))
            .or_else(rpc_err_to_daemon_err)
    }

    fn get_new_secret_key(&self) -> Result<SecretKey, DaemonError> {
        let sk = SecretKey::new(&mut thread_rng());
        self.client
            .import_private_key(
                &PrivateKey {
                    compressed: true,
                    network: self.network,
                    key: sk,
                },
                None,
                Some(false),
            )
            .or_else(rpc_err_to_daemon_err)?;

        Ok(sk)
    }

    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey, DaemonError> {
        let b_pubkey = bitcoin::PublicKey {
            compressed: true,
            key: pubkey.clone(),
        };
        let address = Address::p2wpkh(&b_pubkey, self.network).or(Err(Error::BitcoinError))?;
        self.get_secret_key_for_address(&address)
    }

    fn get_secret_key_for_address(
        &self,
        address: &Address,
    ) -> Result<SecretKey, dlc_daemon::daemon::Error> {
        let pk = self
            .client
            .dump_private_key(address)
            .or_else(rpc_err_to_daemon_err)?;
        Ok(pk.key)
    }

    fn get_utxos_for_amount(
        &self,
        amount: u64,
        fee_rate: Option<u64>,
        lock_utxos: Option<bool>,
    ) -> Result<Vec<Utxo>, dlc_daemon::daemon::Error> {
        let utxo_res = self
            .client
            .list_unspent(None, None, None, None, None)
            .or_else(rpc_err_to_daemon_err)?;
        let mut utxo_pool: Vec<UtxoWrap> = utxo_res
            .iter()
            .map(|x| {
                Ok(UtxoWrap(Utxo {
                    tx_out: TxOut {
                        value: x.amount.as_sat(),
                        script_pubkey: x.script_pub_key.clone(),
                    },
                    outpoint: OutPoint {
                        txid: x.txid.clone(),
                        vout: x.vout,
                    },
                    address: x.address.as_ref().ok_or(Error::InvalidState)?.clone(),
                    redeem_script: x.redeem_script.as_ref().unwrap_or(&Script::new()).clone(),
                }))
            })
            .collect::<Result<Vec<UtxoWrap>, Error>>()?;
        // TODO(tibo): properly compute the cost of change
        let selection = select_coins(amount, 20, &mut utxo_pool).ok_or(Error::NotEnoughCoins)?;
        Ok(selection.into_iter().map(|x| x.0).collect())
    }

    fn import_address(&self, address: &Address) -> Result<(), DaemonError> {
        self.client
            .import_address(address, None, None)
            .or_else(rpc_err_to_daemon_err)
    }
}

impl Blockchain for BitcoinCoreProvider {
    fn send_transaction(&self, transaction: &Transaction) -> Result<(), DaemonError> {
        self.client
            .send_raw_transaction(transaction)
            .or_else(rpc_err_to_daemon_err)?;
        Ok(())
    }

    fn get_transaction(&self, tx_id: &Txid) -> Result<Transaction, DaemonError> {
        let tx_info = self
            .client
            .get_transaction(tx_id, None)
            .or_else(rpc_err_to_daemon_err)?;
        let tx = Transaction::consensus_decode(&*tx_info.hex).or(Err(Error::BitcoinError))?;
        Ok(tx)
    }

    fn get_transaction_confirmations(&self, tx_id: &Txid) -> Result<u32, DaemonError> {
        let tx_info_res = self.client.get_transaction(tx_id, None);
        match tx_info_res {
            Ok(tx_info) => Ok(tx_info.info.confirmations as u32),
            Err(e) => match e {
                bitcoincore_rpc::Error::JsonRpc(json_rpc_err) => match json_rpc_err {
                    bitcoincore_rpc::jsonrpc::Error::Rpc(rpc_error) => {
                        if rpc_error.code == -5
                            && rpc_error.message
                                == "Invalid or non-wallet transaction id".to_string()
                        {
                            return Ok(0);
                        }

                        rpc_err_to_daemon_err(bitcoincore_rpc::Error::JsonRpc(
                            bitcoincore_rpc::jsonrpc::Error::Rpc(rpc_error),
                        ))
                    }
                    other => rpc_err_to_daemon_err(bitcoincore_rpc::Error::JsonRpc(other)),
                },
                _ => rpc_err_to_daemon_err(e),
            },
        }
    }

    fn get_network(&self) -> Network {
        self.network
    }
}
