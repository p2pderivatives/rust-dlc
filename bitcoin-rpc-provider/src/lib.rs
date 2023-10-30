//! # Bitcoin rpc provider

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::consensus::encode::Error as EncodeError;
use bitcoin::secp256k1::rand::thread_rng;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{
    consensus::Decodable, network::constants::Network, Amount, PrivateKey, Script, Transaction,
    Txid,
};
use bitcoin::{Address, OutPoint, TxOut};
use bitcoincore_rpc::jsonrpc::serde_json::{self};
use bitcoincore_rpc::{json, Auth, Client, RpcApi};
use dlc_manager::error::Error as ManagerError;
use dlc_manager::{Blockchain, Signer, Utxo, Wallet};
use json::EstimateMode;
use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator};
use log::error;
use rust_bitcoin_coin_selection::select_coins;

/// The minimum feerate we are allowed to send, as specify by LDK.
const MIN_FEERATE: u32 = 253;

pub struct BitcoinCoreProvider {
    client: Arc<Mutex<Client>>,
    // Used to implement the FeeEstimator interface, heavily inspired by
    // https://github.com/lightningdevkit/ldk-sample/blob/main/src/bitcoind_client.rs#L26
    fees: Arc<HashMap<ConfirmationTarget, AtomicU32>>,
    /// Indicates whether the wallet is descriptor based or not.
    is_descriptor: bool,
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

impl From<Error> for ManagerError {
    fn from(e: Error) -> ManagerError {
        ManagerError::WalletError(Box::new(e))
    }
}

impl From<EncodeError> for Error {
    fn from(_e: EncodeError) -> Error {
        Error::BitcoinError
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::RpcError(_) => write!(f, "Bitcoin Rpc Error"),
            Error::NotEnoughCoins => {
                write!(f, "Utxo pool did not contain enough coins to reach target.")
            }
            Error::BitcoinError => write!(f, "Bitcoin related error"),
            Error::InvalidState => write!(f, "Unexpected state was encountered"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::RpcError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl BitcoinCoreProvider {
    pub fn new(
        host: String,
        port: u16,
        wallet: Option<String>,
        rpc_user: String,
        rpc_password: String,
    ) -> Result<Self, Error> {
        let rpc_base = format!("http://{}:{}", host, port);
        let rpc_url = if let Some(wallet_name) = wallet {
            format!("{}/wallet/{}", rpc_base, wallet_name)
        } else {
            rpc_base
        };
        let auth = Auth::UserPass(rpc_user, rpc_password);
        Self::new_from_rpc_client(Client::new(&rpc_url, auth)?)
    }

    pub fn new_from_rpc_client(rpc_client: Client) -> Result<Self, Error> {
        let client = Arc::new(Mutex::new(rpc_client));
        let mut fees: HashMap<ConfirmationTarget, AtomicU32> = HashMap::new();
        fees.insert(ConfirmationTarget::Background, AtomicU32::new(MIN_FEERATE));
        fees.insert(ConfirmationTarget::Normal, AtomicU32::new(2000));
        fees.insert(ConfirmationTarget::HighPriority, AtomicU32::new(5000));
        let fees = Arc::new(fees);
        poll_for_fee_estimates(client.clone(), fees.clone());

        #[derive(serde::Deserialize)]
        struct Descriptor {
            descriptors: bool,
        }

        let is_descriptor = client
            .lock()
            .unwrap()
            .call::<Descriptor>("getwalletinfo", &[])?
            .descriptors;
        Ok(BitcoinCoreProvider {
            client,
            fees,
            is_descriptor,
        })
    }
}

fn query_fee_estimate(
    client: &Arc<Mutex<Client>>,
    conf_target: u16,
    estimate_mode: EstimateMode,
) -> Result<u32, bitcoincore_rpc::Error> {
    let client = client.lock().unwrap();
    let resp = client.estimate_smart_fee(conf_target, Some(estimate_mode))?;
    let res = match resp.fee_rate {
        Some(feerate) => std::cmp::max(
            (feerate.to_btc() * 100_000_000.0 / 4.0).round() as u32,
            MIN_FEERATE,
        ),
        None => MIN_FEERATE,
    };
    Ok(res)
}

#[derive(Clone)]
struct UtxoWrap(Utxo);

impl rust_bitcoin_coin_selection::Utxo for UtxoWrap {
    fn get_value(&self) -> u64 {
        self.0.tx_out.value
    }
}

fn rpc_err_to_manager_err(e: bitcoincore_rpc::Error) -> ManagerError {
    Error::RpcError(e).into()
}

fn enc_err_to_manager_err(_e: EncodeError) -> ManagerError {
    Error::BitcoinError.into()
}

#[derive(serde::Deserialize, Debug)]
struct DescriptorInfo {
    desc: String,
}

#[derive(serde::Deserialize, Debug)]
struct DescriptorListResponse {
    descriptors: Vec<DescriptorInfo>,
}

impl Signer for BitcoinCoreProvider {
    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey, ManagerError> {
        if self.is_descriptor {
            let client = self.client.lock().unwrap();
            let DescriptorListResponse { descriptors } = client
                .call::<DescriptorListResponse>("listdescriptors", &[serde_json::Value::Bool(true)])
                .map_err(rpc_err_to_manager_err)?;
            descriptors
                .iter()
                .filter_map(|x| descriptor_to_secret_key(&x.desc))
                .find(|x| x.public_key(secp256k1_zkp::SECP256K1) == *pubkey)
                .ok_or(ManagerError::InvalidState(
                    "Expected a descriptor at this position".to_string(),
                ))
        } else {
            let b_pubkey = bitcoin::PublicKey {
                compressed: true,
                inner: *pubkey,
            };
            let address =
                Address::p2wpkh(&b_pubkey, self.get_network()?).or(Err(Error::BitcoinError))?;

            let pk = self
                .client
                .lock()
                .unwrap()
                .dump_private_key(&address)
                .map_err(rpc_err_to_manager_err)?;
            Ok(pk.inner)
        }
    }

    fn sign_tx_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        tx_out: &TxOut,
        redeem_script: Option<Script>,
    ) -> Result<(), ManagerError> {
        let outpoint = &tx.input[input_index].previous_output;

        let input = json::SignRawTransactionInput {
            txid: outpoint.txid,
            vout: outpoint.vout,
            script_pub_key: tx_out.script_pubkey.clone(),
            redeem_script,
            amount: Some(Amount::from_sat(tx_out.value)),
        };

        let sign_result = self
            .client
            .lock()
            .unwrap()
            .sign_raw_transaction_with_wallet(&*tx, Some(&[input]), None)
            .map_err(rpc_err_to_manager_err)?;
        let signed_tx = Transaction::consensus_decode(&mut sign_result.hex.as_slice())
            .map_err(enc_err_to_manager_err)?;

        tx.input[input_index].script_sig = signed_tx.input[input_index].script_sig.clone();
        tx.input[input_index].witness = signed_tx.input[input_index].witness.clone();

        Ok(())
    }
}

impl Wallet for BitcoinCoreProvider {
    fn get_new_address(&self) -> Result<Address, ManagerError> {
        self.client
            .lock()
            .unwrap()
            .call(
                "getnewaddress",
                &[
                    serde_json::Value::Null,
                    serde_json::Value::String("bech32m".to_string()),
                ],
            )
            .map_err(rpc_err_to_manager_err)
    }

    fn get_new_secret_key(&self) -> Result<SecretKey, ManagerError> {
        let sk = SecretKey::new(&mut thread_rng());
        let network = self.get_network()?;
        let client = self.client.lock().unwrap();
        let pk = PrivateKey {
            compressed: true,
            network,
            inner: sk,
        };
        if self.is_descriptor {
            let wif = pk.to_wif();
            let desc = format!("rawtr({wif})");
            import_descriptor(&client, &desc)?;
        } else {
            client
                .import_private_key(&pk, None, Some(false))
                .map_err(rpc_err_to_manager_err)?;
        }
        Ok(sk)
    }

    fn get_utxos_for_amount(
        &self,
        amount: u64,
        _fee_rate: Option<u64>,
        lock_utxos: bool,
    ) -> Result<Vec<Utxo>, ManagerError> {
        let client = self.client.lock().unwrap();
        let utxo_res = client
            .list_unspent(None, None, None, Some(false), None)
            .map_err(rpc_err_to_manager_err)?;
        let locked = client
            .call::<Vec<serde_json::Value>>("listlockunspent", &[])
            .map_err(rpc_err_to_manager_err)?
            .iter()
            .map(|x| OutPoint {
                txid: x["txid"].as_str().unwrap().parse().unwrap(),
                vout: x["vout"].as_u64().unwrap() as u32,
            })
            .collect::<Vec<_>>();
        let mut utxo_pool: Vec<UtxoWrap> = utxo_res
            .iter()
            .filter(|x| x.spendable && locked.iter().all(|y| y.txid != x.txid || y.vout != x.vout))
            .map(|x| {
                Ok(UtxoWrap(Utxo {
                    tx_out: TxOut {
                        value: x.amount.to_sat(),
                        script_pubkey: x.script_pub_key.clone(),
                    },
                    outpoint: OutPoint {
                        txid: x.txid,
                        vout: x.vout,
                    },
                    address: x.address.as_ref().ok_or(Error::InvalidState)?.clone(),
                    redeem_script: x.redeem_script.as_ref().unwrap_or(&Script::new()).clone(),
                    reserved: false,
                }))
            })
            .collect::<Result<Vec<UtxoWrap>, Error>>()?;
        // TODO(tibo): properly compute the cost of change
        let selection = select_coins(amount, 20, &mut utxo_pool).ok_or(Error::NotEnoughCoins)?;

        if lock_utxos {
            let outputs: Vec<_> = selection.iter().map(|x| x.0.outpoint).collect();
            client
                .lock_unspent(&outputs)
                .map_err(rpc_err_to_manager_err)?;
        }

        Ok(selection.into_iter().map(|x| x.0).collect())
    }

    fn import_address(&self, address: &Address) -> Result<(), ManagerError> {
        if self.is_descriptor {
            let desc = format!("addr({address})");
            import_descriptor(&self.client.lock().unwrap(), &desc)
        } else {
            self.client
                .lock()
                .unwrap()
                .import_address(address, None, Some(false))
                .map_err(rpc_err_to_manager_err)
        }
    }
}

impl Blockchain for BitcoinCoreProvider {
    fn send_transaction(&self, transaction: &Transaction) -> Result<(), ManagerError> {
        self.client
            .lock()
            .unwrap()
            .send_raw_transaction(transaction)
            .map_err(rpc_err_to_manager_err)?;
        Ok(())
    }

    fn get_network(&self) -> Result<Network, ManagerError> {
        let network = match self
            .client
            .lock()
            .unwrap()
            .get_blockchain_info()
            .map_err(rpc_err_to_manager_err)?
            .chain
            .as_ref()
        {
            "main" => Network::Bitcoin,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            _ => {
                return Err(ManagerError::BlockchainError(
                    "Unknown Bitcoin network".to_string(),
                ))
            }
        };

        Ok(network)
    }

    fn get_blockchain_height(&self) -> Result<u64, ManagerError> {
        self.client
            .lock()
            .unwrap()
            .get_block_count()
            .map_err(rpc_err_to_manager_err)
    }

    fn get_block_at_height(&self, height: u64) -> Result<bitcoin::Block, ManagerError> {
        let client = self.client.lock().unwrap();
        let hash = client
            .get_block_hash(height)
            .map_err(rpc_err_to_manager_err)?;
        client.get_block(&hash).map_err(rpc_err_to_manager_err)
    }

    fn get_transaction(&self, tx_id: &Txid) -> Result<Transaction, ManagerError> {
        let tx_info = self
            .client
            .lock()
            .unwrap()
            .get_transaction(tx_id, None)
            .map_err(rpc_err_to_manager_err)?;
        let tx = Transaction::consensus_decode(&mut tx_info.hex.as_slice())
            .or(Err(Error::BitcoinError))?;
        Ok(tx)
    }

    fn get_transaction_confirmations(&self, tx_id: &Txid) -> Result<u32, ManagerError> {
        let tx_info_res = self.client.lock().unwrap().get_transaction(tx_id, None);
        match tx_info_res {
            Ok(tx_info) => Ok(tx_info.info.confirmations as u32),
            Err(e) => match e {
                bitcoincore_rpc::Error::JsonRpc(json_rpc_err) => match json_rpc_err {
                    bitcoincore_rpc::jsonrpc::Error::Rpc(rpc_error) => {
                        if rpc_error.code == -5
                            && rpc_error.message == *"Invalid or non-wallet transaction id"
                        {
                            return Ok(0);
                        }

                        Err(rpc_err_to_manager_err(bitcoincore_rpc::Error::JsonRpc(
                            bitcoincore_rpc::jsonrpc::Error::Rpc(rpc_error),
                        )))
                    }
                    other => Err(rpc_err_to_manager_err(bitcoincore_rpc::Error::JsonRpc(
                        other,
                    ))),
                },
                _ => Err(rpc_err_to_manager_err(e)),
            },
        }
    }
}

impl FeeEstimator for BitcoinCoreProvider {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        self.fees
            .get(&confirmation_target)
            .unwrap()
            .load(Ordering::Acquire)
    }
}

fn poll_for_fee_estimates(
    client: Arc<Mutex<Client>>,
    fees: Arc<HashMap<ConfirmationTarget, AtomicU32>>,
) {
    std::thread::spawn(move || loop {
        match query_fee_estimate(&client, 144, EstimateMode::Economical) {
            Ok(fee_rate) => {
                fees.get(&ConfirmationTarget::Background)
                    .unwrap()
                    .store(fee_rate, Ordering::Release);
            }
            Err(e) => {
                error!("Error querying fee estimate: {}", e);
            }
        };
        match query_fee_estimate(&client, 18, EstimateMode::Conservative) {
            Ok(fee_rate) => {
                fees.get(&ConfirmationTarget::Normal)
                    .unwrap()
                    .store(fee_rate, Ordering::Release);
            }
            Err(e) => {
                error!("Error querying fee estimate: {}", e);
            }
        };
        match query_fee_estimate(&client, 6, EstimateMode::Conservative) {
            Ok(fee_rate) => {
                fees.get(&ConfirmationTarget::HighPriority)
                    .unwrap()
                    .store(fee_rate, Ordering::Release);
            }
            Err(e) => {
                error!("Error querying fee estimate: {}", e);
            }
        };

        std::thread::sleep(Duration::from_secs(60));
    });
}

fn import_descriptor(client: &Client, desc: &str) -> Result<(), ManagerError> {
    let info = client
        .get_descriptor_info(desc)
        .map_err(rpc_err_to_manager_err)?;
    let checksum = info.checksum;
    let args: serde_json::Value = serde_json::from_str(&format!(
        "[{{ \"desc\": \"{desc}#{checksum}\", \"timestamp\": \"now\" }}]"
    ))
    .unwrap();
    client
        .call::<Vec<serde_json::Value>>("importdescriptors", &[args])
        .map_err(rpc_err_to_manager_err)?;
    Ok(())
}

fn descriptor_to_secret_key(desc: &str) -> Option<SecretKey> {
    if !desc.starts_with("rawtr") {
        return None;
    }
    let wif = desc.split_once('(')?.1.split_once(')')?.0;
    let priv_key = PrivateKey::from_wif(wif).ok()?;
    Some(priv_key.inner)
}
