//! # Bitcoin rpc provider

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::Error as EncodeError;
use bitcoin::hashes::serde;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::rand::thread_rng;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{consensus::Decodable, Network, PrivateKey, Transaction, Txid};
use bitcoin::{secp256k1::PublicKey, Address, OutPoint, ScriptBuf, TxOut};
use bitcoincore_rpc::jsonrpc::serde_json;
use bitcoincore_rpc::jsonrpc::serde_json::Value;
use bitcoincore_rpc::{json, Auth, Client, RpcApi};
use bitcoincore_rpc_json::AddressType;
use ddk_manager::error::Error as ManagerError;
use ddk_manager::{Blockchain, ContractSignerProvider, SimpleSigner, Utxo, Wallet};
use hex::DisplayHex;
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
        Ok(Self::new_from_rpc_client(Client::new(&rpc_url, auth)?))
    }

    pub fn new_from_rpc_client(rpc_client: Client) -> Self {
        let client = Arc::new(Mutex::new(rpc_client));
        let mut fees: HashMap<ConfirmationTarget, AtomicU32> = HashMap::with_capacity(7);
        fees.insert(ConfirmationTarget::UrgentOnChainSweep, AtomicU32::new(5000));
        fees.insert(
            ConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
            AtomicU32::new(MIN_FEERATE),
        );
        fees.insert(
            ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
            AtomicU32::new(MIN_FEERATE),
        );
        fees.insert(
            ConfirmationTarget::AnchorChannelFee,
            AtomicU32::new(MIN_FEERATE),
        );
        fees.insert(
            ConfirmationTarget::NonAnchorChannelFee,
            AtomicU32::new(2000),
        );
        fees.insert(
            ConfirmationTarget::ChannelCloseMinimum,
            AtomicU32::new(MIN_FEERATE),
        );
        let fees = Arc::new(fees);
        poll_for_fee_estimates(client.clone(), fees.clone());
        BitcoinCoreProvider { client, fees }
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
        self.0.tx_out.value.to_sat()
    }
}

fn rpc_err_to_manager_err(e: bitcoincore_rpc::Error) -> ManagerError {
    Error::RpcError(e).into()
}

fn enc_err_to_manager_err(_e: EncodeError) -> ManagerError {
    Error::BitcoinError.into()
}

impl ContractSignerProvider for BitcoinCoreProvider {
    type Signer = SimpleSigner;

    fn derive_signer_key_id(&self, _is_offer_party: bool, temp_id: [u8; 32]) -> [u8; 32] {
        temp_id // fixme not safe
    }

    fn derive_contract_signer(&self, keys_id: [u8; 32]) -> Result<Self::Signer, ManagerError> {
        let label_map = self
            .client
            .lock()
            .unwrap()
            .call::<HashMap<Address<NetworkUnchecked>, Value>>(
                "getaddressesbylabel",
                &[Value::String(keys_id.to_lower_hex_string())],
            )
            .unwrap_or_default();

        if let Some(address) = label_map.keys().next() {
            // note: importing a private key seem to generate three different addresses, we thus
            // check that we have exactly three addresses for a single `keys_id`.
            assert_eq!(label_map.len(), 3);

            let sk = self
                .client
                .lock()
                .unwrap()
                .dump_private_key(&address.clone().assume_checked())
                .map_err(rpc_err_to_manager_err)?;
            Ok(SimpleSigner::new(sk.inner))
        } else {
            let sk = SecretKey::new(&mut thread_rng());
            let network = self.get_network()?;
            self.client
                .lock()
                .unwrap()
                .import_private_key(
                    &PrivateKey {
                        compressed: true,
                        network: network.into(),
                        inner: sk,
                    },
                    Some(&keys_id.to_lower_hex_string()),
                    Some(false),
                )
                .map_err(rpc_err_to_manager_err)?;

            Ok(SimpleSigner::new(sk))
        }
    }

    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey, ManagerError> {
        let b_pubkey = bitcoin::CompressedPublicKey(*pubkey);
        let address = Address::p2wpkh(&b_pubkey, self.get_network()?);

        let pk = self
            .client
            .lock()
            .unwrap()
            .dump_private_key(&address)
            .map_err(rpc_err_to_manager_err)?;
        Ok(pk.inner)
    }

    fn get_new_secret_key(&self) -> Result<SecretKey, ManagerError> {
        let sk = SecretKey::new(&mut thread_rng());
        let network = self.get_network()?;
        self.client
            .lock()
            .unwrap()
            .import_private_key(
                &PrivateKey {
                    compressed: true,
                    network: network.into(),
                    inner: sk,
                },
                None,
                Some(false),
            )
            .map_err(rpc_err_to_manager_err)?;

        Ok(sk)
    }
}

impl Wallet for BitcoinCoreProvider {
    fn get_new_address(&self) -> Result<Address, ManagerError> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .get_new_address(None, Some(AddressType::Bech32))
            .map_err(rpc_err_to_manager_err)?
            .assume_checked())
    }

    fn get_new_change_address(&self) -> Result<Address, ManagerError> {
        Ok(self
            .client
            .lock()
            .unwrap()
            .call::<Address<NetworkUnchecked>>(
                "getrawchangeaddress",
                &[opt_into_json(Some(AddressType::Bech32))?],
            )
            .map_err(rpc_err_to_manager_err)?
            .assume_checked())
    }

    fn get_utxos_for_amount(
        &self,
        amount: u64,
        _fee_rate: u64,
        lock_utxos: bool,
    ) -> Result<Vec<Utxo>, ManagerError> {
        let client = self.client.lock().unwrap();
        let utxo_res = client
            .list_unspent(None, None, None, Some(false), None)
            .map_err(rpc_err_to_manager_err)?;
        let mut utxo_pool: Vec<UtxoWrap> = utxo_res
            .iter()
            .filter(|x| x.spendable)
            .map(|x| {
                Ok(UtxoWrap(Utxo {
                    tx_out: TxOut {
                        value: x.amount,
                        script_pubkey: x.script_pub_key.clone(),
                    },
                    outpoint: OutPoint {
                        txid: x.txid,
                        vout: x.vout,
                    },
                    address: x
                        .address
                        .as_ref()
                        .map(|x| x.clone().assume_checked())
                        .ok_or(Error::InvalidState)?,
                    redeem_script: x
                        .redeem_script
                        .as_ref()
                        .cloned()
                        .unwrap_or(ScriptBuf::new()),
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
        self.client
            .lock()
            .unwrap()
            .import_address(address, None, Some(false))
            .map_err(rpc_err_to_manager_err)
    }

    fn sign_psbt_input(&self, psbt: &mut Psbt, input_index: usize) -> Result<(), ManagerError> {
        let outpoint = &psbt.unsigned_tx.input[input_index].previous_output;
        let tx_out = if let Some(input) = psbt.inputs.get(input_index) {
            if let Some(wit_utxo) = &input.witness_utxo {
                Ok(wit_utxo.clone())
            } else if let Some(in_tx) = &input.non_witness_utxo {
                Ok(in_tx.output[outpoint.vout as usize].clone())
            } else {
                Err(ManagerError::InvalidParameters(
                    "No TxOut for PSBT input".to_string(),
                ))
            }
        } else {
            Err(ManagerError::InvalidParameters(
                "No TxOut for PSBT input".to_string(),
            ))
        }?;

        let redeem_script = psbt
            .inputs
            .get(input_index)
            .and_then(|i| i.redeem_script.clone());

        let input = json::SignRawTransactionInput {
            txid: outpoint.txid,
            vout: outpoint.vout,
            script_pub_key: tx_out.script_pubkey.clone(),
            redeem_script,
            amount: Some(tx_out.value),
        };

        let sign_result = self
            .client
            .lock()
            .unwrap()
            .sign_raw_transaction_with_wallet(&psbt.unsigned_tx, Some(&[input]), None)
            .map_err(rpc_err_to_manager_err)?;
        let signed_tx = Transaction::consensus_decode(&mut sign_result.hex.as_slice())
            .map_err(enc_err_to_manager_err)?;

        psbt.inputs[input_index].final_script_sig =
            Some(signed_tx.input[input_index].script_sig.clone());
        psbt.inputs[input_index].final_script_witness =
            Some(signed_tx.input[input_index].witness.clone());

        Ok(())
    }

    fn unreserve_utxos(&self, outpoints: &[OutPoint]) -> Result<(), ManagerError> {
        match self
            .client
            .lock()
            .unwrap()
            .unlock_unspent(outpoints)
            .map_err(rpc_err_to_manager_err)?
        {
            true => Ok(()),
            false => Err(ManagerError::StorageError(format!(
                "Failed to unlock utxos: {outpoints:?}"
            ))),
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
        let network = self
            .client
            .lock()
            .unwrap()
            .get_blockchain_info()
            .map_err(rpc_err_to_manager_err)?
            .chain;

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
        match query_fee_estimate(&client, 1008, EstimateMode::Economical) {
            Ok(fee_rate) => {
                fees.get(&ConfirmationTarget::MinAllowedAnchorChannelRemoteFee)
                    .unwrap()
                    .store(fee_rate, Ordering::Release);
            }
            Err(e) => {
                error!("Error querying fee estimate: {}", e);
            }
        };
        match query_fee_estimate(&client, 144, EstimateMode::Economical) {
            Ok(fee_rate) => {
                fees.get(&ConfirmationTarget::AnchorChannelFee)
                    .unwrap()
                    .store(fee_rate, Ordering::Release);
                fees.get(&ConfirmationTarget::ChannelCloseMinimum)
                    .unwrap()
                    .store(fee_rate, Ordering::Release);
                fees.get(&ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee)
                    .unwrap()
                    .store(fee_rate - 250, Ordering::Release);
            }
            Err(e) => {
                error!("Error querying fee estimate: {}", e);
            }
        };
        match query_fee_estimate(&client, 18, EstimateMode::Conservative) {
            Ok(fee_rate) => {
                fees.get(&ConfirmationTarget::NonAnchorChannelFee)
                    .unwrap()
                    .store(fee_rate, Ordering::Release);
            }
            Err(e) => {
                error!("Error querying fee estimate: {}", e);
            }
        };
        match query_fee_estimate(&client, 6, EstimateMode::Conservative) {
            Ok(fee_rate) => {
                fees.get(&ConfirmationTarget::UrgentOnChainSweep)
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

/// Shorthand for converting a variable into a serde_json::Value.
fn into_json<T>(val: T) -> bitcoincore_rpc::Result<Value>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
fn opt_into_json<T>(opt: Option<T>) -> Result<Value, ManagerError>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(into_json(val).map_err(rpc_err_to_manager_err)?),
        None => Ok(Value::Null),
    }
}
