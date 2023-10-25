use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::consensus::Decodable;
use bitcoin::hashes::hex::FromHex;
use bitcoin::util::uint::Uint256;
use bitcoin::{Block, BlockHash, BlockHeader, Network, OutPoint, Script, Transaction, TxOut, Txid};
use bitcoin_test_utils::tx_to_string;
use dlc_manager::{error::Error, Blockchain, Utxo};
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning_block_sync::{BlockData, BlockHeaderData, BlockSource, BlockSourceError};
use reqwest::blocking::Response;
use serde::Deserialize;
use serde::Serialize;

const MIN_FEERATE: u32 = 253;

#[derive(Clone, Eq, Hash, PartialEq)]
pub enum Target {
    Minimum = 1008,
    Background = 144,
    Normal = 18,
    HighPriority = 6,
}

pub struct ElectrsBlockchainProvider {
    host: String,
    client: reqwest::blocking::Client,
    async_client: reqwest::Client,
    network: Network,
    fees: Arc<HashMap<Target, AtomicU32>>,
}

impl ElectrsBlockchainProvider {
    pub fn new(host: String, network: Network) -> Self {
        let mut fees: HashMap<Target, AtomicU32> = HashMap::new();
        fees.insert(Target::Background, AtomicU32::new(MIN_FEERATE));
        fees.insert(Target::Normal, AtomicU32::new(2000));
        fees.insert(Target::HighPriority, AtomicU32::new(5000));
        let fees = Arc::new(fees);
        poll_for_fee_estimates(fees.clone(), &host);
        Self {
            host,
            network,
            client: reqwest::blocking::Client::new(),
            async_client: reqwest::Client::new(),
            fees,
        }
    }

    fn get(&self, sub_url: &str) -> Result<Response, Error> {
        self.client
            .get(format!("{}{}", self.host, sub_url))
            .send()
            .map_err(|x| {
                dlc_manager::error::Error::IOError(lightning::io::Error::new(
                    lightning::io::ErrorKind::Other,
                    x,
                ))
            })
    }

    async fn get_async(&self, sub_url: &str) -> Result<reqwest::Response, reqwest::Error> {
        self.async_client
            .get(format!("{}{}", self.host, sub_url))
            .send()
            .await
    }

    fn get_text(&self, sub_url: &str) -> Result<String, Error> {
        self.get(sub_url)?.text().map_err(|x| {
            dlc_manager::error::Error::IOError(lightning::io::Error::new(
                lightning::io::ErrorKind::Other,
                x,
            ))
        })
    }

    fn get_u64(&self, sub_url: &str) -> Result<u64, Error> {
        self.get_text(sub_url)?
            .parse()
            .map_err(|e: std::num::ParseIntError| Error::BlockchainError(e.to_string()))
    }

    fn get_bytes(&self, sub_url: &str) -> Result<Vec<u8>, Error> {
        let bytes = self.get(sub_url)?.bytes();
        Ok(bytes
            .map_err(|e| Error::BlockchainError(e.to_string()))?
            .into_iter()
            .collect::<Vec<_>>())
    }

    fn get_from_json<T>(&self, sub_url: &str) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        self.get(sub_url)?
            .json::<T>()
            .map_err(|e| Error::BlockchainError(e.to_string()))
    }

    pub fn get_outspends(&self, txid: &Txid) -> Result<Vec<OutSpendResp>, Error> {
        self.get_from_json(&format!("tx/{txid}/outspends"))
    }
}

impl Blockchain for ElectrsBlockchainProvider {
    fn send_transaction(&self, transaction: &Transaction) -> Result<(), dlc_manager::error::Error> {
        let res = self
            .client
            .post(format!("{}tx", self.host))
            .body(tx_to_string(transaction))
            .send()
            .map_err(|x| {
                dlc_manager::error::Error::IOError(lightning::io::Error::new(
                    lightning::io::ErrorKind::Other,
                    x,
                ))
            })?;
        if let Err(error) = res.error_for_status_ref() {
            let body = res.text().unwrap_or_default();
            return Err(dlc_manager::error::Error::InvalidParameters(format!(
                "Server returned error: {error} {body}"
            )));
        }
        Ok(())
    }

    fn get_network(
        &self,
    ) -> Result<bitcoin::network::constants::Network, dlc_manager::error::Error> {
        Ok(self.network)
    }

    fn get_blockchain_height(&self) -> Result<u64, dlc_manager::error::Error> {
        self.get_u64("blocks/tip/height")
    }

    fn get_block_at_height(&self, height: u64) -> Result<Block, dlc_manager::error::Error> {
        let hash_at_height = self.get_text(&format!("block-height/{height}"))?;
        let raw_block = self.get_bytes(&format!("block/{hash_at_height}/raw"))?;
        Block::consensus_decode(&mut std::io::Cursor::new(&*raw_block))
            .map_err(|e| Error::BlockchainError(e.to_string()))
    }

    fn get_transaction(&self, tx_id: &Txid) -> Result<Transaction, dlc_manager::error::Error> {
        let raw_tx = self.get_bytes(&format!("tx/{tx_id}/raw"))?;
        Transaction::consensus_decode(&mut std::io::Cursor::new(&*raw_tx))
            .map_err(|e| Error::BlockchainError(e.to_string()))
    }

    fn get_transaction_confirmations(
        &self,
        tx_id: &Txid,
    ) -> Result<u32, dlc_manager::error::Error> {
        let tx_status = self.get_from_json::<TxStatus>(&format!("tx/{tx_id}/status"))?;
        if tx_status.confirmed {
            let block_chain_height = self.get_blockchain_height()?;
            if let Some(block_height) = tx_status.block_height {
                return Ok((block_chain_height - block_height + 1) as u32);
            }
        }

        Ok(0)
    }
}

impl simple_wallet::WalletBlockchainProvider for ElectrsBlockchainProvider {
    fn get_utxos_for_address(&self, address: &bitcoin::Address) -> Result<Vec<Utxo>, Error> {
        let utxos: Vec<UtxoResp> = self.get_from_json(&format!("address/{address}/utxo"))?;

        utxos
            .into_iter()
            .map(|x| {
                Ok(Utxo {
                    address: address.clone(),
                    outpoint: OutPoint {
                        txid: x
                            .txid
                            .parse()
                            .map_err(|e: <bitcoin::Txid as FromStr>::Err| {
                                Error::BlockchainError(e.to_string())
                            })?,
                        vout: x.vout,
                    },
                    redeem_script: Script::default(),
                    reserved: false,
                    tx_out: TxOut {
                        value: x.value,
                        script_pubkey: address.script_pubkey(),
                    },
                })
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    fn is_output_spent(&self, txid: &Txid, vout: u32) -> Result<bool, Error> {
        let is_spent: SpentResp = self.get_from_json(&format!("tx/{txid}/outspend/{vout}"))?;
        Ok(is_spent.spent)
    }
}

impl FeeEstimator for ElectrsBlockchainProvider {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        let est = match confirmation_target {
            ConfirmationTarget::MempoolMinimum => self
                .fees
                .get(&Target::Minimum)
                .unwrap()
                .load(Ordering::Acquire),
            ConfirmationTarget::Background => self
                .fees
                .get(&Target::Background)
                .unwrap()
                .load(Ordering::Acquire),
            ConfirmationTarget::Normal => self
                .fees
                .get(&Target::Normal)
                .unwrap()
                .load(Ordering::Acquire),
            ConfirmationTarget::HighPriority => self
                .fees
                .get(&Target::HighPriority)
                .unwrap()
                .load(Ordering::Acquire),
        };
        u32::max(est, MIN_FEERATE)
    }
}

impl BlockSource for ElectrsBlockchainProvider {
    fn get_header<'a>(
        &'a self,
        header_hash: &'a bitcoin::BlockHash,
        _: Option<u32>,
    ) -> lightning_block_sync::AsyncBlockSourceResult<'a, lightning_block_sync::BlockHeaderData>
    {
        Box::pin(async move {
            let block_info: BlockInfo = self
                .get_async(&format!("block/{header_hash:x}"))
                .await
                .map_err(BlockSourceError::transient)?
                .json()
                .await
                .map_err(BlockSourceError::transient)?;
            let header_hex_str = self
                .get_async(&format!("block/{header_hash:x}/header"))
                .await
                .map_err(BlockSourceError::transient)?
                .text()
                .await
                .map_err(BlockSourceError::transient)?;
            let header_hex = bitcoin_test_utils::str_to_hex(&header_hex_str);
            let header = BlockHeader::consensus_decode(&mut std::io::Cursor::new(&*header_hex))
                .expect("to have a valid header");
            header.validate_pow(&header.target()).unwrap();
            Ok(BlockHeaderData {
                header,
                height: block_info.height,
                // Electrs doesn't seem to make this available.
                chainwork: Uint256::from_u64(10).unwrap(),
            })
        })
    }

    fn get_block<'a>(
        &'a self,
        header_hash: &'a bitcoin::BlockHash,
    ) -> lightning_block_sync::AsyncBlockSourceResult<'a, BlockData> {
        Box::pin(async move {
            let block_raw = self
                .get_async(&format!("block/{header_hash:x}/raw"))
                .await
                .map_err(BlockSourceError::transient)?
                .bytes()
                .await
                .map_err(BlockSourceError::transient)?;
            let block = Block::consensus_decode(&mut std::io::Cursor::new(&*block_raw))
                .expect("to have a valid header");
            Ok(BlockData::FullBlock(block))
        })
    }

    fn get_best_block(
        &self,
    ) -> lightning_block_sync::AsyncBlockSourceResult<(bitcoin::BlockHash, Option<u32>)> {
        Box::pin(async move {
            let block_tip_hash: String = self
                .get_async("blocks/tip/hash")
                .await
                .map_err(BlockSourceError::transient)?
                .text()
                .await
                .map_err(BlockSourceError::transient)?;
            let block_tip_height: u32 = self
                .get_async("blocks/tip/height")
                .await
                .map_err(BlockSourceError::transient)?
                .text()
                .await
                .map_err(BlockSourceError::transient)?
                .parse()
                .map_err(BlockSourceError::transient)?;
            Ok((
                BlockHash::from_hex(&block_tip_hash).map_err(BlockSourceError::transient)?,
                Some(block_tip_height),
            ))
        })
    }
}

impl BroadcasterInterface for ElectrsBlockchainProvider {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        let client = self.client.clone();
        let host = self.host.clone();
        let bodies = txs
            .iter()
            .map(|tx| bitcoin_test_utils::tx_to_string(tx))
            .collect::<Vec<_>>();
        std::thread::spawn(move || {
            for body in bodies {
                match client.post(format!("{host}tx")).body(body).send() {
                    Err(_) => {}
                    Ok(res) => {
                        if res.error_for_status_ref().is_err() {
                            // let body = res.text().unwrap_or_default();
                            // TODO(tibo): log
                        }
                    }
                };
            }
        });
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TxStatus {
    confirmed: bool,
    block_height: Option<u64>,
    block_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct UtxoResp {
    txid: String,
    vout: u32,
    value: u64,
    status: UtxoStatus,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum UtxoStatus {
    Confirmed {
        confirmed: bool,
        block_height: u64,
        block_hash: String,
        block_time: u64,
    },
    Unconfirmed {
        confirmed: bool,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct SpentResp {
    spent: bool,
}

type FeeEstimates = std::collections::HashMap<u16, f32>;

fn store_estimate_for_target(
    fees: &Arc<HashMap<Target, AtomicU32>>,
    fee_estimates: &FeeEstimates,
    target: Target,
) {
    #[allow(clippy::redundant_clone)]
    let val = get_estimate_for_target(fee_estimates, &(target.clone() as u16));
    fees.get(&target)
        .unwrap()
        .store(val, std::sync::atomic::Ordering::Relaxed);
}

fn poll_for_fee_estimates(fees: Arc<HashMap<Target, AtomicU32>>, host: &str) {
    let host = host.to_owned();
    std::thread::spawn(move || loop {
        if let Ok(res) = reqwest::blocking::get(format!("{host}fee-estimates")) {
            if let Ok(fee_estimates) = res.json::<FeeEstimates>() {
                store_estimate_for_target(&fees, &fee_estimates, Target::Background);
                store_estimate_for_target(&fees, &fee_estimates, Target::HighPriority);
                store_estimate_for_target(&fees, &fee_estimates, Target::Normal);
            }
        }

        std::thread::sleep(Duration::from_secs(60));
    });
}

fn get_estimate_for_target(fee_estimates: &FeeEstimates, target: &u16) -> u32 {
    match fee_estimates.get(target) {
        Some(sats_per_vbytes) => sats_per_vbyte_to_sats_per_1000_weight(*sats_per_vbytes),
        None => MIN_FEERATE,
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct BlockInfo {
    height: u32,
}

fn sats_per_vbyte_to_sats_per_1000_weight(input: f32) -> u32 {
    (input * 1000.0 / 4.0).round() as u32
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum OutSpendResp {
    Spent(OutSpendInfo),
    Unspent { spent: bool },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutSpendInfo {
    pub spent: bool,
    pub txid: Txid,
    pub vin: usize,
    pub status: UtxoStatus,
}
