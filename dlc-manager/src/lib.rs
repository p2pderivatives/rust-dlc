//! # Library providing data structures and functions supporting the execution
//! and management of DLC.

#![crate_name = "dlc_manager"]
// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

extern crate async_trait;
extern crate bitcoin;
extern crate dlc;
#[macro_use]
extern crate dlc_messages;
extern crate core;
extern crate dlc_trie;
extern crate lightning;
extern crate log;
#[cfg(feature = "fuzztarget")]
extern crate rand_chacha;
extern crate secp256k1_zkp;

#[macro_use]
mod utils;

pub mod chain_monitor;
pub mod channel;
pub mod channel_updater;
pub mod contract;
pub mod contract_updater;
mod conversion_utils;
pub mod error;
pub mod manager;
pub mod payout_curve;
pub mod sub_channel_manager;
pub mod subchannel;

use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{Address, Block, OutPoint, Script, Transaction, TxOut, Txid};
use chain_monitor::ChainMonitor;
use channel::offered_channel::OfferedChannel;
use channel::signed_channel::{SignedChannel, SignedChannelStateType};
use channel::Channel;
use contract::PreClosedContract;
use contract::{offered_contract::OfferedContract, signed_contract::SignedContract, Contract};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::ser_impls::{read_address, write_address};
use error::Error;
use lightning::ln::msgs::DecodeError;
use lightning::ln::ChannelId;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::XOnlyPublicKey;
use secp256k1_zkp::{PublicKey, SecretKey};
use sub_channel_manager::Action;
use subchannel::SubChannel;

/// Type alias for a contract id.
pub type ContractId = [u8; 32];

/// Type alias for a DLC channel ID.
pub type DlcChannelId = [u8; 32];

/// The reference id struct for a user provided id to refer to the rust dlc data and messages
pub type ReferenceId = [u8; 32];

/// Time trait to provide current unix time. Mainly defined to facilitate testing.
pub trait Time {
    /// Must return the unix epoch corresponding to the current time.
    fn unix_time_now(&self) -> u64;
}

/// Provide current time through `SystemTime`.
pub struct SystemTimeProvider {}

impl Time for SystemTimeProvider {
    fn unix_time_now(&self) -> u64 {
        let now = std::time::SystemTime::now();
        now.duration_since(std::time::UNIX_EPOCH)
            .expect("Unexpected time error")
            .as_secs()
    }
}

/// Provides signing related functionalities.
pub trait Signer {
    /// Signs a transaction input
    fn sign_psbt_input(
        &self,
        psbt: &mut PartiallySignedTransaction,
        input_index: usize,
    ) -> Result<(), Error>;
    /// Get the secret key associated with the provided public key.
    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey, Error>;
}

/// Wallet trait to provide functionalities related to generating, storing and
/// managing bitcoin addresses and UTXOs.
pub trait Wallet: Signer {
    /// Returns a new (unused) address.
    fn get_new_address(&self) -> Result<Address, Error>;
    /// Generate a new secret key and store it in the wallet so that it can later
    /// be retrieved.
    fn get_new_secret_key(&self) -> Result<SecretKey, Error>;
    /// Get a set of UTXOs to fund the given amount.
    fn get_utxos_for_amount(
        &self,
        amount: u64,
        fee_rate: Option<u64>,
        lock_utxos: bool,
    ) -> Result<Vec<Utxo>, Error>;
    /// Import the provided address.
    fn import_address(&self, address: &Address) -> Result<(), Error>;
    /// Unlock reserved utxo
    fn unreserve_utxos(&self, outpoints: &[OutPoint]) -> Result<(), Error>;
}

/// Blockchain trait provides access to the bitcoin blockchain.
pub trait Blockchain {
    /// Broadcast the given transaction to the bitcoin network.
    fn send_transaction(&self, transaction: &Transaction) -> Result<(), Error>;
    /// Returns the network currently used (mainnet, testnet or regtest).
    fn get_network(&self) -> Result<bitcoin::network::constants::Network, Error>;
    /// Returns the height of the blockchain
    fn get_blockchain_height(&self) -> Result<u64, Error>;
    /// Returns the block at given height
    fn get_block_at_height(&self, height: u64) -> Result<Block, Error>;
    /// Get the transaction with given id.
    fn get_transaction(&self, tx_id: &Txid) -> Result<Transaction, Error>;
    /// Get the number of confirmation for the transaction with given id.
    fn get_transaction_confirmations(&self, tx_id: &Txid) -> Result<u32, Error>;
}

/// Storage trait provides functionalities to store and retrieve DLCs.
pub trait Storage {
    /// Returns the contract with given id if found.
    fn get_contract(&self, id: &ContractId) -> Result<Option<Contract>, Error>;
    /// Return all contracts
    fn get_contracts(&self) -> Result<Vec<Contract>, Error>;
    /// Create a record for the given contract.
    fn create_contract(&self, contract: &OfferedContract) -> Result<(), Error>;
    /// Delete the record for the contract with the given id.
    fn delete_contract(&self, id: &ContractId) -> Result<(), Error>;
    /// Update the given contract.
    fn update_contract(&self, contract: &Contract) -> Result<(), Error>;
    /// Returns the set of contracts in offered state.
    fn get_contract_offers(&self) -> Result<Vec<OfferedContract>, Error>;
    /// Returns the set of contracts in signed state.
    fn get_signed_contracts(&self) -> Result<Vec<SignedContract>, Error>;
    /// Returns the set of confirmed contracts.
    fn get_confirmed_contracts(&self) -> Result<Vec<SignedContract>, Error>;
    /// Returns the set of contracts whos broadcasted cet has not been verified to be confirmed on
    /// blockchain
    fn get_preclosed_contracts(&self) -> Result<Vec<PreClosedContract>, Error>;
    /// Update the state of the channel and optionally its associated contract
    /// atomically.
    fn upsert_channel(&self, channel: Channel, contract: Option<Contract>) -> Result<(), Error>;
    /// Delete the channel with given [`DlcChannelId`] if any.
    fn delete_channel(&self, channel_id: &DlcChannelId) -> Result<(), Error>;
    /// Returns the channel with given [`DlcChannelId`] if any.
    fn get_channel(&self, channel_id: &DlcChannelId) -> Result<Option<Channel>, Error>;
    /// Returns all channels in the store.
    fn get_channels(&self) -> Result<Vec<Channel>, Error>;
    /// Returns the set of [`SignedChannel`] in the store. Returns only the one
    /// with matching `channel_state` if set.
    fn get_signed_channels(
        &self,
        channel_state: Option<SignedChannelStateType>,
    ) -> Result<Vec<SignedChannel>, Error>;
    /// Returns the set of channels in offer state.
    fn get_offered_channels(&self) -> Result<Vec<OfferedChannel>, Error>;
    /// Writes the [`ChainMonitor`] data to the store.
    fn persist_chain_monitor(&self, monitor: &ChainMonitor) -> Result<(), Error>;
    /// Returns the latest [`ChainMonitor`] in the store if any.
    fn get_chain_monitor(&self) -> Result<Option<ChainMonitor>, Error>;
    /// Creates or updates a [`SubChannel`].
    fn upsert_sub_channel(&self, subchannel: &SubChannel) -> Result<(), Error>;
    /// Returns the [`SubChannel`] with given [`ChannelId`] if it exists.
    fn get_sub_channel(&self, channel_id: ChannelId) -> Result<Option<SubChannel>, Error>;
    /// Return all the [`SubChannel`] within the store.
    fn get_sub_channels(&self) -> Result<Vec<SubChannel>, Error>;
    /// Returns all the [`SubChannel`] in the `Offered` state.
    fn get_offered_sub_channels(&self) -> Result<Vec<SubChannel>, Error>;
    /// Save sub channel actions
    fn save_sub_channel_actions(&self, actions: &[Action]) -> Result<(), Error>;
    /// Get saved sub channel actions
    fn get_sub_channel_actions(&self) -> Result<Vec<Action>, Error>;
}

/// Oracle trait provides access to oracle information.
pub trait Oracle {
    /// Returns the public key of the oracle.
    fn get_public_key(&self) -> XOnlyPublicKey;
    /// Returns the announcement for the event with the given id if found.
    fn get_announcement(&self, event_id: &str) -> Result<OracleAnnouncement, Error>;
    /// Returns the attestation for the event with the given id if found.
    fn get_attestation(&self, event_id: &str) -> Result<OracleAttestation, Error>;
}

/// Represents a UTXO.
#[derive(Clone, Debug)]
pub struct Utxo {
    /// The TxOut containing the value and script pubkey of the referenced output.
    pub tx_out: TxOut,
    /// The outpoint containing the txid and vout of the referenced output.
    pub outpoint: OutPoint,
    /// The address associated with the referenced output.
    pub address: Address,
    /// The redeem script for the referenced output.
    pub redeem_script: Script,
    /// Whether this Utxo has been reserved (and so should not be used to fund
    /// a DLC).
    pub reserved: bool,
}

impl_dlc_writeable!(Utxo, {
    (tx_out, writeable),
    (outpoint, writeable),
    (address, {cb_writeable, write_address, read_address}),
    (redeem_script, writeable),
    (reserved, writeable)
});
