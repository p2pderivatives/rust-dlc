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
extern crate dlc_trie;
extern crate lightning;
extern crate log;
#[cfg(feature = "fuzztarget")]
extern crate rand_chacha;
extern crate secp256k1_zkp;

pub mod contract;
pub mod contract_updater;
mod conversion_utils;
pub mod error;
pub mod manager;
pub mod payout_curve;
mod utils;

use bitcoin::{Address, OutPoint, Script, Transaction, TxOut, Txid};
use contract::{offered_contract::OfferedContract, signed_contract::SignedContract, Contract};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use error::Error;
use secp256k1_zkp::schnorrsig::PublicKey as SchnorrPublicKey;
use secp256k1_zkp::{PublicKey, SecretKey};

/// Type alias for a contract id.
pub type ContractId = [u8; 32];

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
    fn sign_tx_input(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        tx_out: &TxOut,
        redeem_script: Option<Script>,
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
    /// Get the transaction with given id.
    fn get_transaction(&self, tx_id: &Txid) -> Result<Transaction, Error>;
    /// Get the number of confirmation for the transaction with given id.
    fn get_transaction_confirmations(&self, tx_id: &Txid) -> Result<u32, Error>;
}

/// Blockchain trait provides access to the bitcoin blockchain.
pub trait Blockchain {
    /// Broadcast the given transaction to the bitcoin network.
    fn send_transaction(&self, transaction: &Transaction) -> Result<(), Error>;
    /// Returns the network currently used (mainnet, testnet or regtest).
    fn get_network(&self) -> Result<bitcoin::network::constants::Network, Error>;
}

/// Storage trait provides functionalities to store and retrieve DLCs.
pub trait Storage {
    /// Returns the contract with given id if found.
    fn get_contract(&self, id: &ContractId) -> Result<Option<Contract>, Error>;
    /// Return all contracts
    fn get_contracts(&self) -> Result<Vec<Contract>, Error>;
    /// Create a record for the given contract.
    fn create_contract(&mut self, contract: &OfferedContract) -> Result<(), Error>;
    /// Delete the record for the contract with the given id.
    fn delete_contract(&mut self, id: &ContractId) -> Result<(), Error>;
    /// Update the given contract.
    fn update_contract(&mut self, contract: &Contract) -> Result<(), Error>;
    /// Returns the set of contracts in offered state.
    fn get_contract_offers(&self) -> Result<Vec<OfferedContract>, Error>;
    /// Returns the set of contracts in signed state.
    fn get_signed_contracts(&self) -> Result<Vec<SignedContract>, Error>;
    /// Returns the set of confirmed contracts.
    fn get_confirmed_contracts(&self) -> Result<Vec<SignedContract>, Error>;
}

/// Oracle trait provides access to oracle information.
pub trait Oracle {
    /// Returns the public key of the oracle.
    fn get_public_key(&self) -> SchnorrPublicKey;
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
}
