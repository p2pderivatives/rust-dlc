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

pub mod chain_monitor;
pub mod channel;
pub mod channel_updater;
pub mod contract;
pub mod contract_updater;
mod conversion_utils;
pub mod error;
pub mod manager;
pub mod payout_curve;
mod utils;

use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, Block, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
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
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::{PublicKey, SecretKey, Signing};
use secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::RwLock;

/// Type alias for a contract id.
pub type ContractId = [u8; 32];

/// Type alias for a keys id.
pub type KeysId = [u8; 32];

/// Type alias for a channel id.
pub type ChannelId = [u8; 32];

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
pub trait ContractSigner: Clone {
    /// Get the public key associated with the [`ContractSigner`].
    fn get_public_key<C: Signing>(&self, secp: &Secp256k1<C>) -> Result<PublicKey, Error>;
    /// Returns the secret key associated with the [`ContractSigner`].
    // todo: remove this method and add create_adaptor_signature to the trait
    fn get_secret_key(&self) -> Result<SecretKey, Error>;
}

/// Simple sample implementation of [`ContractSigner`].
#[derive(Debug, Copy, Clone)]
pub struct SimpleSigner {
    secret_key: SecretKey,
}

impl SimpleSigner {
    /// Creates a new [`SimpleSigner`] from the provided secret key.
    pub fn new(secret_key: SecretKey) -> Self {
        Self { secret_key }
    }
}

impl ContractSigner for SimpleSigner {
    fn get_public_key<C: Signing>(&self, secp: &Secp256k1<C>) -> Result<PublicKey, Error> {
        Ok(self.secret_key.public_key(secp))
    }

    fn get_secret_key(&self) -> Result<SecretKey, Error> {
        Ok(self.secret_key)
    }
}

impl ContractSigner for SecretKey {
    fn get_public_key<C: Signing>(&self, secp: &Secp256k1<C>) -> Result<PublicKey, Error> {
        Ok(self.public_key(secp))
    }

    fn get_secret_key(&self) -> Result<SecretKey, Error> {
        Ok(*self)
    }
}

/// Derives a [`ContractSigner`] from a [`ContractSignerProvider`] and a `contract_keys_id`.
pub trait ContractSignerProvider {
    /// A type which implements [`ContractSigner`]
    type Signer: ContractSigner;

    /// Create a keys id for deriving a `Signer`.
    fn derive_signer_key_id(&self, is_offer_party: bool, temp_id: [u8; 32]) -> [u8; 32];

    /// Derives the private key material backing a `Signer`.
    fn derive_contract_signer(&self, key_id: [u8; 32]) -> Result<Self::Signer, Error>;

    /// Get the secret key associated with the provided public key.
    ///
    /// Only used for Channels.
    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey, Error>;
    /// Generate a new secret key and store it in the wallet so that it can later be retrieved.
    ///
    /// Only used for Channels.
    fn get_new_secret_key(&self) -> Result<SecretKey, Error>;
}

/// Wallet trait to provide functionalities related to generating, storing and
/// managing bitcoin addresses and UTXOs.
pub trait Wallet {
    /// Returns a new (unused) address.
    fn get_new_address(&self) -> Result<Address, Error>;
    /// Returns a new (unused) change address.
    fn get_new_change_address(&self) -> Result<Address, Error>;
    /// Get a set of UTXOs to fund the given amount.
    fn get_utxos_for_amount(
        &self,
        amount: Amount,
        fee_rate: u64,
        lock_utxos: bool,
    ) -> Result<Vec<Utxo>, Error>;
    /// Import the provided address.
    fn import_address(&self, address: &Address) -> Result<(), Error>;
    /// Signs a transaction input
    fn sign_psbt_input(&self, psbt: &mut Psbt, input_index: usize) -> Result<(), Error>;
    /// Unlock reserved utxo
    fn unreserve_utxos(&self, outpoints: &[OutPoint]) -> Result<(), Error>;
}

/// Blockchain trait provides access to the bitcoin blockchain.
pub trait Blockchain {
    /// Broadcast the given transaction to the bitcoin network.
    fn send_transaction(&self, transaction: &Transaction) -> Result<(), Error>;
    /// Returns the network currently used (mainnet, testnet or regtest).
    fn get_network(&self) -> Result<bitcoin::Network, Error>;
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
    /// Delete the channel with given [`ChannelId`] if any.
    fn delete_channel(&self, channel_id: &ChannelId) -> Result<(), Error>;
    /// Returns the channel with given [`ChannelId`] if any.
    fn get_channel(&self, channel_id: &ChannelId) -> Result<Option<Channel>, Error>;
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
}

/// Oracle trait provides access to oracle information.
pub trait Oracle {
    /// Returns the public key of the oracle.
    fn get_public_key(&self) -> XOnlyPublicKey;
    /// Returns the announcement for the event with the given id if found.
    #[cfg(not(feature = "async"))]
    fn get_announcement(&self, event_id: &str) -> Result<OracleAnnouncement, Error>;
    /// Returns the attestation for the event with the given id if found.
    #[cfg(not(feature = "async"))]
    fn get_attestation(&self, event_id: &str) -> Result<OracleAttestation, Error>;
    /// Returns the announcement for the event with the given id if found.
    #[cfg(feature = "async")]
    fn get_announcement(
        &self,
        event_id: &str,
    ) -> impl std::future::Future<Output = Result<OracleAnnouncement, Error>> + Send;
    /// Returns the attestation for the event with the given id if found.
    #[cfg(feature = "async")]
    fn get_attestation(
        &self,
        event_id: &str,
    ) -> impl std::future::Future<Output = Result<OracleAttestation, Error>> + Send;
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
    pub redeem_script: ScriptBuf,
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

/// A ContractSignerProvider that caches the signers
pub struct CachedContractSignerProvider<SP: Deref, X>
where
    SP::Target: ContractSignerProvider<Signer = X>,
{
    pub(crate) signer_provider: SP,
    pub(crate) cache: RwLock<HashMap<KeysId, X>>,
}

impl<SP: Deref, X> CachedContractSignerProvider<SP, X>
where
    SP::Target: ContractSignerProvider<Signer = X>,
{
    /// Create a new [`ContractSignerProvider`]
    pub fn new(signer_provider: SP) -> Self {
        Self {
            signer_provider,
            cache: RwLock::new(HashMap::new()),
        }
    }
}

impl<SP: Deref, X: ContractSigner> ContractSignerProvider for CachedContractSignerProvider<SP, X>
where
    SP::Target: ContractSignerProvider<Signer = X>,
{
    type Signer = X;

    fn derive_signer_key_id(&self, is_offer_party: bool, temp_id: [u8; 32]) -> KeysId {
        self.signer_provider
            .derive_signer_key_id(is_offer_party, temp_id)
    }

    fn derive_contract_signer(&self, key_id: KeysId) -> Result<Self::Signer, Error> {
        match self.cache.try_read().unwrap().get(&key_id) {
            Some(signer) => Ok(signer.clone()),
            None => self.signer_provider.derive_contract_signer(key_id),
        }
    }

    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey, Error> {
        self.signer_provider.get_secret_key_for_pubkey(pubkey)
    }

    fn get_new_secret_key(&self) -> Result<SecretKey, Error> {
        self.signer_provider.get_new_secret_key()
    }
}
