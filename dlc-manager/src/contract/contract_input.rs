//! #ContractInput

use super::ContractDescriptor;
use bitcoin::XOnlyPublicKey;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Oracle information required for the initial creation of a contract.
#[derive(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct OracleInput {
    /// The set of public keys for each of the used oracles.
    pub public_keys: Vec<XOnlyPublicKey>,
    /// The id of the event being used for the contract. Note that at the moment
    /// a single event id is used, while multiple ids would be preferable.
    pub event_id: String,
    /// The number of oracles that need to provide attestations satisfying the
    /// contract conditions to be able to close the contract.
    pub threshold: u16,
}

/// Represents the contract specifications.
#[derive(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct ContractInputInfo {
    /// The contract conditions.
    pub contract_descriptor: ContractDescriptor,
    /// The oracle information.
    pub oracles: OracleInput,
}

#[derive(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains all the information necessary for the initialization of a DLC.
pub struct ContractInput {
    /// The collateral for the offering party.
    pub offer_collateral: u64,
    /// The collateral for the accepting party.
    pub accept_collateral: u64,
    /// The time at which the contract is expected to mature.
    pub maturity_time: u32,
    /// The fee rate used to construct the transactions.
    pub fee_rate: u64,
    /// The set of contract that make up the DLC (a single DLC can be based
    /// on multiple contracts).
    pub contract_infos: Vec<ContractInputInfo>,
}
