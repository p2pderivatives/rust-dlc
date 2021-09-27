//! #OfferedContract

use super::contract_info::ContractInfo;
use super::FundingInputInfo;
use dlc::PartyParams;
use secp256k1_zkp::PublicKey;

/// Contains information about a contract that was offered.
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct OfferedContract {
    /// The temporary id of the contract.
    pub id: [u8; 32],
    /// Indicated whether the contract was proposed or received.
    pub is_offer_party: bool,
    /// The set of contract information that are used to generate CET and
    /// adaptor signatures.
    pub contract_info: Vec<ContractInfo>,
    /// The public key of the counter-party's node.
    pub counter_party: PublicKey,
    /// The parameters of the offering party.
    pub offer_params: PartyParams,
    /// The sum of both parties collateral.
    pub total_collateral: u64,
    /// Information about the offering party's funding inputs.
    pub funding_inputs_info: Vec<FundingInputInfo>,
    /// The serial id of the fund output used for output ordering.
    pub fund_output_serial_id: u64,
    /// The fee rate to be used to construct the DLC transactions.
    pub fee_rate_per_vb: u64,
    /// The time at which the contract is expected to be closeable.
    pub contract_maturity_bound: u32,
    /// The time at which the contract becomes refundable.
    pub contract_timeout: u32,
}
