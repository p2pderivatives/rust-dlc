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

impl OfferedContract {
    /// Validate that the contract info covers all the possible outcomes that
    /// can be attested by the oracle(s).
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        for info in &self.contract_info {
            info.validate()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_offer_test_common(input: &str) {
        let offer: OfferedContract = serde_json::from_str(input).unwrap();
        assert!(offer.validate().is_err());
    }

    #[test]
    fn offer_enum_missing_payout() {
        validate_offer_test_common(include_str!(
            "../../test_inputs/offer_enum_missing_payout.json"
        ));
    }

    #[test]
    fn offer_enum_oracle_with_diff_payout() {
        validate_offer_test_common(include_str!(
            "../../test_inputs/offer_enum_oracle_with_diff_payout.json"
        ));
    }

    #[test]
    fn offer_numerical_bad_first_payout() {
        validate_offer_test_common(include_str!(
            "../../test_inputs/offer_numerical_bad_first_payout.json"
        ));
    }

    #[test]
    fn offer_numerical_bad_last_payout() {
        validate_offer_test_common(include_str!(
            "../../test_inputs/offer_numerical_bad_last_payout.json"
        ));
    }

    #[test]
    fn offer_numerical_non_continuous() {
        validate_offer_test_common(include_str!(
            "../../test_inputs/offer_numerical_non_continuous.json"
        ));
    }
}
