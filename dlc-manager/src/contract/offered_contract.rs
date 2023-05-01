//! #OfferedContract

use crate::conversion_utils::{
    get_contract_info_and_announcements, get_tx_input_infos, BITCOIN_CHAINHASH, PROTOCOL_VERSION,
};
use crate::utils::get_new_serial_id;
use crate::ContractId;

use super::contract_info::ContractInfo;
use super::contract_input::ContractInput;
use super::{ContractDescriptor, FundingInputInfo};
use dlc::PartyParams;
use dlc_messages::oracle_msgs::OracleAnnouncement;
use dlc_messages::OfferDlc;
use secp256k1_zkp::PublicKey;

/// Contains information about a contract that was offered.
#[derive(Clone, Debug)]
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
    pub cet_locktime: u32,
    /// The time at which the contract becomes refundable.
    pub refund_locktime: u32,
}

impl OfferedContract {
    /// Validate that the contract info covers all the possible outcomes that
    /// can be attested by the oracle(s).
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        dlc::util::validate_fee_rate(self.fee_rate_per_vb).map_err(|_| {
            crate::error::Error::InvalidParameters("Fee rate is too high".to_string())
        })?;

        for info in &self.contract_info {
            info.validate()?;
            let payouts = match &info.contract_descriptor {
                ContractDescriptor::Enum(e) => e.get_payouts(),
                ContractDescriptor::Numerical(e) => e.get_payouts(self.total_collateral)?,
            };
            let valid = payouts
                .iter()
                .all(|p| p.accept + p.offer == self.total_collateral);
            if !valid {
                return Err(crate::error::Error::InvalidParameters(
                    "Sum of payout doesn't equal total collateral".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Creates a new [`OfferedContract`] from the given parameters.
    pub fn new(
        contract: &ContractInput,
        oracle_announcements: Vec<Vec<OracleAnnouncement>>,
        offer_params: &PartyParams,
        funding_inputs_info: &[FundingInputInfo],
        counter_party: &PublicKey,
        refund_delay: u32,
        cet_locktime: u32,
        temporary_contract_id: ContractId,
    ) -> Self {
        let total_collateral = contract.offer_collateral + contract.accept_collateral;

        assert_eq!(contract.contract_infos.len(), oracle_announcements.len());

        let latest_maturity = crate::utils::get_latest_maturity_date(&oracle_announcements)
            .expect("to be able to retrieve latest maturity date");

        let fund_output_serial_id = get_new_serial_id();
        let contract_info = contract
            .contract_infos
            .iter()
            .zip(oracle_announcements.into_iter())
            .map(|(x, y)| ContractInfo {
                contract_descriptor: x.contract_descriptor.clone(),
                oracle_announcements: y,
                threshold: x.oracles.threshold as usize,
            })
            .collect::<Vec<ContractInfo>>();
        OfferedContract {
            id: temporary_contract_id,
            is_offer_party: true,
            contract_info,
            offer_params: offer_params.clone(),
            total_collateral,
            funding_inputs_info: funding_inputs_info.to_vec(),
            fund_output_serial_id,
            fee_rate_per_vb: contract.fee_rate,
            cet_locktime,
            refund_locktime: latest_maturity + refund_delay,
            counter_party: *counter_party,
        }
    }

    pub(crate) fn try_from_offer_dlc(
        offer_dlc: &OfferDlc,
        counter_party: PublicKey,
    ) -> Result<OfferedContract, crate::conversion_utils::Error> {
        let contract_info = get_contract_info_and_announcements(&offer_dlc.contract_info)?;

        let (inputs, input_amount) = get_tx_input_infos(&offer_dlc.funding_inputs)?;

        Ok(OfferedContract {
            id: offer_dlc.temporary_contract_id,
            is_offer_party: false,
            contract_info,
            offer_params: PartyParams {
                fund_pubkey: offer_dlc.funding_pubkey,
                change_script_pubkey: offer_dlc.change_spk.clone(),
                change_serial_id: offer_dlc.change_serial_id,
                payout_script_pubkey: offer_dlc.payout_spk.clone(),
                payout_serial_id: offer_dlc.payout_serial_id,
                collateral: offer_dlc.offer_collateral,
                inputs,
                input_amount,
            },
            cet_locktime: offer_dlc.cet_locktime,
            refund_locktime: offer_dlc.refund_locktime,
            fee_rate_per_vb: offer_dlc.fee_rate_per_vb,
            fund_output_serial_id: offer_dlc.fund_output_serial_id,
            funding_inputs_info: offer_dlc.funding_inputs.iter().map(|x| x.into()).collect(),
            total_collateral: offer_dlc.contract_info.get_total_collateral(),
            counter_party,
        })
    }
}

impl From<&OfferedContract> for OfferDlc {
    fn from(offered_contract: &OfferedContract) -> OfferDlc {
        OfferDlc {
            protocol_version: PROTOCOL_VERSION,
            temporary_contract_id: offered_contract.id,
            contract_flags: 0,
            chain_hash: BITCOIN_CHAINHASH,
            contract_info: offered_contract.into(),
            funding_pubkey: offered_contract.offer_params.fund_pubkey,
            payout_spk: offered_contract.offer_params.payout_script_pubkey.clone(),
            payout_serial_id: offered_contract.offer_params.payout_serial_id,
            offer_collateral: offered_contract.offer_params.collateral,
            funding_inputs: offered_contract
                .funding_inputs_info
                .iter()
                .map(|x| x.into())
                .collect(),
            change_spk: offered_contract.offer_params.change_script_pubkey.clone(),
            change_serial_id: offered_contract.offer_params.change_serial_id,
            cet_locktime: offered_contract.cet_locktime,
            refund_locktime: offered_contract.refund_locktime,
            fee_rate_per_vb: offered_contract.fee_rate_per_vb,
            fund_output_serial_id: offered_contract.fund_output_serial_id,
        }
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

    #[test]
    fn offer_enum_collateral_not_equal_payout() {
        validate_offer_test_common(include_str!(
            "../../test_inputs/offer_enum_collateral_not_equal_payout.json"
        ));
    }

    #[test]
    fn offer_numerical_collateral_less_than_payout() {
        validate_offer_test_common(include_str!(
            "../../test_inputs/offer_numerical_collateral_less_than_payout.json"
        ));
    }

    #[test]
    fn offer_numerical_invalid_rounding_interval() {
        validate_offer_test_common(include_str!(
            "../../test_inputs/offer_numerical_invalid_rounding_interval.json"
        ));
    }

    #[test]
    fn offer_numerical_empty_rounding_interval() {
        validate_offer_test_common(include_str!(
            "../../test_inputs/offer_numerical_empty_rounding_interval.json"
        ));
    }
}
