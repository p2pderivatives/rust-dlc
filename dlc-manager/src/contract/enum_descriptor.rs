//! #EnumDescriptor

use super::contract_info::OracleIndexAndPrefixLength;
use super::utils::unordered_equal;
use super::AdaptorInfo;
use crate::error::Error;
use bitcoin::{Script, Transaction};
use dlc::{DlcTransactions, OracleInfo, PartyParams};
use dlc::{EnumerationPayout, Payout};
use dlc_messages::oracle_msgs::EnumEventDescriptor;
use dlc_trie::RangeInfo;
use secp256k1_zkp::{All, EcdsaAdaptorSignature, Message, PublicKey, Secp256k1, SecretKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A descriptor for a contract whose outcomes are represented as an enumeration.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct EnumDescriptor {
    /// The set of outcomes.
    pub outcome_payouts: Vec<EnumerationPayout>,
}

impl EnumDescriptor {
    /// Returns the set of payouts.
    pub fn get_payouts(&self) -> Vec<Payout> {
        self.outcome_payouts.iter().map(|x| x.payout).collect()
    }

    /// Validate that the descriptor covers all possible outcomes of the given
    /// enum event descriptor.
    pub fn validate(&self, enum_event_descriptor: &EnumEventDescriptor) -> Result<(), Error> {
        if unordered_equal(
            &enum_event_descriptor.outcomes.iter().collect::<Vec<_>>(),
            &self
                .outcome_payouts
                .iter()
                .map(|x| &x.outcome)
                .collect::<Vec<_>>(),
        ) {
            Ok(())
        } else {
            Err(Error::InvalidParameters(
                "Oracle outcomes do not each have a single associated payout.".to_string(),
            ))
        }
    }

    /// Returns the `RangeInfo` that matches the given set of outcomes if any.
    pub fn get_range_info_for_outcome(
        &self,
        nb_oracles: usize,
        threshold: usize,
        outcomes: &[(usize, &Vec<String>)],
        adaptor_sig_start: usize,
    ) -> Option<(OracleIndexAndPrefixLength, RangeInfo)> {
        let payout_outcomes = self
            .outcome_payouts
            .iter()
            .map(|x| &x.outcome)
            .cloned()
            .collect::<Vec<_>>();
        super::utils::get_range_info_for_enum_outcome(
            nb_oracles,
            threshold,
            outcomes,
            &payout_outcomes,
            adaptor_sig_start,
        )
    }

    /// Verify the given set adaptor signatures.
    pub fn verify_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        adaptor_sigs: &[EcdsaAdaptorSignature],
        adaptor_sig_start: usize,
    ) -> Result<usize, dlc::Error> {
        let messages = self.get_outcome_messages(threshold);
        super::utils::verify_adaptor_info(
            secp,
            &messages,
            oracle_infos,
            threshold,
            fund_pubkey,
            funding_script_pubkey,
            fund_output_value,
            cets,
            adaptor_sigs,
            adaptor_sig_start,
        )
    }

    /// Verify the given set of adaptor signature and generates the adaptor info.
    pub fn verify_and_get_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        adaptor_sigs: &[EcdsaAdaptorSignature],
        adaptor_sig_start: usize,
    ) -> Result<(AdaptorInfo, usize), dlc::Error> {
        let adaptor_sig_index = self.verify_adaptor_info(
            secp,
            oracle_infos,
            threshold,
            fund_pubkey,
            funding_script_pubkey,
            fund_output_value,
            cets,
            adaptor_sigs,
            adaptor_sig_start,
        )?;

        Ok((AdaptorInfo::Enum, adaptor_sig_index))
    }

    /// Generate the set of adaptor signatures and return the adaptor info.
    pub fn get_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
    ) -> Result<(AdaptorInfo, Vec<EcdsaAdaptorSignature>), Error> {
        let adaptor_sigs = self.get_adaptor_signatures(
            secp,
            oracle_infos,
            threshold,
            cets,
            fund_privkey,
            funding_script_pubkey,
            fund_output_value,
        )?;

        Ok((AdaptorInfo::Enum, adaptor_sigs))
    }

    /// Generate the set of adaptor signatures.
    pub fn get_adaptor_signatures(
        &self,
        secp: &Secp256k1<All>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        cets: &[Transaction],
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
    ) -> Result<Vec<EcdsaAdaptorSignature>, Error> {
        let messages = self.get_outcome_messages(threshold);
        super::utils::get_enum_adaptor_signatures(
            secp,
            &messages,
            oracle_infos,
            threshold,
            cets,
            fund_privkey,
            funding_script_pubkey,
            fund_output_value,
        )
    }

    fn get_outcome_messages(&self, threshold: usize) -> Vec<Vec<Vec<Message>>> {
        self.outcome_payouts
            .iter()
            .map(|x| {
                let message = vec![Message::from_hashed_data::<
                    secp256k1_zkp::hashes::sha256::Hash,
                >(x.outcome.as_bytes())];
                std::iter::repeat(message).take(threshold).collect()
            })
            .collect()
    }

    pub(crate) fn create_dlc_transactions(
        &self,
        offer_params: &PartyParams,
        accept_params: &PartyParams,
        refund_locktime: u32,
        fee_rate_per_vb: u64,
        fund_locktime: u32,
        cet_locktime: u32,
        fund_output_serial_id: u64,
    ) -> Result<DlcTransactions, Error> {
        crate::utils::create_dlc_transactions_from_payouts(
            offer_params,
            accept_params,
            &self.get_payouts(),
            refund_locktime,
            fee_rate_per_vb,
            fund_locktime,
            cet_locktime,
            fund_output_serial_id,
        )
    }
}
