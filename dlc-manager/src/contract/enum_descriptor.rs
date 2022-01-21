//! #EnumDescriptor

use super::contract_info::OracleIndexAndPrefixLength;
use super::utils::{get_majority_combination, unordered_equal};
use super::AdaptorInfo;
use crate::error::Error;
use bitcoin::{Script, Transaction};
use dlc::OracleInfo;
use dlc::{EnumerationPayout, Payout};
use dlc_messages::oracle_msgs::EnumEventDescriptor;
use dlc_trie::{combination_iterator::CombinationIterator, RangeInfo};
use secp256k1_zkp::{
    All, EcdsaAdaptorSignature, Message, PublicKey, Secp256k1, SecretKey, Verification,
};
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
        self.outcome_payouts
            .iter()
            .map(|x| x.payout.clone())
            .collect()
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
        if outcomes.len() < threshold {
            return None;
        }

        let filtered_outcomes: Vec<(usize, &Vec<String>)> = outcomes
            .iter()
            .filter(|x| x.1.len() == 1)
            .cloned()
            .collect();
        let (mut outcome, mut actual_combination) = get_majority_combination(&filtered_outcomes)?;
        let outcome = outcome.remove(0);

        if actual_combination.len() < threshold {
            return None;
        }

        actual_combination.truncate(threshold);

        let pos = self
            .outcome_payouts
            .iter()
            .position(|x| x.outcome == outcome)?;

        let combinator = CombinationIterator::new(nb_oracles, threshold);
        let mut comb_pos = 0;
        let mut comb_count = 0;

        for (i, combination) in combinator.enumerate() {
            if combination == actual_combination {
                comb_pos = i;
            }
            comb_count += 1;
        }

        let range_info = RangeInfo {
            cet_index: pos,
            adaptor_index: comb_count * pos + comb_pos + adaptor_sig_start,
        };

        Some((
            actual_combination.iter().map(|x| (*x, 1)).collect(),
            range_info,
        ))
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
        let mut adaptor_sig_index = adaptor_sig_start;
        let mut callback =
            |adaptor_point: &PublicKey, cet_index: usize| -> Result<(), dlc::Error> {
                let sig = adaptor_sigs[adaptor_sig_index];
                adaptor_sig_index += 1;
                dlc::verify_cet_adaptor_sig_from_point(
                    secp,
                    &sig,
                    &cets[cet_index],
                    adaptor_point,
                    fund_pubkey,
                    funding_script_pubkey,
                    fund_output_value,
                )?;
                Ok(())
            };

        self.iter_outcomes(secp, oracle_infos, threshold, &mut callback)?;

        Ok(adaptor_sig_index)
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
        let mut adaptor_sigs = Vec::new();
        let mut callback =
            |adaptor_point: &PublicKey, cet_index: usize| -> Result<(), dlc::Error> {
                let sig = dlc::create_cet_adaptor_sig_from_point(
                    secp,
                    &cets[cet_index],
                    adaptor_point,
                    fund_privkey,
                    funding_script_pubkey,
                    fund_output_value,
                )?;
                adaptor_sigs.push(sig);
                Ok(())
            };

        self.iter_outcomes(secp, oracle_infos, threshold, &mut callback)?;

        Ok(adaptor_sigs)
    }

    fn iter_outcomes<C: Verification, F>(
        &self,
        secp: &Secp256k1<C>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        callback: &mut F,
    ) -> Result<(), dlc::Error>
    where
        F: FnMut(&PublicKey, usize) -> Result<(), dlc::Error>,
    {
        let messages: Vec<Vec<Vec<Message>>> = self
            .outcome_payouts
            .iter()
            .map(|x| {
                let message = vec![Message::from_hashed_data::<
                    secp256k1_zkp::bitcoin_hashes::sha256::Hash,
                >(x.outcome.as_bytes())];
                std::iter::repeat(message).take(threshold).collect()
            })
            .collect();
        let combination_iter = CombinationIterator::new(oracle_infos.len(), threshold);
        let combinations: Vec<Vec<usize>> = combination_iter.collect();

        for (i, outcome_messages) in messages.iter().enumerate() {
            for selector in &combinations {
                let cur_oracle_infos: Vec<_> = oracle_infos
                    .iter()
                    .enumerate()
                    .filter_map(|(i, x)| {
                        if selector.contains(&i) {
                            Some(x.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                let adaptor_point = dlc::get_adaptor_point_from_oracle_info(
                    secp,
                    &cur_oracle_infos,
                    outcome_messages,
                )?;
                callback(&adaptor_point, i)?;
            }
        }

        Ok(())
    }
}
