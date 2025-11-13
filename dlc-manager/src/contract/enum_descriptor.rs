//! #EnumDescriptor

use super::contract_info::OracleIndexAndPrefixLength;
use super::utils::{get_majority_combination, unordered_equal};
use crate::error::Error;
use bitcoin::hashes::Hash;
use bitcoin::{Script, ScriptBuf};
use dlc::OracleInfo;
use dlc::{EnumerationPayout, Payout};
use dlc_messages::oracle_msgs::EnumEventDescriptor;
use dlc_trie::{combination_iterator::CombinationIterator, RangeInfo};
use secp256k1_zkp::{All, Message, PublicKey, Secp256k1, Verification};
#[cfg(feature = "use-serde")]
use serde::{Deserialize, Serialize};

/// A descriptor for a contract whose outcomes are represented as an enumeration.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "use-serde",
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
            script_index: comb_count * pos + comb_pos + adaptor_sig_start,
            payout_index: pos,
        };

        Some((
            actual_combination.iter().map(|x| (*x, 1)).collect(),
            range_info,
        ))
    }

    /// Returns scripts for the different outcomes
    pub fn get_scripts(
        &self,
        secp: &Secp256k1<All>,
        offer_spk: &Script,
        accept_spk: &Script,
        oracle_infos: &[OracleInfo],
        threshold: usize,
    ) -> Result<Vec<ScriptBuf>, dlc::Error> {
        let mut scripts = Vec::new();
        let mut callback = |adaptor_point: PublicKey, payout: Payout| -> Result<(), dlc::Error> {
            use bitcoin::XOnlyPublicKey;

            use dlc::opcat_utils::vault_dlc_withdrawal;

            let outputs = dlc::get_payout_outputs(&payout, offer_spk, accept_spk);
            let pubkey: XOnlyPublicKey = adaptor_point.into();
            let script = vault_dlc_withdrawal(&outputs, pubkey);
            scripts.push(script);
            Ok(())
        };

        self.iter_outcomes(secp, oracle_infos, threshold, &mut callback)?;

        Ok(scripts)
    }

    fn iter_outcomes<C: Verification, F>(
        &self,
        secp: &Secp256k1<C>,
        oracle_infos: &[OracleInfo],
        threshold: usize,
        callback: &mut F,
    ) -> Result<(), dlc::Error>
    where
        F: FnMut(PublicKey, Payout) -> Result<(), dlc::Error>,
    {
        let messages: Vec<Vec<Vec<Message>>> = self
            .outcome_payouts
            .iter()
            .map(|x| {
                let hash =
                    bitcoin::hashes::sha256::Hash::hash(x.outcome.as_bytes()).to_byte_array();
                let message = vec![Message::from_digest(hash)];
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
                callback(adaptor_point, self.outcome_payouts[i].payout)?;
            }
        }

        Ok(())
    }
}
