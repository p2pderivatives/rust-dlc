//! #NumericalDescriptor

use super::AdaptorInfo;
use crate::error::Error;
use crate::payout_curve::{PayoutFunction, RoundingIntervals};
use bitcoin::{Script, Transaction};
use dlc::{Payout, RangePayout};
use dlc_trie::multi_oracle_trie::MultiOracleTrie;
use dlc_trie::multi_oracle_trie_with_diff::MultiOracleTrieWithDiff;
use dlc_trie::DlcTrie;
use secp256k1_zkp::{All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Information about the base, number of digits and unit of a numerical event.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct NumericalEventInfo {
    /// The base in which the event outcome will be reported.
    pub base: usize,
    /// The number of digits that will be used to represent the outcome.
    pub nb_digits: usize,
    /// The unit of the event outcome.
    pub unit: String,
}

/// Information about the allowed deviation in outcome value between the oracles.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct DifferenceParams {
    /// The maximum error above which the contract should failed to close. Note
    /// that this value represents a power of two.
    pub max_error_exp: usize,
    /// The minimum error deviation under which the contract should be guaranteed
    /// to be closeable.
    pub min_support_exp: usize,
    /// Whether to maximize the coverage of the [min;max] interval to increase
    /// the probability of the contract being closeable within it.
    pub maximize_coverage: bool,
}

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains information about a contract based on a numerical outcome.
pub struct NumericalDescriptor {
    /// The function representing the set of payouts.
    pub payout_function: PayoutFunction,
    /// Rounding intervals enabling reducing the precision of the payout values
    /// which in turns reduces the number of required adaptor signatures.
    pub rounding_intervals: RoundingIntervals,
    /// Information about the event itself.
    pub info: NumericalEventInfo,
    /// Information about the allowed differences in outcome value between oracles.
    /// If None, a quorum of oracle needs to sign the same value for the contract
    /// to be closeable.
    pub difference_params: Option<DifferenceParams>,
}

impl NumericalDescriptor {
    /// Returns the set of RangePayout for the descriptor generated from the
    /// payout function.
    pub fn get_range_payouts(&self, total_collateral: u64) -> Vec<RangePayout> {
        self.payout_function
            .to_range_payouts(total_collateral, &self.rounding_intervals)
    }

    /// Returns the set of payouts for the descriptor generated from the payout
    /// function.
    pub fn get_payouts(&self, total_collateral: u64) -> Vec<Payout> {
        self.get_range_payouts(total_collateral)
            .iter()
            .map(|x| x.payout.clone())
            .collect()
    }

    /// Verify the given set of adaptor signatures and generate the adaptor info.
    pub fn verify_and_get_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        total_collateral: u64,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        threshold: usize,
        precomputed_points: &Vec<Vec<Vec<PublicKey>>>,
        cets: &[Transaction],
        adaptor_pairs: &[EcdsaAdaptorSignature],
        adaptor_index_start: usize,
    ) -> Result<(AdaptorInfo, usize), Error> {
        match &self.difference_params {
            Some(params) => {
                let mut multi_trie = MultiOracleTrieWithDiff::new(
                    self.info.base,
                    precomputed_points.len(),
                    threshold,
                    self.info.nb_digits,
                    params.min_support_exp,
                    params.max_error_exp,
                );
                let index = multi_trie.generate_verify(
                    secp,
                    fund_pubkey,
                    funding_script_pubkey,
                    fund_output_value,
                    &self.get_range_payouts(total_collateral),
                    cets,
                    &precomputed_points,
                    adaptor_pairs,
                    adaptor_index_start,
                )?;
                Ok((AdaptorInfo::NumericalWithDifference(multi_trie), index))
            }
            None => {
                let mut trie = MultiOracleTrie::new(
                    self.info.base,
                    precomputed_points.len(),
                    threshold,
                    self.info.nb_digits,
                );
                let index = trie.generate_verify(
                    secp,
                    fund_pubkey,
                    funding_script_pubkey,
                    fund_output_value,
                    &self.get_range_payouts(total_collateral),
                    cets,
                    &precomputed_points,
                    adaptor_pairs,
                    adaptor_index_start,
                )?;
                Ok((AdaptorInfo::Numerical(trie), index))
            }
        }
    }

    /// Generate the set of adaptor signatures and the adaptor info.
    pub fn get_adaptor_info(
        &self,
        secp: &Secp256k1<All>,
        total_collateral: u64,
        fund_priv_key: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        threshold: usize,
        precomputed_points: &Vec<Vec<Vec<PublicKey>>>,
        cets: &[Transaction],
        adaptor_index_start: usize,
    ) -> Result<(AdaptorInfo, Vec<EcdsaAdaptorSignature>), Error> {
        match &self.difference_params {
            Some(params) => {
                let mut multi_trie = MultiOracleTrieWithDiff::new(
                    self.info.base,
                    precomputed_points.len(),
                    threshold,
                    self.info.nb_digits,
                    params.min_support_exp,
                    params.max_error_exp,
                );
                let adaptor_pairs = multi_trie.generate_sign(
                    secp,
                    fund_priv_key,
                    funding_script_pubkey,
                    fund_output_value,
                    &self.get_range_payouts(total_collateral),
                    cets,
                    &precomputed_points,
                    adaptor_index_start,
                )?;
                Ok((
                    AdaptorInfo::NumericalWithDifference(multi_trie),
                    adaptor_pairs,
                ))
            }

            None => {
                let mut trie = MultiOracleTrie::new(
                    self.info.base,
                    precomputed_points.len(),
                    threshold,
                    self.info.nb_digits,
                );
                let sigs = trie.generate_sign(
                    secp,
                    &fund_priv_key,
                    &funding_script_pubkey,
                    fund_output_value,
                    &self.get_range_payouts(total_collateral),
                    cets,
                    &precomputed_points,
                    adaptor_index_start,
                )?;
                Ok((AdaptorInfo::Numerical(trie), sigs))
            }
        }
    }
}
