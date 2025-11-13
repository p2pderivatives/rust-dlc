//! #NumericalDescriptor

use super::AdaptorInfo;
use crate::error::Error;
use crate::payout_curve::{PayoutFunction, RoundingIntervals};
use bitcoin::{Amount, Script, ScriptBuf};
use dlc::{Payout, RangePayout};
use dlc_trie::multi_oracle_trie::MultiOracleTrie;
use dlc_trie::multi_oracle_trie_with_diff::MultiOracleTrieWithDiff;
use dlc_trie::{DlcTrie, OracleNumericInfo};
use secp256k1_zkp::PublicKey;
#[cfg(feature = "use-serde")]
use serde::{Deserialize, Serialize};

/// Information about the allowed deviation in outcome value between the oracles.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "use-serde",
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
    /// Whether to maximize the coverage of the \[min;max\] interval to increase
    /// the probability of the contract being closeable within it.
    pub maximize_coverage: bool,
}

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "use-serde",
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
    /// Information about the allowed differences in outcome value between oracles.
    /// If None, a quorum of oracle needs to sign the same value for the contract
    /// to be closeable.
    pub difference_params: Option<DifferenceParams>,
    /// Information about base and number of digits for each oracle.
    pub oracle_numeric_infos: OracleNumericInfo,
}

impl NumericalDescriptor {
    /// Returns the set of RangePayout for the descriptor generated from the
    /// payout function.
    pub fn get_range_payouts(&self, total_collateral: Amount) -> Result<Vec<RangePayout>, Error> {
        self.payout_function
            .to_range_payouts(total_collateral, &self.rounding_intervals)
    }

    /// Validate that the descriptor covers all possible outcomes of the given
    /// digit decomposition event descriptor.
    pub fn validate(&self, max_value: u64) -> Result<(), Error> {
        self.rounding_intervals.validate()?;
        self.payout_function.validate(max_value)
    }

    /// Returns the set of payouts for the descriptor generated from the payout
    /// function.
    pub fn get_payouts(&self, total_collateral: Amount) -> Result<Vec<Payout>, Error> {
        Ok(self
            .get_range_payouts(total_collateral)?
            .iter()
            .map(|x| x.payout)
            .collect())
    }

    /// Verify the given set of adaptor signatures and generate the adaptor info.
    pub fn get_scripts(
        &self,
        offer_spk: &Script,
        accept_spk: &Script,
        total_collateral: Amount,
        precomputed_points: &[Vec<Vec<PublicKey>>],
        index_start: usize,
        threshold: usize,
    ) -> Result<(AdaptorInfo, Vec<ScriptBuf>), Error> {
        match &self.difference_params {
            Some(params) => {
                let mut multi_trie = MultiOracleTrieWithDiff::new(
                    &self.oracle_numeric_infos,
                    threshold,
                    params.min_support_exp,
                    params.max_error_exp,
                )?;
                let scripts = multi_trie.generate_scripts(
                    offer_spk,
                    accept_spk,
                    &self.get_range_payouts(total_collateral)?,
                    precomputed_points,
                    index_start,
                )?;
                Ok((AdaptorInfo::NumericalWithDifference(multi_trie), scripts))
            }
            None => {
                let mut trie = MultiOracleTrie::new(&self.oracle_numeric_infos, threshold)?;
                let scripts = trie.generate_scripts(
                    offer_spk,
                    accept_spk,
                    &self.get_range_payouts(total_collateral)?,
                    precomputed_points,
                    index_start,
                )?;
                Ok((AdaptorInfo::Numerical(trie), scripts))
            }
        }
    }

    /// Generate the set of adaptor signatures and the adaptor info.
    pub fn get_adaptor_info(
        &self,
        total_collateral: Amount,
        offer_spk: &Script,
        accept_spk: &Script,
        threshold: usize,
        precomputed_points: &[Vec<Vec<PublicKey>>],
        adaptor_index_start: usize,
    ) -> Result<(AdaptorInfo, Vec<ScriptBuf>), Error> {
        match &self.difference_params {
            Some(params) => {
                let mut multi_trie = MultiOracleTrieWithDiff::new(
                    &self.oracle_numeric_infos,
                    threshold,
                    params.min_support_exp,
                    params.max_error_exp,
                )?;
                let scripts = multi_trie.generate_scripts(
                    offer_spk,
                    accept_spk,
                    &self.get_range_payouts(total_collateral)?,
                    precomputed_points,
                    adaptor_index_start,
                )?;
                Ok((AdaptorInfo::NumericalWithDifference(multi_trie), scripts))
            }

            None => {
                let mut trie = MultiOracleTrie::new(&self.oracle_numeric_infos, threshold)?;
                let sigs = trie.generate_scripts(
                    offer_spk,
                    accept_spk,
                    &self.get_range_payouts(total_collateral)?,
                    precomputed_points,
                    adaptor_index_start,
                )?;
                Ok((AdaptorInfo::Numerical(trie), sigs))
            }
        }
    }
}
