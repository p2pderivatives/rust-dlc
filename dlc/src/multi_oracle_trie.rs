//! # MultiOracleTrie
//! Data structure and functions used to store adaptor signature information
//! for numerical outcome DLC with t of n oracles where at least t oracles
//! need to sign the same outcome for the contract to be able to close.

use crate::combination_iterator::CombinationIterator;
use crate::digit_decomposition::group_by_ignoring_digits;
use crate::digit_trie::{DigitTrie, DigitTrieIter};
use crate::dlc_trie::DlcTrie;
use crate::dlc_trie_utils::get_adaptor_point_for_indexed_paths;
use crate::{Error, OracleInfo, RangeInfo, RangePayout};
use bitcoin::{Script, Transaction};
use secp256k1::{
    ecdsa_adaptor::{AdaptorProof, AdaptorSignature},
    All, PublicKey, Secp256k1, SecretKey, Signing,
};

/// Data structure used to store adaptor signature information for numerical
/// outcome DLC with t of n oracles where at least t oracles need to sign the
/// same outcome for the contract to be able to close.
#[derive(Clone)]
pub struct MultiOracleTrie {
    /// The underlying trie data structure.
    pub digit_trie: DigitTrie<Vec<RangeInfo>>,
    nb_oracles: usize,
    threshold: usize,
    nb_digits: usize,
}

impl MultiOracleTrie {
    /// Creates a new MultiOracleTrie
    pub fn new(base: usize, nb_oracles: usize, threshold: usize, nb_digits: usize) -> Self {
        let digit_trie = DigitTrie::new(base);
        MultiOracleTrie {
            digit_trie,
            nb_oracles,
            threshold,
            nb_digits,
        }
    }
}

impl DlcTrie for MultiOracleTrie {
    fn generate<C: Signing, F>(
        &mut self,
        secp: &Secp256k1<C>,
        outcomes: &[RangePayout],
        oracle_infos: &[OracleInfo],
        callback: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(usize, &PublicKey) -> Result<usize, Error>,
    {
        let mut cet_index = 0;
        let threshold = self.threshold;
        let nb_oracles = self.nb_oracles;
        for outcome in outcomes {
            let groups = group_by_ignoring_digits(
                outcome.start,
                outcome.start + outcome.count - 1,
                self.digit_trie.base,
                self.nb_digits,
            )
            .unwrap();
            for group in groups {
                let mut get_value = |_: Option<Vec<RangeInfo>>| -> Result<Vec<RangeInfo>, Error> {
                    let combination_iterator = CombinationIterator::new(nb_oracles, threshold);
                    let mut range_infos: Vec<RangeInfo> = Vec::new();
                    for selector in combination_iterator {
                        let adaptor_point = get_adaptor_point_for_indexed_paths(
                            &secp,
                            &oracle_infos,
                            &selector,
                            &std::iter::repeat(group.clone()).take(threshold).collect(),
                        )?;
                        let adaptor_index = callback(cet_index, &adaptor_point)?;
                        range_infos.push(RangeInfo {
                            cet_index,
                            adaptor_index,
                        });
                    }
                    Ok(range_infos)
                };
                self.digit_trie.insert(&group, &mut get_value)?;
            }
            cet_index += 1;
        }
        Ok(())
    }

    fn iter<F>(
        &self,
        secp: &Secp256k1<All>,
        oracle_infos: &[OracleInfo],
        callback: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(&PublicKey, &RangeInfo) -> Result<(), Error>,
    {
        let trie_iter = DigitTrieIter::new(&self.digit_trie);
        let combinations: Vec<Vec<usize>> =
            CombinationIterator::new(oracle_infos.len(), self.threshold).collect();
        for res in trie_iter {
            let path = res.path;
            for (i, selector) in combinations.iter().enumerate() {
                let adaptor_point = get_adaptor_point_for_indexed_paths(
                    secp,
                    &oracle_infos,
                    &selector,
                    &std::iter::repeat(path.clone())
                        .take(self.threshold)
                        .collect(),
                )?;
                callback(&adaptor_point, &res.value[i])?;
            }
        }
        Ok(())
    }

    fn sign(
        &self,
        secp: &Secp256k1<All>,
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        oracle_infos: &[OracleInfo],
    ) -> Result<Vec<(AdaptorSignature, AdaptorProof)>, Error> {
        let mut adaptor_pairs = Vec::new();
        let mut callback =
            |adaptor_point: &PublicKey, range_info: &RangeInfo| -> Result<(), Error> {
                let adaptor_pair = crate::create_cet_adaptor_sig_from_point(
                    &secp,
                    &cets[range_info.cet_index],
                    &adaptor_point,
                    fund_privkey,
                    &funding_script_pubkey,
                    fund_output_value,
                )?;
                adaptor_pairs.push(adaptor_pair);
                Ok(())
            };

        self.iter(secp, oracle_infos, &mut callback)?;
        Ok(adaptor_pairs)
    }
}
