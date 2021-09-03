//! # MultiOracleTrie
//! Data structure and functions used to store adaptor signature information
//! for numerical outcome DLC with t of n oracles where at least t oracles
//! need to sign the same outcome for the contract to be able to close.

use crate::combination_iterator::CombinationIterator;
use crate::digit_decomposition::group_by_ignoring_digits;
use crate::digit_trie::{DigitTrie, DigitTrieDump, DigitTrieIter};
use crate::utils::get_adaptor_point_for_indexed_paths;
use crate::DlcTrie;
use crate::{Error, OracleInfo, RangeInfo, RangePayout};
use bitcoin::{Script, Transaction};
use secp256k1_zkp::{All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey, Verification};

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

/// Container for a dump of a MultiOracleTrie used for serialization purpose.
pub struct MultiOracleTrieDump {
    /// A dump of the underlying digit trie.
    pub digit_trie_dump: DigitTrieDump<Vec<RangeInfo>>,
    /// The total number of oracles for this trie.
    pub nb_oracles: usize,
    /// The required number of oracles for this trie.
    pub threshold: usize,
    /// The maximum number of digits for a path in the trie.
    pub nb_digits: usize,
}

impl MultiOracleTrie {
    /// Dump the trie information.
    pub fn dump(&self) -> MultiOracleTrieDump {
        MultiOracleTrieDump {
            digit_trie_dump: self.digit_trie.dump(),
            nb_oracles: self.nb_oracles,
            threshold: self.threshold,
            nb_digits: self.nb_digits,
        }
    }

    /// Recover a MultiOracleTrie from a dump.
    pub fn from_dump(dump: MultiOracleTrieDump) -> MultiOracleTrie {
        let MultiOracleTrieDump {
            digit_trie_dump,
            nb_oracles,
            threshold,
            nb_digits,
        } = dump;
        MultiOracleTrie {
            digit_trie: DigitTrie::from_dump(digit_trie_dump),
            nb_oracles,
            threshold,
            nb_digits,
        }
    }
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
    fn generate<C: Verification, F>(
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
    ) -> Result<Vec<EcdsaAdaptorSignature>, Error> {
        let mut adaptor_pairs = Vec::new();
        let mut callback =
            |adaptor_point: &PublicKey, range_info: &RangeInfo| -> Result<(), Error> {
                let adaptor_pair = dlc::create_cet_adaptor_sig_from_point(
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
