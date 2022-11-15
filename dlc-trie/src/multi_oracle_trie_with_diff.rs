//! # MultiOracleTrieWithDiff
//! Data structure and functions used to store adaptor signature information
//! for numerical outcome DLC with t of n oracles where some difference
//! between the outcomes of each oracle can be supported.

use crate::digit_decomposition::group_by_ignoring_digits;
use crate::multi_trie::{MultiTrie, MultiTrieDump, MultiTrieIterator};
use crate::utils::get_value_callback;

use crate::{DlcTrie, OracleNumericInfo, RangeInfo, TrieIterInfo};
use dlc::{Error, RangePayout};

/// Data structure used to store adaptor signature information for numerical
/// outcome DLC with multiple oracles where some difference between the outcomes
/// of each oracle can be supported.
#[derive(Clone)]
pub struct MultiOracleTrieWithDiff {
    /// The underlying trie of trie
    pub multi_trie: MultiTrie<RangeInfo>,
    /// Information on the numeric representation used by each oracle.
    pub oracle_numeric_infos: OracleNumericInfo,
}

impl MultiOracleTrieWithDiff {
    /// Create a new MultiOracleTrieWithDiff
    pub fn new(
        oracle_numeric_infos: &OracleNumericInfo,
        threshold: usize,
        min_support_exp: usize,
        max_error_exp: usize,
    ) -> Result<Self, Error> {
        let nb_oracles = oracle_numeric_infos.nb_digits.len();
        let is_valid =
            nb_oracles >= 1 && threshold <= nb_oracles && min_support_exp < max_error_exp;
        if !is_valid {
            return Err(Error::InvalidArgument);
        }
        let multi_trie = MultiTrie::new(
            oracle_numeric_infos,
            threshold,
            min_support_exp,
            max_error_exp,
            true,
        );
        Ok(MultiOracleTrieWithDiff {
            multi_trie,
            oracle_numeric_infos: oracle_numeric_infos.clone(),
        })
    }
}

impl<'a> DlcTrie<'a, MultiOracleTrieWithDiffIter<'a>> for MultiOracleTrieWithDiff {
    fn generate(
        &mut self,
        adaptor_index_start: usize,
        outcomes: &[RangePayout],
    ) -> Result<Vec<TrieIterInfo>, Error> {
        let mut adaptor_index = adaptor_index_start;
        let mut trie_infos = Vec::new();

        for (cet_index, outcome) in outcomes.iter().enumerate() {
            let groups = group_by_ignoring_digits(
                outcome.start,
                outcome.start + outcome.count - 1,
                self.oracle_numeric_infos.base,
                self.oracle_numeric_infos.get_min_nb_digits(),
            );
            for group in groups {
                let mut get_value =
                    |paths: &[Vec<usize>], oracle_indexes: &[usize]| -> Result<RangeInfo, Error> {
                        get_value_callback(
                            paths,
                            oracle_indexes,
                            cet_index,
                            &mut adaptor_index,
                            &mut trie_infos,
                        )
                    };
                self.multi_trie.insert(&group, &mut get_value)?;
            }
        }

        if self.oracle_numeric_infos.has_diff_nb_digits() {
            let mut get_value =
                |paths: &[Vec<usize>], oracle_indexes: &[usize]| -> Result<RangeInfo, Error> {
                    get_value_callback(
                        paths,
                        oracle_indexes,
                        outcomes.len() - 1,
                        &mut adaptor_index,
                        &mut trie_infos,
                    )
                };
            self.multi_trie.insert_max_paths(&mut get_value)?;
        }

        Ok(trie_infos)
    }

    fn iter(&'a self) -> MultiOracleTrieWithDiffIter<'a> {
        let multi_trie_iterator = MultiTrieIterator::new(&self.multi_trie);
        MultiOracleTrieWithDiffIter {
            multi_trie_iterator,
        }
    }
}

/// Container for a dump of a MultiOracleTrieWithDiff used for serialization purpose.
pub struct MultiOracleTrieWithDiffDump {
    /// The dump of the underlying MultiTrie.
    pub multi_trie_dump: MultiTrieDump<RangeInfo>,
    /// Information about numerical representation used by oracles.
    pub oracle_numeric_infos: OracleNumericInfo,
}

impl MultiOracleTrieWithDiff {
    /// Dump the content of the trie for the purpose of serialization.
    pub fn dump(&self) -> MultiOracleTrieWithDiffDump {
        let multi_trie_dump = self.multi_trie.dump();
        MultiOracleTrieWithDiffDump {
            multi_trie_dump,
            oracle_numeric_infos: self.oracle_numeric_infos.clone(),
        }
    }

    /// Restore a trie from a dump.
    pub fn from_dump(dump: MultiOracleTrieWithDiffDump) -> MultiOracleTrieWithDiff {
        let MultiOracleTrieWithDiffDump {
            multi_trie_dump,
            oracle_numeric_infos,
        } = dump;
        MultiOracleTrieWithDiff {
            multi_trie: MultiTrie::from_dump(multi_trie_dump),
            oracle_numeric_infos,
        }
    }
}

/// Iterator for a MultiOracleTrieWithDiff trie.
pub struct MultiOracleTrieWithDiffIter<'a> {
    multi_trie_iterator: MultiTrieIterator<'a, RangeInfo>,
}

impl<'a> Iterator for MultiOracleTrieWithDiffIter<'a> {
    type Item = TrieIterInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let res = match self.multi_trie_iterator.next() {
            None => return None,
            Some(res) => res,
        };
        let (indexes, paths) =
            res.path
                .iter()
                .fold((Vec::new(), Vec::new()), |(mut indexes, mut paths), x| {
                    indexes.push(x.0);
                    paths.push(x.1.clone());
                    (indexes, paths)
                });
        Some(TrieIterInfo {
            indexes,
            paths,
            value: res.value.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use dlc::{Payout, RangePayout};

    use crate::{test_utils::get_variable_oracle_numeric_infos, DlcTrie};

    use super::MultiOracleTrieWithDiff;
    #[test]
    fn test_is_ordered() {
        let range_payouts = vec![
            RangePayout {
                start: 0,
                count: 1,
                payout: Payout {
                    offer: 0,
                    accept: 200000000,
                },
            },
            RangePayout {
                start: 1,
                count: 1,
                payout: Payout {
                    offer: 40000000,
                    accept: 160000000,
                },
            },
            RangePayout {
                start: 2,
                count: 1,
                payout: Payout {
                    offer: 80000000,
                    accept: 120000000,
                },
            },
            RangePayout {
                start: 3,
                count: 1,
                payout: Payout {
                    offer: 120000000,
                    accept: 80000000,
                },
            },
            RangePayout {
                start: 4,
                count: 1,
                payout: Payout {
                    offer: 160000000,
                    accept: 40000000,
                },
            },
            RangePayout {
                start: 5,
                count: 1019,
                payout: Payout {
                    offer: 200000000,
                    accept: 0,
                },
            },
        ];

        let oracle_numeric_infos = get_variable_oracle_numeric_infos(&[13, 12], 2);
        let mut multi_oracle_trie =
            MultiOracleTrieWithDiff::new(&oracle_numeric_infos, 2, 1, 2).unwrap();
        let info = multi_oracle_trie.generate(0, &range_payouts).unwrap();
        let mut indexes: Vec<_> = info
            .into_iter()
            .map(|info| info.value.adaptor_index)
            .collect();

        let lookup_res = multi_oracle_trie
            .multi_trie
            .look_up(&[
                (0, vec![0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0]),
                (1, vec![0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0]),
            ])
            .expect("Could not find");

        indexes.sort();

        for (prev_index, i) in indexes.iter().skip(1).enumerate() {
            assert_eq!(*i, prev_index + 1);
        }

        let mut indexes: Vec<_> = multi_oracle_trie
            .iter()
            .map(|info| info.value.adaptor_index)
            .collect();

        indexes.sort();

        for (prev_index, i) in indexes.iter().skip(1).enumerate() {
            assert_eq!(*i, prev_index + 1);
        }

        let iter_res = multi_oracle_trie
            .iter()
            .find(|x| x.value.adaptor_index == 22)
            .unwrap();
        assert_eq!(
            &lookup_res
                .1
                .iter()
                .map(|(_, x)| x.clone())
                .collect::<Vec<_>>(),
            &iter_res.paths
        );
    }
}
