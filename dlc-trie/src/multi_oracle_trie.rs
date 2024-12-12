//! # MultiOracleTrie
//! Data structure and functions used to store adaptor signature information
//! for numerical outcome DLC with t of n oracles where at least t oracles
//! need to sign the same outcome for the contract to be able to close.

use crate::combination_iterator::CombinationIterator;
use crate::digit_decomposition::group_by_ignoring_digits;
use crate::digit_trie::{DigitTrie, DigitTrieDump, DigitTrieIter};
use crate::multi_trie::{MultiTrie, MultiTrieDump, MultiTrieIterator};
use crate::utils::{get_value_callback, pre_pad_vec};
use crate::{DlcTrie, IndexedPath, LookupResult, OracleNumericInfo, RangeInfo, TrieIterInfo};
use dlc::{Error, RangePayout};

/// Data structure used to store adaptor signature information for numerical
/// outcome DLC with t of n oracles where at least t oracles need to sign the
/// same outcome for the contract to be able to close.
#[derive(Clone)]
pub struct MultiOracleTrie {
    /// The underlying trie data structure.
    digit_trie: DigitTrie<Vec<RangeInfo>>,
    threshold: usize,
    oracle_numeric_infos: OracleNumericInfo,
    extra_cover_trie: Option<MultiTrie<RangeInfo>>,
}

/// Container for a dump of a MultiOracleTrie used for serialization purpose.
pub struct MultiOracleTrieDump {
    /// A dump of the underlying digit trie.
    pub digit_trie_dump: DigitTrieDump<Vec<RangeInfo>>,
    /// The required number of oracles for this trie.
    pub threshold: usize,
    /// Information about each oracle numerical representation.
    pub oracle_numeric_infos: OracleNumericInfo,
    /// A dump of the trie for extra coverage.
    pub extra_cover_trie_dump: Option<MultiTrieDump<RangeInfo>>,
}

impl MultiOracleTrie {
    /// Dump the trie information.
    pub fn dump(&self) -> MultiOracleTrieDump {
        MultiOracleTrieDump {
            digit_trie_dump: self.digit_trie.dump(),
            threshold: self.threshold,
            oracle_numeric_infos: self.oracle_numeric_infos.clone(),
            extra_cover_trie_dump: self.extra_cover_trie.as_ref().map(|trie| trie.dump()),
        }
    }

    /// Recover a MultiOracleTrie from a dump.
    pub fn from_dump(dump: MultiOracleTrieDump) -> MultiOracleTrie {
        let MultiOracleTrieDump {
            digit_trie_dump,
            threshold,
            oracle_numeric_infos,
            extra_cover_trie_dump,
        } = dump;
        MultiOracleTrie {
            digit_trie: DigitTrie::from_dump(digit_trie_dump),
            threshold,
            oracle_numeric_infos,
            extra_cover_trie: extra_cover_trie_dump.map(MultiTrie::from_dump),
        }
    }

    fn get_agreeing_oracles(
        &self,
        paths: &[(usize, Vec<usize>)],
    ) -> Option<Vec<(Vec<usize>, Vec<usize>)>> {
        let mut hash_set: std::collections::HashMap<Vec<usize>, Vec<usize>> =
            std::collections::HashMap::new();

        for path in paths {
            let index = path.0;
            let outcome_path = &path.1;

            if let Some(index_set) = hash_set.get_mut(outcome_path) {
                index_set.push(index);
            } else {
                let index_set = vec![index];
                hash_set.insert(outcome_path.to_vec(), index_set);
            }
        }

        if hash_set.is_empty() {
            return None;
        }

        let mut values: Vec<_> = hash_set.into_iter().collect();
        values.sort_by(|x, y| x.1.len().partial_cmp(&y.1.len()).unwrap());
        let res = values
            .into_iter()
            .filter(|x| x.1.len() >= self.threshold)
            .collect::<Vec<_>>();
        if !res.is_empty() {
            Some(res)
        } else {
            None
        }
    }

    /// Lookup for nodes whose path is either equal or a prefix of `path`.
    pub fn look_up(&self, paths: &[(usize, Vec<usize>)]) -> Option<(RangeInfo, Vec<IndexedPath>)> {
        let min_nb_digits = self.oracle_numeric_infos.get_min_nb_digits();
        // Take all the paths that have a max value of base^min_nb_digits - 1, and
        // shorten them to min_nb_digits.
        let stripped_paths = paths
            .iter()
            .filter_map(|x| {
                let extra_len = x.1.len().checked_sub(min_nb_digits)?;
                if extra_len == 0 {
                    Some((x.0, x.1.clone()))
                } else if x.1.iter().take(extra_len).all(|x| *x == 0) {
                    let mut cloned = x.1.clone();
                    cloned.drain(..extra_len);
                    Some((x.0, cloned))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        // Try to get the combinations of at least threshold oracles that agree on the outcome.
        let agreeing_combinations = self.get_agreeing_oracles(&stripped_paths);
        if let Some(sufficient_combinations) = agreeing_combinations {
            for (path, combination) in sufficient_combinations {
                debug_assert_eq!(
                    path.len(),
                    min_nb_digits,
                    "Expected length {} got length {}",
                    min_nb_digits,
                    path.len()
                );

                if let Some(res) = self.digit_trie.look_up(&path) {
                    let sufficient_combination: Vec<_> =
                        combination.into_iter().take(self.threshold).collect();
                    if let Some(position) = CombinationIterator::new(
                        self.oracle_numeric_infos.nb_digits.len(),
                        self.threshold,
                    )
                    .get_index_for_combination(&sufficient_combination)
                    {
                        return Some((
                            res[0].value[position].clone(),
                            sufficient_combination
                                .iter()
                                .map(|x| {
                                    let actual_len = res[0].path.len()
                                        + self.oracle_numeric_infos.nb_digits[*x]
                                        - min_nb_digits;
                                    (*x, pre_pad_vec(res[0].path.clone(), actual_len))
                                })
                                .collect::<Vec<_>>(),
                        ));
                    }
                }
            }
        }

        if let Some(extra_cover_trie) = &self.extra_cover_trie {
            if let Some(res) = extra_cover_trie.look_up(paths) {
                return Some((res.0.clone(), res.1));
            }
        }

        None
    }

    /// Creates a new MultiOracleTrie
    pub fn new(oracle_numeric_infos: &OracleNumericInfo, threshold: usize) -> Result<Self, Error> {
        if oracle_numeric_infos.nb_digits.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let digit_trie = DigitTrie::new(oracle_numeric_infos.base);
        let extra_cover_trie = if oracle_numeric_infos.has_diff_nb_digits() {
            // The support and coverage parameters don't matter as we only use this trie for coverage of
            // the "out of bounds" outcomes.
            Some(MultiTrie::new(oracle_numeric_infos, threshold, 1, 2, true))
        } else {
            None
        };
        Ok(MultiOracleTrie {
            digit_trie,
            threshold,
            oracle_numeric_infos: oracle_numeric_infos.clone(),
            extra_cover_trie,
        })
    }
}

impl<'a> DlcTrie<'a, MultiOracleTrieIter<'a>> for MultiOracleTrie {
    fn generate(
        &mut self,
        adaptor_index_start: usize,
        outcomes: &[RangePayout],
    ) -> Result<Vec<TrieIterInfo>, Error> {
        let threshold = self.threshold;
        let nb_oracles = self.oracle_numeric_infos.nb_digits.len();
        let min_nb_digits = self.oracle_numeric_infos.get_min_nb_digits();
        let mut adaptor_index = adaptor_index_start;
        let mut trie_infos = Vec::new();
        let oracle_numeric_infos = &self.oracle_numeric_infos;
        for (cet_index, outcome) in outcomes.iter().enumerate() {
            let groups = group_by_ignoring_digits(
                outcome.start,
                outcome.start + outcome.count - 1,
                self.digit_trie.base,
                min_nb_digits,
            );
            for group in groups {
                let mut get_value = |_: Option<Vec<RangeInfo>>| -> Result<Vec<RangeInfo>, Error> {
                    let combination_iterator = CombinationIterator::new(nb_oracles, threshold);
                    let mut range_infos: Vec<RangeInfo> = Vec::new();
                    for selector in combination_iterator {
                        let range_info = RangeInfo {
                            cet_index,
                            adaptor_index,
                        };
                        adaptor_index += 1;
                        let paths = oracle_numeric_infos
                            .nb_digits
                            .iter()
                            .enumerate()
                            .filter_map(|(i, nb_digits)| {
                                if !selector.contains(&i) {
                                    return None;
                                }
                                let expected_len = group.len() + nb_digits - min_nb_digits;
                                Some(pre_pad_vec(group.clone(), expected_len))
                            })
                            .collect();
                        let trie_info = TrieIterInfo {
                            paths,
                            indexes: selector,
                            value: range_info.clone(),
                        };
                        trie_infos.push(trie_info);
                        range_infos.push(range_info);
                    }
                    Ok(range_infos)
                };
                self.digit_trie.insert(&group, &mut get_value)?;
            }
        }

        if let Some(extra_cover_trie) = &mut self.extra_cover_trie {
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
            extra_cover_trie.insert_max_paths(&mut get_value)?;
        }

        Ok(trie_infos)
    }

    fn iter(&'a self) -> MultiOracleTrieIter<'a> {
        let digit_trie_iterator = DigitTrieIter::new(&self.digit_trie);
        let extra_cover_trie_iterator = self.extra_cover_trie.as_ref().map(MultiTrieIterator::new);
        MultiOracleTrieIter {
            digit_trie_iterator,
            extra_cover_trie_iterator,
            cur_res: None,
            cur_index: 0,
            combination_iter: CombinationIterator::new(
                self.oracle_numeric_infos.nb_digits.len(),
                self.threshold,
            ),
            oracle_numeric_infos: self.oracle_numeric_infos.clone(),
        }
    }
}

/// Iterator for a MultiOracleTrie.
pub struct MultiOracleTrieIter<'a> {
    digit_trie_iterator: DigitTrieIter<'a, Vec<RangeInfo>>,
    extra_cover_trie_iterator: Option<MultiTrieIterator<'a, RangeInfo>>,
    cur_res: Option<LookupResult<'a, Vec<RangeInfo>, usize>>,
    cur_index: usize,
    combination_iter: CombinationIterator,
    oracle_numeric_infos: OracleNumericInfo,
}

impl Iterator for MultiOracleTrieIter<'_> {
    type Item = TrieIterInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur_res.is_none() {
            self.cur_res = self.digit_trie_iterator.next();
        }
        let res = match &self.cur_res {
            None => {
                if let Some(extra_cover_trie_iterator) = &mut self.extra_cover_trie_iterator {
                    let res = match extra_cover_trie_iterator.next() {
                        None => return None,
                        Some(res) => res,
                    };
                    let (indexes, paths) = res.path.iter().fold(
                        (Vec::new(), Vec::new()),
                        |(mut indexes, mut paths), x| {
                            indexes.push(x.0);
                            paths.push(x.1.clone());
                            (indexes, paths)
                        },
                    );
                    return Some(TrieIterInfo {
                        indexes,
                        paths,
                        value: res.value.clone(),
                    });
                } else {
                    return None;
                }
            }
            Some(res) => res,
        };

        let indexes = match self.combination_iter.next() {
            Some(selector) => selector,
            None => {
                self.cur_res = None;
                self.cur_index = 0;
                self.combination_iter = CombinationIterator::new(
                    self.combination_iter.nb_elements,
                    self.combination_iter.nb_selected,
                );
                return self.next();
            }
        };
        let min_nb_digits = self.oracle_numeric_infos.get_min_nb_digits();
        let paths = &std::iter::repeat(res.path.clone())
            .take(indexes.len())
            .zip(indexes.iter())
            .map(|(x, i)| {
                let extra_len = self.oracle_numeric_infos.nb_digits[*i] - min_nb_digits;
                if extra_len == 0 {
                    x
                } else {
                    let expected_size = extra_len + x.len();
                    pre_pad_vec(x, expected_size)
                }
            })
            .collect::<Vec<Vec<_>>>();
        let value = res.value[self.cur_index].clone();
        self.cur_index += 1;
        Some(TrieIterInfo {
            indexes,
            paths: paths.clone(),
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Amount;
    use dlc::{Payout, RangePayout};

    use crate::{test_utils::get_variable_oracle_numeric_infos, DlcTrie};

    use super::MultiOracleTrie;
    #[test]
    fn test_longer_outcome_len() {
        let range_payouts = vec![RangePayout {
            start: 0,
            count: 1023,
            payout: Payout {
                offer: Amount::from_sat(200000000),
                accept: Amount::ZERO,
            },
        }];
        let oracle_numeric_infos = get_variable_oracle_numeric_infos(&[10, 15, 15, 15, 12], 2);
        let mut multi_oracle_trie = MultiOracleTrie::new(&oracle_numeric_infos, 2).unwrap();
        multi_oracle_trie.generate(0, &range_payouts).unwrap();
        multi_oracle_trie
            .look_up(&[
                (1, vec![0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0]),
                (4, vec![0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0]),
            ])
            .expect("Could not retrieve path with extra len.");
    }

    #[test]
    fn test_over_bound_outcome() {
        let range_payouts = vec![RangePayout {
            start: 0,
            count: 1023,
            payout: Payout {
                offer: Amount::from_sat(200000000),
                accept: Amount::ZERO,
            },
        }];
        let oracle_numeric_infos = get_variable_oracle_numeric_infos(&[10, 15, 15, 15, 12], 2);
        let mut multi_oracle_trie = MultiOracleTrie::new(&oracle_numeric_infos, 2).unwrap();
        multi_oracle_trie.generate(0, &range_payouts).unwrap();
        multi_oracle_trie
            .look_up(&[
                (1, vec![1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0]),
                (4, vec![0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0]),
            ])
            .expect("Could not retrieve path with extra len.");
    }
}
