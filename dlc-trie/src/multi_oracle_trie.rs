//! # MultiOracleTrie
//! Data structure and functions used to store adaptor signature information
//! for numerical outcome DLC with t of n oracles where at least t oracles
//! need to sign the same outcome for the contract to be able to close.

use crate::combination_iterator::CombinationIterator;
use crate::digit_decomposition::group_by_ignoring_digits;
use crate::digit_trie::{DigitTrie, DigitTrieDump, DigitTrieIter};
use crate::{DlcTrie, LookupResult, RangeInfo, TrieIterInfo};
use dlc::{Error, RangePayout};

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

impl<'a> DlcTrie<'a, MultiOracleTrieIter<'a>> for MultiOracleTrie {
    fn generate(
        &mut self,
        adaptor_index_start: usize,
        outcomes: &[RangePayout],
    ) -> Result<Vec<TrieIterInfo>, Error> {
        let mut cet_index = 0;
        let threshold = self.threshold;
        let nb_oracles = self.nb_oracles;
        let mut adaptor_index = adaptor_index_start;
        let mut trie_infos = Vec::new();
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
                        let range_info = RangeInfo {
                            cet_index,
                            adaptor_index,
                        };
                        adaptor_index += 1;
                        let trie_info = TrieIterInfo {
                            indexes: selector,
                            paths: std::iter::repeat(group.clone()).take(threshold).collect(),
                            value: range_info.clone(),
                        };
                        trie_infos.push(trie_info);
                        range_infos.push(range_info);
                    }
                    Ok(range_infos)
                };
                self.digit_trie.insert(&group, &mut get_value)?;
            }
            cet_index += 1;
        }
        Ok(trie_infos)
    }

    fn iter(&'a self) -> MultiOracleTrieIter {
        let digit_trie_iterator = DigitTrieIter::new(&self.digit_trie);
        MultiOracleTrieIter {
            digit_trie_iterator,
            cur_res: None,
            cur_index: 0,
            combination_iter: CombinationIterator::new(self.nb_oracles, self.threshold),
        }
    }
}

/// Iterator for a MultiOracleTrie.
pub struct MultiOracleTrieIter<'a> {
    digit_trie_iterator: DigitTrieIter<'a, Vec<RangeInfo>>,
    cur_res: Option<LookupResult<'a, Vec<RangeInfo>, usize>>,
    cur_index: usize,
    combination_iter: CombinationIterator,
}

impl<'a> Iterator for MultiOracleTrieIter<'a> {
    type Item = TrieIterInfo;

    fn next(&mut self) -> Option<Self::Item> {
        match &self.cur_res {
            None => self.cur_res = self.digit_trie_iterator.next(),
            _ => {}
        };
        let res = match &self.cur_res {
            None => return None,
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
        let paths = &std::iter::repeat(res.path.clone())
            .take(self.combination_iter.nb_selected)
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
