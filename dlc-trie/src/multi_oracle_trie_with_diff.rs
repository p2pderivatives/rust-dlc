//! # MultiOracleTrieWithDiff
//! Data structure and functions used to store adaptor signature information
//! for numerical outcome DLC with t of n oracles where some difference
//! between the outcomes of each oracle can be supported.

use crate::digit_decomposition::group_by_ignoring_digits;
use crate::multi_trie::{MultiTrie, MultiTrieDump, MultiTrieIterator};

use crate::RangeInfo;
use crate::{DlcTrie, TrieIterInfo};
use dlc::{Error, RangePayout};

/// Data structure used to store adaptor signature information for numerical
/// outcome DLC with multiple oracles where some difference between the outcomes
/// of each oracle can be supported.
#[derive(Clone)]
pub struct MultiOracleTrieWithDiff {
    /// The underlying trie of trie
    pub multi_trie: MultiTrie<RangeInfo>,
    base: usize,
    nb_digits: usize,
}

impl MultiOracleTrieWithDiff {
    /// Create a new MultiOracleTrieWithDiff
    pub fn new(
        base: usize,
        nb_oracles: usize,
        threshold: usize,
        nb_digits: usize,
        min_support_exp: usize,
        max_error_exp: usize,
    ) -> Self {
        let multi_trie = MultiTrie::new(
            nb_oracles,
            threshold,
            base,
            min_support_exp,
            max_error_exp,
            nb_digits,
            true,
        );
        MultiOracleTrieWithDiff {
            multi_trie,
            base,
            nb_digits,
        }
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
                self.base,
                self.nb_digits,
            );
            for group in groups {
                let mut get_value =
                    |paths: &[Vec<usize>], oracle_indexes: &[usize]| -> Result<RangeInfo, Error> {
                        let range_info = RangeInfo {
                            cet_index,
                            adaptor_index,
                        };
                        let iter_info = TrieIterInfo {
                            value: range_info.clone(),
                            indexes: oracle_indexes.to_vec(),
                            paths: paths.to_vec(),
                        };
                        trie_infos.push(iter_info);
                        adaptor_index += 1;
                        Ok(range_info)
                    };
                self.multi_trie.insert(&group, &mut get_value)?;
            }
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
    /// The base for which the trie was created for.
    pub base: usize,
    /// The maximum number of digits for a path in the trie.
    pub nb_digits: usize,
}

impl MultiOracleTrieWithDiff {
    /// Dump the content of the trie for the purpose of serialization.
    pub fn dump(&self) -> MultiOracleTrieWithDiffDump {
        let multi_trie_dump = self.multi_trie.dump();
        MultiOracleTrieWithDiffDump {
            multi_trie_dump,
            base: self.base,
            nb_digits: self.nb_digits,
        }
    }

    /// Restore a trie from a dump.
    pub fn from_dump(dump: MultiOracleTrieWithDiffDump) -> MultiOracleTrieWithDiff {
        let MultiOracleTrieWithDiffDump {
            multi_trie_dump,
            base,
            nb_digits,
        } = dump;
        MultiOracleTrieWithDiff {
            multi_trie: MultiTrie::from_dump(multi_trie_dump),
            base,
            nb_digits,
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
