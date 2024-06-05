//! Utility functions when working with DLC trie

use bitcoin::secp256k1::PublicKey;
use dlc::Error;

use crate::{
    combination_iterator::CombinationIterator, OracleNumericInfo, RangeInfo, TrieIterInfo,
};

/// Creates an adaptor point using the provided oracle infos and paths, selecting
/// the oracle info at the provided indexes only. The paths are converted to
/// strings and hashed to be used as messages in adaptor signature creation.
pub(crate) fn get_adaptor_point_for_indexed_paths(
    indexes: &[usize],
    paths: &[Vec<usize>],
    precomputed_points: &[Vec<Vec<PublicKey>>],
) -> Result<PublicKey, super::Error> {
    debug_assert!(indexes.len() == paths.len());
    debug_assert!(precomputed_points.len() >= indexes.len());
    if indexes.is_empty() {
        return Err(super::Error::InvalidArgument);
    }

    let mut keys = Vec::new();

    for (i, j) in indexes.iter().enumerate() {
        let path = &paths[i];
        let k: Vec<&PublicKey> = precomputed_points[*j]
            .iter()
            .zip(path.iter())
            .map(|(y, p)| &y[*p])
            .collect();
        keys.extend(k);
    }

    Ok(PublicKey::combine_keys(&keys)?)
}

/// Prepend zeros to the given vector until its size matches `expected_size`.
pub(crate) fn pre_pad_vec(mut input: Vec<usize>, expected_size: usize) -> Vec<usize> {
    if input.len() == expected_size {
        return input;
    }

    let mut res = Vec::with_capacity(expected_size);
    res.resize(expected_size - input.len(), 0);
    res.append(&mut input);
    res
}

pub(crate) fn get_max_covering_paths(
    oracle_numeric_infos: &OracleNumericInfo,
    threshold: usize,
) -> Vec<Vec<(usize, Vec<usize>)>> {
    let mut paths: Vec<Vec<(usize, Vec<usize>)>> = Vec::new();
    let min_nb_digits = oracle_numeric_infos.get_min_nb_digits();
    let combination_iter =
        CombinationIterator::new(oracle_numeric_infos.nb_digits.len(), threshold);
    for combination in combination_iter {
        let infos = oracle_numeric_infos
            .nb_digits
            .iter()
            .enumerate()
            .filter_map(|(i, x)| {
                if combination.contains(&i) {
                    Some(x)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if infos.iter().all(|x| *x == &min_nb_digits) {
            continue;
        }

        // The extra digits that each oracle has compared to `min_nb_digits`.
        let max = infos.iter().map(|x| *x - min_nb_digits).collect::<Vec<_>>();

        // Counters for the extra length of prefixes of each oracle. 0 if the oracle
        // has nb_digit, starts at 1 for others since at the minimum we want to generate
        // a prefix with `min_nb_digits + 1`.
        let mut counters = infos
            .iter()
            .map(|x| usize::from(**x != min_nb_digits))
            .collect::<Vec<_>>();
        let mut i = 0;
        loop {
            let path = counters
                .iter()
                .zip(combination.iter())
                .map(|(x, i)| {
                    // For oracles with `min_nb_digits` we just generate the max value.
                    let p = if *x == 0 {
                        std::iter::repeat(1).take(min_nb_digits).collect()
                    } else {
                        // For others we generate the prefix based on their current
                        // counter value. We insert `counter - 1` zero and then a 1.
                        let mut p = Vec::with_capacity(*x);
                        p.resize(x - 1, 0);
                        p.push(1);
                        p
                    };
                    (*i, p)
                })
                .collect::<Vec<_>>();
            paths.push(path);

            // If all counters have reached their max prefix size value, we're done.
            if counters.iter().zip(max.iter()).all(|(x, y)| x == y) {
                break;
            }

            // We reset the counters of oracles that had reached their max length
            // prefixes, until we reach one that had not yet. We increment the counter
            // for that one.
            while counters[i] == max[i] {
                if *infos[i] != min_nb_digits {
                    counters[i] = 1;
                }
                i += 1;
            }
            counters[i] += 1;
            i = 0;
        }
    }
    paths
}

pub(crate) fn get_value_callback(
    paths: &[Vec<usize>],
    oracle_indexes: &[usize],
    cet_index: usize,
    adaptor_index: &mut usize,
    trie_infos: &mut Vec<TrieIterInfo>,
) -> Result<RangeInfo, Error> {
    let range_info = RangeInfo {
        cet_index,
        adaptor_index: *adaptor_index,
    };
    let iter_info = TrieIterInfo {
        value: range_info.clone(),
        indexes: oracle_indexes.to_vec(),
        paths: paths.to_vec(),
    };
    trie_infos.push(iter_info);
    *adaptor_index += 1;
    Ok(range_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::get_variable_oracle_numeric_infos;

    struct TestCase {
        nb_digits: Vec<usize>,
        threshold: usize,
        expected_paths: Vec<Vec<(usize, Vec<usize>)>>,
    }

    fn test_cases() -> Vec<TestCase> {
        vec![
            TestCase {
                nb_digits: vec![10, 12, 11, 10],
                threshold: 4,
                expected_paths: vec![
                    vec![
                        (0, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
                        (1, vec![1]),
                        (2, vec![1]),
                        (3, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
                    ],
                    vec![
                        (0, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
                        (1, vec![0, 1]),
                        (2, vec![1]),
                        (3, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
                    ],
                ],
            },
            TestCase {
                nb_digits: vec![10, 12, 11, 10],
                threshold: 2,
                expected_paths: vec![
                    vec![(0, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1]), (1, vec![1])],
                    vec![(0, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1]), (1, vec![0, 1])],
                    vec![(0, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1]), (2, vec![1])],
                    vec![(1, vec![1]), (2, vec![1])],
                    vec![(1, vec![0, 1]), (2, vec![1])],
                    vec![(1, vec![1]), (3, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1])],
                    vec![(1, vec![0, 1]), (3, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1])],
                    vec![(2, vec![1]), (3, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1])],
                ],
            },
        ]
    }

    #[test]
    fn max_covering_paths_test() {
        for test_case in test_cases() {
            let oracle_infos = get_variable_oracle_numeric_infos(&test_case.nb_digits, 2);
            let max_covering_paths = get_max_covering_paths(&oracle_infos, test_case.threshold);

            assert_eq!(test_case.expected_paths, max_covering_paths);
        }
    }
}
