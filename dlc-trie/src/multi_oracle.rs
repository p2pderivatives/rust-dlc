//! Utility functions to compute outcome combinations to work with
//! multi oracle DLC.

use digit_decomposition::{compose_value, decompose_value};

/// Returns the interval represented by the given prefix in the given base with
/// the given number of digits.
fn compute_interval_from_prefix(
    prefix: &[usize],
    num_digits: usize,
    base: usize,
) -> (usize, usize) {
    let suffix_len = num_digits - prefix.len();
    let start = compose_value(
        &prefix
            .iter()
            .cloned()
            .chain((0..suffix_len).map(|_| 0))
            .collect::<Vec<_>>(),
        base,
    );
    let end = compose_value(
        &prefix
            .iter()
            .cloned()
            .chain((0..suffix_len).map(|_| base - 1))
            .collect::<Vec<_>>(),
        base,
    );
    (start, end)
}

fn num_to_vec(input: usize, nb_digits: usize, ignored_digits: usize, base: usize) -> Vec<usize> {
    let decomposed = decompose_value(input, base, nb_digits);
    let to_take = decomposed.len() - ignored_digits;

    decomposed.into_iter().take(to_take).collect::<Vec<_>>()
}

fn compute_min_support_covering_prefix(
    start: usize,
    end: usize,
    min_support: usize,
    nb_digits: usize,
) -> Vec<usize> {
    let left_bound = start - min_support;
    let right_bound = end + min_support;
    let left_bound = decompose_value(left_bound, 2, nb_digits);
    let right_bound = decompose_value(right_bound, 2, nb_digits);

    left_bound
        .into_iter()
        .zip(right_bound.into_iter())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x)
        .collect()
}

/// Take the largest prefix of the smallest interval that contains [max_error; end + min_support]
fn compute_left_covering_prefix(
    start: usize,
    max_error_exp: usize,
    min_support: usize,
    nb_digits: usize,
) -> Vec<usize> {
    let left_bound = start - min_support;
    let left_bound = decompose_value(left_bound, 2, nb_digits);
    let (prefix, suffix) = left_bound.split_at(nb_digits - max_error_exp);

    prefix
        .into_iter()
        .chain(suffix.into_iter().take_while(|x| **x == 1))
        .cloned()
        .collect()
}

/// Take the largest prefix of the smallest interval that contains [start - min_support; max_error]
fn compute_right_covering_prefix(
    end: usize,
    max_error_exp: usize,
    min_support: usize,
    nb_digits: usize,
) -> Vec<usize> {
    let left_bound = end + min_support;
    let left_bound = decompose_value(left_bound, 2, nb_digits);
    let (prefix, suffix) = left_bound.split_at(nb_digits - max_error_exp);

    prefix
        .into_iter()
        .chain(suffix.into_iter().take_while(|x| **x == 0))
        .cloned()
        .collect()
}

fn single_covering_prefix_combinations(
    main_outcome_prefix: &[usize],
    secondary_outcomes_prefix: &[usize],
    nb_oracles: usize,
) -> Vec<Vec<usize>> {
    let mut secondary = (0..nb_oracles - 1)
        .map(|_| secondary_outcomes_prefix.to_vec())
        .collect::<Vec<Vec<_>>>();
    let mut res = vec![main_outcome_prefix.to_vec()];
    res.append(&mut secondary);
    res
}

/// All combinations of main outcome and other except for the one that contains
/// only main outcome.
fn double_covering_restricted_prefix_combinations(
    main_outcome_prefix: &[usize],
    other_interval_prefix: &[usize],
    nb_oracles: usize,
) -> Vec<Vec<Vec<usize>>> {
    let mut combinations = double_covering_prefix_combinations(
        main_outcome_prefix,
        main_outcome_prefix,
        other_interval_prefix,
        nb_oracles,
    );

    if main_outcome_prefix > other_interval_prefix {
        combinations.remove(combinations.len() - 1);
        combinations
    } else {
        combinations.into_iter().skip(1).collect::<Vec<_>>()
    }
}

/// Generates all the combination of prefixes starting with `main_outcome_prefix`
/// with `left_interval_prefix` and `right_interval_prefix` in lexicographic
/// order.
fn double_covering_prefix_combinations(
    main_outcome_prefix: &[usize],
    left_interval_prefix: &[usize],
    right_interval_prefix: &[usize],
    nb_oracles: usize,
) -> Vec<Vec<Vec<usize>>> {
    let mut res = Vec::with_capacity(nb_oracles);
    let (first, second) = if left_interval_prefix <= right_interval_prefix {
        (left_interval_prefix, right_interval_prefix)
    } else {
        (right_interval_prefix, left_interval_prefix)
    };

    for i in 0..(1 << (nb_oracles - 1)) {
        let mut mid_res = Vec::with_capacity(nb_oracles);
        for j in 0..(nb_oracles - 1) {
            let val: Vec<usize> = match i & (1 << j) {
                0 => first.to_vec(),
                _ => second.to_vec(),
            };
            mid_res.push(val);
        }
        mid_res.push(main_outcome_prefix.to_vec());
        mid_res.reverse();
        res.push(mid_res);
    }

    res
}

/// Compute the outcome combinations required to cover intervals that will
/// satisfy the specified min support and max error parameters.
pub fn compute_outcome_combinations(
    nb_digits: usize,
    main_outcome_prefix: &[usize],
    max_error_exp: usize,
    min_support_exp: usize,
    maximize_coverage: bool,
    nb_oracles: usize,
) -> Vec<Vec<Vec<usize>>> {
    assert!(nb_oracles > 1 && max_error_exp > min_support_exp);

    let max_num: usize = (1 << nb_digits) - 1;
    let max_error: usize = 1 << max_error_exp;
    let half_max_error: usize = max_error >> 1;
    let min_support: usize = 1 << min_support_exp;
    let suffix_len = nb_digits - main_outcome_prefix.len();

    let (start, end) = compute_interval_from_prefix(main_outcome_prefix, nb_digits, 2);

    // interval length is strictly smaller than max_error
    if suffix_len < max_error_exp {
        let start_max_error_suffix = start & ((1 << max_error_exp) - 1);
        let left_bound = (start >> max_error_exp) << max_error_exp;
        let right_bound = left_bound | (max_error - 1);
        let error_interval_prefix = num_to_vec(left_bound, nb_digits, max_error_exp, 2);

        // interval length is less than or equal to min_support
        if start_max_error_suffix >= min_support && end <= right_bound - min_support {
            let support_interval_prefix = if maximize_coverage {
                error_interval_prefix
            } else {
                compute_min_support_covering_prefix(start, end, min_support, nb_digits)
            };

            return vec![single_covering_prefix_combinations(
                main_outcome_prefix,
                &support_interval_prefix,
                nb_oracles,
            )];
        } else if start_max_error_suffix < min_support {
            let right_interval_prefix = if maximize_coverage {
                error_interval_prefix
            } else {
                compute_right_covering_prefix(end, max_error_exp, min_support, nb_digits)
            };

            return if left_bound == 0 {
                vec![single_covering_prefix_combinations(
                    main_outcome_prefix,
                    &right_interval_prefix,
                    nb_oracles,
                )]
            } else {
                let left_interval_prefix = if maximize_coverage {
                    num_to_vec(left_bound - half_max_error, nb_digits, max_error_exp - 1, 2)
                } else {
                    compute_left_covering_prefix(start, max_error_exp, min_support, nb_digits)
                };
                double_covering_prefix_combinations(
                    main_outcome_prefix,
                    &right_interval_prefix,
                    &left_interval_prefix,
                    nb_oracles,
                )
            };
        } else if end > right_bound - min_support {
            let left_interval_prefix = if maximize_coverage {
                error_interval_prefix
            } else {
                compute_left_covering_prefix(start, max_error_exp, min_support, nb_digits)
            };

            return if right_bound == max_num {
                vec![single_covering_prefix_combinations(
                    main_outcome_prefix,
                    &left_interval_prefix,
                    nb_oracles,
                )]
            } else {
                let right_interval_prefix = if maximize_coverage {
                    num_to_vec(right_bound + 1, nb_digits, max_error_exp - 1, 2)
                } else {
                    compute_right_covering_prefix(end, max_error_exp, min_support, nb_digits)
                };

                double_covering_prefix_combinations(
                    &main_outcome_prefix,
                    &left_interval_prefix,
                    &right_interval_prefix,
                    nb_oracles,
                )
            };
        } else {
            unreachable!();
        }
    }

    let mut res = Vec::new();

    if start != 0 {
        let right_interval_prefix = if maximize_coverage {
            num_to_vec(start, nb_digits, max_error_exp - 1, 2)
        } else {
            num_to_vec(start, nb_digits, min_support_exp, 2)
        };

        let left_interval_prefix = if maximize_coverage {
            num_to_vec(start - half_max_error, nb_digits, max_error_exp - 1, 2)
        } else {
            num_to_vec(start - min_support, nb_digits, min_support_exp, 2)
        };

        let mut combination = double_covering_restricted_prefix_combinations(
            &right_interval_prefix,
            &left_interval_prefix,
            nb_oracles,
        );

        res.append(&mut combination);
    }

    res.push(single_covering_prefix_combinations(
        main_outcome_prefix,
        main_outcome_prefix,
        nb_oracles,
    ));

    if end != max_num {
        let right_interval_prefix = if maximize_coverage {
            num_to_vec(end - half_max_error + 1, nb_digits, max_error_exp - 1, 2)
        } else {
            num_to_vec(end - min_support + 1, nb_digits, min_support_exp, 2)
        };

        let left_interval_prefix = if maximize_coverage {
            num_to_vec(end + 1, nb_digits, max_error_exp - 1, 2)
        } else {
            num_to_vec(end + 1, nb_digits, min_support_exp, 2)
        };

        let mut combination = double_covering_restricted_prefix_combinations(
            &right_interval_prefix,
            &left_interval_prefix,
            nb_oracles,
        );
        res.append(&mut combination);
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::rand::{thread_rng, RngCore};

    fn compute_covering_cets_min_and_max(
        nb_digits: usize,
        main_outcome_prefix: &[usize],
        max_error_exp: usize,
        min_support_exp: usize,
    ) -> (Vec<(Vec<usize>, Vec<usize>)>, Vec<(Vec<usize>, Vec<usize>)>) {
        let covering_max = compute_outcome_combinations(
            nb_digits,
            main_outcome_prefix,
            max_error_exp,
            min_support_exp,
            true,
            2,
        );
        let covering_min = compute_outcome_combinations(
            nb_digits,
            main_outcome_prefix,
            max_error_exp,
            min_support_exp,
            false,
            2,
        );

        assert!(covering_max.iter().all(|x| x.len() == 2));
        assert!(covering_min.iter().all(|x| x.len() == 2));

        (
            covering_max
                .into_iter()
                .map(|mut x| (x.remove(0), x.remove(x.len() - 1)))
                .collect(),
            covering_min
                .into_iter()
                .map(|mut x| (x.remove(0), x.remove(x.len() - 1)))
                .collect(),
        )
    }

    struct TestCase {
        main_outcome_prefix: Vec<usize>,
        nb_digits: usize,
        max_error_exp: usize,
        min_support_exp: usize,
        expected_max: Vec<(Vec<usize>, Vec<usize>)>,
        expected_min: Vec<(Vec<usize>, Vec<usize>)>,
    }

    fn outcome_prefixes() -> Vec<Vec<usize>> {
        vec![
            vec![0, 0, 1, 0, 1, 1, 0, 0, 1],
            vec![0, 1, 0, 0, 0, 0, 0, 1, 1],
            vec![0, 1, 1, 1, 1, 1, 0, 1, 0],
            vec![0, 1],
            vec![0, 0, 1],
            vec![1, 1, 1, 1, 1, 1, 1, 1],
            vec![0, 0],
            vec![1, 1],
        ]
    }

    fn prefix(index: usize) -> Vec<usize> {
        outcome_prefixes().remove(index)
    }

    fn test_cases() -> Vec<TestCase> {
        vec![
            TestCase {
                main_outcome_prefix: prefix(0),
                nb_digits: 14,
                max_error_exp: 11,
                min_support_exp: 7,
                expected_max: vec![(prefix(0), vec![0, 0, 1])],
                expected_min: vec![(prefix(0), vec![0, 0, 1, 0, 1])],
            },
            TestCase {
                main_outcome_prefix: prefix(1),
                nb_digits: 13,
                max_error_exp: 11,
                min_support_exp: 7,
                expected_max: vec![(prefix(1), vec![0, 0, 1]), (prefix(1), vec![0, 1])],
                expected_min: vec![
                    (prefix(1), vec![0, 0, 1, 1, 1, 1]),
                    (prefix(1), vec![0, 1, 0, 0, 0]),
                ],
            },
            TestCase {
                main_outcome_prefix: prefix(2),
                nb_digits: 13,
                max_error_exp: 11,
                min_support_exp: 7,
                expected_max: vec![(prefix(2), vec![0, 1]), (prefix(2), vec![1, 0, 0])],
                expected_min: vec![
                    (prefix(2), vec![0, 1, 1, 1, 1]),
                    (prefix(2), vec![1, 0, 0, 0, 0, 0, 0]),
                ],
            },
            TestCase {
                main_outcome_prefix: prefix(3),
                nb_digits: 13,
                max_error_exp: 11,
                min_support_exp: 7,
                expected_max: vec![
                    (vec![0, 1, 0], vec![0, 0, 1]),
                    (prefix(3), prefix(3)),
                    (vec![0, 1, 1], vec![1, 0, 0]),
                ],
                expected_min: vec![
                    (vec![0, 1, 0, 0, 0, 0], vec![0, 0, 1, 1, 1, 1]),
                    (prefix(3), prefix(3)),
                    (vec![0, 1, 1, 1, 1, 1], vec![1, 0, 0, 0, 0, 0]),
                ],
            },
            TestCase {
                main_outcome_prefix: prefix(4),
                nb_digits: 15,
                max_error_exp: 11,
                min_support_exp: 7,
                expected_max: vec![
                    (vec![0, 0, 1, 0, 0], vec![0, 0, 0, 1, 1]),
                    (prefix(4), prefix(4)),
                    (vec![0, 0, 1, 1, 1], vec![0, 1, 0, 0, 0]),
                ],
                expected_min: vec![
                    (vec![0, 0, 1, 0, 0, 0, 0, 0], vec![0, 0, 0, 1, 1, 1, 1, 1]),
                    (prefix(4), prefix(4)),
                    (vec![0, 0, 1, 1, 1, 1, 1, 1], vec![0, 1, 0, 0, 0, 0, 0, 0]),
                ],
            },
            TestCase {
                main_outcome_prefix: prefix(5),
                nb_digits: 13,
                max_error_exp: 11,
                min_support_exp: 7,
                expected_max: vec![(prefix(5), vec![1, 1])],
                expected_min: vec![(prefix(5), vec![1, 1, 1, 1, 1])],
            },
            TestCase {
                main_outcome_prefix: prefix(6),
                nb_digits: 13,
                max_error_exp: 11,
                min_support_exp: 7,
                expected_max: vec![(prefix(6), prefix(6)), (vec![0, 0, 1], vec![0, 1, 0])],
                expected_min: vec![
                    (prefix(6), prefix(6)),
                    (vec![0, 0, 1, 1, 1, 1], vec![0, 1, 0, 0, 0, 0]),
                ],
            },
            TestCase {
                main_outcome_prefix: prefix(7),
                nb_digits: 14,
                max_error_exp: 11,
                min_support_exp: 7,
                expected_max: vec![(vec![1, 1, 0, 0], vec![1, 0, 1, 1]), (prefix(7), prefix(7))],
                expected_min: vec![
                    (vec![1, 1, 0, 0, 0, 0, 0], vec![1, 0, 1, 1, 1, 1, 1]),
                    (prefix(7), prefix(7)),
                ],
            },
        ]
    }

    #[test]
    fn compute_outcome_combination_tests() {
        for case in test_cases() {
            let (max, min) = compute_covering_cets_min_and_max(
                case.nb_digits,
                &case.main_outcome_prefix,
                case.max_error_exp,
                case.min_support_exp,
            );
            assert_eq!(case.expected_max, max);
            assert_eq!(case.expected_min, min);
        }
    }

    #[test]
    fn compute_outcome_three_oracles() {
        let prefix = vec![0, 1, 0];

        let res = compute_outcome_combinations(3, &prefix, 2, 1, true, 3);

        let expected = vec![
            vec![vec![0, 1, 0], vec![0], vec![0]],
            vec![vec![0, 1, 0], vec![0], vec![1, 0]],
            vec![vec![0, 1, 0], vec![1, 0], vec![0]],
            vec![vec![0, 1, 0], vec![1, 0], vec![1, 0]],
        ];

        assert_eq!(res, expected);
    }

    #[test]
    fn multiple_interval_within_bounds() {
        let mut rng = thread_rng();

        let nb_digits = (rng.next_u32() % 29) + 2;
        let nb_digits_used = rng.next_u32() % nb_digits + 1;
        let mut main_outcome_prefix = Vec::with_capacity(nb_digits_used as usize);
        for _ in 0..nb_digits_used {
            main_outcome_prefix.push((rng.next_u32() % 2) as usize);
        }
        let max_error_exp = (rng.next_u32() % (nb_digits - 1)) + 1;
        let min_support_exp = rng.next_u32() % max_error_exp;
        let nb_digits = nb_digits as usize;
        let max_error_exp = max_error_exp as usize;
        let min_support_exp = min_support_exp as usize;
        let max_error = 1 << max_error_exp;
        let min_support = 1 << min_support_exp;
        let max_val = (1 << nb_digits) - 1;

        let (cover_max, cover_min) = compute_covering_cets_min_and_max(
            nb_digits,
            &main_outcome_prefix,
            max_error_exp,
            min_support_exp,
        );

        assert_eq!(cover_min.len(), cover_max.len());
        assert!(cover_min
            .iter()
            .map(|(a, _)| a)
            .zip(cover_max.iter().map(|(a, _)| a))
            .all(|(a, b)| a.iter().zip(b.iter()).all(|(c, d)| c == d)));

        let relevant_primary_prefixes = cover_max.iter().map(|(a, _)| a).collect::<Vec<_>>();
        let (left, right) = compute_interval_from_prefix(&main_outcome_prefix, nb_digits, 2);

        let primary_and_covering_intervals_max: Vec<((usize, usize), (usize, usize))> = cover_max
            .iter()
            .map(|(a, b)| {
                (
                    compute_interval_from_prefix(&a, nb_digits, 2),
                    compute_interval_from_prefix(&b, nb_digits, 2),
                )
            })
            .collect();
        let cover_intervals_min: Vec<(usize, usize)> = cover_max
            .iter()
            .map(|(_, b)| compute_interval_from_prefix(&b, nb_digits, 2))
            .collect();

        for (
            ((primary_left, primary_right), (max_cover_left, max_cover_right)),
            (min_cover_left, min_cover_right),
        ) in primary_and_covering_intervals_max
            .iter()
            .cloned()
            .zip(cover_intervals_min.iter().cloned())
        {
            assert!(max_cover_left <= min_cover_left);
            assert!(max_cover_right <= min_cover_right);

            if primary_left == max_cover_left && primary_right == max_cover_right {
                assert_eq!(min_cover_left, max_cover_left);
                assert_eq!(min_cover_right, max_cover_right);
            }

            let assert_valid_cover = |cover_left: usize, cover_right: usize, max_coverage: bool| {
                if primary_left == cover_left && primary_right == cover_right {
                    return;
                } else if primary_left >= cover_left && primary_right <= cover_right {
                    if max_coverage {
                        assert_eq!(cover_right - cover_left + 1, max_error);
                    } else {
                        let side_to_boundary = std::cmp::max(
                            primary_right % max_error,
                            max_error - (primary_left % max_error),
                        );
                        assert!(cover_right - cover_left + 1 <= 2 * side_to_boundary);
                        assert!(cover_right - cover_left + 1 >= side_to_boundary);
                    }

                    assert!(
                        primary_left - cover_left >= min_support
                            || cover_left == 0
                            || relevant_primary_prefixes.len() == 2
                    );
                    assert!(primary_right - cover_left < max_error);
                    assert!(
                        cover_right - primary_right >= min_support
                            || cover_right == max_val
                            || relevant_primary_prefixes.len() == 2
                    );
                } else {
                    let (most_inner, least_inner, most_outer) = if primary_left <= cover_left {
                        (primary_left, primary_right, cover_right)
                    } else {
                        (primary_right, primary_left, cover_left)
                    };

                    let diff = |x: usize, y: usize| -> usize {
                        if x > y {
                            x - y
                        } else {
                            y - x
                        }
                    };

                    assert!(diff(least_inner, most_outer) >= min_support);
                    assert!(diff(most_inner, most_outer) < max_error);
                }
            };

            assert_valid_cover(max_cover_left, max_cover_right, true);
            assert_valid_cover(min_cover_left, min_cover_right, false);
        }

        let primary_interval = primary_and_covering_intervals_max
            .iter()
            .map(|(a, _)| *a)
            .fold((usize::MAX, 0), |(min, max), (start, end)| {
                (std::cmp::min(min, start), std::cmp::max(max, end))
            });
        assert_eq!(primary_interval, (left, right));

        let (max_cover_interval_left, max_cover_interval_right) =
            primary_and_covering_intervals_max
                .iter()
                .map(|(_, b)| *b)
                .fold((usize::MAX, 0), |(min, max), (start, end)| {
                    (std::cmp::min(min, start), std::cmp::max(max, end))
                });
        let (min_cover_interval_left, min_cover_interval_right) = cover_intervals_min
            .iter()
            .fold((usize::MAX, 0), |(min, max), (start, end)| {
                (std::cmp::min(min, *start), std::cmp::max(max, *end))
            });
        assert!(max_cover_interval_left <= min_cover_interval_left);
        assert!(max_cover_interval_right >= min_cover_interval_right);

        assert!(left - max_cover_interval_left >= min_support || max_cover_interval_left == 0);
        assert!(left - max_cover_interval_left < max_error);
        assert!(
            max_cover_interval_right - right >= min_support || max_cover_interval_right == max_val
        );
        assert!(max_cover_interval_right - right < max_error);

        assert!(left - min_cover_interval_left >= min_support || min_cover_interval_left == 0);
        assert!(left - min_cover_interval_left < max_error);
        assert!(
            min_cover_interval_right - right >= min_support || min_cover_interval_right == max_val
        );
        assert!(min_cover_interval_right - right < max_error);
    }
}
