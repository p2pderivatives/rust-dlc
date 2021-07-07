//! Utility functions to decompose numeric outcome values

use dlc::{Error, Payout, RangePayout};

/// Describes an interval that starts at `prefix || start` and terminates at `prefix || end`.
struct PrefixInterval {
    /// The prefix common to all numbers within the interval.
    prefix: Vec<usize>,
    /// The suffix of the first number in the interval.
    start: Vec<usize>,
    /// The suffix of the last number in the interval.
    end: Vec<usize>,
}

/// Decompose a numeric value into digits in the specified base. If the decomposed
/// value contains less than `nb_digits`, zeroes will be prepended to reach `nb_digits`
/// size.
pub fn decompose_value(mut value: usize, base: usize, nb_digits: usize) -> Vec<usize> {
    let mut res = Vec::new();

    while value > 0 {
        res.push(value % base);
        value = ((value as f64) / (base as f64)).floor() as usize;
    }

    while res.len() < nb_digits {
        res.push(0);
    }

    assert_eq!(nb_digits, res.len());

    res.into_iter().rev().collect()
}

/// Takes a decomposed representation of a numerical value in a given base and returns
/// the represented value as a `usize`
pub fn compose_value(values: &[usize], base: usize) -> usize {
    let mut composed = 0;
    for i in 0..values.len() {
        let pow = values.len() - i - 1;
        composed += values[i] * base.pow(pow as u32);
    }

    composed
}

/// Takes a vector or `RangePayout` and (if necessary) updates the first element
/// to cover the range [0, first_end] where first_end is the end value of the
/// first element, and updates the last element to cover the range
/// [last_start, max_val] where last_start is the start value of the last
/// `RangePayout` in `original_outcomes` and max_val is equal to base^nb_digits - 1.
pub fn pad_range_payouts(
    original_outcomes: Vec<RangePayout>,
    base: usize,
    nb_digits: usize,
) -> Vec<RangePayout> {
    let mut outcomes: Vec<RangePayout> = original_outcomes;
    if outcomes[0].start != 0 {
        outcomes[0] = RangePayout {
            start: 0,
            count: outcomes[0].count + outcomes[0].start,
            payout: Payout {
                offer: outcomes[0].payout.offer,
                accept: outcomes[0].payout.accept,
            },
        };
    }
    let last_index = outcomes.len() - 1;
    let last_outcome = &outcomes[last_index];
    let max_value = base.pow(nb_digits as u32);
    if last_outcome.start + last_outcome.count != max_value {
        outcomes[last_index] = RangePayout {
            start: last_outcome.start,
            count: max_value - last_outcome.start,
            payout: Payout {
                offer: last_outcome.payout.offer,
                accept: last_outcome.payout.accept,
            },
        }
    }

    outcomes
}

/// Returns the interval [start, end] as a `PrefixInterval`, which will contain
/// the common prefix to all numbers in the interval as well as the start and end
/// suffixes decomposed in the specified base, and zero padded to `nb_digits` if
/// necessary.
fn separate_prefix(
    start: usize,
    end: usize,
    base: usize,
    nb_digits: usize,
) -> Result<PrefixInterval, Error> {
    let start_digits = decompose_value(start, base, nb_digits);
    let end_digits = decompose_value(end, base, nb_digits);
    let mut prefix = Vec::new();

    let mut i = 0;
    while i < nb_digits && start_digits[i] == end_digits[i] {
        prefix.push(start_digits[i]);
        i += 1;
    }
    let start = start_digits.into_iter().skip(prefix.len()).collect();

    let end = end_digits.into_iter().skip(prefix.len()).collect();

    Ok(PrefixInterval { prefix, start, end })
}

/// Removes the trailing digits from `digits` that are equal to `num`.
fn remove_tail_if_equal(mut digits: Vec<usize>, num: usize) -> Vec<usize> {
    let mut i = digits.len();
    while i > 1 && digits[i - 1] == num {
        i -= 1;
    }
    digits.truncate(i);
    digits
}

/// Compute the groupings for the end of the interval.
fn back_groupings(digits: Vec<usize>, base: usize) -> Vec<Vec<usize>> {
    let digits = remove_tail_if_equal(digits, base - 1);
    if digits.len() == 0 {
        return vec![vec![base - 1]];
    }
    let mut prefix = vec![digits[0]];
    let mut res: Vec<Vec<usize>> = Vec::new();
    for digit in digits.iter().skip(1) {
        let mut last = 0;
        let digit = digit.clone();
        while last < digit {
            let mut new_res = prefix.clone();
            new_res.push(last);
            res.push(new_res);
            last += 1;
        }
        prefix.push(digit);
    }
    res.push(digits);
    res
}

/// Compute the groupings for the beginning of the interval.
fn front_groupings(digits: Vec<usize>, base: usize) -> Vec<Vec<usize>> {
    let digits = remove_tail_if_equal(digits, 0);
    if digits.len() == 0 {
        return vec![vec![0]];
    }
    let mut prefix = digits.clone();
    let mut res: Vec<Vec<usize>> = vec![digits.clone()];
    for digit in digits.into_iter().skip(1).rev() {
        prefix.pop();
        let mut last = digit + 1;
        while last < base {
            let mut new_res = prefix.clone();
            new_res.push(last);
            res.push(new_res);
            last += 1;
        }
    }

    res
}

/// Compute the groupings for the middle of the interval.
fn middle_grouping(first_digit_start: usize, first_digit_end: usize) -> Vec<Vec<usize>> {
    let mut res: Vec<Vec<usize>> = Vec::new();
    let mut first_digit_start = first_digit_start + 1;
    while first_digit_start < first_digit_end {
        res.push(vec![first_digit_start]);
        first_digit_start += 1;
    }

    res
}

/// Returns the set of decomposed prefixes that cover the range [start, end].
pub fn group_by_ignoring_digits(
    start: usize,
    end: usize,
    base: usize,
    num_digits: usize,
) -> Result<Vec<Vec<usize>>, Error> {
    let prefix_range = separate_prefix(start, end, base, num_digits)?;
    let start_is_all_zeros = prefix_range.start.iter().all(|x| *x == 0);
    let end_is_all_max = prefix_range.end.iter().all(|x| *x == base - 1);

    if start == end || start_is_all_zeros && end_is_all_max && prefix_range.prefix.len() > 0 {
        return Ok(vec![prefix_range.prefix]);
    }
    let mut res: Vec<Vec<usize>> = Vec::new();
    if prefix_range.prefix.len() == num_digits - 1 {
        for i in prefix_range.start[prefix_range.start.len() - 1]
            ..prefix_range.end[prefix_range.end.len() - 1] + 1
        {
            let mut new_res = prefix_range.prefix.clone();
            new_res.push(i);
            res.push(new_res)
        }
    } else {
        let mut front = front_groupings(prefix_range.start.clone(), base);
        let mut middle = middle_grouping(prefix_range.start[0], prefix_range.end[0]);
        let mut back = back_groupings(prefix_range.end.clone(), base);
        res.append(&mut front);
        res.append(&mut middle);
        res.append(&mut back);
        res = res
            .into_iter()
            .map(|x| {
                prefix_range
                    .prefix
                    .iter()
                    .cloned()
                    .chain(x.into_iter())
                    .collect()
            })
            .collect();
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use dlc::{Payout, RangePayout};
    struct DecompositionTestCase {
        composed: usize,
        decomposed: Vec<usize>,
        base: usize,
        nb_digits: usize,
    }

    struct GroupingTestCase {
        start_index: usize,
        end_index: usize,
        base: usize,
        nb_digits: usize,
        expected: Vec<Vec<usize>>,
    }
    struct SetMaxRangeTestCase {
        original: Vec<RangePayout>,
        expected: Vec<RangePayout>,
        base: usize,
        nb_digits: usize,
    }

    fn decomposition_test_cases() -> Vec<DecompositionTestCase> {
        vec![
            DecompositionTestCase {
                composed: 123456789,
                decomposed: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
                base: 10,
                nb_digits: 9,
            },
            DecompositionTestCase {
                composed: 4321,
                decomposed: vec![1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1],
                base: 2,
                nb_digits: 13,
            },
            DecompositionTestCase {
                composed: 0,
                decomposed: vec![0, 0, 0, 0],
                base: 8,
                nb_digits: 4,
            },
            DecompositionTestCase {
                composed: 2,
                decomposed: vec![0, 2],
                base: 10,
                nb_digits: 2,
            },
            DecompositionTestCase {
                composed: 1,
                decomposed: vec![1],
                base: 2,
                nb_digits: 1,
            },
        ]
    }

    fn grouping_test_cases() -> Vec<GroupingTestCase> {
        vec![
            GroupingTestCase {
                start_index: 123,
                end_index: 123,
                base: 10,
                nb_digits: 3,
                expected: vec![vec![1, 2, 3]],
            },
            GroupingTestCase {
                start_index: 171,
                end_index: 210,
                base: 16,
                nb_digits: 2,
                expected: vec![
                    vec![10, 11],
                    vec![10, 12],
                    vec![10, 13],
                    vec![10, 14],
                    vec![10, 15],
                    vec![11],
                    vec![12],
                    vec![13, 0],
                    vec![13, 1],
                    vec![13, 2],
                ],
            },
            GroupingTestCase {
                start_index: 73899,
                end_index: 73938,
                base: 16,
                nb_digits: 6,
                expected: vec![
                    vec![0, 1, 2, 0, 10, 11],
                    vec![0, 1, 2, 0, 10, 12],
                    vec![0, 1, 2, 0, 10, 13],
                    vec![0, 1, 2, 0, 10, 14],
                    vec![0, 1, 2, 0, 10, 15],
                    vec![0, 1, 2, 0, 11],
                    vec![0, 1, 2, 0, 12],
                    vec![0, 1, 2, 0, 13, 0],
                    vec![0, 1, 2, 0, 13, 1],
                    vec![0, 1, 2, 0, 13, 2],
                ],
            },
            GroupingTestCase {
                start_index: 1234,
                end_index: 4321,
                base: 10,
                nb_digits: 4,
                expected: vec![
                    vec![1, 2, 3, 4],
                    vec![1, 2, 3, 5],
                    vec![1, 2, 3, 6],
                    vec![1, 2, 3, 7],
                    vec![1, 2, 3, 8],
                    vec![1, 2, 3, 9],
                    vec![1, 2, 4],
                    vec![1, 2, 5],
                    vec![1, 2, 6],
                    vec![1, 2, 7],
                    vec![1, 2, 8],
                    vec![1, 2, 9],
                    vec![1, 3],
                    vec![1, 4],
                    vec![1, 5],
                    vec![1, 6],
                    vec![1, 7],
                    vec![1, 8],
                    vec![1, 9],
                    vec![2],
                    vec![3],
                    vec![4, 0],
                    vec![4, 1],
                    vec![4, 2],
                    vec![4, 3, 0],
                    vec![4, 3, 1],
                    vec![4, 3, 2, 0],
                    vec![4, 3, 2, 1],
                ],
            },
            GroupingTestCase {
                start_index: 1201234,
                end_index: 1204321,
                base: 10,
                nb_digits: 8,
                expected: vec![
                    vec![0, 1, 2, 0, 1, 2, 3, 4],
                    vec![0, 1, 2, 0, 1, 2, 3, 5],
                    vec![0, 1, 2, 0, 1, 2, 3, 6],
                    vec![0, 1, 2, 0, 1, 2, 3, 7],
                    vec![0, 1, 2, 0, 1, 2, 3, 8],
                    vec![0, 1, 2, 0, 1, 2, 3, 9],
                    vec![0, 1, 2, 0, 1, 2, 4],
                    vec![0, 1, 2, 0, 1, 2, 5],
                    vec![0, 1, 2, 0, 1, 2, 6],
                    vec![0, 1, 2, 0, 1, 2, 7],
                    vec![0, 1, 2, 0, 1, 2, 8],
                    vec![0, 1, 2, 0, 1, 2, 9],
                    vec![0, 1, 2, 0, 1, 3],
                    vec![0, 1, 2, 0, 1, 4],
                    vec![0, 1, 2, 0, 1, 5],
                    vec![0, 1, 2, 0, 1, 6],
                    vec![0, 1, 2, 0, 1, 7],
                    vec![0, 1, 2, 0, 1, 8],
                    vec![0, 1, 2, 0, 1, 9],
                    vec![0, 1, 2, 0, 2],
                    vec![0, 1, 2, 0, 3],
                    vec![0, 1, 2, 0, 4, 0],
                    vec![0, 1, 2, 0, 4, 1],
                    vec![0, 1, 2, 0, 4, 2],
                    vec![0, 1, 2, 0, 4, 3, 0],
                    vec![0, 1, 2, 0, 4, 3, 1],
                    vec![0, 1, 2, 0, 4, 3, 2, 0],
                    vec![0, 1, 2, 0, 4, 3, 2, 1],
                ],
            },
            GroupingTestCase {
                start_index: 2200,
                end_index: 4999,
                base: 10,
                nb_digits: 4,
                expected: vec![
                    vec![2, 2],
                    vec![2, 3],
                    vec![2, 4],
                    vec![2, 5],
                    vec![2, 6],
                    vec![2, 7],
                    vec![2, 8],
                    vec![2, 9],
                    vec![3],
                    vec![4],
                ],
            },
            GroupingTestCase {
                start_index: 0,
                end_index: 99,
                base: 10,
                nb_digits: 2,
                expected: vec![
                    vec![0],
                    vec![1],
                    vec![2],
                    vec![3],
                    vec![4],
                    vec![5],
                    vec![6],
                    vec![7],
                    vec![8],
                    vec![9],
                ],
            },
            GroupingTestCase {
                start_index: 100,
                end_index: 199,
                base: 10,
                nb_digits: 3,
                expected: vec![vec![1]],
            },
            GroupingTestCase {
                start_index: 100,
                end_index: 200,
                base: 10,
                nb_digits: 3,
                expected: vec![vec![1], vec![2, 0, 0]],
            },
            GroupingTestCase {
                start_index: 11,
                end_index: 18,
                base: 10,
                nb_digits: 2,
                expected: vec![
                    vec![1, 1],
                    vec![1, 2],
                    vec![1, 3],
                    vec![1, 4],
                    vec![1, 5],
                    vec![1, 6],
                    vec![1, 7],
                    vec![1, 8],
                ],
            },
            GroupingTestCase {
                start_index: 11,
                end_index: 23,
                base: 2,
                nb_digits: 5,
                expected: vec![vec![0, 1, 0, 1, 1], vec![0, 1, 1], vec![1, 0]],
            },
            GroupingTestCase {
                start_index: 5677,
                end_index: 8621,
                base: 2,
                nb_digits: 14,
                expected: vec![
                    vec![0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1],
                    vec![0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1],
                    vec![0, 1, 0, 1, 1, 0, 0, 0, 1, 1],
                    vec![0, 1, 0, 1, 1, 0, 0, 1],
                    vec![0, 1, 0, 1, 1, 0, 1],
                    vec![0, 1, 0, 1, 1, 1],
                    vec![0, 1, 1],
                    vec![1, 0, 0, 0, 0, 0],
                    vec![1, 0, 0, 0, 0, 1, 0],
                    vec![1, 0, 0, 0, 0, 1, 1, 0, 0],
                    vec![1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0],
                    vec![1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0],
                    vec![1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0],
                ],
            },
        ]
    }

    fn get_max_range_test_cases() -> Vec<SetMaxRangeTestCase> {
        vec![
            SetMaxRangeTestCase {
                original: vec![
                    RangePayout {
                        start: 10,
                        count: 10,
                        payout: Payout {
                            offer: 0,
                            accept: 10,
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 10,
                        payout: Payout {
                            offer: 10,
                            accept: 0,
                        },
                    },
                ],
                expected: vec![
                    RangePayout {
                        start: 0,
                        count: 20,
                        payout: Payout {
                            offer: 0,
                            accept: 10,
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 80,
                        payout: Payout {
                            offer: 10,
                            accept: 0,
                        },
                    },
                ],
                base: 10,
                nb_digits: 2,
            },
            SetMaxRangeTestCase {
                original: vec![RangePayout {
                    start: 10,
                    count: 50,
                    payout: Payout {
                        offer: 0,
                        accept: 10,
                    },
                }],
                expected: vec![RangePayout {
                    start: 0,
                    count: 100,
                    payout: Payout {
                        offer: 0,
                        accept: 10,
                    },
                }],
                base: 10,
                nb_digits: 2,
            },
            SetMaxRangeTestCase {
                original: vec![
                    RangePayout {
                        start: 10,
                        count: 10,
                        payout: Payout {
                            offer: 0,
                            accept: 10,
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 10,
                        payout: Payout {
                            offer: 10,
                            accept: 0,
                        },
                    },
                ],
                expected: vec![
                    RangePayout {
                        start: 0,
                        count: 20,
                        payout: Payout {
                            offer: 0,
                            accept: 10,
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 12,
                        payout: Payout {
                            offer: 10,
                            accept: 0,
                        },
                    },
                ],
                base: 2,
                nb_digits: 5,
            },
            SetMaxRangeTestCase {
                original: vec![
                    RangePayout {
                        start: 0,
                        count: 20,
                        payout: Payout {
                            offer: 0,
                            accept: 10,
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 10,
                        payout: Payout {
                            offer: 10,
                            accept: 0,
                        },
                    },
                ],
                expected: vec![
                    RangePayout {
                        start: 0,
                        count: 20,
                        payout: Payout {
                            offer: 0,
                            accept: 10,
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 12,
                        payout: Payout {
                            offer: 10,
                            accept: 0,
                        },
                    },
                ],
                base: 2,
                nb_digits: 5,
            },
        ]
    }

    #[test]
    fn compose_value_test() {
        for test_case in decomposition_test_cases() {
            assert_eq!(
                test_case.composed,
                super::compose_value(&test_case.decomposed, test_case.base)
            );
        }
    }

    #[test]
    fn decompose_value_test() {
        for test_case in decomposition_test_cases() {
            assert_eq!(
                test_case.decomposed,
                super::decompose_value(test_case.composed, test_case.base, test_case.nb_digits)
            );
        }
    }

    #[test]
    fn group_by_ignoring_digits_test() {
        for test_case in grouping_test_cases() {
            assert_eq!(
                test_case.expected,
                super::group_by_ignoring_digits(
                    test_case.start_index,
                    test_case.end_index,
                    test_case.base,
                    test_case.nb_digits
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn get_max_ranges_test() {
        for test_case in get_max_range_test_cases() {
            assert_eq!(
                test_case.expected,
                super::pad_range_payouts(test_case.original, test_case.base, test_case.nb_digits)
            );
        }
    }
}
