//! Utility functions to decompose numeric outcome values

use dlc::{Payout, RangePayout};

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

/// Takes away the common prefix of start and end and returns it.
#[inline]
fn take_prefix(start: &mut Vec<usize>, end: &mut Vec<usize>) -> Vec<usize> {
    if start == end {
        end.clear();
        return core::mem::take(start);
    }
    let mut i = 0;
    while start[i] == end[i] {
        i += 1;
    }

    start.drain(0..i);
    end.drain(0..i).collect()
}

/// Remove the trailing digits of `v` if equal to `to_remove`.
#[inline]
fn remove_tail(v: &mut Vec<usize>, to_remove: usize) {
    while v.len() > 1 && v[v.len() - 1] == to_remove {
        v.pop();
    }
}

/// Returns the set of decomposed prefixes that cover the range [start, end].
///
/// # Panics
///
/// Panics if `start` is greater than `end`.
pub fn group_by_ignoring_digits(
    start: usize,
    end: usize,
    base: usize,
    nb_digits: usize,
) -> Vec<Vec<usize>> {
    assert!(start <= end);

    let mut ds = decompose_value(start, base, nb_digits);
    let mut de = decompose_value(end, base, nb_digits);

    // We take the common prefix of start and end and save it, so we are guaranteed that ds[0] != de[0].
    let prefix = take_prefix(&mut ds, &mut de);

    // If start is all 0 and end is all base - 1, the prefix is enough to cover the interval.
    if (ds.is_empty() && de.is_empty())
        || (ds.iter().all(|x| *x == 0) && de.iter().all(|x| *x == base - 1))
    {
        return vec![prefix];
    }

    // We can remove the trailing 0s from the start and trailing base - 1 from the end
    // as they will be covered the interval represented by the digits in front of them.
    remove_tail(&mut ds, 0);
    remove_tail(&mut de, base - 1);

    // We initialize the stack with the start digits.
    let mut stack = ds.clone();
    let mut list = Vec::new();

    // This will generate all the prefixes for the interval [start, start[0]..base - 1]. E.g.
    // if start is 1234 in base 10, this will generate for [1234, 1999].
    while stack.len() != 1 {
        let i = stack.len() - 1;
        // Once the last digit of the stack is base - 1, we can save the prefix and pop a digit.
        // E.g. if we have our stack as [1, 2, 3, 9], next is [1, 2, 4, 0], but we don't need the last 0
        // as we can cover with [1, 2, 4].
        if stack[i] == base - 1 {
            list.push(stack.clone());
            stack.pop();
            // We can remove any base - 1 digits at this point. E.g. if we had [1, 2, 9, 9] above,
            // now we have [1, 2, 9], next is [1, 3, 0], but similarly as above we can get rid of
            // the trailing zero.
            remove_tail(&mut stack, base - 1);
            // We increment the last digit (e.g. move from [1, 2] to [1, 3] in the example above).
            let j = stack.len() - 1;
            stack[j] += 1;
        } else if stack[i] == 0 {
            // We can always get rid of trailing zeros (up to the first digit). E.g. if we have
            // out stack as [1, 3, 0, 0], [1, 3] is enough to cover the interval
            remove_tail(&mut stack, 0);
        } else {
            // We save the stack an increment the last digit. E.g. if we had [1, 2, 3, 4], we save it
            // and move to [1, 2, 3, 5].
            list.push(stack.clone());
            stack[i] += 1;
        }
        assert!(stack.iter().all(|x| x < &base));
    }

    // All the single digits in ]start[0]; end[0][ are sufficient to cover their respective intervals.
    // E.g. with start = 1234 and end = 4567, 2___ and 3___ are enough to cover between 2000 and 3999.
    while stack[0] != de[0] {
        list.push(stack.clone());
        stack[0] += 1;
    }

    // We take care of the interval [end[0]..0; end]. E.g. if end is 4567 that's [4000; 4567].
    while stack != de {
        let i = stack.len() - 1;
        // If stack has common prefix with end, we need to push a zero. E.g. if stack is [4], we
        // want then have stack as [4, 0], so we will cover [4000; 4499] with (40, 41, 42, 43).
        if stack[i] == de[i] {
            stack.push(0);
        } else {
            // We save the stack and increment the last digit. E.g. if we have [4, 0], we move to [4, 1].
            list.push(stack.clone());
            stack[i] += 1;
        }
    }

    // We need to include end (previous condition exit when stack is equal to end).
    list.push(de);

    // We add the common prefix of start and end if there was one and return our list of prefixes.
    if !prefix.is_empty() {
        list.into_iter()
            .map(|mut x| {
                let mut p = prefix.clone();
                p.append(&mut x);
                p
            })
            .collect()
    } else {
        list
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Amount;
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
                            offer: Amount::ZERO,
                            accept: Amount::from_sat(10),
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 10,
                        payout: Payout {
                            offer: Amount::from_sat(10),
                            accept: Amount::ZERO,
                        },
                    },
                ],
                expected: vec![
                    RangePayout {
                        start: 0,
                        count: 20,
                        payout: Payout {
                            offer: Amount::ZERO,
                            accept: Amount::from_sat(10),
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 80,
                        payout: Payout {
                            offer: Amount::from_sat(10),
                            accept: Amount::ZERO,
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
                        offer: Amount::ZERO,
                        accept: Amount::from_sat(10),
                    },
                }],
                expected: vec![RangePayout {
                    start: 0,
                    count: 100,
                    payout: Payout {
                        offer: Amount::ZERO,
                        accept: Amount::from_sat(10),
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
                            offer: Amount::ZERO,
                            accept: Amount::from_sat(10),
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 10,
                        payout: Payout {
                            offer: Amount::from_sat(10),
                            accept: Amount::ZERO,
                        },
                    },
                ],
                expected: vec![
                    RangePayout {
                        start: 0,
                        count: 20,
                        payout: Payout {
                            offer: Amount::ZERO,
                            accept: Amount::from_sat(10),
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 12,
                        payout: Payout {
                            offer: Amount::from_sat(10),
                            accept: Amount::ZERO,
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
                            offer: Amount::ZERO,
                            accept: Amount::from_sat(10),
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 10,
                        payout: Payout {
                            offer: Amount::from_sat(10),
                            accept: Amount::ZERO,
                        },
                    },
                ],
                expected: vec![
                    RangePayout {
                        start: 0,
                        count: 20,
                        payout: Payout {
                            offer: Amount::ZERO,
                            accept: Amount::from_sat(10),
                        },
                    },
                    RangePayout {
                        start: 20,
                        count: 12,
                        payout: Payout {
                            offer: Amount::from_sat(10),
                            accept: Amount::ZERO,
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
            );
        }
    }

    #[test]
    #[should_panic]
    fn group_by_ignoring_digits_start_greater_than_end_panics() {
        super::group_by_ignoring_digits(11, 10, 2, 4);
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
