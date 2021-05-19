use dlc::{Payout, RangePayout};

#[derive(Clone, Debug)]
pub struct PayoutFunction {
    pub payout_function_pieces: Vec<PayoutFunctionPiece>,
}

impl PayoutFunction {
    pub fn to_range_payouts(
        &self,
        total_collateral: u64,
        rounding_intervals: &RoundingIntervals,
    ) -> Vec<RangePayout> {
        self.payout_function_pieces
            .iter()
            .flat_map(|x| x.to_range_payouts(total_collateral, rounding_intervals))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub enum PayoutFunctionPiece {
    PolynomialPayoutCurvePiece(PolynomialPayoutCurvePiece),
    HyperbolaPayoutCurvePiece(HyperbolaPayoutCurvePiece),
}

impl PayoutFunctionPiece {
    pub fn to_range_payouts(
        &self,
        total_collateral: u64,
        rounding_intervals: &RoundingIntervals,
    ) -> Vec<RangePayout> {
        match &self {
            PayoutFunctionPiece::PolynomialPayoutCurvePiece(p) => {
                p.to_range_payouts(rounding_intervals, total_collateral)
            }
            PayoutFunctionPiece::HyperbolaPayoutCurvePiece(h) => {
                h.to_range_payouts(rounding_intervals, total_collateral)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum PayoutCurvePiece {
    PolynomialPayoutCurvePiece(PolynomialPayoutCurvePiece),
    HyperbolaPayoutCurvePiece(HyperbolaPayoutCurvePiece),
}

#[derive(Clone, Debug)]
pub struct ConstantPayoutCurvePiece {}

impl ConstantPayoutCurvePiece {
    fn to_range_payouts(
        &self,
        left_end_point: &PayoutPoint,
        right_end_point: &PayoutPoint,
        rounding_intervals: &RoundingIntervals,
        total_collateral: u64,
    ) -> Vec<RangePayout> {
        let payout = rounding_intervals.round(
            left_end_point.event_outcome,
            left_end_point.get_outcome_payout(),
        );
        vec![RangePayout {
            start: payout as usize,
            payout: Payout {
                offer: payout,
                accept: total_collateral - payout,
            },
            count: (right_end_point.event_outcome - left_end_point.event_outcome) as usize,
        }]
    }
}

trait Evaluable {
    fn evaluate(&self, outcome: u64) -> f64;

    fn get_rounded_payout(&self, outcome: u64, rounding_intervals: &RoundingIntervals) -> u64 {
        let payout_double = self.evaluate(outcome);
        rounding_intervals.round(outcome, payout_double)
    }

    fn get_first_outcome(&self) -> u64;

    fn get_last_outcome(&self) -> u64;

    fn to_range_payouts(
        &self,
        rounding_intervals: &RoundingIntervals,
        total_collateral: u64,
    ) -> Vec<RangePayout> {
        let mut res = Vec::new();
        let first_outcome = self.get_first_outcome();
        let first_payout = self.get_rounded_payout(first_outcome, rounding_intervals);
        let mut cur_range = RangePayout {
            start: first_outcome as usize,
            count: 1,
            payout: Payout {
                offer: first_payout,
                accept: total_collateral - first_payout,
            },
        };

        for outcome in (first_outcome + 1)..(self.get_last_outcome() + 1) {
            let payout = self.get_rounded_payout(outcome, rounding_intervals);
            if cur_range.payout.offer == payout {
                cur_range.count += 1;
            } else {
                res.push(cur_range);
                cur_range = RangePayout {
                    start: outcome as usize,
                    count: 1,
                    payout: Payout {
                        offer: payout,
                        accept: total_collateral - payout,
                    },
                };
            }
        }

        res.push(cur_range);
        res
    }
}

#[derive(Clone, Debug)]
pub struct PolynomialPayoutCurvePiece {
    pub payout_points: Vec<PayoutPoint>,
}

impl Evaluable for PolynomialPayoutCurvePiece {
    fn evaluate(&self, outcome: u64) -> f64 {
        let nb_points = self.payout_points.len() as usize;
        let mut result = 0.0;
        let outcome = outcome as f64;

        for i in 0..nb_points {
            let mut l = self.payout_points[i].get_outcome_payout() as f64;
            for j in 0..nb_points {
                if i != j {
                    debug_assert!(
                        self.payout_points[i].event_outcome != self.payout_points[j].event_outcome
                    );
                    let i_outcome = self.payout_points[i].event_outcome as f64;
                    let j_outcome = self.payout_points[j].event_outcome as f64;
                    let denominator = i_outcome - j_outcome;
                    let numerator = outcome - j_outcome;
                    l = l * (numerator / denominator);
                }
            }
            result += l;
        }

        result
    }

    fn get_first_outcome(&self) -> u64 {
        self.payout_points[0].event_outcome
    }

    fn get_last_outcome(&self) -> u64 {
        self.payout_points.last().unwrap().event_outcome
    }
}

#[derive(Clone, Debug)]
pub struct PayoutPoint {
    pub event_outcome: u64,
    pub outcome_payout: u64,
    pub extra_precision: u16,
}

impl PayoutPoint {
    fn get_outcome_payout(&self) -> f64 {
        (self.outcome_payout as f64) + ((self.extra_precision as f64) / ((1 << 16) as f64))
    }
}

#[derive(Clone, Debug)]
pub struct HyperbolaPayoutCurvePiece {
    pub left_end_point: PayoutPoint,
    pub right_end_point: PayoutPoint,
    pub use_positive_piece: bool,
    pub translate_outcome: f64,
    pub translate_payout: f64,
    pub a: f64,
    pub b: f64,
    pub c: f64,
    pub d: f64,
}

impl Evaluable for HyperbolaPayoutCurvePiece {
    fn evaluate(&self, outcome: u64) -> f64 {
        let outcome = outcome as f64;
        let translated_outcome = outcome as f64 - self.translate_outcome;
        let sqrt_term_abs_val = (translated_outcome.powi(2) - 4.0 * self.a * self.b).sqrt();
        let sqrt_term = if self.use_positive_piece {
            sqrt_term_abs_val
        } else {
            -sqrt_term_abs_val
        };

        let first_term = self.c * (translated_outcome + sqrt_term) / (2.0 * self.a);
        let second_term = 2.0 * self.a * self.d / (translated_outcome + sqrt_term);
        let value = first_term + second_term + self.translate_payout;

        value
    }

    fn get_first_outcome(&self) -> u64 {
        self.left_end_point.event_outcome
    }
    fn get_last_outcome(&self) -> u64 {
        self.right_end_point.event_outcome
    }
}

#[derive(Clone, Debug)]
pub struct RoundingInterval {
    pub begin_interval: u64,
    pub rounding_mod: u64,
}

#[derive(Clone, Debug)]
pub struct RoundingIntervals {
    pub intervals: Vec<RoundingInterval>,
}

impl RoundingIntervals {
    pub fn round(&self, outcome: u64, payout: f64) -> u64 {
        let rounding_mod = match self
            .intervals
            .binary_search_by(|x| x.begin_interval.cmp(&outcome))
        {
            Ok(index) => self.intervals[index].rounding_mod,
            Err(index) if index != 0 => self.intervals[index - 1].rounding_mod,
            _ => unreachable!(),
        } as f64;

        let m = if payout >= 0.0 {
            payout % rounding_mod
        } else {
            payout % rounding_mod + rounding_mod
        };

        if m >= rounding_mod / 2.0 {
            (payout + rounding_mod - m).round() as u64
        } else {
            (payout - m).round() as u64
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lagrange_interpolate_test() {
        let polynomial = PolynomialPayoutCurvePiece {
            payout_points: vec![
                PayoutPoint {
                    event_outcome: 0,
                    outcome_payout: 1,
                    extra_precision: 0,
                },
                PayoutPoint {
                    event_outcome: 2,
                    outcome_payout: 5,
                    extra_precision: 0,
                },
                PayoutPoint {
                    event_outcome: 4,
                    outcome_payout: 17,
                    extra_precision: 0,
                },
            ],
        };

        assert_eq!(101_f64, polynomial.evaluate(10));
        assert_eq!(10001_f64, polynomial.evaluate(100));
    }

    #[test]
    fn polynomial_to_range_outcome_test() {
        struct TestCase {
            payout_points: Vec<PayoutPoint>,
            expected_len: usize,
            expected_first_start: usize,
            expected_first_payout: u64,
            expected_last_start: usize,
            expected_last_payout: u64,
            total_collateral: u64,
        }
        let test_cases: Vec<TestCase> = vec![
            TestCase {
                payout_points: vec![
                    PayoutPoint {
                        event_outcome: 0,
                        outcome_payout: 0,
                        extra_precision: 0,
                    },
                    PayoutPoint {
                        event_outcome: 20,
                        outcome_payout: 20,
                        extra_precision: 0,
                    },
                ],
                expected_len: 21,
                expected_first_start: 0,
                expected_first_payout: 0,
                expected_last_start: 20,
                expected_last_payout: 20,
                total_collateral: 20,
            },
            TestCase {
                payout_points: vec![
                    PayoutPoint {
                        event_outcome: 10,
                        outcome_payout: 10,
                        extra_precision: 0,
                    },
                    PayoutPoint {
                        event_outcome: 20,
                        outcome_payout: 10,
                        extra_precision: 0,
                    },
                ],
                expected_len: 1,
                expected_first_start: 10,
                expected_first_payout: 10,
                expected_last_start: 10,
                expected_last_payout: 10,
                total_collateral: 10,
            },
        ];

        for test_case in test_cases {
            let polynomial = PolynomialPayoutCurvePiece {
                payout_points: test_case.payout_points,
            };

            let rounding_intervals = RoundingIntervals {
                intervals: vec![RoundingInterval {
                    begin_interval: 0,
                    rounding_mod: 1,
                }],
            };

            let range_payouts =
                polynomial.to_range_payouts(&rounding_intervals, test_case.total_collateral);
            let first = range_payouts.first().unwrap();
            let last = range_payouts.last().unwrap();

            assert_eq!(test_case.expected_len, range_payouts.len());
            assert_eq!(test_case.expected_first_start, first.start);
            assert_eq!(test_case.expected_first_payout, first.payout.offer);
            assert_eq!(test_case.expected_last_start, last.start);
            assert_eq!(test_case.expected_last_payout, last.payout.offer);
        }
    }
}
