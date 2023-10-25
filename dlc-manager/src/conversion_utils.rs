use crate::contract::{
    contract_info::ContractInfo,
    enum_descriptor::EnumDescriptor,
    numerical_descriptor::{DifferenceParams, NumericalDescriptor},
    offered_contract::OfferedContract,
    ord_descriptor::{
        OrdDescriptor, OrdEnumDescriptor, OrdNumericalDescriptor, OrdOutcomeDescriptor,
    },
    ContractDescriptor, FundingInputInfo,
};
use crate::payout_curve::{
    HyperbolaPayoutCurvePiece, PayoutFunction, PayoutFunctionPiece, PayoutPoint,
    PolynomialPayoutCurvePiece, RoundingInterval, RoundingIntervals,
};
use bitcoin::{consensus::encode::Decodable, OutPoint, Transaction};
use dlc::{EnumerationPayout, Payout, TxInputInfo};
use dlc_messages::{
    contract_msgs::{
        ContractDescriptor as SerContractDescriptor, ContractInfo as SerContractInfo,
        ContractInfoInner, ContractOutcome, DisjointContractInfo, EnumeratedContractDescriptor,
        HyperbolaPayoutCurvePiece as SerHyperbolaPayoutCurvePiece,
        NumericOutcomeContractDescriptor, PayoutCurvePiece as SerPayoutCurvePiece,
        PayoutFunction as SerPayoutFunction, PayoutFunctionPiece as SerPayoutFunctionPiece,
        PayoutPoint as SerPayoutPoint, PolynomialPayoutCurvePiece as SerPolynomialPayoutCurvePiece,
        RoundingInterval as SerRoundingInterval, RoundingIntervals as SerRoundingIntervals,
        SingleContractInfo,
    },
    oracle_msgs::{EventDescriptor, OracleAnnouncement},
};
use dlc_messages::{
    contract_msgs::{OrdContractDescriptor, OrdEnumContractDescriptor},
    FundingInput,
};
use dlc_messages::{
    contract_msgs::{OrdContractInfo, OrdNumericalContractDescriptor},
    oracle_msgs::{MultiOracleInfo, OracleInfo as SerOracleInfo, OracleParams, SingleOracleInfo},
};
use dlc_trie::OracleNumericInfo;
use std::fmt;

pub(crate) const BITCOIN_CHAINHASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

pub(crate) const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug)]
pub enum Error {
    BitcoinEncoding(bitcoin::consensus::encode::Error),
    InvalidParameters,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::BitcoinEncoding(_) => write!(f, "Invalid encoding"),
            Error::InvalidParameters => write!(f, "Invalid parameters."),
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            Error::BitcoinEncoding(ref e) => Some(e),
            Error::InvalidParameters => None,
        }
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(e: bitcoin::consensus::encode::Error) -> Error {
        Error::BitcoinEncoding(e)
    }
}

pub fn get_tx_input_infos(
    funding_inputs: &[FundingInput],
) -> Result<(Vec<TxInputInfo>, u64), Error> {
    let mut input_amount = 0;
    let mut inputs = Vec::new();

    for fund_input in funding_inputs {
        let tx = Transaction::consensus_decode(&mut fund_input.prev_tx.as_slice())?;
        let vout = fund_input.prev_tx_vout;
        let tx_out = tx
            .output
            .get(vout as usize)
            .ok_or(Error::InvalidParameters)?;
        input_amount += tx_out.value;
        inputs.push(TxInputInfo {
            outpoint: OutPoint {
                txid: tx.txid(),
                vout,
            },
            max_witness_len: 107,
            redeem_script: fund_input.redeem_script.clone(),
            serial_id: fund_input.input_serial_id,
        });
    }

    Ok((inputs, input_amount))
}

pub(crate) fn get_contract_info_and_announcements(
    contract_info: &SerContractInfo,
) -> Result<Vec<ContractInfo>, Error> {
    let mut contract_infos = Vec::new();
    let (total_collateral, inner_contract_infos) = match contract_info {
        SerContractInfo::SingleContractInfo(single) => {
            (single.total_collateral, vec![single.contract_info.clone()])
        }
        SerContractInfo::DisjointContractInfo(disjoint) => {
            (disjoint.total_collateral, disjoint.contract_infos.clone())
        }
        SerContractInfo::OrdContractInfo(o) => {
            let mut threshold = 1;
            let announcements = match &o.oracle_info {
                SerOracleInfo::Single(single) => vec![single.oracle_announcement.clone()],
                SerOracleInfo::Multi(multi) => {
                    threshold = multi.threshold as usize;
                    multi.oracle_announcements.clone()
                }
            };
            return Ok(vec![ContractInfo {
                contract_descriptor: ContractDescriptor::Ord(OrdDescriptor {
                    outcome_descriptor: ord_contract_descriptor_to_ord_outcome_descriptor(
                        &o.contract_descriptor,
                        &o.oracle_info,
                        contract_info.get_total_collateral(),
                    )?,
                    ordinal_sat_point: o.ordinal_sat_point,
                    ordinal_tx: o.ordinal_tx.clone(),
                    refund_offer: o.refund_offer,
                }),
                oracle_announcements: announcements,
                threshold,
            }]);
        }
    };

    for contract_info in inner_contract_infos {
        let (descriptor, oracle_announcements, threshold) = match contract_info.contract_descriptor
        {
            SerContractDescriptor::EnumeratedContractDescriptor(enumerated) => {
                let descriptor =
                    ContractDescriptor::Enum(enumerated_contract_descriptor_to_enum_descriptor(
                        &enumerated,
                        total_collateral,
                    ));
                let mut threshold = 1;
                let announcements = match contract_info.oracle_info {
                    SerOracleInfo::Single(single) => vec![single.oracle_announcement],
                    SerOracleInfo::Multi(multi) => {
                        threshold = multi.threshold;
                        multi.oracle_announcements
                    }
                };

                if announcements
                    .iter()
                    .any(|x| match &x.oracle_event.event_descriptor {
                        EventDescriptor::EnumEvent(_) => false,
                        EventDescriptor::DigitDecompositionEvent(_) => true,
                    })
                {
                    return Err(Error::InvalidParameters);
                }

                (descriptor, announcements, threshold)
            }
            SerContractDescriptor::NumericOutcomeContractDescriptor(numeric) => {
                let (numeric_descriptor, announcements, threshold) =
                    get_numeric_contract_descriptor(&numeric, &contract_info.oracle_info)?;
                let descriptor = ContractDescriptor::Numerical(numeric_descriptor);
                (descriptor, announcements, threshold)
            }
        };
        contract_infos.push(ContractInfo {
            contract_descriptor: descriptor,
            oracle_announcements,
            threshold: threshold as usize,
        });
    }

    Ok(contract_infos)
}

fn get_numeric_contract_descriptor(
    numeric: &NumericOutcomeContractDescriptor,
    oracle_info: &SerOracleInfo,
) -> Result<(NumericalDescriptor, Vec<OracleAnnouncement>, u16), Error> {
    let threshold;
    let mut difference_params: Option<DifferenceParams> = None;
    let announcements = match oracle_info {
        SerOracleInfo::Single(single) => {
            threshold = 1;
            vec![single.oracle_announcement.clone()]
        }
        SerOracleInfo::Multi(multi) => {
            threshold = multi.threshold;
            if let Some(params) = &multi.oracle_params {
                difference_params = Some(DifferenceParams {
                    max_error_exp: params.max_error_exp as usize,
                    min_support_exp: params.min_fail_exp as usize,
                    maximize_coverage: params.maximize_coverage,
                })
            }
            multi.oracle_announcements.clone()
        }
    };
    if announcements.is_empty() {
        return Err(Error::InvalidParameters);
    }
    let expected_base = if let EventDescriptor::DigitDecompositionEvent(d) =
        &announcements[0].oracle_event.event_descriptor
    {
        d.base
    } else {
        return Err(Error::InvalidParameters);
    };

    let nb_digits = announcements
        .iter()
        .map(|x| match &x.oracle_event.event_descriptor {
            EventDescriptor::DigitDecompositionEvent(d) => {
                if d.base == expected_base {
                    Ok(d.nb_digits as usize)
                } else {
                    Err(Error::InvalidParameters)
                }
            }
            _ => Err(Error::InvalidParameters),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let numeric_descriptor = NumericalDescriptor {
        payout_function: (&numeric.payout_function).into(),
        rounding_intervals: (&numeric.rounding_intervals).into(),
        difference_params,
        oracle_numeric_infos: OracleNumericInfo {
            base: expected_base as usize,
            nb_digits,
        },
    };

    Ok((numeric_descriptor, announcements, threshold))
}

impl From<&OfferedContract> for SerContractInfo {
    fn from(offered_contract: &OfferedContract) -> SerContractInfo {
        let oracle_infos: Vec<SerOracleInfo> = offered_contract.into();
        if let ContractDescriptor::Ord(o) = &offered_contract.contract_info[0].contract_descriptor {
            SerContractInfo::OrdContractInfo(OrdContractInfo {
                total_collateral: offered_contract.total_collateral,
                contract_descriptor: (&o.outcome_descriptor).into(),
                ordinal_sat_point: o.ordinal_sat_point,
                ordinal_tx: o.ordinal_tx.clone(),
                refund_offer: o.refund_offer,
                oracle_info: oracle_infos[0].clone(),
            })
        } else {
            let mut contract_infos: Vec<ContractInfoInner> = offered_contract
                .contract_info
                .iter()
                .zip(oracle_infos)
                .map(|(c, o)| ContractInfoInner {
                    contract_descriptor: (&c.contract_descriptor).into(),
                    oracle_info: o,
                })
                .collect();
            if contract_infos.len() == 1 {
                SerContractInfo::SingleContractInfo(SingleContractInfo {
                    total_collateral: offered_contract.total_collateral,
                    contract_info: contract_infos.remove(0),
                })
            } else {
                SerContractInfo::DisjointContractInfo(DisjointContractInfo {
                    total_collateral: offered_contract.total_collateral,
                    contract_infos,
                })
            }
        }
    }
}

impl From<&OrdOutcomeDescriptor> for OrdContractDescriptor {
    fn from(value: &OrdOutcomeDescriptor) -> Self {
        match value {
            OrdOutcomeDescriptor::Enum(e) => {
                OrdContractDescriptor::Enum(OrdEnumContractDescriptor {
                    ord_payouts: e.to_offer_payouts.clone(),
                    descriptor: (&e.descriptor).into(),
                })
            }
            OrdOutcomeDescriptor::Numerical(n) => {
                OrdContractDescriptor::Numerical(OrdNumericalContractDescriptor {
                    to_offer_payouts: n.to_offer_ranges.clone(),
                    descriptor: (&n.descriptor).into(),
                })
            }
        }
    }
}

fn ord_contract_descriptor_to_ord_outcome_descriptor(
    value: &OrdContractDescriptor,
    oracle_info: &SerOracleInfo,
    total_collateral: u64,
) -> Result<OrdOutcomeDescriptor, Error> {
    match value {
        OrdContractDescriptor::Enum(e) => Ok(OrdOutcomeDescriptor::Enum(OrdEnumDescriptor {
            descriptor: enumerated_contract_descriptor_to_enum_descriptor(
                &e.descriptor,
                total_collateral,
            ),
            to_offer_payouts: e.ord_payouts.clone(),
        })),
        OrdContractDescriptor::Numerical(n) => {
            let (numeric_descriptor, _, _) =
                get_numeric_contract_descriptor(&n.descriptor, oracle_info)?;
            Ok(OrdOutcomeDescriptor::Numerical(OrdNumericalDescriptor {
                descriptor: numeric_descriptor,
                to_offer_ranges: n.to_offer_payouts.clone(),
            }))
        }
    }
}

fn enumerated_contract_descriptor_to_enum_descriptor(
    value: &EnumeratedContractDescriptor,
    total_collateral: u64,
) -> EnumDescriptor {
    EnumDescriptor {
        outcome_payouts: value
            .payouts
            .iter()
            .map(|x| EnumerationPayout {
                outcome: x.outcome.clone(),
                payout: Payout {
                    offer: x.offer_payout,
                    accept: total_collateral - x.offer_payout,
                },
            })
            .collect(),
    }
}

impl From<&OfferedContract> for Vec<SerOracleInfo> {
    fn from(offered_contract: &OfferedContract) -> Vec<SerOracleInfo> {
        let mut infos = Vec::new();
        for contract_info in &offered_contract.contract_info {
            let announcements = &contract_info.oracle_announcements;
            if announcements.len() == 1 {
                infos.push(SerOracleInfo::Single(SingleOracleInfo {
                    oracle_announcement: announcements[0].clone(),
                }));
            } else {
                if let ContractDescriptor::Numerical(n) = &contract_info.contract_descriptor {
                    if let Some(params) = &n.difference_params {
                        infos.push(SerOracleInfo::Multi(MultiOracleInfo {
                            threshold: contract_info.threshold as u16,
                            oracle_announcements: announcements.clone(),
                            oracle_params: Some(OracleParams {
                                max_error_exp: params.max_error_exp as u16,
                                min_fail_exp: params.min_support_exp as u16,
                                maximize_coverage: params.maximize_coverage,
                            }),
                        }));
                        continue;
                    }
                }
                infos.push(SerOracleInfo::Multi(MultiOracleInfo {
                    threshold: contract_info.threshold as u16,
                    oracle_announcements: announcements.clone(),
                    oracle_params: None,
                }))
            }
        }

        infos
    }
}

impl From<&EnumDescriptor> for EnumeratedContractDescriptor {
    fn from(enum_descriptor: &EnumDescriptor) -> EnumeratedContractDescriptor {
        let payouts: Vec<ContractOutcome> = enum_descriptor
            .outcome_payouts
            .iter()
            .map(|x| ContractOutcome {
                outcome: x.outcome.clone(),
                offer_payout: x.payout.offer,
            })
            .collect();
        EnumeratedContractDescriptor { payouts }
    }
}

impl From<&NumericalDescriptor> for NumericOutcomeContractDescriptor {
    fn from(num_descriptor: &NumericalDescriptor) -> NumericOutcomeContractDescriptor {
        NumericOutcomeContractDescriptor {
            num_digits: *num_descriptor
                .oracle_numeric_infos
                .nb_digits
                .iter()
                .min()
                .expect("to have at least a value") as u16,
            payout_function: (&num_descriptor.payout_function).into(),
            rounding_intervals: (&num_descriptor.rounding_intervals).into(),
        }
    }
}

impl From<&ContractDescriptor> for SerContractDescriptor {
    fn from(descriptor: &ContractDescriptor) -> SerContractDescriptor {
        match descriptor {
            ContractDescriptor::Enum(e) => {
                SerContractDescriptor::EnumeratedContractDescriptor(e.into())
            }
            ContractDescriptor::Numerical(n) => {
                SerContractDescriptor::NumericOutcomeContractDescriptor(n.into())
            }
            ContractDescriptor::Ord(_) => unimplemented!(),
        }
    }
}

impl From<&PayoutFunction> for SerPayoutFunction {
    fn from(payout_function: &PayoutFunction) -> SerPayoutFunction {
        SerPayoutFunction {
            payout_function_pieces: payout_function
                .payout_function_pieces
                .iter()
                .map(|x| {
                    let (left, piece) = match x {
                        PayoutFunctionPiece::PolynomialPayoutCurvePiece(p) => (
                            (&p.payout_points[0]).into(),
                            SerPayoutCurvePiece::PolynomialPayoutCurvePiece(
                                SerPolynomialPayoutCurvePiece {
                                    payout_points: p
                                        .payout_points
                                        .iter()
                                        .skip(1)
                                        .take(p.payout_points.len() - 2)
                                        .map(|x| x.into())
                                        .collect(),
                                },
                            ),
                        ),
                        PayoutFunctionPiece::HyperbolaPayoutCurvePiece(h) => (
                            (&h.left_end_point).into(),
                            SerPayoutCurvePiece::HyperbolaPayoutCurvePiece(h.into()),
                        ),
                    };
                    SerPayoutFunctionPiece {
                        end_point: left,
                        payout_curve_piece: piece,
                    }
                })
                .collect(),
            last_endpoint: {
                let last_piece = payout_function.payout_function_pieces.last().unwrap();
                match last_piece {
                    PayoutFunctionPiece::PolynomialPayoutCurvePiece(p) => {
                        p.payout_points.last().unwrap().into()
                    }
                    PayoutFunctionPiece::HyperbolaPayoutCurvePiece(h) => {
                        (&h.right_end_point).into()
                    }
                }
            },
        }
    }
}

impl From<&SerPayoutFunction> for PayoutFunction {
    fn from(payout_function: &SerPayoutFunction) -> PayoutFunction {
        PayoutFunction {
            payout_function_pieces: payout_function
                .payout_function_pieces
                .iter()
                .zip(
                    payout_function
                        .payout_function_pieces
                        .iter()
                        .skip(1)
                        .map(|x| &x.end_point)
                        .chain(vec![&payout_function.last_endpoint]),
                )
                .map(|(x, y)| from_ser_payout_function_piece(x, y))
                .collect(),
        }
    }
}

fn from_ser_payout_function_piece(
    piece: &SerPayoutFunctionPiece,
    right_end_point: &SerPayoutPoint,
) -> PayoutFunctionPiece {
    match &piece.payout_curve_piece {
        SerPayoutCurvePiece::PolynomialPayoutCurvePiece(p) => {
            PayoutFunctionPiece::PolynomialPayoutCurvePiece(PolynomialPayoutCurvePiece {
                payout_points: vec![(&piece.end_point).into()]
                    .into_iter()
                    .chain(p.payout_points.iter().map(|x| x.into()))
                    .chain(vec![(right_end_point).into()])
                    .collect(),
            })
        }
        SerPayoutCurvePiece::HyperbolaPayoutCurvePiece(h) => {
            PayoutFunctionPiece::HyperbolaPayoutCurvePiece(HyperbolaPayoutCurvePiece {
                left_end_point: (&piece.end_point).into(),
                right_end_point: right_end_point.into(),
                use_positive_piece: h.use_positive_piece,
                translate_outcome: h.translate_outcome,
                translate_payout: h.translate_payout,
                a: h.a,
                b: h.b,
                c: h.c,
                d: h.d,
            })
        }
    }
}

impl From<&RoundingIntervals> for SerRoundingIntervals {
    fn from(rounding_intervals: &RoundingIntervals) -> SerRoundingIntervals {
        let intervals = rounding_intervals
            .intervals
            .iter()
            .map(|x| x.into())
            .collect();
        SerRoundingIntervals { intervals }
    }
}

impl From<&SerRoundingIntervals> for RoundingIntervals {
    fn from(rounding_intervals: &SerRoundingIntervals) -> RoundingIntervals {
        let intervals = rounding_intervals
            .intervals
            .iter()
            .map(|x| x.into())
            .collect();
        RoundingIntervals { intervals }
    }
}

impl From<&RoundingInterval> for SerRoundingInterval {
    fn from(rounding_interval: &RoundingInterval) -> SerRoundingInterval {
        SerRoundingInterval {
            begin_interval: rounding_interval.begin_interval,
            rounding_mod: rounding_interval.rounding_mod,
        }
    }
}

impl From<&SerRoundingInterval> for RoundingInterval {
    fn from(rounding_interval: &SerRoundingInterval) -> RoundingInterval {
        RoundingInterval {
            begin_interval: rounding_interval.begin_interval,
            rounding_mod: rounding_interval.rounding_mod,
        }
    }
}

impl From<&PayoutPoint> for SerPayoutPoint {
    fn from(payout_point: &PayoutPoint) -> SerPayoutPoint {
        SerPayoutPoint {
            event_outcome: payout_point.event_outcome,
            outcome_payout: payout_point.outcome_payout,
            extra_precision: payout_point.extra_precision,
        }
    }
}

impl From<&SerPayoutPoint> for PayoutPoint {
    fn from(payout_point: &SerPayoutPoint) -> PayoutPoint {
        PayoutPoint {
            event_outcome: payout_point.event_outcome,
            outcome_payout: payout_point.outcome_payout,
            extra_precision: payout_point.extra_precision,
        }
    }
}

impl From<&HyperbolaPayoutCurvePiece> for SerHyperbolaPayoutCurvePiece {
    fn from(piece: &HyperbolaPayoutCurvePiece) -> SerHyperbolaPayoutCurvePiece {
        SerHyperbolaPayoutCurvePiece {
            use_positive_piece: piece.use_positive_piece,
            translate_outcome: piece.translate_outcome,
            translate_payout: piece.translate_payout,
            a: piece.a,
            b: piece.b,
            c: piece.c,
            d: piece.d,
        }
    }
}

impl From<&PolynomialPayoutCurvePiece> for SerPolynomialPayoutCurvePiece {
    fn from(piece: &PolynomialPayoutCurvePiece) -> SerPolynomialPayoutCurvePiece {
        SerPolynomialPayoutCurvePiece {
            payout_points: piece
                .payout_points
                .iter()
                .skip(1)
                .take(piece.payout_points.len() - 2)
                .map(|x| x.into())
                .collect(),
        }
    }
}

impl From<&SerPolynomialPayoutCurvePiece> for PolynomialPayoutCurvePiece {
    fn from(piece: &SerPolynomialPayoutCurvePiece) -> PolynomialPayoutCurvePiece {
        PolynomialPayoutCurvePiece {
            payout_points: piece.payout_points.iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<&FundingInputInfo> for FundingInput {
    fn from(info: &FundingInputInfo) -> FundingInput {
        info.funding_input.clone()
    }
}

impl From<&FundingInput> for FundingInputInfo {
    fn from(input: &FundingInput) -> FundingInputInfo {
        FundingInputInfo {
            funding_input: input.clone(),
            address: None,
        }
    }
}

impl From<&DifferenceParams> for OracleParams {
    fn from(input: &DifferenceParams) -> OracleParams {
        OracleParams {
            max_error_exp: input.max_error_exp as u16,
            min_fail_exp: input.min_support_exp as u16,
            maximize_coverage: input.maximize_coverage,
        }
    }
}

impl From<&OracleParams> for DifferenceParams {
    fn from(input: &OracleParams) -> DifferenceParams {
        DifferenceParams {
            max_error_exp: input.max_error_exp as usize,
            min_support_exp: input.min_fail_exp as usize,
            maximize_coverage: input.maximize_coverage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payout_function_round_trip() {
        let payout_function = PayoutFunction {
            payout_function_pieces: vec![
                PayoutFunctionPiece::PolynomialPayoutCurvePiece(PolynomialPayoutCurvePiece {
                    payout_points: vec![
                        PayoutPoint {
                            event_outcome: 0,
                            outcome_payout: 0,
                            extra_precision: 0,
                        },
                        PayoutPoint {
                            event_outcome: 9,
                            outcome_payout: 0,
                            extra_precision: 0,
                        },
                    ],
                }),
                PayoutFunctionPiece::PolynomialPayoutCurvePiece(PolynomialPayoutCurvePiece {
                    payout_points: vec![
                        PayoutPoint {
                            event_outcome: 9,
                            outcome_payout: 0,
                            extra_precision: 0,
                        },
                        PayoutPoint {
                            event_outcome: 10,
                            outcome_payout: 10,
                            extra_precision: 0,
                        },
                    ],
                }),
                PayoutFunctionPiece::PolynomialPayoutCurvePiece(PolynomialPayoutCurvePiece {
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
                }),
            ],
        };
        let ser_payout_function: SerPayoutFunction = (&payout_function).into();
        let res: PayoutFunction = (&ser_payout_function).into();
        assert_eq!(payout_function, res);
    }
}
