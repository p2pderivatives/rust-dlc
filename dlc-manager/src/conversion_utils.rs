use crate::contract::{
    accepted_contract::AcceptedContract,
    contract_info::ContractInfo,
    enum_descriptor::EnumDescriptor,
    numerical_descriptor::{DifferenceParams, NumericalDescriptor, NumericalEventInfo},
    offered_contract::OfferedContract,
    signed_contract::SignedContract,
    ContractDescriptor, FundingInputInfo,
};
use crate::payout_curve::{
    HyperbolaPayoutCurvePiece, PayoutFunction, PayoutFunctionPiece, PayoutPoint,
    PolynomialPayoutCurvePiece, RoundingInterval, RoundingIntervals,
};
use bitcoin::{consensus::encode::Decodable, OutPoint, Transaction};
use dlc::{EnumerationPayout, PartyParams, Payout, TxInputInfo};
use dlc_messages::contract_msgs::{
    ContractDescriptor as SerContractDescriptor, ContractDescriptorV0, ContractDescriptorV1,
    ContractInfo as SerContractInfo, ContractInfoInner, ContractInfoV0, ContractInfoV1,
    ContractOutcome, HyperbolaPayoutCurvePiece as SerHyperbolaPayoutCurvePiece,
    PayoutCurvePiece as SerPayoutCurvePiece, PayoutFunction as SerPayoutFunction,
    PayoutFunctionPiece as SerPayoutFunctionPiece, PayoutPoint as SerPayoutPoint,
    PolynomialPayoutCurvePiece as SerPolynomialPayoutCurvePiece,
    RoundingInterval as SerRoundingInterval, RoundingIntervalsV0,
};
use dlc_messages::oracle_msgs::{
    EventDescriptor, OracleInfo as SerOracleInfo, OracleInfoV0, OracleInfoV1, OracleInfoV2,
    OracleParamsV0,
};
use dlc_messages::{
    AcceptDlc, CetAdaptorSignature, CetAdaptorSignatures, FundingInput, OfferDlc, SignDlc,
};
use std::convert::TryFrom;
use std::error;
use std::fmt;

const BITCOIN_CHAINHASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

#[derive(Debug)]
pub enum Error {
    BitcoinEncoding(bitcoin::consensus::encode::Error),
    InvalidParameters,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::BitcoinEncoding(ref e) => write!(f, "Invalid encoding {}", e),
            Error::InvalidParameters => write!(f, "Invalid parameters."),
        }
    }
}
impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
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

impl From<&OfferedContract> for OfferDlc {
    fn from(offered_contract: &OfferedContract) -> OfferDlc {
        OfferDlc {
            contract_flags: 0,
            chain_hash: BITCOIN_CHAINHASH,
            contract_info: offered_contract.into(),
            funding_pubkey: offered_contract.offer_params.fund_pubkey.clone(),
            payout_spk: offered_contract.offer_params.payout_script_pubkey.clone(),
            payout_serial_id: offered_contract.offer_params.payout_serial_id.clone(),
            offer_collateral: offered_contract.offer_params.collateral,
            funding_inputs: offered_contract
                .funding_inputs_info
                .iter()
                .map(|x| x.into())
                .collect(),
            change_spk: offered_contract.offer_params.change_script_pubkey.clone(),
            change_serial_id: offered_contract.offer_params.change_serial_id,
            contract_maturity_bound: offered_contract.contract_maturity_bound,
            contract_timeout: offered_contract.contract_timeout,
            fee_rate_per_vb: offered_contract.fee_rate_per_vb,
            fund_output_serial_id: offered_contract.fund_output_serial_id,
        }
    }
}

pub fn get_tx_input_infos(
    funding_inputs: &[FundingInput],
) -> Result<(Vec<TxInputInfo>, u64), Error> {
    let mut input_amount = 0;
    let mut inputs = Vec::new();

    for fund_input in funding_inputs {
        let tx = Transaction::consensus_decode(&*fund_input.prev_tx)?;
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

impl TryFrom<&OfferDlc> for OfferedContract {
    type Error = Error;

    fn try_from(offer_dlc: &OfferDlc) -> Result<OfferedContract, Error> {
        let contract_info = get_contract_info_and_announcements(offer_dlc)?;

        let (inputs, input_amount) = get_tx_input_infos(&offer_dlc.funding_inputs)?;

        Ok(OfferedContract {
            id: offer_dlc.get_hash().unwrap(),
            is_offer_party: false,
            contract_info,
            offer_params: PartyParams {
                fund_pubkey: offer_dlc.funding_pubkey.clone(),
                change_script_pubkey: offer_dlc.change_spk.clone(),
                change_serial_id: offer_dlc.change_serial_id,
                payout_script_pubkey: offer_dlc.payout_spk.clone(),
                payout_serial_id: offer_dlc.payout_serial_id,
                collateral: offer_dlc.offer_collateral,
                inputs,
                input_amount,
            },
            contract_maturity_bound: offer_dlc.contract_maturity_bound,
            contract_timeout: offer_dlc.contract_timeout,
            fee_rate_per_vb: offer_dlc.fee_rate_per_vb,
            fund_output_serial_id: offer_dlc.fund_output_serial_id,
            funding_inputs_info: offer_dlc.funding_inputs.iter().map(|x| x.into()).collect(),
            total_collateral: offer_dlc.contract_info.get_total_collateral(),
        })
    }
}

fn get_contract_info_and_announcements(offer_dlc: &OfferDlc) -> Result<Vec<ContractInfo>, Error> {
    let mut contract_infos = Vec::new();
    let (total_collateral, inner_contract_infos) = match &offer_dlc.contract_info {
        SerContractInfo::ContractInfoV0(v0) => {
            (v0.total_collateral, vec![v0.contract_info.clone()])
        }
        SerContractInfo::ContractInfoV1(v1) => (v1.total_collateral, v1.contract_infos.clone()),
    };

    for contract_info in inner_contract_infos {
        let (descriptor, oracle_announcements, threshold) = match contract_info.contract_descriptor
        {
            SerContractDescriptor::ContractDescriptorV0(v0) => {
                let outcome_payouts = v0
                    .payouts
                    .iter()
                    .map(|x| EnumerationPayout {
                        outcome: x.outcome.clone(),
                        payout: Payout {
                            offer: x.local_payout,
                            accept: total_collateral - x.local_payout,
                        },
                    })
                    .collect();
                let descriptor = ContractDescriptor::Enum(EnumDescriptor { outcome_payouts });
                let mut threshold = 1;
                let announcements = match contract_info.oracle_info {
                    SerOracleInfo::OracleInfoV0(v0) => vec![v0.oracle_announcement],
                    SerOracleInfo::OracleInfoV1(v1) => {
                        threshold = v1.threshold;
                        v1.oracle_announcements
                    }
                    _ => return Err(Error::InvalidParameters),
                };

                (descriptor, announcements, threshold)
            }
            SerContractDescriptor::ContractDescriptorV1(v1) => {
                let threshold;
                let mut difference_params: Option<DifferenceParams> = None;
                let announcements = match contract_info.oracle_info {
                    SerOracleInfo::OracleInfoV0(v0) => {
                        threshold = 1;
                        vec![v0.oracle_announcement]
                    }
                    SerOracleInfo::OracleInfoV1(v1) => {
                        threshold = v1.threshold;
                        v1.oracle_announcements.clone()
                    }
                    SerOracleInfo::OracleInfoV2(v2) => {
                        threshold = v2.threshold;
                        difference_params = Some(DifferenceParams {
                            max_error_exp: v2.oracle_params.max_error_exp as usize,
                            min_support_exp: v2.oracle_params.min_fail_exp as usize,
                            maximize_coverage: v2.oracle_params.maximize_coverage,
                        });
                        v2.oracle_announcements.clone()
                    }
                };
                if announcements.len() < 1 {
                    return Err(Error::InvalidParameters);
                }
                let info = match &announcements[0].oracle_event.event_descriptor {
                    EventDescriptor::EnumEventDescriptorV0(_) => {
                        return Err(Error::InvalidParameters)
                    }
                    EventDescriptor::DigitDecompositionEventDescriptorV0(d) => NumericalEventInfo {
                        base: d.base as usize,
                        nb_digits: d.nb_digits as usize,
                        unit: d.unit.clone(),
                    },
                };
                let descriptor = ContractDescriptor::Numerical(NumericalDescriptor {
                    payout_function: (&v1.payout_function).into(),
                    rounding_intervals: (&v1.rounding_intervals).into(),
                    info,
                    difference_params,
                });
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

impl From<&OfferedContract> for SerContractInfo {
    fn from(offered_contract: &OfferedContract) -> SerContractInfo {
        let oracle_infos: Vec<SerOracleInfo> = offered_contract.into();
        let mut contract_infos: Vec<ContractInfoInner> = offered_contract
            .contract_info
            .iter()
            .zip(oracle_infos.into_iter())
            .map(|(c, o)| ContractInfoInner {
                contract_descriptor: (&c.contract_descriptor).into(),
                oracle_info: o,
            })
            .collect();
        return if contract_infos.len() == 1 {
            SerContractInfo::ContractInfoV0(ContractInfoV0 {
                total_collateral: offered_contract.total_collateral,
                contract_info: contract_infos.remove(0),
            })
        } else {
            SerContractInfo::ContractInfoV1(ContractInfoV1 {
                total_collateral: offered_contract.total_collateral,
                contract_infos,
            })
        };
    }
}

impl From<&OfferedContract> for Vec<SerOracleInfo> {
    fn from(offered_contract: &OfferedContract) -> Vec<SerOracleInfo> {
        let mut infos = Vec::new();
        for contract_info in &offered_contract.contract_info {
            let announcements = &contract_info.oracle_announcements;
            if announcements.len() == 1 {
                infos.push(SerOracleInfo::OracleInfoV0(OracleInfoV0 {
                    oracle_announcement: announcements[0].clone(),
                }));
            } else {
                match &contract_info.contract_descriptor {
                    ContractDescriptor::Numerical(n) => {
                        if let Some(params) = &n.difference_params {
                            infos.push(SerOracleInfo::OracleInfoV2(OracleInfoV2 {
                                threshold: contract_info.threshold as u16,
                                oracle_announcements: announcements.clone(),
                                oracle_params: OracleParamsV0 {
                                    max_error_exp: params.max_error_exp as u16,
                                    min_fail_exp: params.min_support_exp as u16,
                                    maximize_coverage: params.maximize_coverage,
                                },
                            }));
                            continue;
                        }
                    }
                    _ => {}
                }
                infos.push(SerOracleInfo::OracleInfoV1(OracleInfoV1 {
                    threshold: contract_info.threshold as u16,
                    oracle_announcements: announcements.clone(),
                }))
            }
        }

        infos
    }
}

impl From<&EnumDescriptor> for ContractDescriptorV0 {
    fn from(enum_descriptor: &EnumDescriptor) -> ContractDescriptorV0 {
        let payouts: Vec<ContractOutcome> = enum_descriptor
            .outcome_payouts
            .iter()
            .map(|x| ContractOutcome {
                outcome: x.outcome.clone(),
                local_payout: x.payout.offer,
            })
            .collect();
        ContractDescriptorV0 { payouts }
    }
}

impl From<&NumericalDescriptor> for ContractDescriptorV1 {
    fn from(num_descriptor: &NumericalDescriptor) -> ContractDescriptorV1 {
        ContractDescriptorV1 {
            payout_function: (&num_descriptor.payout_function).into(),
            rounding_intervals: (&num_descriptor.rounding_intervals).into(),
        }
    }
}

impl From<&ContractDescriptor> for SerContractDescriptor {
    fn from(descriptor: &ContractDescriptor) -> SerContractDescriptor {
        match descriptor {
            ContractDescriptor::Enum(e) => SerContractDescriptor::ContractDescriptorV0(e.into()),
            ContractDescriptor::Numerical(n) => {
                SerContractDescriptor::ContractDescriptorV1(n.into())
            }
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
                        left_end_point: left,
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
                        .map(|x| &x.left_end_point)
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
                payout_points: vec![(&piece.left_end_point).into()]
                    .into_iter()
                    .chain(p.payout_points.iter().map(|x| x.into()))
                    .chain(vec![(right_end_point).into()])
                    .collect(),
            })
        }
        SerPayoutCurvePiece::HyperbolaPayoutCurvePiece(h) => {
            PayoutFunctionPiece::HyperbolaPayoutCurvePiece(HyperbolaPayoutCurvePiece {
                left_end_point: (&piece.left_end_point).into(),
                right_end_point: right_end_point.into(),
                use_positive_piece: h.use_positive_piece,
                translate_outcome: h.translate_outcome,
                translate_payout: h.translate_payout,
                a: h.a,
                b: h.b,
                c: h.c,
                d: h.b,
            })
        }
    }
}

impl From<&RoundingIntervals> for RoundingIntervalsV0 {
    fn from(rounding_intervals: &RoundingIntervals) -> RoundingIntervalsV0 {
        let intervals = rounding_intervals
            .intervals
            .iter()
            .map(|x| x.into())
            .collect();
        RoundingIntervalsV0 { intervals }
    }
}

impl From<&RoundingIntervalsV0> for RoundingIntervals {
    fn from(rounding_intervals: &RoundingIntervalsV0) -> RoundingIntervals {
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

impl From<&AcceptedContract> for AcceptDlc {
    fn from(contract: &AcceptedContract) -> AcceptDlc {
        AcceptDlc {
            temporary_contract_id: contract.offered_contract.id,
            accept_collateral: contract.accept_params.collateral,
            funding_pubkey: contract.accept_params.fund_pubkey,
            payout_spk: contract.accept_params.payout_script_pubkey.clone(),
            payout_serial_id: contract.accept_params.payout_serial_id,
            funding_inputs: contract.funding_inputs.iter().map(|x| x.into()).collect(),
            change_spk: contract.accept_params.change_script_pubkey.clone(),
            change_serial_id: contract.accept_params.change_serial_id,
            cet_adaptor_signatures: CetAdaptorSignatures {
                ecdsa_adaptor_signatures: contract
                    .adaptor_signatures
                    .as_ref()
                    .unwrap()
                    .iter()
                    .cloned()
                    .map::<CetAdaptorSignature, _>(|x| CetAdaptorSignature {
                        signature: x,
                    })
                    .collect(),
            },
            refund_signature: contract.accept_refund_signature,
        }
    }
}

impl From<&SignedContract> for SignDlc {
    fn from(contract: &SignedContract) -> SignDlc {
        let contract_id = contract.accepted_contract.get_contract_id();

        SignDlc {
            contract_id,
            cet_adaptor_signatures: CetAdaptorSignatures {
                ecdsa_adaptor_signatures: contract
                    .adaptor_signatures
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|x| CetAdaptorSignature {
                        signature: x.clone(),
                    })
                    .collect(),
            },
            refund_signature: contract.offer_refund_signature.clone(),
            funding_signatures: contract.funding_signatures.clone(),
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

impl From<&DifferenceParams> for OracleParamsV0 {
    fn from(input: &DifferenceParams) -> OracleParamsV0 {
        OracleParamsV0 {
            max_error_exp: input.max_error_exp as u16,
            min_fail_exp: input.min_support_exp as u16,
            maximize_coverage: input.maximize_coverage,
        }
    }
}

impl From<&OracleParamsV0> for DifferenceParams {
    fn from(input: &OracleParamsV0) -> DifferenceParams {
        DifferenceParams {
            max_error_exp: input.max_error_exp as usize,
            min_support_exp: input.min_fail_exp as usize,
            maximize_coverage: input.maximize_coverage,
        }
    }
}
