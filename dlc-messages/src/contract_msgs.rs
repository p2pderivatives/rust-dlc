use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use oracle_msgs::OracleInfo;

/// Represents a single outcome of a DLC contract and the associated offer party
/// payout.
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "camelCase")
)]
pub struct ContractOutcome {
    pub outcome: String,
    pub local_payout: u64,
}

impl_dlc_writeable!(ContractOutcome, {(outcome, string), (local_payout, writeable)});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum ContractInfo {
    SingleContractInfo(SingleContractInfo),
    DisjointContractInfo(DisjointContractInfo),
}

impl_dlc_writeable_enum!(ContractInfo,
    (0, SingleContractInfo), (1, DisjointContractInfo);;
);

impl ContractInfo {
    pub fn get_total_collateral(&self) -> u64 {
        match self {
            ContractInfo::SingleContractInfo(v0) => v0.total_collateral,
            ContractInfo::DisjointContractInfo(v1) => v1.total_collateral,
        }
    }
}

/// Structure containing the list of outcome of a DLC contract.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SingleContractInfo {
    pub total_collateral: u64,
    pub contract_info: ContractInfoInner,
}

impl_dlc_writeable!(SingleContractInfo, { (total_collateral, writeable), (contract_info, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct DisjointContractInfo {
    pub total_collateral: u64,
    pub contract_infos: Vec<ContractInfoInner>,
}

impl_dlc_writeable!(DisjointContractInfo, { (total_collateral, writeable), (contract_infos, vec)});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct ContractInfoInner {
    pub contract_descriptor: ContractDescriptor,
    pub oracle_info: OracleInfo,
}

impl_dlc_writeable!(ContractInfoInner, { (contract_descriptor, writeable), (oracle_info, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum ContractDescriptor {
    EnumeratedContractDescriptor(EnumeratedContractDescriptor),
    NumericOutcomeContractDescriptor(NumericOutcomeContractDescriptor),
}

impl_dlc_writeable_enum!(
    ContractDescriptor, (0, EnumeratedContractDescriptor), (1, NumericOutcomeContractDescriptor);;
);

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct EnumeratedContractDescriptor {
    pub payouts: Vec<ContractOutcome>,
}

impl_dlc_writeable!(EnumeratedContractDescriptor, { (payouts, vec) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct NumericOutcomeContractDescriptor {
    pub num_digits: u16,
    pub payout_function: PayoutFunction,
    pub rounding_intervals: RoundingIntervals,
}

impl_dlc_writeable!(NumericOutcomeContractDescriptor, { (num_digits, writeable), (payout_function, writeable), (rounding_intervals, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct PayoutFunction {
    pub payout_function_pieces: Vec<PayoutFunctionPiece>,
    pub last_endpoint: PayoutPoint,
}

impl_dlc_writeable!(PayoutFunction, {(payout_function_pieces, vec), (last_endpoint, writeable)});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct PayoutFunctionPiece {
    pub left_end_point: PayoutPoint,
    pub payout_curve_piece: PayoutCurvePiece,
}

impl_dlc_writeable!(PayoutFunctionPiece, { (left_end_point, writeable), (payout_curve_piece, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum PayoutCurvePiece {
    PolynomialPayoutCurvePiece(PolynomialPayoutCurvePiece),
    HyperbolaPayoutCurvePiece(HyperbolaPayoutCurvePiece),
}

impl_dlc_writeable_enum!(PayoutCurvePiece,
  (0, PolynomialPayoutCurvePiece),
  (1, HyperbolaPayoutCurvePiece);;
);

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct PolynomialPayoutCurvePiece {
    pub payout_points: Vec<PayoutPoint>,
}

impl_dlc_writeable!(PolynomialPayoutCurvePiece, { (payout_points, vec) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct PayoutPoint {
    pub event_outcome: u64,
    pub outcome_payout: u64,
    pub extra_precision: u16,
}

impl_dlc_writeable!(PayoutPoint, { (event_outcome, writeable), (outcome_payout, writeable), (extra_precision, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct HyperbolaPayoutCurvePiece {
    pub use_positive_piece: bool,
    pub translate_outcome: f64,
    pub translate_payout: f64,
    pub a: f64,
    pub b: f64,
    pub c: f64,
    pub d: f64,
}

impl_dlc_writeable!(HyperbolaPayoutCurvePiece, {
    (use_positive_piece, writeable),
    (translate_outcome, float),
    (translate_payout, float),
    (a, float),
    (b, float),
    (c, float),
    (d, float)
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct RoundingInterval {
    pub begin_interval: u64,
    pub rounding_mod: u64,
}

impl_dlc_writeable!(RoundingInterval, { (begin_interval, writeable), (rounding_mod, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct RoundingIntervals {
    pub intervals: Vec<RoundingInterval>,
}

impl_dlc_writeable!(RoundingIntervals, { (intervals, vec) });
