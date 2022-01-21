//! Structure containing information about contract details.

use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use oracle_msgs::OracleInfo;

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "camelCase")
)]
/// Represents a single outcome of a DLC contract and the associated offer party
/// payout.
pub struct ContractOutcome {
    /// The outcome represented as a string.
    pub outcome: String,
    /// The payout of the local party for the outcome.
    pub local_payout: u64,
}

impl_dlc_writeable!(ContractOutcome, {(outcome, string), (local_payout, writeable)});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains information about the contract outcomes, payouts and oracles.
pub enum ContractInfo {
    /// A contract that is based on a single event.
    SingleContractInfo(SingleContractInfo),
    /// A contract that is based on multiple events.
    DisjointContractInfo(DisjointContractInfo),
}

impl_dlc_writeable_enum!(ContractInfo,
    (0, SingleContractInfo), (1, DisjointContractInfo);;
);

impl ContractInfo {
    /// Returns the total collateral locked inside the contract.
    pub fn get_total_collateral(&self) -> u64 {
        match self {
            ContractInfo::SingleContractInfo(v0) => v0.total_collateral,
            ContractInfo::DisjointContractInfo(v1) => v1.total_collateral,
        }
    }

    /// Return the smallet maturity date amongst all events and oracle announcements
    /// used in the contract.
    pub fn get_closest_maturity_date(&self) -> u32 {
        match self {
            ContractInfo::SingleContractInfo(s) => {
                s.contract_info.oracle_info.get_closest_maturity_date()
            }
            ContractInfo::DisjointContractInfo(d) => d
                .contract_infos
                .iter()
                .map(|x| x.oracle_info.get_closest_maturity_date())
                .min()
                .expect("to have at least one element"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Information for a contract based on a single event.

pub struct SingleContractInfo {
    /// The total collateral locked in the contract.
    pub total_collateral: u64,
    /// Information about the contract outcomes, payout and oracles.
    pub contract_info: ContractInfoInner,
}

impl_dlc_writeable!(SingleContractInfo, { (total_collateral, writeable), (contract_info, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Information for a contract based on a multiple events.
pub struct DisjointContractInfo {
    /// The total collateral locked in the contract.
    pub total_collateral: u64,
    /// Information about the contract outcomes, payout and oracles.
    pub contract_infos: Vec<ContractInfoInner>,
}

impl_dlc_writeable!(DisjointContractInfo, { (total_collateral, writeable), (contract_infos, vec)});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Payout and oracle information for a contract.
pub struct ContractInfoInner {
    /// Payout information for the contract.
    pub contract_descriptor: ContractDescriptor,
    /// Oracle information for the contract.
    pub oracle_info: OracleInfo,
}

impl_dlc_writeable!(ContractInfoInner, { (contract_descriptor, writeable), (oracle_info, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Information about the outcomes and payouts of a contract.
pub enum ContractDescriptor {
    /// Used for contract based on enumerated outcomes.
    EnumeratedContractDescriptor(EnumeratedContractDescriptor),
    /// Used for contract based on numerical outcomes.
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
/// Information about outcomes and payouts for a contract based on enumerated
/// outcome event.
pub struct EnumeratedContractDescriptor {
    /// The payouts for the different outcomes.
    pub payouts: Vec<ContractOutcome>,
}

impl_dlc_writeable!(EnumeratedContractDescriptor, { (payouts, vec) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Information about outcomes and payouts for a contract based on numerical
/// outcome event.
pub struct NumericOutcomeContractDescriptor {
    /// The number of digits used by the oracle with smallest number of digits.
    pub num_digits: u16,
    /// The function representing the payout depending on the outcomes.
    pub payout_function: PayoutFunction,
    /// The rounding intervals to be applied to the payouts.
    pub rounding_intervals: RoundingIntervals,
}

impl_dlc_writeable!(NumericOutcomeContractDescriptor, { (num_digits, writeable), (payout_function, writeable), (rounding_intervals, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Function representing the payouts based on the outcomes of a numerical contract.
pub struct PayoutFunction {
    /// The pieces that make up the function.
    pub payout_function_pieces: Vec<PayoutFunctionPiece>,
    /// The right most point of the function.
    pub last_endpoint: PayoutPoint,
}

impl_dlc_writeable!(PayoutFunction, {(payout_function_pieces, vec), (last_endpoint, writeable)});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// A piece of a [`PayoutFunction`].
pub struct PayoutFunctionPiece {
    /// The left end point of the piece.
    pub end_point: PayoutPoint,
    /// The function describing the curve for this piece.
    pub payout_curve_piece: PayoutCurvePiece,
}

impl_dlc_writeable!(PayoutFunctionPiece, { (end_point, writeable), (payout_curve_piece, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Representations of functions describing the payout curve over a given interval.
pub enum PayoutCurvePiece {
    /// Used for curves represented as polynomial functions.
    PolynomialPayoutCurvePiece(PolynomialPayoutCurvePiece),
    /// Used for curves represented as hyperbola functions.
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
/// A payout curve represented by a polynomial function.
pub struct PolynomialPayoutCurvePiece {
    /// The points to be used to interpolate the polynomial.
    pub payout_points: Vec<PayoutPoint>,
}

impl_dlc_writeable!(PolynomialPayoutCurvePiece, { (payout_points, vec) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// A point on a payout curve.
pub struct PayoutPoint {
    /// The event outcome for this point (X coordinate).
    pub event_outcome: u64,
    /// The payout for this point (Y coordinate).
    pub outcome_payout: u64,
    /// Extra precision to be applied when computing the payout.
    pub extra_precision: u16,
}

impl_dlc_writeable!(PayoutPoint, { (event_outcome, writeable), (outcome_payout, writeable), (extra_precision, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// A payout curve represented as an hyperbola.
pub struct HyperbolaPayoutCurvePiece {
    /// Whether to use the positive or negative piece represented by this
    /// hyperbola.
    pub use_positive_piece: bool,
    /// Parameter to the hyperbola curve.
    pub translate_outcome: f64,
    /// Parameter to the hyperbola curve.
    pub translate_payout: f64,
    /// Parameter to the hyperbola curve.
    pub a: f64,
    /// Parameter to the hyperbola curve.
    pub b: f64,
    /// Parameter to the hyperbola curve.
    pub c: f64,
    /// Parameter to the hyperbola curve.
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
/// Rounding interval to be applied to an interval to increase the set of points
/// with common payouts.
pub struct RoundingInterval {
    /// The beggining of the interval on which to apply the associated rounding.
    pub begin_interval: u64,
    /// The modulus to apply for the rounding.
    pub rounding_mod: u64,
}

impl_dlc_writeable!(RoundingInterval, { (begin_interval, writeable), (rounding_mod, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// A set of [`RoundingInterval`].
pub struct RoundingIntervals {
    /// The intervals to be used to round payouts.
    pub intervals: Vec<RoundingInterval>,
}

impl_dlc_writeable!(RoundingIntervals, { (intervals, vec) });
