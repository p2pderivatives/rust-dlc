use dlc::Payout;
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use oracle_msgs::OracleInfo;
use utils::{read_f64, read_string, read_vec, write_f64, write_string, write_vec};

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

impl ContractOutcome {
    pub fn get_payout(&self, total_collateral: u64) -> Payout {
        Payout {
            offer: self.local_payout,
            accept: total_collateral - self.local_payout,
        }
    }
}

impl Writeable for ContractOutcome {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_string(&self.outcome, writer)?;

        self.local_payout.write(writer)?;
        Ok(())
    }
}

impl Readable for ContractOutcome {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<ContractOutcome, DecodeError> {
        let outcome = read_string(reader)?;
        let local_payout = Readable::read(reader)?;

        Ok(ContractOutcome {
            outcome,
            local_payout,
        })
    }
}

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

impl_writeable_tlv_based_enum!(ContractInfo, ;
    (0, SingleContractInfo),
    (1, DisjointContractInfo),
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

impl_writeable!(SingleContractInfo, 0, { total_collateral, contract_info });

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

impl Writeable for DisjointContractInfo {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.total_collateral.write(writer)?;
        write_vec(&self.contract_infos, writer)?;
        Ok(())
    }
}

impl Readable for DisjointContractInfo {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<DisjointContractInfo, DecodeError> {
        let total_collateral = Readable::read(reader)?;
        let contract_infos = read_vec(reader)?;

        Ok(DisjointContractInfo {
            total_collateral,
            contract_infos,
        })
    }
}

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

impl_writeable!(ContractInfoInner, 0, { contract_descriptor, oracle_info });

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

impl_writeable_tlv_based_enum!(
    ContractDescriptor, ;
    (0, EnumeratedContractDescriptor),
    (1, NumericOutcomeContractDescriptor)
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

impl Writeable for EnumeratedContractDescriptor {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_vec(&self.payouts, writer)
    }
}

impl Readable for EnumeratedContractDescriptor {
    fn read<R: ::std::io::Read>(
        reader: &mut R,
    ) -> Result<EnumeratedContractDescriptor, DecodeError> {
        let payouts = read_vec(reader)?;

        Ok(EnumeratedContractDescriptor { payouts })
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct NumericOutcomeContractDescriptor {
    pub payout_function: PayoutFunction,
    pub rounding_intervals: RoundingIntervals,
}

impl_writeable!(NumericOutcomeContractDescriptor, 0, { payout_function, rounding_intervals });

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

impl Writeable for PayoutFunction {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_vec(&self.payout_function_pieces, writer)?;
        self.last_endpoint.write(writer)
    }
}

impl Readable for PayoutFunction {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<PayoutFunction, DecodeError> {
        let payout_function_pieces = read_vec(reader)?;
        let last_endpoint = Readable::read(reader)?;

        Ok(PayoutFunction {
            payout_function_pieces,
            last_endpoint,
        })
    }
}

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

impl_writeable!(PayoutFunctionPiece, 0, { left_end_point, payout_curve_piece });

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

impl_writeable_tlv_based_enum!(PayoutCurvePiece,;
  (0, PolynomialPayoutCurvePiece),
  (1, HyperbolaPayoutCurvePiece)
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

impl Writeable for PolynomialPayoutCurvePiece {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_vec(&self.payout_points, writer)
    }
}

impl Readable for PolynomialPayoutCurvePiece {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<PolynomialPayoutCurvePiece, DecodeError> {
        let payout_points = read_vec(reader)?;

        Ok(PolynomialPayoutCurvePiece { payout_points })
    }
}

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

impl_writeable!(PayoutPoint, 8 + 8 + 2, { event_outcome, outcome_payout, extra_precision });

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

impl Writeable for HyperbolaPayoutCurvePiece {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.use_positive_piece.write(writer)?;
        write_f64(self.translate_outcome, writer)?;
        write_f64(self.translate_payout, writer)?;
        write_f64(self.a, writer)?;
        write_f64(self.b, writer)?;
        write_f64(self.c, writer)?;
        write_f64(self.d, writer)?;

        Ok(())
    }
}

impl Readable for HyperbolaPayoutCurvePiece {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<HyperbolaPayoutCurvePiece, DecodeError> {
        let use_positive_piece = Readable::read(reader)?;
        let translate_outcome = read_f64(reader)?;
        let translate_payout = read_f64(reader)?;
        let a = read_f64(reader)?;
        let b = read_f64(reader)?;
        let c = read_f64(reader)?;
        let d = read_f64(reader)?;

        Ok(HyperbolaPayoutCurvePiece {
            use_positive_piece,
            translate_outcome,
            translate_payout,
            a,
            b,
            c,
            d,
        })
    }
}

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

impl_writeable!(RoundingInterval, 8 + 8, { begin_interval, rounding_mod });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct RoundingIntervals {
    pub intervals: Vec<RoundingInterval>,
}

impl Writeable for RoundingIntervals {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_vec(&self.intervals, writer)?;

        Ok(())
    }
}

impl Readable for RoundingIntervals {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<RoundingIntervals, DecodeError> {
        let intervals = read_vec(reader)?;

        Ok(RoundingIntervals { intervals })
    }
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
