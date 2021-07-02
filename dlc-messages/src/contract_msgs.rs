use dlc::Payout;
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Encode;
use lightning::util::ser::{BigSize, Readable, Writeable, Writer};
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

#[derive(Clone)]
pub enum ContractInfo {
    ContractInfoV0(ContractInfoV0),
    ContractInfoV1(ContractInfoV1),
}

impl ContractInfo {
    pub fn get_total_collateral(&self) -> u64 {
        match self {
            ContractInfo::ContractInfoV0(v0) => v0.total_collateral,
            ContractInfo::ContractInfoV1(v1) => v1.total_collateral,
        }
    }
}

impl Writeable for ContractInfo {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        match self {
            ContractInfo::ContractInfoV0(v0) => v0.write(writer),
            ContractInfo::ContractInfoV1(v1) => v1.write(writer),
        }
    }
}

impl Readable for ContractInfo {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<ContractInfo, DecodeError> {
        let message_type = <u16 as Readable>::read(reader)?;
        match message_type {
            ContractInfoV0::TYPE => Ok(ContractInfo::ContractInfoV0(Readable::read(reader)?)),
            ContractInfoV1::TYPE => Ok(ContractInfo::ContractInfoV1(Readable::read(reader)?)),
            _ => Err(DecodeError::UnknownVersion),
        }
    }
}

/// Structure containing the list of outcome of a DLC contract.
#[derive(Clone)]
pub struct ContractInfoV0 {
    pub total_collateral: u64,
    pub contract_info: ContractInfoInner,
}

impl Encode for ContractInfoV0 {
    const TYPE: u16 = 55342;
}

impl Writeable for ContractInfoV0 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.total_collateral.write(writer)?;
        self.contract_info.write(writer)?;

        Ok(())
    }
}

impl Readable for ContractInfoV0 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<ContractInfoV0, DecodeError> {
        let total_collateral = Readable::read(reader)?;
        let contract_info = Readable::read(reader)?;

        Ok(ContractInfoV0 {
            total_collateral,
            contract_info,
        })
    }
}

#[derive(Clone)]
pub struct ContractInfoV1 {
    pub total_collateral: u64,
    pub contract_infos: Vec<ContractInfoInner>,
}

impl Encode for ContractInfoV1 {
    const TYPE: u16 = 55344;
}

impl Writeable for ContractInfoV1 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.total_collateral.write(writer)?;
        write_vec(&self.contract_infos, writer)?;
        Ok(())
    }
}

impl Readable for ContractInfoV1 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<ContractInfoV1, DecodeError> {
        let total_collateral = Readable::read(reader)?;
        let contract_infos = read_vec(reader)?;

        Ok(ContractInfoV1 {
            total_collateral,
            contract_infos,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ContractInfoInner {
    pub contract_descriptor: ContractDescriptor,
    pub oracle_info: OracleInfo,
}

impl Writeable for ContractInfoInner {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.contract_descriptor.write(writer)?;
        self.oracle_info.write(writer)?;
        Ok(())
    }
}

impl Readable for ContractInfoInner {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<ContractInfoInner, DecodeError> {
        let contract_descriptor = Readable::read(reader)?;
        let oracle_info = Readable::read(reader)?;

        Ok(ContractInfoInner {
            contract_descriptor,
            oracle_info,
        })
    }
}

#[derive(Clone, Debug)]
pub enum ContractDescriptor {
    ContractDescriptorV0(ContractDescriptorV0),
    ContractDescriptorV1(ContractDescriptorV1),
}

impl Writeable for ContractDescriptor {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        match self {
            ContractDescriptor::ContractDescriptorV0(v0) => {
                ContractDescriptorV0::TYPE.write(writer)?;
                v0.write(writer)
            }
            ContractDescriptor::ContractDescriptorV1(v1) => {
                ContractDescriptorV1::TYPE.write(writer)?;
                v1.write(writer)
            }
        }
    }
}

impl Readable for ContractDescriptor {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<ContractDescriptor, DecodeError> {
        let payouts = read_vec(reader)?;

        Ok(ContractDescriptor::ContractDescriptorV0(
            ContractDescriptorV0 { payouts },
        ))
    }
}

#[derive(Clone, Debug)]
pub struct ContractDescriptorV0 {
    pub payouts: Vec<ContractOutcome>,
}

impl Encode for ContractDescriptorV0 {
    const TYPE: u16 = 42768;
}

impl Writeable for ContractDescriptorV0 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_vec(&self.payouts, writer)?;

        Ok(())
    }
}

impl Readable for ContractDescriptorV0 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<ContractDescriptorV0, DecodeError> {
        let payouts = read_vec(reader)?;

        Ok(ContractDescriptorV0 { payouts })
    }
}

#[derive(Clone, Debug)]
pub struct ContractDescriptorV1 {
    pub payout_function: PayoutFunction,
    pub rounding_intervals: RoundingIntervalsV0,
}

impl Encode for ContractDescriptorV1 {
    const TYPE: u16 = 42768;
}

impl Writeable for ContractDescriptorV1 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.payout_function.write(writer)?;
        self.rounding_intervals.write(writer)?;

        Ok(())
    }
}

impl Readable for ContractDescriptorV1 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<ContractDescriptorV1, DecodeError> {
        let payout_function = Readable::read(reader)?;
        let rounding_intervals = Readable::read(reader)?;

        Ok(ContractDescriptorV1 {
            payout_function,
            rounding_intervals,
        })
    }
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct PayoutFunctionPiece {
    pub left_end_point: PayoutPoint,
    pub payout_curve_piece: PayoutCurvePiece,
}

impl Writeable for PayoutFunctionPiece {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.left_end_point.write(writer)?;
        self.payout_curve_piece.write(writer)
    }
}

impl Readable for PayoutFunctionPiece {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<PayoutFunctionPiece, DecodeError> {
        let left_end_point = Readable::read(reader)?;
        let payout_curve_piece = Readable::read(reader)?;

        Ok(PayoutFunctionPiece {
            left_end_point,
            payout_curve_piece,
        })
    }
}

#[derive(Clone, Debug)]
pub enum PayoutCurvePiece {
    PolynomialPayoutCurvePiece(PolynomialPayoutCurvePiece),
    HyperbolaPayoutCurvePiece(HyperbolaPayoutCurvePiece),
}

impl Writeable for PayoutCurvePiece {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        match self {
            PayoutCurvePiece::PolynomialPayoutCurvePiece(p) => {
                PolynomialPayoutCurvePiece::TYPE.write(writer)?;
                p.write(writer)
            }
            PayoutCurvePiece::HyperbolaPayoutCurvePiece(h) => {
                HyperbolaPayoutCurvePiece::TYPE.write(writer)?;
                h.write(writer)
            }
        }
    }
}

impl Readable for PayoutCurvePiece {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<PayoutCurvePiece, DecodeError> {
        let message_type = <u16 as Readable>::read(reader)?;
        match message_type {
            PolynomialPayoutCurvePiece::TYPE => Ok(PayoutCurvePiece::PolynomialPayoutCurvePiece(
                Readable::read(reader)?,
            )),
            HyperbolaPayoutCurvePiece::TYPE => Ok(PayoutCurvePiece::HyperbolaPayoutCurvePiece(
                Readable::read(reader)?,
            )),
            _ => Err(DecodeError::UnknownVersion),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PolynomialPayoutCurvePiece {
    pub payout_points: Vec<PayoutPoint>,
}

impl Encode for PolynomialPayoutCurvePiece {
    const TYPE: u16 = 42792;
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

#[derive(Clone, Debug)]
pub struct PayoutPoint {
    pub event_outcome: u64,
    pub outcome_payout: u64,
    pub extra_precision: u16,
}

impl Writeable for PayoutPoint {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        BigSize(self.event_outcome).write(writer)?;
        BigSize(self.outcome_payout).write(writer)?;
        self.extra_precision.write(writer)?;

        Ok(())
    }
}

impl Readable for PayoutPoint {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<PayoutPoint, DecodeError> {
        let event_outcome: BigSize = Readable::read(reader)?;
        let outcome_payout: BigSize = Readable::read(reader)?;
        let extra_precision = Readable::read(reader)?;

        Ok(PayoutPoint {
            event_outcome: event_outcome.0,
            outcome_payout: outcome_payout.0,
            extra_precision,
        })
    }
}

#[derive(Clone, Debug)]
pub struct HyperbolaPayoutCurvePiece {
    pub use_positive_piece: bool,
    pub translate_outcome: f64,
    pub translate_payout: f64,
    pub a: f64,
    pub b: f64,
    pub c: f64,
    pub d: f64,
}

impl Encode for HyperbolaPayoutCurvePiece {
    const TYPE: u16 = 42794;
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

#[derive(Clone, Debug)]
pub struct RoundingInterval {
    pub begin_interval: u64,
    pub rounding_mod: u64,
}

impl Writeable for RoundingInterval {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.begin_interval.write(writer)?;
        self.rounding_mod.write(writer)?;

        Ok(())
    }
}

impl Readable for RoundingInterval {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<RoundingInterval, DecodeError> {
        let begin_interval = Readable::read(reader)?;
        let rounding_mod = Readable::read(reader)?;

        Ok(RoundingInterval {
            begin_interval,
            rounding_mod,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RoundingIntervalsV0 {
    pub intervals: Vec<RoundingInterval>,
}

impl Writeable for RoundingIntervalsV0 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_vec(&self.intervals, writer)?;

        Ok(())
    }
}

impl Readable for RoundingIntervalsV0 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<RoundingIntervalsV0, DecodeError> {
        let intervals = read_vec(reader)?;

        Ok(RoundingIntervalsV0 { intervals })
    }
}

impl RoundingIntervalsV0 {
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
