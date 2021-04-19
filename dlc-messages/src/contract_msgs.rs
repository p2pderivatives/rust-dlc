use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Encode;
use lightning::util::ser::{Readable, Writeable, Writer};
use oracle_msgs::OracleInfo;
use utils::{read_string, read_vec, write_string, write_vec};

/// Represents a single outcome of a DLC contract and the associated offer party
/// payout.
#[derive(Clone, PartialEq)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "camelCase")
)]
pub struct ContractOutcome {
    pub outcome: String,
    pub local_payout: u64,
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

pub enum ContractInfo {
    ContractInfoV0(ContractInfoV0),
    ContractInfoV1(ContractInfoV1),
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
pub struct ContractInfoV0 {
    total_collateral: u64,
    contract_info: ContractInfoInner,
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

pub struct ContractInfoV1 {
    total_collateral: u64,
    contract_infos: Vec<ContractInfoInner>,
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

pub struct ContractInfoInner {
    contract_descriptor: ContractDescriptor,
    oracle_info: OracleInfo,
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

pub enum ContractDescriptor {
    ContractDescriptorV0(ContractDescriptorV0),
}

impl Writeable for ContractDescriptor {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        match self {
            ContractDescriptor::ContractDescriptorV0(v0) => {
                ContractDescriptorV0::TYPE.write(writer)?;
                v0.write(writer)
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

pub struct ContractDescriptorV0 {
    payouts: Vec<ContractOutcome>,
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
