use dlc::OracleInfo as DlcOracleInfo;
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Encode;
use lightning::util::ser::{BigSize, Readable, Writeable, Writer};
use secp256k1::schnorrsig::{PublicKey as SchnorrPublicKey, Signature as SchnorrSignature};
use utils::{read_string, read_strings, read_vec, write_string, write_strings, write_vec};

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum OracleInfo {
    OracleInfoV0(OracleInfoV0),
    OracleInfoV1(OracleInfoV1),
    OracleInfoV2(OracleInfoV2),
}

impl<'a> OracleInfo {
    pub fn get_first_event_descriptor(&'a self) -> &'a EventDescriptor {
        match self {
            OracleInfo::OracleInfoV0(v0) => &v0.oracle_announcement.oracle_event.event_descriptor,
            OracleInfo::OracleInfoV1(v1) => {
                &v1.oracle_announcements[0].oracle_event.event_descriptor
            }
            OracleInfo::OracleInfoV2(v2) => {
                &v2.oracle_announcements[0].oracle_event.event_descriptor
            }
        }
    }
}

impl Writeable for OracleInfo {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        match self {
            OracleInfo::OracleInfoV0(oracle_info) => oracle_info.write(writer),
            OracleInfo::OracleInfoV1(oracle_info) => oracle_info.write(writer),
            OracleInfo::OracleInfoV2(oracle_info) => oracle_info.write(writer),
        }
    }
}

impl Readable for OracleInfo {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleInfo, DecodeError> {
        let message_type = <u16 as Readable>::read(reader)?;
        match message_type {
            OracleInfoV0::TYPE => Ok(OracleInfo::OracleInfoV0(Readable::read(reader)?)),
            OracleInfoV1::TYPE => Ok(OracleInfo::OracleInfoV1(Readable::read(reader)?)),
            OracleInfoV2::TYPE => Ok(OracleInfo::OracleInfoV2(Readable::read(reader)?)),
            _ => Err(DecodeError::UnknownVersion),
        }
    }
}

/// Structure containing information about an oracle to be used as external
/// data source for a DLC contract.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OracleInfoV0 {
    pub oracle_announcement: OracleAnnouncement,
}

impl Encode for OracleInfoV0 {
    const TYPE: u16 = 42770;
}

impl Writeable for OracleInfoV0 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.oracle_announcement.write(writer)?;
        Ok(())
    }
}

impl Readable for OracleInfoV0 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleInfoV0, DecodeError> {
        let oracle_announcement = Readable::read(reader)?;

        Ok(OracleInfoV0 {
            oracle_announcement,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OracleInfoV1 {
    pub threshold: u16,
    pub oracle_announcements: Vec<OracleAnnouncement>,
}

impl Encode for OracleInfoV1 {
    const TYPE: u16 = 42786;
}

impl Writeable for OracleInfoV1 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.threshold.write(writer)?;
        write_vec(&self.oracle_announcements, writer)?;
        Ok(())
    }
}

impl Readable for OracleInfoV1 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleInfoV1, DecodeError> {
        let threshold: u16 = Readable::read(reader)?;
        let oracle_announcements = read_vec(reader)?;

        Ok(OracleInfoV1 {
            threshold,
            oracle_announcements,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OracleInfoV2 {
    pub threshold: u16,
    pub oracle_announcements: Vec<OracleAnnouncement>,
    pub oracle_params: OracleParamsV0,
}

impl Encode for OracleInfoV2 {
    const TYPE: u16 = 55340;
}

impl Writeable for OracleInfoV2 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.threshold.write(writer)?;
        write_vec(&self.oracle_announcements, writer)?;
        self.oracle_params.write(writer)?;
        Ok(())
    }
}

impl Readable for OracleInfoV2 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleInfoV2, DecodeError> {
        let threshold: u16 = Readable::read(reader)?;
        let oracle_announcements = read_vec(reader)?;
        let oracle_params: OracleParamsV0 = Readable::read(reader)?;

        Ok(OracleInfoV2 {
            threshold,
            oracle_announcements,
            oracle_params,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OracleParamsV0 {
    pub max_error_exp: u16,
    pub min_fail_exp: u16,
    pub maximize_coverage: bool,
}

impl Encode for OracleParamsV0 {
    const TYPE: u16 = 55338;
}

impl Writeable for OracleParamsV0 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.max_error_exp.write(writer)?;
        self.min_fail_exp.write(writer)?;
        self.maximize_coverage.write(writer)?;
        Ok(())
    }
}

impl Readable for OracleParamsV0 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleParamsV0, DecodeError> {
        let max_error_exp: u16 = Readable::read(reader)?;
        let min_fail_exp: u16 = Readable::read(reader)?;
        let maximize_coverage: bool = Readable::read(reader)?;

        Ok(OracleParamsV0 {
            max_error_exp,
            min_fail_exp,
            maximize_coverage,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OracleAnnouncement {
    pub announcement_signature: SchnorrSignature,
    pub oracle_public_key: SchnorrPublicKey,
    pub oracle_event: OracleEventV0,
}

impl Encode for OracleAnnouncement {
    const TYPE: u16 = 55332;
}

impl Writeable for OracleAnnouncement {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.announcement_signature.write(writer)?;
        self.oracle_public_key.write(writer)?;
        self.oracle_event.write(writer)?;
        Ok(())
    }
}

impl Readable for OracleAnnouncement {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleAnnouncement, DecodeError> {
        let announcement_signature: SchnorrSignature = Readable::read(reader)?;
        let oracle_public_key: SchnorrPublicKey = Readable::read(reader)?;
        let oracle_event: OracleEventV0 = Readable::read(reader)?;

        Ok(OracleAnnouncement {
            announcement_signature,
            oracle_public_key,
            oracle_event,
        })
    }
}

impl From<&OracleAnnouncement> for DlcOracleInfo {
    fn from(input: &OracleAnnouncement) -> DlcOracleInfo {
        DlcOracleInfo {
            public_key: input.oracle_public_key,
            nonces: input.oracle_event.oracle_nonces.clone(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OracleEventV0 {
    pub oracle_nonces: Vec<SchnorrPublicKey>,
    pub event_maturity_epoch: u32,
    pub event_descriptor: EventDescriptor,
    pub event_id: String,
}

impl Encode for OracleEventV0 {
    const TYPE: u16 = 55330;
}

impl Writeable for OracleEventV0 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.oracle_nonces.write(writer)?;
        self.event_maturity_epoch.write(writer)?;
        self.event_descriptor.write(writer)?;
        write_string(&self.event_id, writer)?;
        Ok(())
    }
}

impl Readable for OracleEventV0 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleEventV0, DecodeError> {
        let oracle_nonces: Vec<SchnorrPublicKey> = Readable::read(reader)?;
        let event_maturity_epoch: u32 = Readable::read(reader)?;
        let event_descriptor: EventDescriptor = Readable::read(reader)?;
        let event_id = read_string(reader)?;

        Ok(OracleEventV0 {
            oracle_nonces,
            event_maturity_epoch,
            event_descriptor,
            event_id,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EventDescriptor {
    EnumEventDescriptorV0(EnumEventDescriptorV0),
    DigitDecompositionEventDescriptorV0(DigitDecompositionEventDescriptorV0),
}

impl Writeable for EventDescriptor {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        match self {
            EventDescriptor::EnumEventDescriptorV0(enum_event) => enum_event.write(writer),
            EventDescriptor::DigitDecompositionEventDescriptorV0(decomp_event) => {
                decomp_event.write(writer)
            }
        }
    }
}

impl Readable for EventDescriptor {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<EventDescriptor, DecodeError> {
        let message_type = <u16 as Readable>::read(reader)?;
        match message_type {
            EnumEventDescriptorV0::TYPE => Ok(EventDescriptor::EnumEventDescriptorV0(
                Readable::read(reader)?,
            )),
            DigitDecompositionEventDescriptorV0::TYPE => Ok(
                EventDescriptor::DigitDecompositionEventDescriptorV0(Readable::read(reader)?),
            ),
            _ => Err(DecodeError::UnknownVersion),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EnumEventDescriptorV0 {
    pub outcomes: Vec<String>,
}

impl Encode for EnumEventDescriptorV0 {
    const TYPE: u16 = 55302;
}

impl Writeable for EnumEventDescriptorV0 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        (self.outcomes.len() as u16).write(writer)?;
        for outcome in &self.outcomes {
            write_string(outcome, writer)?;
        }

        Ok(())
    }
}

impl Readable for EnumEventDescriptorV0 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<EnumEventDescriptorV0, DecodeError> {
        let len: u16 = Readable::read(reader)?;
        let mut outcomes: Vec<String> = Vec::new();
        for _ in 0..len {
            outcomes.push(read_string(reader)?);
        }

        Ok(EnumEventDescriptorV0 { outcomes })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DigitDecompositionEventDescriptorV0 {
    pub base: u64,
    pub is_signed: bool,
    pub unit: String,
    pub precision: i32,
    pub nb_digits: u16,
}

impl Encode for DigitDecompositionEventDescriptorV0 {
    const TYPE: u16 = 55306;
}

impl Writeable for DigitDecompositionEventDescriptorV0 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        BigSize(self.base).write(writer)?;
        self.is_signed.write(writer)?;
        write_string(&self.unit, writer)?;
        self.precision.to_be_bytes().write(writer)?;
        self.nb_digits.write(writer)?;
        Ok(())
    }
}

impl Readable for DigitDecompositionEventDescriptorV0 {
    fn read<R: ::std::io::Read>(
        reader: &mut R,
    ) -> Result<DigitDecompositionEventDescriptorV0, DecodeError> {
        let base: BigSize = Readable::read(reader)?;
        let is_signed = Readable::read(reader)?;
        let unit = read_string(reader)?;
        let mut precision_buf = [0u8; 4];
        for i in 0..4 {
            precision_buf[i] = Readable::read(reader)?;
        }

        let precision = i32::from_be_bytes(precision_buf);
        let nb_digits: u16 = Readable::read(reader)?;

        Ok(DigitDecompositionEventDescriptorV0 {
            base: base.0,
            is_signed,
            unit,
            precision,
            nb_digits,
        })
    }
}

#[derive(Clone)]
pub struct OracleAttestationV0 {
    pub oracle_public_key: SchnorrPublicKey,
    pub signatures: Vec<SchnorrSignature>,
    pub outcomes: Vec<String>,
}

impl Encode for OracleAttestationV0 {
    const TYPE: u16 = 55400;
}

impl Writeable for OracleAttestationV0 {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.oracle_public_key.write(writer)?;
        write_vec(&self.signatures, writer)?;
        write_strings(&self.outcomes, writer)?;

        Ok(())
    }
}

impl Readable for OracleAttestationV0 {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleAttestationV0, DecodeError> {
        let oracle_public_key = Readable::read(reader)?;
        let signatures = Readable::read(reader)?;
        let outcomes = read_strings(reader)?;
        Ok(OracleAttestationV0 {
            oracle_public_key,
            signatures,
            outcomes,
        })
    }
}
