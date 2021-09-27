use dlc::OracleInfo as DlcOracleInfo;
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{BigSize, Readable, Writeable, Writer};
use secp256k1_zkp::schnorrsig::{PublicKey as SchnorrPublicKey, Signature as SchnorrSignature};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use utils::{
    read_schnorr_pubkey, read_schnorr_pubkeys, read_schnorr_signatures, read_schnorrsig,
    read_string, read_strings, write_schnorr_pubkey, write_schnorr_pubkeys,
    write_schnorr_signatures, write_schnorrsig, write_string, write_strings,
};

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum OracleInfo {
    Single(SingleOracleInfo),
    Multi(MultiOracleInfo),
}

impl<'a> OracleInfo {
    pub fn get_first_event_descriptor(&'a self) -> &'a EventDescriptor {
        match self {
            OracleInfo::Single(single) => &single.oracle_announcement.oracle_event.event_descriptor,
            OracleInfo::Multi(multi) => {
                &multi.oracle_announcements[0].oracle_event.event_descriptor
            }
        }
    }
}

impl_writeable_tlv_based_enum!(
    OracleInfo, ;
    (0, Single),
    (1, Multi)
);

/// Structure containing information about an oracle to be used as external
/// data source for a DLC contract.
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SingleOracleInfo {
    pub oracle_announcement: OracleAnnouncement,
}

impl_writeable!(SingleOracleInfo, 0, { oracle_announcement });

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct MultiOracleInfo {
    pub threshold: u16,
    pub oracle_announcements: Vec<OracleAnnouncement>,
    pub oracle_params: Option<OracleParams>,
}

impl_writeable_tlv_based!(MultiOracleInfo, {
    (0, threshold, required),
    (1, oracle_announcements, vec_type),
    (2, oracle_params, option),
});

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct OracleParams {
    pub max_error_exp: u16,
    pub min_fail_exp: u16,
    pub maximize_coverage: bool,
}

impl_writeable!(OracleParams, 33, {max_error_exp, min_fail_exp, maximize_coverage});

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct OracleAnnouncement {
    pub announcement_signature: SchnorrSignature,
    pub oracle_public_key: SchnorrPublicKey,
    pub oracle_event: OracleEvent,
}

impl Writeable for OracleAnnouncement {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_schnorrsig(&self.announcement_signature, writer)?;
        write_schnorr_pubkey(&self.oracle_public_key, writer)?;
        self.oracle_event.write(writer)?;
        Ok(())
    }
}

impl Readable for OracleAnnouncement {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleAnnouncement, DecodeError> {
        let announcement_signature: SchnorrSignature = read_schnorrsig(reader)?;
        let oracle_public_key: SchnorrPublicKey = read_schnorr_pubkey(reader)?;
        let oracle_event: OracleEvent = Readable::read(reader)?;

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
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct OracleEvent {
    pub oracle_nonces: Vec<SchnorrPublicKey>,
    pub event_maturity_epoch: u32,
    pub event_descriptor: EventDescriptor,
    pub event_id: String,
}

impl Writeable for OracleEvent {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_schnorr_pubkeys(&self.oracle_nonces, writer)?;
        self.event_maturity_epoch.write(writer)?;
        self.event_descriptor.write(writer)?;
        write_string(&self.event_id, writer)?;
        Ok(())
    }
}

impl Readable for OracleEvent {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleEvent, DecodeError> {
        let oracle_nonces: Vec<SchnorrPublicKey> = read_schnorr_pubkeys(reader)?;
        let event_maturity_epoch: u32 = Readable::read(reader)?;
        let event_descriptor: EventDescriptor = Readable::read(reader)?;
        let event_id = read_string(reader)?;

        Ok(OracleEvent {
            oracle_nonces,
            event_maturity_epoch,
            event_descriptor,
            event_id,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum EventDescriptor {
    EnumEvent(EnumEventDescriptor),
    DigitDecompositionEvent(DigitDecompositionEventDescriptor),
}

impl_writeable_tlv_based_enum!(EventDescriptor, ;
 (0, EnumEvent),
 (1, DigitDecompositionEvent)
);

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct EnumEventDescriptor {
    pub outcomes: Vec<String>,
}

impl Writeable for EnumEventDescriptor {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        (self.outcomes.len() as u16).write(writer)?;
        for outcome in &self.outcomes {
            write_string(outcome, writer)?;
        }

        Ok(())
    }
}

impl Readable for EnumEventDescriptor {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<EnumEventDescriptor, DecodeError> {
        let len: u16 = Readable::read(reader)?;
        let mut outcomes: Vec<String> = Vec::new();
        for _ in 0..len {
            outcomes.push(read_string(reader)?);
        }

        Ok(EnumEventDescriptor { outcomes })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct DigitDecompositionEventDescriptor {
    pub base: u64,
    pub is_signed: bool,
    pub unit: String,
    pub precision: i32,
    pub nb_digits: u16,
}

impl Writeable for DigitDecompositionEventDescriptor {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        BigSize(self.base).write(writer)?;
        self.is_signed.write(writer)?;
        write_string(&self.unit, writer)?;
        self.precision.to_be_bytes().write(writer)?;
        self.nb_digits.write(writer)?;
        Ok(())
    }
}

impl Readable for DigitDecompositionEventDescriptor {
    fn read<R: ::std::io::Read>(
        reader: &mut R,
    ) -> Result<DigitDecompositionEventDescriptor, DecodeError> {
        let base: BigSize = Readable::read(reader)?;
        let is_signed = Readable::read(reader)?;
        let unit = read_string(reader)?;
        let mut precision_buf = [0u8; 4];
        for i in 0..4 {
            precision_buf[i] = Readable::read(reader)?;
        }

        let precision = i32::from_be_bytes(precision_buf);
        let nb_digits: u16 = Readable::read(reader)?;

        Ok(DigitDecompositionEventDescriptor {
            base: base.0,
            is_signed,
            unit,
            precision,
            nb_digits,
        })
    }
}

#[derive(Clone)]
pub struct OracleAttestation {
    pub oracle_public_key: SchnorrPublicKey,
    pub signatures: Vec<SchnorrSignature>,
    pub outcomes: Vec<String>,
}

impl Writeable for OracleAttestation {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_schnorr_pubkey(&self.oracle_public_key, writer)?;
        write_schnorr_signatures(&self.signatures, writer)?;
        write_strings(&self.outcomes, writer)?;

        Ok(())
    }
}

impl Readable for OracleAttestation {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleAttestation, DecodeError> {
        let oracle_public_key = read_schnorr_pubkey(reader)?;
        let signatures = read_schnorr_signatures(reader)?;
        let outcomes = read_strings(reader)?;
        Ok(OracleAttestation {
            oracle_public_key,
            signatures,
            outcomes,
        })
    }
}
