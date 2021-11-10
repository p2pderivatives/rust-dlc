use crate::ser_impls::{
    read_as_tlv, read_i32, read_schnorr_pubkey, read_schnorrsig, read_strings_u16, write_as_tlv,
    write_i32, write_schnorr_pubkey, write_schnorrsig, write_strings_u16,
};
use dlc::OracleInfo as DlcOracleInfo;
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::schnorrsig::{PublicKey as SchnorrPublicKey, Signature as SchnorrSignature};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const ANNOUNCEMENT_TYPE: u16 = 55332;
pub const ATTESTATION_TYPE: u16 = 55400;

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

impl_dlc_writeable_enum!(
    OracleInfo, (0, Single), (1, Multi);;
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

impl_dlc_writeable!(SingleOracleInfo, {
    (oracle_announcement, {cb_writeable, write_as_tlv, read_as_tlv })
});

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

impl_dlc_writeable!(MultiOracleInfo, {
    (threshold, writeable),
    (oracle_announcements, {vec_cb, write_as_tlv, read_as_tlv}),
    (oracle_params, option)
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

impl_dlc_writeable!(OracleParams, {
    (max_error_exp, writeable),
    (min_fail_exp, writeable),
    (maximize_coverage, writeable)
});

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

impl Type for OracleAnnouncement {
    fn type_id(&self) -> u16 {
        ANNOUNCEMENT_TYPE
    }
}

impl_dlc_writeable!(OracleAnnouncement, {
    (announcement_signature, {cb_writeable, write_schnorrsig, read_schnorrsig}),
    (oracle_public_key, {cb_writeable, write_schnorr_pubkey, read_schnorr_pubkey}),
    (oracle_event, {cb_writeable, write_as_tlv, read_as_tlv})
});

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

impl Type for OracleEvent {
    fn type_id(&self) -> u16 {
        55330
    }
}

impl_dlc_writeable!(OracleEvent, {
    (oracle_nonces, {vec_u16_cb, write_schnorr_pubkey, read_schnorr_pubkey}),
    (event_maturity_epoch, writeable),
    (event_descriptor, writeable),
    (event_id, string)
});

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

impl_dlc_writeable_enum_as_tlv!(EventDescriptor, (55302, EnumEvent), (55306, DigitDecompositionEvent););

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct EnumEventDescriptor {
    pub outcomes: Vec<String>,
}

impl_dlc_writeable!(EnumEventDescriptor, {
    (outcomes, {cb_writeable, write_strings_u16, read_strings_u16})
});

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

impl_dlc_writeable!(DigitDecompositionEventDescriptor, {
    (base, writeable),
    (is_signed, writeable),
    (unit, string),
    (precision, {cb_writeable, write_i32, read_i32}),
    (nb_digits, writeable)
});

#[derive(Clone, Debug)]
pub struct OracleAttestation {
    pub oracle_public_key: SchnorrPublicKey,
    pub signatures: Vec<SchnorrSignature>,
    pub outcomes: Vec<String>,
}

impl Type for OracleAttestation {
    fn type_id(&self) -> u16 {
        ATTESTATION_TYPE
    }
}

impl_dlc_writeable!(OracleAttestation, {
    (oracle_public_key, {cb_writeable, write_schnorr_pubkey, read_schnorr_pubkey}),
    (signatures, {vec_u16_cb, write_schnorrsig, read_schnorrsig}),
    (outcomes, {cb_writeable, write_strings_u16, read_strings_u16})
});
