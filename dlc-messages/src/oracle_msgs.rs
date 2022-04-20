//! Structs containing oracle information.

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

/// The type of the announcement struct.
pub const ANNOUNCEMENT_TYPE: u16 = 55332;
/// The type of the attestation struct.
pub const ATTESTATION_TYPE: u16 = 55400;

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Information about an oracle used in a contract.
pub enum OracleInfo {
    /// Used when a contract uses a single oracle.
    Single(SingleOracleInfo),
    /// Used when a contract uses multiple oracles.
    Multi(MultiOracleInfo),
}

impl<'a> OracleInfo {
    /// Returns the first event descriptor.
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

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Structure containing information about an oracle to be used as external
/// data source for a DLC contract.
pub struct SingleOracleInfo {
    /// The oracle announcement from the oracle.
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
/// Information about oracles used in multi oracle based contracts.
pub struct MultiOracleInfo {
    /// The threshold to be used for the contract (e.g. 2 of 3).
    pub threshold: u16,
    /// The set of oracle announcements.
    pub oracle_announcements: Vec<OracleAnnouncement>,
    /// The parameters to be used when allowing differences between oracle
    /// outcomes in numerical outcome contracts.
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
/// Parameter describing allowed differences between oracles in numerical outcome
/// contracts.
pub struct OracleParams {
    /// The maximum allowed difference between oracle expressed as a power of 2.
    pub max_error_exp: u16,
    /// The minimum allowed difference that should be supported by the contract
    /// expressed as a power of 2.
    pub min_fail_exp: u16,
    /// Whether to maximize coverage of the interval between [`Self::max_error_exp`]
    /// and [`Self::min_fail_exp`].
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
/// An oracle announcement that describe an event and the way that an oracle will
/// attest to it.
pub struct OracleAnnouncement {
    /// The signature enabling verifying the origin of the announcement.
    pub announcement_signature: SchnorrSignature,
    /// The public key of the oracle.
    pub oracle_public_key: SchnorrPublicKey,
    /// The description of the event and attesting.
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
/// Information about an event and the way that the oracle will attest to it.
pub struct OracleEvent {
    /// The nonces that the oracle will use to attest to the event outcome.
    pub oracle_nonces: Vec<SchnorrPublicKey>,
    /// The expected maturity of the contract.
    // TODO(tibo): should validate that with the contract maturity.
    pub event_maturity_epoch: u32,
    /// The description of the event.
    pub event_descriptor: EventDescriptor,
    /// The id of the event.
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
/// Description of an event.
pub enum EventDescriptor {
    /// Used for events based on enumerated outcomes.
    EnumEvent(EnumEventDescriptor),
    /// Used for event based on numerical outcomes.
    DigitDecompositionEvent(DigitDecompositionEventDescriptor),
}

impl_dlc_writeable_enum_as_tlv!(EventDescriptor, (55302, EnumEvent), (55306, DigitDecompositionEvent););

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// Describes the outcomes of an event as an enumeration.
pub struct EnumEventDescriptor {
    /// The possible outcomes of the event.
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
/// Describes the outcomes of a numerical outcome event.
pub struct DigitDecompositionEventDescriptor {
    /// The base in which the outcome will be represented.
    pub base: u64,
    /// Whether the outcome value is signed.
    pub is_signed: bool,
    /// The unit in which the outcome is represented.
    pub unit: String,
    /// The precision used to represent the event outcome.
    pub precision: i32,
    /// The number of digits used to represent the event outcome.
    // TODO:(tibo) should validate that nb_digits == nb_nonces
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
/// An attestation from an oracle providing signatures over an outcome value.
pub struct OracleAttestation {
    /// The public key of the oracle.
    pub oracle_public_key: SchnorrPublicKey,
    /// The signatures over the event outcome.
    pub signatures: Vec<SchnorrSignature>,
    /// The set of strings representing the outcome value.
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
