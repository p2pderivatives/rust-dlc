//! Structs containing oracle information.

use std::convert::TryFrom;

use crate::ser_impls::{
    read_as_tlv, read_i32, read_schnorr_pubkey, read_schnorrsig, read_strings_u16, write_as_tlv,
    write_i32, write_schnorr_pubkey, write_schnorrsig, write_strings_u16, Serializable,
};
use dlc::{Error, OracleInfo as DlcOracleInfo};
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::{hashes::*, schnorr::Signature, KeyPair, Message, Secp256k1, XOnlyPublicKey};
use secp256k1_zkp::{Signing, Verification};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The type of the announcement struct.
pub const ANNOUNCEMENT_TYPE: u16 = 55354;
/// The type of the attestation struct.
pub const ATTESTATION_TYPE: u16 = 55400;

const ORACLE_METADATA_MIDSTATE: [u8; 32] = [
    63, 234, 0, 129, 156, 122, 132, 66, 160, 214, 166, 237, 42, 243, 232, 161, 211, 152, 25, 192,
    248, 135, 93, 67, 177, 21, 70, 230, 198, 187, 18, 136,
];

const ORACLE_ANNOUNCEMENT_MIDSTATE: [u8; 32] = [
    43, 14, 155, 124, 254, 144, 191, 54, 143, 23, 160, 6, 229, 47, 246, 49, 130, 189, 90, 180, 57,
    21, 106, 44, 63, 247, 104, 198, 169, 184, 109, 91,
];

sha256t_hash_newtype!(
    OracleMetadataHash,
    OracleMetadataTag,
    ORACLE_METADATA_MIDSTATE,
    64,
    doc = "Oracle metadata tagged hash for signing oracle metadata.",
    false
);

sha256t_hash_newtype!(
    OracleAnnouncementHash,
    OracleAnnouncementTag,
    ORACLE_ANNOUNCEMENT_MIDSTATE,
    64,
    doc = "Oracle announcement tagged hash for signing oracle announcement.",
    false
);

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

impl OracleInfo {
    /// Returns the closest maturity date amongst all events
    pub fn get_closest_maturity_date(&self) -> u32 {
        match self {
            OracleInfo::Single(s) => s
                .oracle_announcement
                .oracle_event
                .timestamp
                .get_earliest_time(),
            OracleInfo::Multi(m) => m
                .oracle_announcements
                .iter()
                .map(|x| x.oracle_event.timestamp.get_earliest_time())
                .min()
                .expect("to have at least one event"),
        }
    }

    /// Returns the latest maturity date amongst all events
    pub fn get_latest_maturity_date(&self) -> u32 {
        match self {
            OracleInfo::Single(s) => s
                .oracle_announcement
                .oracle_event
                .timestamp
                .get_latest_time(),
            OracleInfo::Multi(m) => m
                .oracle_announcements
                .iter()
                .map(|x| x.oracle_event.timestamp.get_latest_time())
                .max()
                .expect("to have at least one event"),
        }
    }

    /// Checks that the info satisfies the validity conditions.
    pub fn validate<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<(), Error> {
        match self {
            OracleInfo::Single(s) => s.oracle_announcement.validate(secp)?,
            OracleInfo::Multi(m) => {
                for o in &m.oracle_announcements {
                    o.validate(secp)?;
                }
            }
        };

        Ok(())
    }
}

impl_dlc_writeable_enum!(
    OracleInfo, (0, Single), (1, Multi);;;
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
/// An oracle scheme represent a way in which an oracle will attest to an event
/// outcome and contains the necessary data to make use of the associated
/// attestation.
pub enum OracleScheme {
    /// The Schnorr scheme uses Schnorr signatures and pre-computed nonces as in
    /// the original DLC paper.
    Schnorr {
        /// The public key that the oracle will use to create the Schnorr signature(s).
        attestation_public_key: XOnlyPublicKey,
        /// The nonce(s) that the oracle will use to create the Schnorr signature(s).
        oracle_nonces: Vec<XOnlyPublicKey>,
    },
}

struct SignedOracleMetadata {
    oracle_name: String,
    oracle_description: String,
    timestamp: u32,
    oracle_schemes: Vec<OracleScheme>,
}

impl SignedOracleMetadata {
    fn get_sign_data(&self) -> Result<Message, Error> {
        let mut buf = Vec::new();
        self.write(&mut buf).map_err(|_| Error::InvalidArgument)?;
        let msg = Message::from_slice(&OracleMetadataHash::hash(&buf).into_inner())?;
        Ok(msg)
    }
}

impl_dlc_writeable!(SignedOracleMetadata, {
    (oracle_name, string),
    (oracle_description, string),
    (timestamp, writeable),
    (oracle_schemes, {vec_tlv, OracleScheme, (0, Schnorr, {(attestation_public_key, {cb_writeable, write_schnorr_pubkey, read_schnorr_pubkey}), (oracle_nonces, {vec_cb, write_schnorr_pubkey, read_schnorr_pubkey})});})
});

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct OracleMetadata {
    ///
    pub announcement_public_key: XOnlyPublicKey,
    ///
    pub oracle_name: String,
    ///
    pub oracle_description: String,
    ///
    pub timestamp: u32,
    ///
    pub oracle_schemes: Vec<OracleScheme>,
    ///
    pub oracle_meta_data_signature: Signature,
}

impl OracleMetadata {
    /// Try to generate a new signed [`OracleMetadata`] structure using the given
    /// [`SecretKey`] to create the `oracle_metadata_signature`.
    pub fn try_new_signed<C: Signing>(
        secp: &Secp256k1<C>,
        announcement_key_pair: &KeyPair,
        oracle_name: String,
        oracle_description: String,
        timestamp: u32,
        oracle_schemes: Vec<OracleScheme>,
    ) -> Result<Self, Error> {
        let announcement_public_key = XOnlyPublicKey::from_keypair(announcement_key_pair);
        let sig_data = SignedOracleMetadata {
            oracle_name,
            oracle_description,
            timestamp,
            oracle_schemes,
        };

        let sign_data = sig_data.get_sign_data()?;

        let SignedOracleMetadata {
            oracle_name,
            oracle_description,
            timestamp,
            oracle_schemes,
        } = sig_data;

        let oracle_meta_data_signature = secp.sign_schnorr(&sign_data, announcement_key_pair);

        Ok(Self {
            announcement_public_key,
            oracle_name,
            oracle_description,
            timestamp,
            oracle_schemes,
            oracle_meta_data_signature,
        })
    }

    /// Validate that the metadata hash expected information (a single Schnorr
    /// scheme).
    pub fn validate<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<(), Error> {
        if self.oracle_schemes.len() != 1 {
            return Err(Error::InvalidArgument);
        }

        let sig_data = SignedOracleMetadata {
            oracle_name: self.oracle_name.clone(),
            oracle_description: self.oracle_description.clone(),
            timestamp: self.timestamp,
            oracle_schemes: self.oracle_schemes.clone(),
        };

        let sign_data = sig_data.get_sign_data()?;

        secp.verify_schnorr(
            &self.oracle_meta_data_signature,
            &sign_data,
            &self.announcement_public_key,
        )?;

        let OracleScheme::Schnorr {
            attestation_public_key,
            ..
        } = &self.oracle_schemes[0];

        if attestation_public_key == &self.announcement_public_key {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }
}

impl_dlc_writeable!(OracleMetadata, {
    (announcement_public_key, {cb_writeable, write_schnorr_pubkey, read_schnorr_pubkey}),
    (oracle_name, string),
    (oracle_description, string),
    (timestamp, writeable),
    (oracle_schemes, {vec_tlv, OracleScheme, (1, Schnorr, {(attestation_public_key, {cb_writeable, write_schnorr_pubkey, read_schnorr_pubkey}), (oracle_nonces, {vec_cb, write_schnorr_pubkey, read_schnorr_pubkey})});}),
    (oracle_meta_data_signature, {cb_writeable, write_schnorrsig, read_schnorrsig})
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
    pub announcement_signature: Signature,
    /// Metadata describing the oracle providing the announcement.
    pub oracle_metadata: OracleMetadata,
    /// The description of the event and attesting.
    pub oracle_event: OracleEvent,
}

impl Type for OracleAnnouncement {
    fn type_id(&self) -> u16 {
        ANNOUNCEMENT_TYPE
    }
}

impl OracleAnnouncement {
    /// Returns a signed [`OracleAnnouncement`]
    pub fn try_new_signed<C: Signing>(
        secp: &Secp256k1<C>,
        key_pair: &KeyPair,
        oracle_metadata: OracleMetadata,
        oracle_event: OracleEvent,
    ) -> Result<Self, Error> {
        let event_hash = oracle_event.get_tagged_hash()?;
        let announcement_signature = secp.sign_schnorr(&event_hash, key_pair);
        Ok(OracleAnnouncement {
            oracle_event,
            oracle_metadata,
            announcement_signature,
        })
    }

    /// Returns whether the announcement satisfy validity checks.
    pub fn validate<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<(), Error> {
        let event_hash = self.oracle_event.get_tagged_hash()?;
        secp.verify_schnorr(
            &self.announcement_signature,
            &event_hash,
            &self.oracle_metadata.announcement_public_key,
        )?;
        let expected_nb_nonces = match &self.oracle_event.event_descriptor {
            EventDescriptor::EnumEvent(_) => 1,
            EventDescriptor::DigitDecompositionEvent(d) => d.nb_digits as usize,
        };

        self.oracle_metadata.validate(secp)?;

        self.oracle_event.timestamp.validate()?;

        let actual_nb_nonces = self
            .oracle_metadata
            .oracle_schemes
            .iter()
            .find_map(|scheme| {
                let OracleScheme::Schnorr { oracle_nonces, .. } = scheme;
                Some(oracle_nonces.len())
            })
            .ok_or(Error::InvalidArgument)?;

        if expected_nb_nonces == actual_nb_nonces {
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }
}

impl_dlc_writeable!(OracleAnnouncement, {
    (announcement_signature, {cb_writeable, write_schnorrsig, read_schnorrsig}),
    (oracle_metadata, writeable),
    (oracle_event, {cb_writeable, write_as_tlv, read_as_tlv})
});

impl TryFrom<&OracleAnnouncement> for DlcOracleInfo {
    type Error = Error;
    fn try_from(input: &OracleAnnouncement) -> Result<Self, Self::Error> {
        let (public_key, nonces) = {
            let OracleScheme::Schnorr {
                attestation_public_key,
                oracle_nonces,
            } = input
                .oracle_metadata
                .oracle_schemes
                .get(0)
                .ok_or(Error::InvalidArgument)?;
            (attestation_public_key, oracle_nonces)
        };
        Ok(DlcOracleInfo {
            public_key: *public_key,
            nonces: nonces.clone(),
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// Represent the time or interval of time at which the oracle expects to release
/// an attestation for an event.
pub enum OracleTimestamp {
    /// Timestamp for an event expected to occur at a given time.
    FixedOracleEventTimestamp {
        /// The expected time.
        expected_time_epoch: u32,
    },
    /// Timestamp for an event expected to occur within a time interval.
    RangeOracleEventTimestamp {
        /// The earliest time at which the event is expected to occur.
        earliest_expected_time_epoch: u32,
        /// The latest time at which the event is expected to occur.
        latest_expected_time_epoch: u32,
    },
}

impl OracleTimestamp {
    /// Return the earliest time at which the associated event is expected to
    /// occur.
    pub fn get_earliest_time(&self) -> u32 {
        match self {
            OracleTimestamp::FixedOracleEventTimestamp {
                expected_time_epoch,
            } => *expected_time_epoch,

            OracleTimestamp::RangeOracleEventTimestamp {
                earliest_expected_time_epoch,
                ..
            } => *earliest_expected_time_epoch,
        }
    }

    /// Return the latest time at which the associated event is expected to
    /// occur.
    pub fn get_latest_time(&self) -> u32 {
        match self {
            OracleTimestamp::FixedOracleEventTimestamp {
                expected_time_epoch,
            } => *expected_time_epoch,

            OracleTimestamp::RangeOracleEventTimestamp {
                latest_expected_time_epoch,
                ..
            } => *latest_expected_time_epoch,
        }
    }

    /// Validate that the timestamp is well formed.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            OracleTimestamp::FixedOracleEventTimestamp { .. } => Ok(()),
            OracleTimestamp::RangeOracleEventTimestamp {
                earliest_expected_time_epoch,
                latest_expected_time_epoch,
            } => {
                if earliest_expected_time_epoch < latest_expected_time_epoch {
                    Ok(())
                } else {
                    Err(Error::InvalidArgument)
                }
            }
        }
    }
}

impl_dlc_writeable_enum!(OracleTimestamp,;
    (0, FixedOracleEventTimestamp, {(expected_time_epoch, writeable)}),
    (1, RangeOracleEventTimestamp, {(earliest_expected_time_epoch, writeable), (latest_expected_time_epoch, writeable)})
;;);

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// Information about an event and the way that the oracle will attest to it.
pub struct OracleEvent {
    ///
    pub timestamp: OracleTimestamp,
    /// The description of the event.
    pub event_descriptor: EventDescriptor,
    /// The id of the event.
    pub event_id: String,
}

impl OracleEvent {
    /// Returns a hash of the event tagged with [`OracleAnnouncementTag`].
    pub fn get_tagged_hash(&self) -> Result<Message, Error> {
        let hex = Serializable::serialize(self).map_err(|_| Error::InvalidArgument)?;
        let hash = OracleAnnouncementHash::hash(&hex).0;
        let msg = Message::from_slice(&hash)?;
        Ok(msg)
    }
}

impl Type for OracleEvent {
    fn type_id(&self) -> u16 {
        55330
    }
}

impl_dlc_writeable!(OracleEvent, {
    (timestamp, writeable),
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

impl_dlc_writeable_enum!(EventDescriptor, (0, EnumEvent), (1, DigitDecompositionEvent);;;);

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
    pub base: u8,
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

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct SignedOutcome {
    ///
    pub signature: Signature,
    ///
    pub outcome: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// All possible scheme that can be used by oracles to attest to event outcomes.
pub enum AttestationScheme {
    /// The Schnorr scheme uses the Schnorr signature scheme to sign event
    /// outcomes.
    Schnorr {
        /// The public key that was used to create the attestation signatures.
        oracle_attestation_public_key: XOnlyPublicKey,
        /// The outcomes and signatures for the event.
        attestations: Vec<SignedOutcome>,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// An attestation from an oracle providing signatures over an outcome value.
pub struct OracleAttestation {
    /// The public key of the oracle.
    pub oracle_public_key: XOnlyPublicKey,
    /// The signatures over the event outcome.
    pub signatures: Vec<Signature>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1_zkp::{rand::thread_rng, SECP256K1};
    use secp256k1_zkp::{schnorr::Signature, KeyPair, XOnlyPublicKey};

    fn enum_descriptor() -> EnumEventDescriptor {
        EnumEventDescriptor {
            outcomes: vec!["1".to_string(), "2".to_string(), "3".to_string()],
        }
    }

    fn digit_descriptor() -> DigitDecompositionEventDescriptor {
        DigitDecompositionEventDescriptor {
            base: 2,
            is_signed: false,
            unit: "kg/sats".to_string(),
            precision: 1,
            nb_digits: 10,
        }
    }

    fn some_schnorr_pubkey() -> XOnlyPublicKey {
        let key_pair = KeyPair::new(SECP256K1, &mut thread_rng());
        XOnlyPublicKey::from_keypair(&key_pair)
    }

    fn digit_event() -> OracleEvent {
        OracleEvent {
            event_descriptor: EventDescriptor::DigitDecompositionEvent(digit_descriptor()),
            event_id: "test".to_string(),
            timestamp: OracleTimestamp::FixedOracleEventTimestamp {
                expected_time_epoch: 1234567,
            },
        }
    }

    fn enum_event() -> OracleEvent {
        OracleEvent {
            event_descriptor: EventDescriptor::EnumEvent(enum_descriptor()),
            event_id: "test".to_string(),
            timestamp: OracleTimestamp::FixedOracleEventTimestamp {
                expected_time_epoch: 1234567,
            },
        }
    }

    fn get_oracle_announcement(oracle_event: OracleEvent, nb_nonces: usize) -> OracleAnnouncement {
        let announcement_key_pair = KeyPair::new(SECP256K1, &mut thread_rng());
        let attestation_key_pair = KeyPair::new(SECP256K1, &mut thread_rng());
        let oracle_attestation_pubkey = XOnlyPublicKey::from_keypair(&attestation_key_pair);
        let oracle_metadata = OracleMetadata::try_new_signed(
            SECP256K1,
            &announcement_key_pair,
            "Olivia".to_string(),
            "Super honest oracle".to_string(),
            1,
            vec![OracleScheme::Schnorr {
                attestation_public_key: oracle_attestation_pubkey,
                oracle_nonces: (0..nb_nonces).map(|_| some_schnorr_pubkey()).collect(),
            }],
        )
        .unwrap();
        OracleAnnouncement::try_new_signed(
            SECP256K1,
            &announcement_key_pair,
            oracle_metadata,
            oracle_event,
        )
        .unwrap()
    }

    fn break_sig(input: &Signature) -> Signature {
        let mut sig_data = input.as_ref().clone();
        sig_data[10] += 1;
        Signature::from_slice(&sig_data).unwrap()
    }

    #[test]
    fn valid_oracle_announcement_passes_validation_test() {
        let events = [(digit_event(), 10), (enum_event(), 1)];
        for (event, nb_nonces) in events {
            let valid_announcement = get_oracle_announcement(event, nb_nonces);
            valid_announcement
                .validate(SECP256K1)
                .expect("a valid announcement.");
        }
    }

    #[test]
    fn invalid_nb_nonces_oracle_announcement_fails_validation_test() {
        let events = [(digit_event(), 9), (enum_event(), 2)];
        for (event, nb_nonces) in events {
            let invalid_announcement = get_oracle_announcement(event, nb_nonces);
            invalid_announcement
                .validate(SECP256K1)
                .expect_err("invalid announcement should fail validation.");
        }
    }

    #[test]
    fn invalid_oracle_announcement_signature_fails_validation_test() {
        let (event, nb_nonces) = (digit_event(), 10);
        let mut announcement = get_oracle_announcement(event, nb_nonces);
        announcement.announcement_signature = break_sig(&announcement.announcement_signature);
        announcement
            .validate(SECP256K1)
            .expect_err("to fail with an invalid signature");
    }

    #[test]
    fn invalid_oracle_metadata_signature_fails_validation_test() {
        let (event, nb_nonces) = (digit_event(), 10);
        let mut announcement = get_oracle_announcement(event, nb_nonces);
        announcement.oracle_metadata.oracle_meta_data_signature =
            break_sig(&announcement.oracle_metadata.oracle_meta_data_signature);
        announcement
            .validate(SECP256K1)
            .expect_err("to fail with an invalid metadata signature");
    }

    #[test]
    fn invalid_event_timestamp_fails_validation_test() {
        let (event, nb_nonces) = (digit_event(), 10);
        let mut announcement = get_oracle_announcement(event, nb_nonces);
        announcement.oracle_event.timestamp = OracleTimestamp::RangeOracleEventTimestamp {
            earliest_expected_time_epoch: 3,
            latest_expected_time_epoch: 2,
        };
        announcement
            .validate(SECP256K1)
            .expect_err("to fail with an invalid timestamp");
    }

    #[test]
    fn invalid_event_identical_keys_fails_validation_test() {
        let (event, nb_nonces) = (digit_event(), 10);
        let announcement = {
            let announcement_key_pair = KeyPair::new(SECP256K1, &mut thread_rng());
            let attestation_key_pair = announcement_key_pair.clone();
            let oracle_attestation_pubkey = XOnlyPublicKey::from_keypair(&attestation_key_pair);
            let oracle_metadata = OracleMetadata::try_new_signed(
                SECP256K1,
                &announcement_key_pair,
                "Olivia".to_string(),
                "Super honest oracle".to_string(),
                1,
                vec![OracleScheme::Schnorr {
                    attestation_public_key: oracle_attestation_pubkey,
                    oracle_nonces: (0..nb_nonces).map(|_| some_schnorr_pubkey()).collect(),
                }],
            )
            .unwrap();
            OracleAnnouncement::try_new_signed(
                SECP256K1,
                &announcement_key_pair,
                oracle_metadata,
                event,
            )
            .unwrap()
        };
        announcement
            .validate(SECP256K1)
            .expect_err("to fail with an invalid timestamp");
    }
}
