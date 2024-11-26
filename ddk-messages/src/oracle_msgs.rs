//! Structs containing oracle information.

use crate::ser_impls::{
    read_as_tlv, read_i32, read_schnorr_pubkey, read_schnorrsig, read_strings_u16, write_as_tlv,
    write_i32, write_schnorr_pubkey, write_schnorrsig, write_strings_u16,
};
use bitcoin::hashes::Hash;
use ddk_dlc::{Error, OracleInfo as DlcOracleInfo};
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::Verification;
use secp256k1_zkp::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
#[cfg(feature = "use-serde")]
use serde::{Deserialize, Serialize};

/// The type of the announcement struct.
pub const ANNOUNCEMENT_TYPE: u16 = 55332;
/// The type of the attestation struct.
pub const ATTESTATION_TYPE: u16 = 55400;

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "use-serde",
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
            OracleInfo::Single(s) => s.oracle_announcement.oracle_event.event_maturity_epoch,
            OracleInfo::Multi(m) => m
                .oracle_announcements
                .iter()
                .map(|x| x.oracle_event.event_maturity_epoch)
                .min()
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
    feature = "use-serde",
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
    feature = "use-serde",
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
    feature = "use-serde",
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
    feature = "use-serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// An oracle announcement that describe an event and the way that an oracle will
/// attest to it.
pub struct OracleAnnouncement {
    /// The signature enabling verifying the origin of the announcement.
    pub announcement_signature: Signature,
    /// The public key of the oracle.
    pub oracle_public_key: XOnlyPublicKey,
    /// The description of the event and attesting.
    pub oracle_event: OracleEvent,
}

impl Type for OracleAnnouncement {
    fn type_id(&self) -> u16 {
        ANNOUNCEMENT_TYPE
    }
}

impl OracleAnnouncement {
    /// Returns whether the announcement satisfy validity checks.
    pub fn validate<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<(), Error> {
        let mut event_hex = Vec::new();
        self.oracle_event
            .write(&mut event_hex)
            .expect("Error writing oracle event");

        let hash = bitcoin::hashes::sha256::Hash::hash(&event_hex);
        let msg = Message::from_digest(hash.to_byte_array());
        secp.verify_schnorr(&self.announcement_signature, &msg, &self.oracle_public_key)?;
        self.oracle_event.validate()
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
    feature = "use-serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// Information about an event and the way that the oracle will attest to it.
pub struct OracleEvent {
    /// The nonces that the oracle will use to attest to the event outcome.
    pub oracle_nonces: Vec<XOnlyPublicKey>,
    /// The expected maturity of the contract.
    // TODO(tibo): should validate that with the contract maturity.
    pub event_maturity_epoch: u32,
    /// The description of the event.
    pub event_descriptor: EventDescriptor,
    /// The id of the event.
    pub event_id: String,
}

impl OracleEvent {
    /// Returns whether the event passes validity checks.
    pub fn validate(&self) -> Result<(), Error> {
        let expected_nb_nonces = match &self.event_descriptor {
            EventDescriptor::EnumEvent(_) => 1,
            EventDescriptor::DigitDecompositionEvent(d) => {
                if d.is_signed {
                    d.nb_digits as usize + 1
                } else {
                    d.nb_digits as usize
                }
            }
        };

        if expected_nb_nonces == self.oracle_nonces.len() {
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }
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
    feature = "use-serde",
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
    feature = "use-serde",
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
    feature = "use-serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// Describes the outcomes of a numerical outcome event.
pub struct DigitDecompositionEventDescriptor {
    /// The base in which the outcome will be represented.
    pub base: u16,
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

/// An attestation from an oracle providing signatures over an outcome value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "use-serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct OracleAttestation {
    /// The identifier of the announcement.
    pub event_id: String,
    /// The public key of the oracle.
    pub oracle_public_key: XOnlyPublicKey,
    /// The signatures over the event outcome.
    pub signatures: Vec<Signature>,
    /// The set of strings representing the outcome value.
    pub outcomes: Vec<String>,
}

impl OracleAttestation {
    /// Returns whether the attestation satisfy validity checks.
    pub fn validate<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        announcement: &OracleAnnouncement,
    ) -> Result<(), Error> {
        if self.outcomes.len() != self.signatures.len() {
            return Err(Error::InvalidArgument);
        }

        if self.oracle_public_key != announcement.oracle_public_key {
            return Err(Error::InvalidArgument);
        }

        self.signatures
            .iter()
            .zip(self.outcomes.iter())
            .try_for_each(|(sig, outcome)| {
                let hash = bitcoin::hashes::sha256::Hash::hash(outcome.as_bytes());
                let msg = Message::from_digest(hash.to_byte_array());
                secp.verify_schnorr(sig, &msg, &self.oracle_public_key)
                    .map_err(|_| Error::InvalidArgument)?;

                Ok::<(), ddk_dlc::Error>(())
            })?;

        if !self
            .signatures
            .iter()
            .zip(announcement.oracle_event.oracle_nonces.iter())
            .all(|(sig, nonce)| sig.encode()[..32] == nonce.serialize())
        {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }
    /// Returns the nonces used by the oracle to sign the event outcome.
    /// This is used for finding the matching oracle announcement.
    pub fn nonces(&self) -> Vec<XOnlyPublicKey> {
        self.signatures
            .iter()
            .map(|s| XOnlyPublicKey::from_slice(&s[0..32]).expect("valid signature"))
            .collect()
    }
}

impl Type for OracleAttestation {
    fn type_id(&self) -> u16 {
        ATTESTATION_TYPE
    }
}

impl_dlc_writeable!(OracleAttestation, {
    (event_id, string),
    (oracle_public_key, {cb_writeable, write_schnorr_pubkey, read_schnorr_pubkey}),
    (signatures, {vec_u16_cb, write_schnorrsig, read_schnorrsig}),
    (outcomes, {cb_writeable, write_strings_u16, read_strings_u16})
});

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{ChildNumber, Xpriv};
    use bitcoin::Network;
    use secp256k1_zkp::rand::Fill;
    use secp256k1_zkp::SecretKey;
    use secp256k1_zkp::{rand::thread_rng, Message, SECP256K1};
    use secp256k1_zkp::{schnorr::Signature as SchnorrSignature, Keypair, XOnlyPublicKey};

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

    fn signed_digit_descriptor() -> DigitDecompositionEventDescriptor {
        DigitDecompositionEventDescriptor {
            base: 2,
            is_signed: true,
            unit: "kg/sats".to_string(),
            precision: 1,
            nb_digits: 10,
        }
    }

    fn some_schnorr_pubkey() -> XOnlyPublicKey {
        let key_pair = Keypair::new(SECP256K1, &mut thread_rng());
        XOnlyPublicKey::from_keypair(&key_pair).0
    }

    fn digit_event(nb_nonces: usize) -> OracleEvent {
        OracleEvent {
            oracle_nonces: (0..nb_nonces).map(|_| some_schnorr_pubkey()).collect(),
            event_maturity_epoch: 10,
            event_descriptor: EventDescriptor::DigitDecompositionEvent(digit_descriptor()),
            event_id: "test".to_string(),
        }
    }

    fn signed_digit_event(nb_nonces: usize) -> OracleEvent {
        OracleEvent {
            oracle_nonces: (0..nb_nonces).map(|_| some_schnorr_pubkey()).collect(),
            event_maturity_epoch: 10,
            event_descriptor: EventDescriptor::DigitDecompositionEvent(signed_digit_descriptor()),
            event_id: "test-signed".to_string(),
        }
    }

    fn enum_event(nb_nonces: usize) -> OracleEvent {
        OracleEvent {
            oracle_nonces: (0..nb_nonces).map(|_| some_schnorr_pubkey()).collect(),
            event_maturity_epoch: 10,
            event_descriptor: EventDescriptor::EnumEvent(enum_descriptor()),
            event_id: "test".to_string(),
        }
    }

    fn create_nonce_key() -> (SecretKey, XOnlyPublicKey) {
        let mut nonce_seed = [0u8; 32];
        nonce_seed.try_fill(&mut thread_rng()).unwrap();
        let nonce_priv = Xpriv::new_master(Network::Bitcoin, &nonce_seed)
            .unwrap()
            .derive_priv(SECP256K1, &[ChildNumber::from_normal_idx(1).unwrap()])
            .unwrap()
            .private_key;

        let nonce_xpub = nonce_priv.x_only_public_key(SECP256K1).0;

        (nonce_priv, nonce_xpub)
    }

    #[test]
    fn valid_oracle_announcement_passes_validation_test() {
        let key_pair = Keypair::new(SECP256K1, &mut thread_rng());
        let oracle_pubkey = XOnlyPublicKey::from_keypair(&key_pair).0;
        let events = [digit_event(10), signed_digit_event(11), enum_event(1)];
        for event in events {
            let mut event_hex = Vec::new();
            event
                .write(&mut event_hex)
                .expect("Error writing oracle event");
            let hash = bitcoin::hashes::sha256::Hash::hash(&event_hex);
            let msg = Message::from_digest(hash.to_byte_array());
            let sig = SECP256K1.sign_schnorr(&msg, &key_pair);
            let valid_announcement = OracleAnnouncement {
                announcement_signature: sig,
                oracle_public_key: oracle_pubkey,
                oracle_event: event,
            };

            valid_announcement
                .validate(SECP256K1)
                .expect("a valid announcement.");
        }
    }

    #[test]
    fn invalid_oracle_announcement_fails_validation_test() {
        let key_pair = Keypair::new(SECP256K1, &mut thread_rng());
        let oracle_pubkey = XOnlyPublicKey::from_keypair(&key_pair).0;
        let events = [digit_event(9), signed_digit_event(10), enum_event(2)];
        for event in events {
            let mut event_hex = Vec::new();
            event
                .write(&mut event_hex)
                .expect("Error writing oracle event");
            let hash = bitcoin::hashes::sha256::Hash::hash(&event_hex);
            let msg = Message::from_digest(hash.to_byte_array());
            let sig = SECP256K1.sign_schnorr(&msg, &key_pair);
            let invalid_announcement = OracleAnnouncement {
                announcement_signature: sig,
                oracle_public_key: oracle_pubkey,
                oracle_event: event,
            };

            invalid_announcement
                .validate(SECP256K1)
                .expect_err("invalid announcement should fail validation.");
        }
    }

    #[test]
    fn invalid_oracle_announcement_signature_fails_validation_test() {
        let key_pair = Keypair::new(SECP256K1, &mut thread_rng());
        let oracle_pubkey = XOnlyPublicKey::from_keypair(&key_pair).0;
        let event = digit_event(10);
        let mut event_hex = Vec::new();
        event
            .write(&mut event_hex)
            .expect("Error writing oracle event");
        let hash = bitcoin::hashes::sha256::Hash::hash(&event_hex);
        let msg = Message::from_digest(hash.to_byte_array());
        let sig = SECP256K1.sign_schnorr(&msg, &key_pair);
        let mut sig_hex = *sig.as_ref();
        sig_hex[10] = sig_hex[10].checked_add(1).unwrap_or(0);
        let sig = SchnorrSignature::from_slice(&sig_hex).unwrap();
        let invalid_announcement = OracleAnnouncement {
            announcement_signature: sig,
            oracle_public_key: oracle_pubkey,
            oracle_event: event,
        };

        assert!(invalid_announcement.validate(SECP256K1).is_err());
    }

    #[test]
    fn valid_oracle_attestation() {
        let key_pair = Keypair::new(SECP256K1, &mut thread_rng());
        let oracle_pubkey = XOnlyPublicKey::from_keypair(&key_pair).0;
        let (nonce_secret, nonce_xpub) = create_nonce_key();

        let oracle_event = OracleEvent {
            event_id: "test".to_string(),
            event_maturity_epoch: 10,
            oracle_nonces: vec![nonce_xpub],
            event_descriptor: EventDescriptor::EnumEvent(enum_descriptor()),
        };

        let mut event_hex = Vec::new();
        oracle_event
            .write(&mut event_hex)
            .expect("Error writing oracle event");
        let hash = bitcoin::hashes::sha256::Hash::hash(&event_hex);
        let msg = Message::from_digest(hash.to_byte_array());
        let sig = SECP256K1.sign_schnorr(&msg, &key_pair);

        let valid_announcement = OracleAnnouncement {
            oracle_public_key: oracle_pubkey,
            announcement_signature: sig,
            oracle_event,
        };

        let hash = bitcoin::hashes::sha256::Hash::hash("1".as_bytes());
        let msg = Message::from_digest(hash.to_byte_array());
        let sig = ddk_dlc::secp_utils::schnorrsig_sign_with_nonce(
            SECP256K1,
            &msg,
            &key_pair,
            &nonce_secret.secret_bytes(),
        );

        let attestation = OracleAttestation {
            event_id: "test".to_string(),
            oracle_public_key: oracle_pubkey,
            signatures: vec![sig],
            outcomes: vec!["1".to_string()],
        };

        let validation = attestation.validate(SECP256K1, &valid_announcement);

        assert!(validation.is_ok())
    }

    #[test]
    fn invalid_attestation_incorrect_nonce() {
        let key_pair = Keypair::new(SECP256K1, &mut thread_rng());
        let oracle_pubkey = XOnlyPublicKey::from_keypair(&key_pair).0;
        let (_, nonce_xpub) = create_nonce_key();
        let (incorrect_nonce_secret, _) = create_nonce_key();

        let oracle_event = OracleEvent {
            event_id: "test".to_string(),
            event_maturity_epoch: 10,
            oracle_nonces: vec![nonce_xpub],
            event_descriptor: EventDescriptor::EnumEvent(enum_descriptor()),
        };

        let mut event_hex = Vec::new();
        oracle_event
            .write(&mut event_hex)
            .expect("Error writing oracle event");
        let hash = bitcoin::hashes::sha256::Hash::hash(&event_hex);
        let msg = Message::from_digest(hash.to_byte_array());
        let sig = SECP256K1.sign_schnorr(&msg, &key_pair);

        let valid_announcement = OracleAnnouncement {
            oracle_public_key: oracle_pubkey,
            announcement_signature: sig,
            oracle_event,
        };

        let hash = bitcoin::hashes::sha256::Hash::hash("1".as_bytes());
        let msg = Message::from_digest(hash.to_byte_array());
        let sig = ddk_dlc::secp_utils::schnorrsig_sign_with_nonce(
            SECP256K1,
            &msg,
            &key_pair,
            &incorrect_nonce_secret.secret_bytes(),
        );

        let attestation = OracleAttestation {
            event_id: "test".to_string(),
            oracle_public_key: oracle_pubkey,
            signatures: vec![sig],
            outcomes: vec!["1".to_string()],
        };

        let validation = attestation.validate(SECP256K1, &valid_announcement);

        assert!(validation.is_err())
    }
}
