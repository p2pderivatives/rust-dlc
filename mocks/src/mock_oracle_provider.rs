use dlc_manager::error::Error as DaemonError;
use dlc_manager::Oracle;
use dlc_messages::oracle_msgs::{
    EventDescriptor, OracleAnnouncement, OracleEvent, OracleMetadata, OracleTimestamp,
    SchnorrAttestation, SchnorrAttestationScheme,
};
use secp256k1_zkp::rand::thread_rng;
use secp256k1_zkp::SecretKey;
use secp256k1_zkp::{All, Message, Secp256k1};
use secp256k1_zkp::{KeyPair, XOnlyPublicKey};

use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct MockOracle {
    announcement_key_pair: KeyPair,
    attestation_key_pair: KeyPair,
    secp: Secp256k1<All>,
    announcements: HashMap<String, OracleAnnouncement>,
    attestations: HashMap<String, SchnorrAttestation>,
    nonces: HashMap<String, Vec<SecretKey>>,
    name: String,
}

impl MockOracle {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let announcement_key_pair = KeyPair::new(&secp, &mut thread_rng());
        let attestation_key_pair = KeyPair::new(&secp, &mut thread_rng());

        MockOracle {
            secp,
            announcement_key_pair,
            attestation_key_pair,
            announcements: HashMap::new(),
            attestations: HashMap::new(),
            nonces: HashMap::new(),
            name: "MockOracle".to_string(),
        }
    }

    pub fn from_secret_keys(announcement_sk: &SecretKey, attestation_sk: &SecretKey) -> Self {
        let secp = Secp256k1::new();
        let announcement_key_pair = KeyPair::from_secret_key(&secp, *announcement_sk);
        let attestation_key_pair = KeyPair::from_secret_key(&secp, *attestation_sk);

        MockOracle {
            secp,
            announcement_key_pair,
            attestation_key_pair,
            announcements: HashMap::new(),
            attestations: HashMap::new(),
            nonces: HashMap::new(),
            name: "MockOracle".to_string(),
        }
    }
}

impl Default for MockOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle for MockOracle {
    fn get_announcement_public_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_keypair(&self.announcement_key_pair)
    }

    fn get_attestation_public_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_keypair(&self.attestation_key_pair)
    }

    fn get_announcement(&self, event_id: &str) -> Result<OracleAnnouncement, DaemonError> {
        let res = self
            .announcements
            .get(event_id)
            .ok_or_else(|| DaemonError::OracleError("Announcement not found".to_string()))?;
        Ok(res.clone())
    }

    fn get_attestation(&self, event_id: &str) -> Result<SchnorrAttestation, DaemonError> {
        let res = self
            .attestations
            .get(event_id)
            .ok_or_else(|| DaemonError::OracleError("Attestation not found".to_string()))?;
        Ok(res.clone())
    }
}

impl MockOracle {
    fn generate_nonces_for_event(
        &mut self,
        event_id: &str,
        event_descriptor: &EventDescriptor,
    ) -> Vec<XOnlyPublicKey> {
        let nb_nonces = match event_descriptor {
            EventDescriptor::EnumEvent(_) => 1,
            EventDescriptor::DigitDecompositionEvent(d) => d.nb_digits,
        };

        let priv_nonces: Vec<_> = (0..nb_nonces)
            .map(|_| SecretKey::new(&mut thread_rng()))
            .collect();
        let key_pairs: Vec<_> = priv_nonces
            .iter()
            .map(|x| KeyPair::from_seckey_slice(&self.secp, x.as_ref()).unwrap())
            .collect();

        let nonces = key_pairs.iter().map(XOnlyPublicKey::from_keypair).collect();

        self.nonces.insert(event_id.to_string(), priv_nonces);

        nonces
    }

    pub fn add_event(&mut self, event_id: &str, event_descriptor: &EventDescriptor, maturity: u32) {
        self.generate_nonces_for_event(event_id, event_descriptor);
        let oracle_event = OracleEvent {
            timestamp: OracleTimestamp::FixedOracleEventTimestamp {
                expected_time_epoch: maturity,
            },
            event_descriptor: event_descriptor.clone(),
            event_id: event_id.to_string(),
        };
        let announcement = OracleAnnouncement::try_new_signed(
            &self.secp,
            &self.announcement_key_pair,
            OracleMetadata::try_new_signed(
                &self.secp,
                &self.announcement_key_pair,
                self.name.clone(),
                "mock oracle".to_string(),
                1,
                SchnorrAttestationScheme::try_new_schnorr_scheme(
                    &self.secp,
                    &self.attestation_key_pair,
                    &self
                        .nonces
                        .get(event_id)
                        .unwrap()
                        .iter()
                        .map(|x| KeyPair::from_secret_key(&self.secp, *x))
                        .collect::<Vec<_>>(),
                )
                .unwrap(),
            )
            .unwrap(),
            oracle_event,
        )
        .unwrap();
        self.announcements
            .insert(event_id.to_string(), announcement);
    }

    pub fn add_attestation(&mut self, event_id: &str, outcomes: &[String]) {
        let nonces = self.nonces.get(event_id).unwrap();
        let signatures = outcomes
            .iter()
            .zip(nonces.iter())
            .map(|(x, nonce)| {
                let msg =
                    Message::from_hashed_data::<secp256k1_zkp::hashes::sha256::Hash>(x.as_bytes());
                dlc::secp_utils::schnorrsig_sign_with_nonce(
                    &self.secp,
                    &msg,
                    &self.attestation_key_pair,
                    nonce.as_ref(),
                )
            })
            .collect();
        let attestation = SchnorrAttestation {
            event_id: event_id.to_string(),
            oracle_public_key: self.get_attestation_public_key(),
            signatures,
            outcomes: outcomes.to_vec(),
        };
        self.attestations.insert(event_id.to_string(), attestation);
    }
}
