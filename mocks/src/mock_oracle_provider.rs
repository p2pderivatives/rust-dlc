use bitcoin::hashes::Hash;
use dlc_manager::error::Error as DaemonError;
use dlc_manager::Oracle;
use dlc_messages::oracle_msgs::{
    EventDescriptor, OracleAnnouncement, OracleAttestation, OracleEvent,
};
use lightning::util::ser::Writeable;
use secp256k1_zkp::rand::thread_rng;
use secp256k1_zkp::SecretKey;
use secp256k1_zkp::{All, Message, Secp256k1};
use secp256k1_zkp::{Keypair, XOnlyPublicKey};

use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct MockOracle {
    key_pair: Keypair,
    secp: Secp256k1<All>,
    announcements: HashMap<String, OracleAnnouncement>,
    attestations: HashMap<String, OracleAttestation>,
    nonces: HashMap<String, Vec<SecretKey>>,
}

impl MockOracle {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let key_pair = Keypair::new(&secp, &mut thread_rng());

        MockOracle {
            secp,
            key_pair,
            announcements: HashMap::new(),
            attestations: HashMap::new(),
            nonces: HashMap::new(),
        }
    }

    pub fn from_secret_key(sk: &SecretKey) -> Self {
        let secp = Secp256k1::new();
        let key_pair = Keypair::from_secret_key(&secp, sk);

        MockOracle {
            secp,
            key_pair,
            announcements: HashMap::new(),
            attestations: HashMap::new(),
            nonces: HashMap::new(),
        }
    }
}

impl Default for MockOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl Oracle for MockOracle {
    fn get_public_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_keypair(&self.key_pair).0
    }

    fn get_announcement(&self, event_id: &str) -> Result<OracleAnnouncement, DaemonError> {
        let res = self
            .announcements
            .get(event_id)
            .ok_or_else(|| DaemonError::OracleError("Announcement not found".to_string()))?;
        Ok(res.clone())
    }

    fn get_attestation(&self, event_id: &str) -> Result<OracleAttestation, DaemonError> {
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
            .map(|x| Keypair::from_seckey_slice(&self.secp, x.as_ref()).unwrap())
            .collect();

        let nonces = key_pairs
            .iter()
            .map(|k| XOnlyPublicKey::from_keypair(k).0)
            .collect();

        self.nonces.insert(event_id.to_string(), priv_nonces);

        nonces
    }

    pub fn add_event(&mut self, event_id: &str, event_descriptor: &EventDescriptor, maturity: u32) {
        let oracle_nonces = self.generate_nonces_for_event(event_id, event_descriptor);
        let oracle_event = OracleEvent {
            oracle_nonces,
            event_maturity_epoch: maturity,
            event_descriptor: event_descriptor.clone(),
            event_id: event_id.to_string(),
        };
        let mut event_hex = Vec::new();
        oracle_event
            .write(&mut event_hex)
            .expect("Error writing oracle event");
        let hash = bitcoin::hashes::sha256::Hash::hash(&event_hex).to_byte_array();
        let msg = Message::from_digest(hash);
        let sig = self.secp.sign_schnorr(&msg, &self.key_pair);
        let announcement = OracleAnnouncement {
            oracle_event,
            oracle_public_key: self.get_public_key(),
            announcement_signature: sig,
        };
        self.announcements
            .insert(event_id.to_string(), announcement);
    }

    pub fn add_attestation(&mut self, event_id: &str, outcomes: &[String]) {
        let nonces = self.nonces.get(event_id).unwrap();
        let signatures = outcomes
            .iter()
            .zip(nonces.iter())
            .map(|(x, nonce)| {
                let hash = bitcoin::hashes::sha256::Hash::hash(x.as_bytes()).to_byte_array();
                let msg = Message::from_digest(hash);
                dlc::secp_utils::schnorrsig_sign_with_nonce(
                    &self.secp,
                    &msg,
                    &self.key_pair,
                    nonce.as_ref(),
                )
            })
            .collect();
        let attestation = OracleAttestation {
            oracle_public_key: self.get_public_key(),
            signatures,
            outcomes: outcomes.to_vec(),
        };
        self.attestations.insert(event_id.to_string(), attestation);
    }
}
