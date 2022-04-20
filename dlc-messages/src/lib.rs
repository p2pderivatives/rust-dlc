//! Data structure and functions related to peer communication.

// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

extern crate bitcoin;
extern crate dlc;
extern crate lightning;
extern crate secp256k1_zkp;
#[macro_use]
pub mod ser_macros;
pub mod ser_impls;

#[cfg(test)]
extern crate bitcoin_test_utils;
#[cfg(any(test, feature = "serde"))]
extern crate serde;

#[cfg(test)]
extern crate serde_json;

pub mod contract_msgs;
pub mod message_handler;
pub mod oracle_msgs;
pub mod segmentation;

#[cfg(any(test, feature = "serde"))]
pub mod serde_utils;

use std::fmt::Display;

use crate::ser_impls::{read_ecdsa_adaptor_signature, write_ecdsa_adaptor_signature};
use bitcoin::{consensus::Decodable, OutPoint, Script, Transaction};
use contract_msgs::ContractInfo;
use dlc::TxInputInfo;
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::bitcoin_hashes::*;
use secp256k1_zkp::EcdsaAdaptorSignature;
use secp256k1_zkp::{PublicKey, Signature};
use segmentation::{SegmentChunk, SegmentStart};

/// The type prefix for an [`OfferDlc`] message.
pub const OFFER_TYPE: u16 = 42778;

/// The type prefix for an [`AcceptDlc`] message.
pub const ACCEPT_TYPE: u16 = 42780;

/// The type prefix for a [`SignDlc`] message.
pub const SIGN_TYPE: u16 = 42782;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains information about a specific input to be used in a funding transaction,
/// as well as its corresponding on-chain UTXO.
pub struct FundingInput {
    /// Serial id used for input ordering in the funding transaction.
    pub input_serial_id: u64,
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_string"
        )
    )]
    /// The previous transaction used by the associated input in serialized format.
    pub prev_tx: Vec<u8>,
    /// The vout of the output used by the associated input.
    pub prev_tx_vout: u32,
    /// The sequence number to use for the input.
    pub sequence: u32,
    /// The maximum witness length that can be used to spend the previous UTXO.
    pub max_witness_len: u16,
    /// The redeem script of the previous UTXO.
    pub redeem_script: Script,
}

impl_dlc_writeable!(FundingInput, {
    (input_serial_id, writeable),
    (prev_tx, vec),
    (prev_tx_vout, writeable),
    (sequence, writeable),
    (max_witness_len, writeable),
    (redeem_script, writeable)
});

impl From<&FundingInput> for TxInputInfo {
    fn from(funding_input: &FundingInput) -> TxInputInfo {
        TxInputInfo {
            outpoint: OutPoint {
                txid: Transaction::consensus_decode(&funding_input.prev_tx[..])
                    .expect("Transaction Decode Error")
                    .txid(),
                vout: funding_input.prev_tx_vout,
            },
            max_witness_len: (funding_input.max_witness_len as usize),
            redeem_script: funding_input.redeem_script.clone(),
            serial_id: funding_input.input_serial_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains an adaptor signature for a CET input and its associated DLEQ proof.
pub struct CetAdaptorSignature {
    /// The signature.
    pub signature: EcdsaAdaptorSignature,
}

impl_dlc_writeable!(CetAdaptorSignature, {
     (signature, { cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature })
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains a list of adaptor signature for a number of CET inputs.
pub struct CetAdaptorSignatures {
    /// The set of signatures.
    pub ecdsa_adaptor_signatures: Vec<CetAdaptorSignature>,
}

impl From<Vec<EcdsaAdaptorSignature>> for CetAdaptorSignatures {
    fn from(signatures: Vec<EcdsaAdaptorSignature>) -> Self {
        CetAdaptorSignatures {
            ecdsa_adaptor_signatures: signatures
                .iter()
                .map(|x| CetAdaptorSignature { signature: *x })
                .collect(),
        }
    }
}

impl_dlc_writeable!(CetAdaptorSignatures, { (ecdsa_adaptor_signatures, vec) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains the witness elements to use to make a funding transaction input valid.
pub struct FundingSignature {
    /// The set of witness elements.
    pub witness_elements: Vec<WitnessElement>,
}

impl_dlc_writeable!(FundingSignature, { (witness_elements, vec) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains a list of witness elements to satisfy the spending conditions of
/// funding inputs.
pub struct FundingSignatures {
    /// The set of funding signatures.
    pub funding_signatures: Vec<FundingSignature>,
}

impl_dlc_writeable!(FundingSignatures, { (funding_signatures, vec) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains serialized data representing a single witness stack element.
pub struct WitnessElement {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_string"
        )
    )]
    /// The serialized witness data.
    pub witness: Vec<u8>,
}

impl_dlc_writeable!(WitnessElement, { (witness, vec) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Fields used to negotiate contract information.
pub enum NegotiationFields {
    /// Negotiation for single event based contract.
    Single(SingleNegotiationFields),
    /// Negotiation for multiple event based contract.
    Disjoint(DisjointNegotiationFields),
}

impl_dlc_writeable_enum!(NegotiationFields, (0, Single), (1, Disjoint);;);

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Negotiation fields for contract based on a single event.
pub struct SingleNegotiationFields {
    /// Proposed rounding intervals.
    rounding_intervals: contract_msgs::RoundingIntervals,
}

impl_dlc_writeable!(SingleNegotiationFields, { (rounding_intervals, writeable) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Negotiation fields for contract based on multiple events.
pub struct DisjointNegotiationFields {
    /// The negotiation fields for each contract event.
    negotiation_fields: Vec<NegotiationFields>,
}

impl_dlc_writeable!(DisjointNegotiationFields, { (negotiation_fields, vec) });

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Contains information about a party wishing to enter into a DLC with
/// another party. The contained information is sufficient for any other party
/// to create a set of transactions representing the contract and its terms.
pub struct OfferDlc {
    /// The version of the protocol used by the peer.
    pub protocol_version: u32,
    /// Feature flags to be used for the offered contract.
    pub contract_flags: u8,
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The identifier of the chain on which the contract will be settled.
    pub chain_hash: [u8; 32],
    /// Information about the contract event, payouts and oracles.
    pub contract_info: ContractInfo,
    /// The public key of the offerer to be used to lock the collateral.
    pub funding_pubkey: PublicKey,
    /// The SPK where the offerer will receive their payout.
    pub payout_spk: Script,
    /// Serial id to order CET outputs.
    pub payout_serial_id: u64,
    /// Collateral of the offer party.
    pub offer_collateral: u64,
    /// Inputs used by the offer party to fund the contract.
    pub funding_inputs: Vec<FundingInput>,
    /// The SPK where the offer party will receive their change.
    pub change_spk: Script,
    /// Serial id to order funding transaction outputs.
    pub change_serial_id: u64,
    /// Serial id to order funding transaction outputs.
    pub fund_output_serial_id: u64,
    /// The fee rate to use to compute transaction fees for this contract.
    pub fee_rate_per_vb: u64,
    /// The expected maturity of the contract.
    pub contract_maturity_bound: u32,
    /// The time at which the contract can be refunded.
    pub contract_timeout: u32,
}

impl Type for OfferDlc {
    fn type_id(&self) -> u16 {
        OFFER_TYPE
    }
}

impl OfferDlc {
    /// Returns the hash of the serialized OfferDlc message.
    pub fn get_hash(&self) -> Result<[u8; 32], ::std::io::Error> {
        let mut buff = Vec::new();
        self.write(&mut buff)?;
        Ok(sha256::Hash::hash(&buff).into_inner())
    }

    /// Returns the total collateral locked in the contract.
    pub fn get_total_collateral(&self) -> u64 {
        match &self.contract_info {
            ContractInfo::SingleContractInfo(single) => single.total_collateral,
            ContractInfo::DisjointContractInfo(disjoint) => disjoint.total_collateral,
        }
    }
}

impl_dlc_writeable!(OfferDlc, {
        (protocol_version, writeable),
        (contract_flags, writeable),
        (chain_hash, writeable),
        (contract_info, writeable),
        (funding_pubkey, writeable),
        (payout_spk, writeable),
        (payout_serial_id, writeable),
        (offer_collateral, writeable),
        (funding_inputs, vec),
        (change_spk, writeable),
        (change_serial_id, writeable),
        (fund_output_serial_id, writeable),
        (fee_rate_per_vb, writeable),
        (contract_maturity_bound, writeable),
        (contract_timeout, writeable)
});

/// Contains information about a party wishing to accept a DLC offer. The contained
/// information is sufficient for the offering party to re-build the set of
/// transactions representing the contract and its terms, and guarantees the offering
/// party that they can safely provide signatures for their funding input.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct AcceptDlc {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The temporary contract id for the contract.
    pub temporary_contract_id: [u8; 32],
    /// The collateral input by the accept party.
    pub accept_collateral: u64,
    /// The public key of the accept party to be used to lock the collateral.
    pub funding_pubkey: PublicKey,
    /// The SPK where the accept party will receive their payout.
    pub payout_spk: Script,
    /// Serial id to order CET outputs.
    pub payout_serial_id: u64,
    /// Inputs used by the accept party to fund the contract.
    pub funding_inputs: Vec<FundingInput>,
    /// The SPK where the accept party will receive their change.
    pub change_spk: Script,
    /// Serial id to order funding transaction outputs.
    pub change_serial_id: u64,
    /// The set of adaptor signatures from the accept party.
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    /// The refund signature of the accept party.
    pub refund_signature: Signature,
    /// The negotiation fields from the accept party.
    pub negotiation_fields: Option<NegotiationFields>,
}

impl_dlc_writeable!(AcceptDlc, {
    (temporary_contract_id, writeable),
    (accept_collateral, writeable),
    (funding_pubkey, writeable),
    (payout_spk, writeable),
    (payout_serial_id, writeable),
    (funding_inputs, vec),
    (change_spk, writeable),
    (change_serial_id, writeable),
    (cet_adaptor_signatures, writeable),
    (refund_signature, writeable),
    (negotiation_fields, option)
});

impl Type for AcceptDlc {
    fn type_id(&self) -> u16 {
        ACCEPT_TYPE
    }
}

/// Contains all the required signatures for the DLC transactions from the offering
/// party.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SignDlc {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the contract referred to by this message.
    pub contract_id: [u8; 32],
    /// The set of adaptor signatures from the offer party.
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    /// The refund signature from the offer party.
    pub refund_signature: Signature,
    /// The set of funding signatures from the offer party.
    pub funding_signatures: FundingSignatures,
}

impl_dlc_writeable!(SignDlc, {
    (contract_id, writeable),
    (cet_adaptor_signatures, writeable),
    (refund_signature, writeable),
    (funding_signatures, writeable)
});

impl Type for SignDlc {
    fn type_id(&self) -> u16 {
        SIGN_TYPE
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub enum Message {
    Offer(OfferDlc),
    Accept(AcceptDlc),
    Sign(SignDlc),
}

impl Type for Message {
    fn type_id(&self) -> u16 {
        match self {
            Message::Offer(o) => o.type_id(),
            Message::Accept(a) => a.type_id(),
            Message::Sign(s) => s.type_id(),
        }
    }
}

impl Writeable for Message {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        match self {
            Message::Offer(o) => o.write(writer),
            Message::Accept(a) => a.write(writer),
            Message::Sign(s) => s.write(writer),
        }
    }
}

#[derive(Debug, Clone)]
/// Wrapper for DLC related message and segmentation related messages.
pub enum WireMessage {
    /// Message related to establishment of a DLC contract.
    Message(Message),
    /// Message indicating an incoming segmented message.
    SegmentStart(SegmentStart),
    /// Message providing a chunk of a segmented message.
    SegmentChunk(SegmentChunk),
}

impl Display for WireMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Message(_) => "Message",
            Self::SegmentStart(_) => "SegmentStart",
            Self::SegmentChunk(_) => "SegmentChunk",
        };
        f.write_str(name)
    }
}

impl Type for WireMessage {
    fn type_id(&self) -> u16 {
        match self {
            WireMessage::Message(m) => m.type_id(),
            WireMessage::SegmentStart(s) => s.type_id(),
            WireMessage::SegmentChunk(s) => s.type_id(),
        }
    }
}

impl Writeable for WireMessage {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        match self {
            WireMessage::Message(m) => m.write(writer),
            WireMessage::SegmentStart(s) => s.write(writer),
            WireMessage::SegmentChunk(s) => s.write(writer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! roundtrip_test {
        ($type: ty, $input: ident) => {
            let msg: $type = serde_json::from_str(&$input).unwrap();
            test_roundtrip(msg);
        };
    }

    fn test_roundtrip<T: Writeable + Readable + PartialEq + std::fmt::Debug>(msg: T) {
        let mut buf = Vec::new();
        msg.write(&mut buf).expect("Error writing message");
        let mut cursor = std::io::Cursor::new(&buf);
        let deser = Readable::read(&mut cursor).expect("Error reading message");
        assert_eq!(msg, deser);
    }

    #[test]
    fn offer_msg_roundtrip() {
        let input = include_str!("./test_inputs/offer_msg.json");
        roundtrip_test!(OfferDlc, input);
    }

    #[test]
    fn accept_msg_roundtrip() {
        let input = include_str!("./test_inputs/accept_msg.json");
        roundtrip_test!(AcceptDlc, input);
    }

    #[test]
    fn sign_msg_roundtrip() {
        let input = include_str!("./test_inputs/sign_msg.json");
        roundtrip_test!(SignDlc, input);
    }
}
