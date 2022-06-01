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
use dlc::{Error, TxInputInfo};
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::Secp256k1;
use secp256k1_zkp::{EcdsaAdaptorSignature, Signing};
use secp256k1_zkp::{PublicKey, Signature};
use segmentation::{SegmentChunk, SegmentStart};

macro_rules! impl_type {
    ($const_name: ident, $type_name: ident, $type_val: expr) => {
        /// The type prefix for an [`$type_name`] message.
        pub const $const_name: u16 = $type_val;

        impl Type for $type_name {
            fn type_id(&self) -> u16 {
                $const_name
            }
        }
    };
}

impl_type!(OFFER_TYPE, OfferDlc, 42778);
impl_type!(ACCEPT_TYPE, AcceptDlc, 42780);
impl_type!(SIGN_TYPE, SignDlc, 42782);

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

impl From<&[EcdsaAdaptorSignature]> for CetAdaptorSignatures {
    fn from(signatures: &[EcdsaAdaptorSignature]) -> Self {
        CetAdaptorSignatures {
            ecdsa_adaptor_signatures: signatures
                .iter()
                .map(|x| CetAdaptorSignature { signature: *x })
                .collect(),
        }
    }
}

impl From<&CetAdaptorSignatures> for Vec<EcdsaAdaptorSignature> {
    fn from(signatures: &CetAdaptorSignatures) -> Vec<EcdsaAdaptorSignature> {
        signatures
            .ecdsa_adaptor_signatures
            .iter()
            .map(|x| x.signature)
            .collect::<Vec<_>>()
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
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// Temporary contract id to identify the contract.
    pub temporary_contract_id: [u8; 32],
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
    /// The lock time for the CETs.
    pub cet_locktime: u32,
    /// The lock time for the refund transactions.
    pub refund_locktime: u32,
}

impl OfferDlc {
    /// Returns the total collateral locked in the contract.
    pub fn get_total_collateral(&self) -> u64 {
        match &self.contract_info {
            ContractInfo::SingleContractInfo(single) => single.total_collateral,
            ContractInfo::DisjointContractInfo(disjoint) => disjoint.total_collateral,
        }
    }

    /// Returns whether the message satisfies validity requirements.
    pub fn validate<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        min_timeout_interval: u32,
        max_timeout_interval: u32,
    ) -> Result<(), Error> {
        let closest_maturity_date = self.contract_info.get_closest_maturity_date();
        let valid_dates = self.cet_locktime <= closest_maturity_date
            && closest_maturity_date + min_timeout_interval <= self.refund_locktime
            && self.refund_locktime <= closest_maturity_date + max_timeout_interval;
        if !valid_dates {
            return Err(Error::InvalidArgument);
        }

        match &self.contract_info {
            ContractInfo::SingleContractInfo(s) => s.contract_info.oracle_info.validate(secp)?,
            ContractInfo::DisjointContractInfo(d) => {
                for c in &d.contract_infos {
                    c.oracle_info.validate(secp)?;
                }
            }
        }

        Ok(())
    }
}

impl_dlc_writeable!(OfferDlc, {
        (protocol_version, writeable),
        (contract_flags, writeable),
        (chain_hash, writeable),
        (temporary_contract_id, writeable),
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
        (cet_locktime, writeable),
        (refund_locktime, writeable)
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
    /// The version of the protocol used by the peer.
    pub protocol_version: u32,
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
    (protocol_version, writeable),
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

/// Contains all the required signatures for the DLC transactions from the offering
/// party.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SignDlc {
    /// The version of the protocol used by the peer.
    pub protocol_version: u32,
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
    (protocol_version, writeable),
    (contract_id, writeable),
    (cet_adaptor_signatures, writeable),
    (refund_signature, writeable),
    (funding_signatures, writeable)
});

#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub enum Message {
    Offer(OfferDlc),
    Accept(AcceptDlc),
    Sign(SignDlc),
}

macro_rules! impl_type_writeable_for_enum {
    ($type_name: ident, {$($variant_name: ident),*}) => {
       impl Type for $type_name {
           fn type_id(&self) -> u16 {
               match self {
                   $($type_name::$variant_name(v) => v.type_id(),)*
               }
           }
       }

       impl Writeable for $type_name {
            fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
                match self {
                   $($type_name::$variant_name(v) => v.write(writer),)*
                }
            }
       }
    };
}

impl_type_writeable_for_enum!(Message,
{
    Offer,
    Accept,
    Sign
});

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

impl_type_writeable_for_enum!(WireMessage, { Message, SegmentStart, SegmentChunk });

#[cfg(test)]
mod tests {
    use secp256k1_zkp::SECP256K1;

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

    #[test]
    fn valid_offer_message_passes_validation() {
        let input = include_str!("./test_inputs/offer_msg.json");
        let valid_offer: OfferDlc = serde_json::from_str(&input).unwrap();
        valid_offer
            .validate(SECP256K1, 86400 * 7, 86400 * 14)
            .expect("to validate valid offer messages.");
    }

    #[test]
    fn invalid_offer_messages_fail_validation() {
        let input = include_str!("./test_inputs/offer_msg.json");
        let offer: OfferDlc = serde_json::from_str(&input).unwrap();

        let mut invalid_maturity = offer.clone();
        invalid_maturity.cet_locktime += 3;

        let mut too_short_timeout = offer.clone();
        too_short_timeout.refund_locktime -= 100;

        let mut too_long_timeout = offer.clone();
        too_long_timeout.refund_locktime -= 100;

        for invalid in &[invalid_maturity, too_short_timeout, too_long_timeout] {
            invalid
                .validate(SECP256K1, 86400 * 7, 86400 * 14)
                .expect_err("Should not pass validation of invalid offer message.");
        }
    }
}
