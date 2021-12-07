//! Data structure and functions related to peer communication.

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
pub mod oracle_msgs;

#[cfg(any(test, feature = "serde"))]
pub mod serde_utils;

use bitcoin::{consensus::Decodable, hash_types::Txid, OutPoint, Script, Transaction};
use contract_msgs::ContractInfo;
use dlc::TxInputInfo;
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::bitcoin_hashes::*;
use secp256k1_zkp::EcdsaAdaptorSignature;
use secp256k1_zkp::{PublicKey, Signature};
use ser_impls::{read_ecdsa_adaptor_signature, write_ecdsa_adaptor_signature};

pub const OFFER_TYPE: u16 = 42778;

pub const ACCEPT_TYPE: u16 = 42780;

pub const SIGN_TYPE: u16 = 42782;

/// Contains information about a specific input to be used in a funding transaction,
/// as well as its corresponding on-chain UTXO.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct FundingInput {
    pub input_serial_id: u64,
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_string"
        )
    )]
    pub prev_tx: Vec<u8>,
    pub prev_tx_vout: u32,
    pub sequence: u32,
    pub max_witness_len: u16,
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

/// Contains an adaptor signature for a CET input and its associated DLEQ proof.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct CetAdaptorSignature {
    pub signature: EcdsaAdaptorSignature,
}

impl_dlc_writeable!(CetAdaptorSignature, {
     (signature, { cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature })
});

/// Contains a list of adaptor signature for a number of CET inputs.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct CetAdaptorSignatures {
    pub ecdsa_adaptor_signatures: Vec<CetAdaptorSignature>,
}

impl From<Vec<EcdsaAdaptorSignature>> for CetAdaptorSignatures {
    fn from(signatures: Vec<EcdsaAdaptorSignature>) -> Self {
        CetAdaptorSignatures {
            ecdsa_adaptor_signatures: signatures
                .iter()
                .map(|x| CetAdaptorSignature {
                    signature: x.clone(),
                })
                .collect(),
        }
    }
}

impl_dlc_writeable!(CetAdaptorSignatures, { (ecdsa_adaptor_signatures, vec) });

/// Contains the witness elements to use to make a funding transaction input valid.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct FundingSignature {
    pub witness_elements: Vec<WitnessElement>,
}

impl_dlc_writeable!(FundingSignature, { (witness_elements, vec) });

/// Contains a list of witness elements to satisfy the spending conditions of
/// funding inputs.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct FundingSignatures {
    pub funding_signatures: Vec<FundingSignature>,
}

impl_dlc_writeable!(FundingSignatures, { (funding_signatures, vec) });

/// Contains serialized data representing a single witness stack element.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct WitnessElement {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_string"
        )
    )]
    pub witness: Vec<u8>,
}

impl_dlc_writeable!(WitnessElement, { (witness, vec) });

///
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum NegotiationFields {
    Single(SingleNegotiationFields),
    Disjoint(DisjointNegotiationFields),
}

impl_dlc_writeable_enum!(NegotiationFields, (0, Single), (1, Disjoint);;);

///
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SingleNegotiationFields {
    rounding_intervals: contract_msgs::RoundingIntervals,
}

impl_dlc_writeable!(SingleNegotiationFields, { (rounding_intervals, writeable) });

///
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct DisjointNegotiationFields {
    negotiation_fields: Vec<NegotiationFields>,
}

impl_dlc_writeable!(DisjointNegotiationFields, { (negotiation_fields, vec) });

/// Contains information about a party wishing to enter into a DLC with
/// another party. The contained information is sufficient for any other party
/// to create a set of transactions representing the contract and its terms.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct OfferDlc {
    pub protocol_version: u32,
    pub contract_flags: u8,
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    pub chain_hash: [u8; 32],
    pub contract_info: ContractInfo,
    pub funding_pubkey: PublicKey,
    pub payout_spk: Script,
    pub payout_serial_id: u64,
    pub offer_collateral: u64,
    pub funding_inputs: Vec<FundingInput>,
    pub change_spk: Script,
    pub change_serial_id: u64,
    pub fund_output_serial_id: u64,
    pub fee_rate_per_vb: u64,
    pub contract_maturity_bound: u32,
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
    pub temporary_contract_id: [u8; 32],
    pub accept_collateral: u64,
    pub funding_pubkey: PublicKey,
    pub payout_spk: Script,
    pub payout_serial_id: u64,
    pub funding_inputs: Vec<FundingInput>,
    pub change_spk: Script,
    pub change_serial_id: u64,
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    pub refund_signature: Signature,
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
    pub contract_id: [u8; 32],
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    pub refund_signature: Signature,
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
#[derive(Debug)]
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

/// Compute the ID of a DLC based on the fund transaction ID and temporary contract ID.
pub fn compute_contract_id(
    fund_tx_id: Txid,
    fund_ouput_index: u16,
    temporary_contract_id: [u8; 32],
) -> [u8; 32] {
    let mut res = [0; 32];
    for i in 0..32 {
        res[i] = fund_tx_id[31 - i] ^ temporary_contract_id[i];
    }
    res[0] ^= ((fund_ouput_index >> 8) & 0xff) as u8;
    res[1] ^= ((fund_ouput_index >> 0) & 0xff) as u8;
    res
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
