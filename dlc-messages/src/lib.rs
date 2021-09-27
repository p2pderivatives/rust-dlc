//! Data structure and functions related to peer communication.

extern crate bitcoin;
#[macro_use]
extern crate lightning;
extern crate dlc;
extern crate secp256k1_zkp;

#[cfg(test)]
extern crate bitcoin_test_utils;
#[cfg(any(test, feature = "serde"))]
extern crate serde;

#[cfg(test)]
extern crate serde_json;

pub mod contract_msgs;
pub mod oracle_msgs;
pub mod utils;

use bitcoin::{consensus::Decodable, hash_types::Txid, OutPoint, Script, Transaction};
use dlc::TxInputInfo;
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::{write, Type};
use lightning::util::ser::{BigSize, Readable, Writeable, Writer};
use secp256k1_zkp::bitcoin_hashes::*;
use secp256k1_zkp::ffi::ECDSA_ADAPTOR_SIGNATURE_LENGTH;
use secp256k1_zkp::EcdsaAdaptorSignature;
use secp256k1_zkp::{PublicKey, Signature};
use utils::{read_vec, write_vec};

use contract_msgs::ContractInfo;

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
    pub prev_tx: Vec<u8>,
    pub prev_tx_vout: u32,
    pub sequence: u32,
    pub max_witness_len: u16,
    pub redeem_script: Script,
}

impl_writeable!(FundingInput, 0, {
    input_serial_id, prev_tx, prev_tx_vout, sequence, max_witness_len, redeem_script
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

impl Writeable for CetAdaptorSignature {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        let mut ser_sig = [0; ECDSA_ADAPTOR_SIGNATURE_LENGTH];
        ser_sig.copy_from_slice(&self.signature.as_ref());
        ser_sig.write(writer)
    }
}

impl Readable for CetAdaptorSignature {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<CetAdaptorSignature, DecodeError> {
        let sig_buf: [u8; ECDSA_ADAPTOR_SIGNATURE_LENGTH] = Readable::read(reader)?;
        let signature = match EcdsaAdaptorSignature::from_slice(&sig_buf) {
            Ok(sig) => sig,
            Err(_) => return Err(DecodeError::InvalidValue),
        };

        Ok(CetAdaptorSignature { signature })
    }
}

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

impl Writeable for CetAdaptorSignatures {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        (BigSize(self.ecdsa_adaptor_signatures.len() as u64)).write(writer)?;
        for ref sig in &self.ecdsa_adaptor_signatures {
            sig.write(writer)?;
        }

        Ok(())
    }
}

impl Readable for CetAdaptorSignatures {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<CetAdaptorSignatures, DecodeError> {
        let sig_count: BigSize = Readable::read(reader)?;
        let mut sigs: Vec<CetAdaptorSignature> = Vec::with_capacity(sig_count.0 as usize);
        for _ in 0..sig_count.0 {
            sigs.push(Readable::read(reader)?);
        }

        Ok(CetAdaptorSignatures {
            ecdsa_adaptor_signatures: sigs,
        })
    }
}

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

impl Writeable for FundingSignature {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_vec(&self.witness_elements, writer)
    }
}

impl Readable for FundingSignature {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<FundingSignature, DecodeError> {
        let witness_elements = read_vec(reader)?;

        Ok(FundingSignature { witness_elements })
    }
}

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

impl Writeable for FundingSignatures {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_vec(&self.funding_signatures, writer)
    }
}

impl Readable for FundingSignatures {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<FundingSignatures, DecodeError> {
        let funding_signatures = read_vec(reader)?;

        Ok(FundingSignatures { funding_signatures })
    }
}

/// Contains serialized data representing a single witness stack element.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct WitnessElement {
    pub witness: Vec<u8>,
}

impl Writeable for WitnessElement {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.witness.write(writer)
    }
}

impl Readable for WitnessElement {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<WitnessElement, DecodeError> {
        let witness = Readable::read(reader)?;
        Ok(WitnessElement { witness })
    }
}

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
    pub contract_flags: u8,
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
        write(self, &mut buff)?;
        Ok(sha256::Hash::hash(&buff).into_inner())
    }

    pub fn get_total_collateral(&self) -> u64 {
        match &self.contract_info {
            ContractInfo::SingleContractInfo(single) => single.total_collateral,
            ContractInfo::DisjointContractInfo(disjoint) => disjoint.total_collateral,
        }
    }
}

impl Writeable for OfferDlc {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.contract_flags.write(writer)?;
        self.chain_hash.write(writer)?;
        self.contract_info.write(writer)?;
        self.funding_pubkey.write(writer)?;
        self.payout_spk.write(writer)?;
        self.payout_serial_id.write(writer)?;
        self.offer_collateral.write(writer)?;
        write_vec(&self.funding_inputs, writer)?;
        self.change_spk.write(writer)?;
        self.change_serial_id.write(writer)?;
        self.fund_output_serial_id.write(writer)?;
        self.fee_rate_per_vb.write(writer)?;
        self.contract_maturity_bound.write(writer)?;
        self.contract_timeout.write(writer)
    }
}

impl Readable for OfferDlc {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OfferDlc, DecodeError> {
        let contract_flags = Readable::read(reader)?;
        let chain_hash = Readable::read(reader)?;
        let contract_info: ContractInfo = Readable::read(reader)?;
        let funding_pubkey = Readable::read(reader)?;
        let payout_spk = Readable::read(reader)?;
        let payout_serial_id = Readable::read(reader)?;
        let offer_collateral = Readable::read(reader)?;
        let funding_inputs = read_vec(reader)?;
        let change_spk = Readable::read(reader)?;
        let change_serial_id = Readable::read(reader)?;
        let fund_output_serial_id = Readable::read(reader)?;
        let fee_rate_per_vb = Readable::read(reader)?;
        let contract_maturity_bound = Readable::read(reader)?;
        let contract_timeout = Readable::read(reader)?;

        Ok(OfferDlc {
            contract_flags,
            chain_hash,
            contract_info,
            funding_pubkey,
            payout_spk,
            payout_serial_id,
            offer_collateral,
            funding_inputs,
            change_spk,
            change_serial_id,
            fund_output_serial_id,
            fee_rate_per_vb,
            contract_maturity_bound,
            contract_timeout,
        })
    }
}

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
}

impl Writeable for AcceptDlc {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.temporary_contract_id.write(writer)?;
        self.accept_collateral.write(writer)?;
        self.funding_pubkey.write(writer)?;
        self.payout_spk.write(writer)?;
        self.payout_serial_id.write(writer)?;
        write_vec(&self.funding_inputs, writer)?;
        self.change_spk.write(writer)?;
        self.change_serial_id.write(writer)?;
        self.cet_adaptor_signatures.write(writer)?;
        self.refund_signature.write(writer)
    }
}

impl Readable for AcceptDlc {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<AcceptDlc, DecodeError> {
        let temporary_contract_id = Readable::read(reader)?;
        let accept_collateral = Readable::read(reader)?;
        let funding_pubkey = Readable::read(reader)?;
        let payout_spk = Readable::read(reader)?;
        let payout_serial_id = Readable::read(reader)?;
        let funding_inputs = read_vec(reader)?;
        let change_spk = Readable::read(reader)?;
        let change_serial_id = Readable::read(reader)?;
        let cet_adaptor_signatures = Readable::read(reader)?;
        let refund_signature = Readable::read(reader)?;

        Ok(AcceptDlc {
            temporary_contract_id,
            accept_collateral,
            funding_pubkey,
            payout_spk,
            payout_serial_id,
            funding_inputs,
            change_spk,
            change_serial_id,
            cet_adaptor_signatures,
            refund_signature,
        })
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
    pub contract_id: [u8; 32],
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    pub refund_signature: Signature,
    pub funding_signatures: FundingSignatures,
}

impl Writeable for SignDlc {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.contract_id.write(writer)?;
        self.cet_adaptor_signatures.write(writer)?;
        self.refund_signature.write(writer)?;
        self.funding_signatures.write(writer)?;
        Ok(())
    }
}

impl Readable for SignDlc {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<SignDlc, DecodeError> {
        let contract_id = Readable::read(reader)?;
        let cet_adaptor_signatures = Readable::read(reader)?;
        let refund_signature = Readable::read(reader)?;
        let funding_signatures = Readable::read(reader)?;

        Ok(SignDlc {
            contract_id,
            cet_adaptor_signatures,
            refund_signature,
            funding_signatures,
        })
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
            Message::Offer(_) => OFFER_TYPE,
            Message::Accept(_) => ACCEPT_TYPE,
            Message::Sign(_) => SIGN_TYPE,
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
