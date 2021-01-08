//! Data structure and functions related to peer communication.

extern crate bitcoin;
#[macro_use]
extern crate lightning;
extern crate dlc;
extern crate secp256k1;
extern crate unicode_normalization;

#[cfg(any(test, feature = "serde"))]
extern crate serde;

#[cfg(test)]
extern crate serde_json;

use bitcoin::hashes::*;
use bitcoin::{consensus::Decodable, hash_types::Txid, OutPoint, Script, Transaction};
use dlc::TxInputInfo;
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::{write, Encode, MessageType};
use lightning::util::ser::{BigSize, Readable, Writeable, Writer};
use secp256k1::ecdsa_adaptor::{AdaptorProof, AdaptorSignature};
use secp256k1::schnorrsig::PublicKey as SchnorrPublicKey;
use secp256k1::{constants, PublicKey, Signature};
use unicode_normalization::UnicodeNormalization;

const CONTRACT_INFO_TYPE: u64 = 42768;
const ORACLE_INFO_TYPE: u64 = 42770;
const FUNDING_INPUT_TYPE: u64 = 42772;
const CET_ADAPTOR_SIGNATURES_TYPE: u64 = 42774;
const FUNDING_SIGNATURES_TYPE: u64 = 42776;

/// Represents a single outcome of a DLC contract and the associated offer party
/// payout.
#[derive(Clone, PartialEq)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "camelCase")
)]
pub struct ContractOutcome {
    pub outcome: String,
    pub local_payout: u64,
}

fn write_string<W: Writer>(input: &str, writer: &mut W) -> Result<(), ::std::io::Error> {
    let nfced = input.nfc().collect::<String>();
    let len = BigSize(nfced.len() as u64);
    len.write(writer)?;
    let bytes = nfced.as_bytes();

    for b in bytes {
        b.write(writer)?;
    }

    Ok(())
}

impl Writeable for ContractOutcome {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        write_string(&self.outcome, writer)?;

        self.local_payout.write(writer)?;
        Ok(())
    }
}

impl Readable for ContractOutcome {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<ContractOutcome, DecodeError> {
        let len: BigSize = Readable::read(reader)?;
        let mut outcome_vec = Vec::with_capacity(len.0 as usize);

        for _ in 0..len.0 {
            let b: u8 = Readable::read(reader)?;
            outcome_vec.push(b);
        }

        let outcome = match String::from_utf8(outcome_vec) {
            Ok(s) => s,
            Err(_) => return Err(DecodeError::InvalidValue),
        };

        let local_payout = Readable::read(reader)?;
        Ok(ContractOutcome {
            outcome,
            local_payout,
        })
    }
}

/// Structure containing the list of outcome of a DLC contract.
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "camelCase")
)]
pub struct ContractInfo {
    pub outcomes: Vec<ContractOutcome>,
}

impl Writeable for ContractInfo {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        let size: BigSize = BigSize(self.outcomes.len() as u64);
        size.write(writer)?;
        for ref outcome in &self.outcomes {
            outcome.write(writer)?;
        }

        Ok(())
    }
}

impl Readable for ContractInfo {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<ContractInfo, DecodeError> {
        let outcomes_count: BigSize = Readable::read(reader)?;
        let mut outcomes: Vec<ContractOutcome> = Vec::new();
        for _ in 0..(outcomes_count.0) {
            outcomes.push(Readable::read(reader)?);
        }

        Ok(ContractInfo { outcomes })
    }
}

/// Structure containing information about an oracle to be used as external
/// data source for a DLC contract.
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "camelCase")
)]
pub struct OracleInfo {
    pub public_key: SchnorrPublicKey,
    pub nonce: SchnorrPublicKey,
}

impl Writeable for OracleInfo {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.public_key.write(writer)?;
        self.nonce.write(writer)?;

        Ok(())
    }
}

impl Readable for OracleInfo {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<OracleInfo, DecodeError> {
        let public_key = Readable::read(reader)?;
        let nonce = Readable::read(reader)?;

        Ok(OracleInfo { public_key, nonce })
    }
}

/// Contains information about a specific input to be used in a funding transaction,
/// as well as its corresponding on-chain UTXO.
pub struct FundingInput {
    pub prev_tx: Vec<u8>,
    pub prev_tx_vout: u32,
    pub sequence: u32,
    pub max_witness_len: u16,
    pub redeem_script: Script,
}

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
        }
    }
}

impl Writeable for FundingInput {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.prev_tx.write(writer)?;
        self.prev_tx_vout.write(writer)?;
        self.sequence.write(writer)?;
        self.max_witness_len.write(writer)?;
        self.redeem_script.write(writer)?;

        Ok(())
    }
}

impl Readable for FundingInput {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<FundingInput, DecodeError> {
        let prev_tx = Readable::read(reader)?;
        let prev_tx_vout = Readable::read(reader)?;
        let sequence = Readable::read(reader)?;
        let max_witness_len = Readable::read(reader)?;
        let redeem_script = Readable::read(reader)?;

        Ok(FundingInput {
            prev_tx,
            prev_tx_vout,
            sequence,
            max_witness_len,
            redeem_script,
        })
    }
}

/// Contains an adaptor signature for a CET input and its associated DLEQ proof.
pub struct CetAdaptorSignature {
    pub signature: AdaptorSignature,
    pub proof: AdaptorProof,
}

impl Writeable for CetAdaptorSignature {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        let mut ser_sig = [0; 65];
        ser_sig.copy_from_slice(&self.signature[..]);
        ser_sig.write(writer)?;
        let mut ser_proof = [0; 97];
        ser_proof.copy_from_slice(&self.proof[..]);
        ser_proof.write(writer)
    }
}

impl Readable for CetAdaptorSignature {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<CetAdaptorSignature, DecodeError> {
        let sig_buf: [u8; constants::ADAPTOR_SIGNATURE_SIZE] = Readable::read(reader)?;
        let signature = match AdaptorSignature::from_slice(&sig_buf) {
            Ok(sig) => sig,
            Err(_) => return Err(DecodeError::InvalidValue),
        };

        let proof_buf: [u8; constants::ADAPTOR_PROOF_SIZE] = Readable::read(reader)?;
        let proof = match AdaptorProof::from_slice(&proof_buf) {
            Ok(proof) => proof,
            Err(_) => return Err(DecodeError::InvalidValue),
        };

        Ok(CetAdaptorSignature { signature, proof })
    }
}

/// Contains a list of adaptor signature for a number of CET inputs.
pub struct CetAdaptorSignatures {
    pub ecdsa_adaptor_signatures: Vec<CetAdaptorSignature>,
}

impl From<Vec<(AdaptorSignature, AdaptorProof)>> for CetAdaptorSignatures {
    fn from(pairs: Vec<(AdaptorSignature, AdaptorProof)>) -> Self {
        CetAdaptorSignatures {
            ecdsa_adaptor_signatures: pairs
                .iter()
                .map(|x| CetAdaptorSignature {
                    signature: x.0,
                    proof: x.1,
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
pub struct FundingSignature {
    pub witness_elements: Vec<WitnessElement>,
}

impl Writeable for FundingSignature {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        let len = self.witness_elements.len() as u16;
        len.write(writer)?;
        for i in 0..(len as usize) {
            self.witness_elements[i].write(writer)?;
        }

        Ok(())
    }
}

impl Readable for FundingSignature {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<FundingSignature, DecodeError> {
        let len: u16 = Readable::read(reader)?;
        let mut witness_elements = Vec::with_capacity(len as usize);

        for _ in 0..(len as usize) {
            let elem: WitnessElement = Readable::read(reader)?;
            witness_elements.push(elem);
        }

        Ok(FundingSignature { witness_elements })
    }
}

/// Contains a list of witness elements to satisfy the spending conditions of
/// funding inputs.
pub struct FundingSignatures {
    pub funding_signatures: Vec<FundingSignature>,
}

impl Writeable for FundingSignatures {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        (self.funding_signatures.len() as u16).write(writer)?;
        for ref sig in &self.funding_signatures {
            sig.write(writer)?;
        }

        Ok(())
    }
}

impl Readable for FundingSignatures {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<FundingSignatures, DecodeError> {
        let sig_count: u64 = Readable::read(reader)?;
        let mut sigs: Vec<FundingSignature> = Vec::with_capacity(sig_count as usize);
        for _ in 0..sig_count {
            sigs.push(Readable::read(reader)?);
        }

        Ok(FundingSignatures {
            funding_signatures: sigs,
        })
    }
}

/// Contains serialized data representing a single witness stack element.
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
pub struct OfferDlc {
    pub contract_flags: u8,
    pub chain_hash: [u8; 32],
    pub contract_info: ContractInfo,
    pub oracle_info: OracleInfo,
    pub funding_pubkey: PublicKey,
    pub payout_spk: Script,
    pub total_collateral: u64,
    pub funding_inputs: Vec<FundingInput>,
    pub change_spk: Script,
    pub fee_rate_per_vb: u64,
    pub contract_maturity_bound: u32,
    pub contract_timeout: u32,
}

impl OfferDlc {
    /// Returns the hash of the serialized OfferDlc message.
    pub fn get_hash(&self) -> Result<[u8; 32], ::std::io::Error> {
        let mut buff = Vec::new();
        write(self, &mut buff)?;
        Ok(sha256::Hash::hash(&buff).into_inner())
    }
}

impl Writeable for OfferDlc {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.contract_flags.write(writer)?;
        self.chain_hash.write(writer)?;
        encode_tlv!(writer, { (CONTRACT_INFO_TYPE, self.contract_info) });
        encode_tlv!(writer, { (ORACLE_INFO_TYPE, self.oracle_info) });
        self.funding_pubkey.write(writer)?;
        self.payout_spk.write(writer)?;
        self.total_collateral.write(writer)?;
        let num_funding_inputs = self.funding_inputs.len();
        (num_funding_inputs as u16).write(writer)?;

        for input in &self.funding_inputs {
            encode_tlv!(writer, { (FUNDING_INPUT_TYPE, input) });
        }

        self.change_spk.write(writer)?;
        self.fee_rate_per_vb.write(writer)?;
        self.contract_maturity_bound.write(writer)?;
        self.contract_timeout.write(writer)
    }
}

impl Readable for OfferDlc {
    fn read<R: ::std::io::Read>(mut reader: &mut R) -> Result<OfferDlc, DecodeError> {
        let contract_flags = Readable::read(reader)?;
        let chain_hash = Readable::read(reader)?;
        let mut contract_info_opt: Option<ContractInfo> = None;
        decode_tlv!(&mut reader, {}, { (CONTRACT_INFO_TYPE, contract_info_opt) });
        let contract_info = contract_info_opt.ok_or(DecodeError::InvalidValue)?;
        let mut oracle_info_opt: Option<OracleInfo> = None;
        decode_tlv!(&mut reader, {}, { (ORACLE_INFO_TYPE, oracle_info_opt) });
        let oracle_info = oracle_info_opt.ok_or(DecodeError::InvalidValue)?;
        let funding_pubkey = Readable::read(reader)?;
        let payout_spk = Readable::read(reader)?;
        let total_collateral = Readable::read(reader)?;
        let num_funding_inputs: u16 = Readable::read(reader)?;
        let mut funding_inputs = Vec::<FundingInput>::with_capacity(num_funding_inputs as usize);

        for _ in 0..num_funding_inputs {
            funding_inputs.push(Readable::read(reader)?);
        }

        let change_spk = Readable::read(reader)?;
        let fee_rate_per_vb = Readable::read(reader)?;
        let contract_maturity_bound = Readable::read(reader)?;
        let contract_timeout = Readable::read(reader)?;

        Ok(OfferDlc {
            contract_flags,
            chain_hash,
            contract_info,
            oracle_info,
            funding_pubkey,
            payout_spk,
            total_collateral,
            funding_inputs,
            change_spk,
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
pub struct AcceptDlc {
    pub temporary_contract_id: [u8; 32],
    pub total_collateral: u64,
    pub funding_pubkey: PublicKey,
    pub payout_spk: Script,
    pub funding_inputs: Vec<FundingInput>,
    pub change_spk: Script,
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    pub refund_signature: Signature,
}

impl Writeable for AcceptDlc {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.temporary_contract_id.write(writer)?;
        self.total_collateral.write(writer)?;
        self.funding_pubkey.write(writer)?;
        self.payout_spk.write(writer)?;
        let num_funding_inputs = self.funding_inputs.len() as u16;
        num_funding_inputs.write(writer)?;

        for input in &self.funding_inputs {
            encode_tlv!(writer, { (FUNDING_INPUT_TYPE, input) });
        }

        self.change_spk.write(writer)?;
        encode_tlv!(writer, {
            (CET_ADAPTOR_SIGNATURES_TYPE, self.cet_adaptor_signatures)
        });
        self.refund_signature.write(writer)
    }
}

impl Readable for AcceptDlc {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<AcceptDlc, DecodeError> {
        let temporary_contract_id = Readable::read(reader)?;
        let total_collateral = Readable::read(reader)?;
        let funding_pubkey = Readable::read(reader)?;
        let payout_spk = Readable::read(reader)?;
        let num_funding_inputs: u16 = Readable::read(reader)?;
        let mut funding_inputs = Vec::with_capacity(num_funding_inputs as usize);

        for _ in 0..num_funding_inputs {
            funding_inputs.push(Readable::read(reader)?);
        }

        let change_spk = Readable::read(reader)?;
        let cet_adaptor_signatures = Readable::read(reader)?;
        let refund_signature = Readable::read(reader)?;

        Ok(AcceptDlc {
            temporary_contract_id,
            total_collateral,
            funding_pubkey,
            payout_spk,
            funding_inputs,
            change_spk,
            cet_adaptor_signatures,
            refund_signature,
        })
    }
}

/// Contains all the required signatures for the DLC transactions from the offering
/// party.
pub struct SignDlc {
    pub contract_id: [u8; 32],
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    pub refund_signature: Signature,
    pub funding_signatures: FundingSignatures,
}

impl Writeable for SignDlc {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
        self.contract_id.write(writer)?;
        encode_tlv!(writer, {
            (CET_ADAPTOR_SIGNATURES_TYPE, self.cet_adaptor_signatures)
        });
        self.refund_signature.write(writer)?;
        encode_tlv!(writer, {
            (FUNDING_SIGNATURES_TYPE, self.funding_signatures)
        });
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
pub enum Message {
    OfferDlc(OfferDlc),
    AcceptDlc(AcceptDlc),
    SignDlc(SignDlc),
}

impl Message {
    ///
    pub fn type_id(&self) -> MessageType {
        match self {
            &Message::OfferDlc(ref msg) => msg.type_id(),
            &Message::AcceptDlc(ref msg) => msg.type_id(),
            &Message::SignDlc(ref msg) => msg.type_id(),
        }
    }
}

impl Encode for OfferDlc {
    const TYPE: u16 = 42778;
}

impl Encode for AcceptDlc {
    const TYPE: u16 = 42780;
}

impl Encode for SignDlc {
    const TYPE: u16 = 42782;
}

impl Encode for ContractInfo {
    const TYPE: u16 = 42768;
}

impl Encode for OracleInfo {
    const TYPE: u16 = 42770;
}

impl Encode for FundingInput {
    const TYPE: u16 = 42772;
}

impl Encode for CetAdaptorSignatures {
    const TYPE: u16 = 42774;
}

impl Encode for FundingSignatures {
    const TYPE: u16 = 42776;
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
