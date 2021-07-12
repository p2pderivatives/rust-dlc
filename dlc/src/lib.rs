//! # Rust DLC Library
//! Library for creating, signing and verifying transactions for the
//! Discreet Log Contract protocol.
//!

#![crate_name = "dlc"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]
// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

extern crate bitcoin;
extern crate core;
extern crate secp256k1_sys;
extern crate secp256k1_zkp;

use bitcoin::blockdata::{
    opcodes,
    script::{Builder, Script},
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
use secp256k1_zkp::schnorrsig::{PublicKey as SchnorrPublicKey, Signature as SchnorrSignature};
use secp256k1_zkp::EcdsaAdaptorSignature;
use secp256k1_zkp::{Message, PublicKey, Secp256k1, SecretKey, Signature, Verification};
use std::fmt;

pub mod secp_utils;
pub mod util;

/// Minimum value that can be included in a transaction output. Under this value,
/// outputs are discarded
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#change-outputs
const DUST_LIMIT: u64 = 1000;

/// The transaction version
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#funding-transaction
const TX_VERSION: i32 = 2;

/// The base weight of a fund transaction
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
const FUND_TX_BASE_WEIGHT: usize = 214;

/// The weight of a CET excluding payout outputs
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
const CET_BASE_WEIGHT: usize = 500;

/// The base weight of a transaction input computed as: (outpoint(36) + sequence(4) + scriptPubKeySize(1)) * 4
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
const TX_INPUT_BASE_WEIGHT: usize = 164;

/// The witness size of a P2WPKH input
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
pub const P2WPKH_WITNESS_SIZE: usize = 107;

// Setting the nSequence for every input of a transaction to this value disables
// both RBF and nLockTime usage.
const DISABLE_LOCKTIME: u32 = 0xffffffff;
// Setting the nSequence for every input of a transaction to this value disables
// RBF but enables nLockTime usage.
const ENABLE_LOCKTIME: u32 = 0xfffffffe;

/// Represents the payouts for a unique contract outcome. Offer party represents
/// the initiator of the contract while accept party represents the party
/// accepting the contract.
#[derive(PartialEq, Debug, Clone)]
pub struct Payout {
    /// Payout for the offering party
    pub offer: u64,
    /// Payout for the accepting party
    pub accept: u64,
}

#[derive(PartialEq, Debug)]
/// Representation of a set of contiguous outcomes that share a single payout.
pub struct RangePayout {
    /// The start of the range
    pub start: usize,
    /// The number of outcomes in the range
    pub count: usize,
    /// The payout associated with all outcomes
    pub payout: Payout,
}

/// Representation of a payout for an enumeration outcome.
#[derive(Clone, Debug)]
pub struct EnumerationPayout {
    /// The outcome value (prior to hashing)
    pub outcome: String,
    /// The corresponding payout
    pub payout: Payout,
}

/// Contains the necessary transactions for establishing a DLC
#[derive(Clone)]
pub struct DlcTransactions {
    /// The fund transaction locking both parties collaterals
    pub fund: Transaction,
    /// The contract execution transactions for closing the contract on a
    /// certain outcome
    pub cets: Vec<Transaction>,
    /// The refund transaction for returning the collateral for each party in
    /// case of an oracle misbehavior
    pub refund: Transaction,

    /// The script pubkey of the fund output in the fund transaction
    pub funding_script_pubkey: Script,
}

impl DlcTransactions {
    /// Get the fund output in the fund transaction
    pub fn get_fund_output(&self) -> &TxOut {
        let v0_witness_fund_script = self.funding_script_pubkey.to_v0_p2wsh();
        util::get_output_for_script_pubkey(&self.fund, &v0_witness_fund_script)
            .unwrap()
            .1
    }

    /// Get the fund output in the fund transaction
    pub fn get_fund_output_index(&self) -> usize {
        let v0_witness_fund_script = self.funding_script_pubkey.to_v0_p2wsh();
        util::get_output_for_script_pubkey(&self.fund, &v0_witness_fund_script)
            .unwrap()
            .0
    }
}

/// Contains info about a utxo used for funding a DLC contract
#[derive(Clone)]
pub struct TxInputInfo {
    /// The outpoint for the utxo
    pub outpoint: OutPoint,
    /// The maximum witness length
    pub max_witness_len: usize,
    /// The redeem script
    pub redeem_script: Script,
    /// The serial id for the input that will be used for ordering inputs of
    /// the fund transaction
    pub serial_id: u64,
}

/// Structure containing oracle information for a single event.
#[derive(Clone)]
pub struct OracleInfo {
    /// The public key of the oracle.
    pub public_key: SchnorrPublicKey,
    /// The nonces that the oracle will use to attest to the event.
    pub nonces: Vec<SchnorrPublicKey>,
}

/// An error code.
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    /// Secp256k1 error
    Secp256k1(secp256k1_zkp::Error),
    /// An invalid argument was provided
    InvalidArgument,
}

impl From<secp256k1_zkp::Error> for Error {
    fn from(error: secp256k1_zkp::Error) -> Error {
        Error::Secp256k1(error)
    }
}

impl From<secp256k1_zkp::UpstreamError> for Error {
    fn from(error: secp256k1_zkp::UpstreamError) -> Error {
        Error::Secp256k1(secp256k1_zkp::Error::Upstream(error))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Secp256k1(ref e) => write!(f, "Secp256k1 error {}", e),
            Error::InvalidArgument => write!(f, "Invalid argument"),
        }
    }
}

/// Contains the parameters required for creating DLC transactions for a single
/// party. Specifically these are the common fields between Offer and Accept
/// messages.
#[derive(Clone)]
pub struct PartyParams {
    /// The public key for the fund multisig script
    pub fund_pubkey: PublicKey,
    /// An address to receive change
    pub change_script_pubkey: Script,
    /// Id used to order fund outputs
    pub change_serial_id: u64,
    /// An address to receive the outcome amount
    pub payout_script_pubkey: Script,
    /// Id used to order CET outputs
    pub payout_serial_id: u64,
    /// A list of inputs to fund the contract
    pub inputs: Vec<TxInputInfo>,
    /// The sum of the inputs values.
    pub input_amount: u64,
    /// The collateral put in the contract by the party
    pub collateral: u64,
}

impl PartyParams {
    /// Returns the change output for a single party as well as the fees that
    /// they are required to pay for the fund transaction and the cet or refund transaction.
    /// The change output value already accounts for the required fees.
    /// If input amount (sum of all input values) is lower than the sum of the collateral
    /// plus the required fees, an error is returned.
    pub fn get_change_output_and_fees(
        &self,
        fee_rate_per_vb: u64,
    ) -> Result<(TxOut, u64, u64), Error> {
        let inputs_weight: usize = self
            .inputs
            .iter()
            .map(|i| {
                let script_size = util::redeem_script_to_script_sig(&i.redeem_script).len();
                // Base tx input weight + redeem script weight (*4 because non witness)
                // + max witness weight (*1 because witness)
                TX_INPUT_BASE_WEIGHT + 4 * script_size + i.max_witness_len
            })
            .sum();

        // Value size + script length var_int + ouput script pubkey size
        let change_size = self.change_script_pubkey.len();
        // Change size is scaled by 4 from vBytes to weight units
        let change_weight = change_size * 4;

        // Base weight (nLocktime, nVersion, ...) is distributed among parties
        // independently of inputs contributed
        let this_party_fund_base_weight = FUND_TX_BASE_WEIGHT / 2;

        let total_fund_weight = this_party_fund_base_weight + inputs_weight + change_weight + 36;
        let fund_fee = util::weight_to_fee(total_fund_weight, fee_rate_per_vb);

        // Base weight (nLocktime, nVersion, funding input ...) is distributed
        // among parties independently of output types
        let this_party_cet_base_weight = CET_BASE_WEIGHT / 2;

        // size of the payout script pubkey scaled by 4 from vBytes to weight units
        let output_spk_weight = self.payout_script_pubkey.len() * 4;
        let total_cet_weight = this_party_cet_base_weight + output_spk_weight;
        let cet_or_refund_fee = util::weight_to_fee(total_cet_weight, fee_rate_per_vb);
        let required_input_funds = self.collateral + fund_fee + cet_or_refund_fee;
        if self.input_amount < required_input_funds {
            return Err(Error::InvalidArgument);
        }

        let change_output = TxOut {
            value: self.input_amount - required_input_funds,
            script_pubkey: self.change_script_pubkey.clone(),
        };

        Ok((change_output, fund_fee, cet_or_refund_fee))
    }

    fn get_unsigned_tx_inputs_and_serial_ids(&self, sequence: u32) -> (Vec<TxIn>, Vec<u64>) {
        let mut tx_ins = Vec::with_capacity(self.inputs.len());
        let mut serial_ids = Vec::with_capacity(self.inputs.len());

        for input in &self.inputs {
            let tx_in = TxIn {
                previous_output: input.outpoint,
                script_sig: util::redeem_script_to_script_sig(&input.redeem_script),
                sequence,
                witness: Vec::new(),
            };
            tx_ins.push(tx_in);
            serial_ids.push(input.serial_id);
        }

        (tx_ins, serial_ids)
    }
}

/// Create the transactions for a DLC contract based on the provided parameters
pub fn create_dlc_transactions(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    payouts: &[Payout],
    refund_lock_time: u32,
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    cet_lock_time: u32,
    fund_output_serial_id: u64,
) -> Result<DlcTransactions, Error> {
    let total_collateral = offer_params.collateral + accept_params.collateral;

    let has_proper_outcomes = payouts
        .iter()
        .all(|o| o.offer + o.accept == total_collateral);

    if !has_proper_outcomes {
        return Err(Error::InvalidArgument);
    }

    let (offer_change_output, offer_fund_fee, offer_cet_fee) =
        offer_params.get_change_output_and_fees(fee_rate_per_vb)?;
    let (accept_change_output, accept_fund_fee, accept_cet_fee) =
        accept_params.get_change_output_and_fees(fee_rate_per_vb)?;

    let fund_output_value = offer_params.input_amount + accept_params.input_amount
        - offer_change_output.value
        - accept_change_output.value
        - offer_fund_fee
        - accept_fund_fee;

    assert_eq!(
        total_collateral + offer_cet_fee + accept_cet_fee,
        fund_output_value
    );

    assert_eq!(
        offer_params.input_amount + accept_params.input_amount,
        fund_output_value
            + offer_change_output.value
            + accept_change_output.value
            + offer_fund_fee
            + accept_fund_fee
    );

    fn get_sequence(lock_time: u32) -> u32 {
        return if lock_time == 0 {
            DISABLE_LOCKTIME
        } else {
            ENABLE_LOCKTIME
        };
    }

    let fund_sequence = get_sequence(fund_lock_time);
    let (offer_tx_ins, offer_inputs_serial_ids) =
        offer_params.get_unsigned_tx_inputs_and_serial_ids(fund_sequence);
    let (accept_tx_ins, accept_inputs_serial_ids) =
        accept_params.get_unsigned_tx_inputs_and_serial_ids(fund_sequence);

    let funding_script_pubkey =
        make_funding_redeemscript(&offer_params.fund_pubkey, &accept_params.fund_pubkey);

    let fund_tx = create_funding_transaction(
        &funding_script_pubkey,
        fund_output_value,
        &offer_tx_ins,
        &offer_inputs_serial_ids,
        &accept_tx_ins,
        &accept_inputs_serial_ids,
        offer_change_output,
        offer_params.change_serial_id,
        accept_change_output,
        accept_params.change_serial_id,
        fund_output_serial_id,
        fund_lock_time,
    );

    let (fund_vout, _) =
        util::get_output_for_script_pubkey(&fund_tx, &funding_script_pubkey.to_v0_p2wsh()).unwrap();

    let fund_outpoint = OutPoint {
        txid: fund_tx.txid(),
        vout: fund_vout as u32,
    };

    let fund_tx_in = TxIn {
        previous_output: fund_outpoint,
        witness: Vec::new(),
        script_sig: Script::new(),
        sequence: get_sequence(cet_lock_time),
    };

    let cets = create_cets(
        &fund_tx_in,
        &offer_params.payout_script_pubkey,
        offer_params.payout_serial_id,
        &accept_params.payout_script_pubkey,
        accept_params.payout_serial_id,
        payouts,
        cet_lock_time,
    );

    let offer_refund_output = TxOut {
        value: offer_params.collateral,
        script_pubkey: offer_params.payout_script_pubkey.clone(),
    };

    let accept_refund_ouput = TxOut {
        value: accept_params.collateral,
        script_pubkey: accept_params.payout_script_pubkey.clone(),
    };

    let refund_tx = create_refund_transaction(
        offer_refund_output,
        accept_refund_ouput,
        fund_tx_in,
        refund_lock_time,
    );

    Ok(DlcTransactions {
        fund: fund_tx,
        cets,
        refund: refund_tx,
        funding_script_pubkey,
    })
}

/// Create a contract execution transaction
pub fn create_cet(
    offer_output: TxOut,
    offer_payout_serial_id: u64,
    accept_output: TxOut,
    accept_payout_serial_id: u64,
    fund_tx_in: &TxIn,
    lock_time: u32,
) -> Transaction {
    let mut output: Vec<TxOut> = if offer_payout_serial_id < accept_payout_serial_id {
        vec![offer_output, accept_output]
    } else {
        vec![accept_output, offer_output]
    };

    output = util::discard_dust(output, DUST_LIMIT);

    Transaction {
        version: TX_VERSION,
        lock_time,
        input: vec![fund_tx_in.clone()],
        output,
    }
}

/// Create a set of contract execution transaction for each provided outcome
pub fn create_cets(
    fund_tx_input: &TxIn,
    offer_payout_script_pubkey: &Script,
    offer_payout_serial_id: u64,
    accept_payout_script_pubkey: &Script,
    accept_payout_serial_id: u64,
    payouts: &[Payout],
    lock_time: u32,
) -> Vec<Transaction> {
    let mut txs: Vec<Transaction> = Vec::new();
    for i in 0..payouts.len() {
        let offer_output = TxOut {
            value: payouts[i].offer,
            script_pubkey: offer_payout_script_pubkey.clone(),
        };
        let accept_output = TxOut {
            value: payouts[i].accept,
            script_pubkey: accept_payout_script_pubkey.clone(),
        };
        let tx = create_cet(
            offer_output,
            offer_payout_serial_id,
            accept_output,
            accept_payout_serial_id,
            fund_tx_input,
            lock_time,
        );

        txs.push(tx);
    }

    txs
}

/// Create a funding transaction
pub fn create_funding_transaction(
    funding_script_pubkey: &Script,
    output_amount: u64,
    offer_inputs: &[TxIn],
    offer_inputs_serial_ids: &[u64],
    accept_inputs: &[TxIn],
    accept_inputs_serial_ids: &[u64],
    offer_change_output: TxOut,
    offer_change_serial_id: u64,
    accept_change_output: TxOut,
    accept_change_serial_id: u64,
    fund_output_serial_id: u64,
    lock_time: u32,
) -> Transaction {
    let fund_tx_out = TxOut {
        value: output_amount,
        script_pubkey: funding_script_pubkey.to_v0_p2wsh(),
    };

    let output: Vec<TxOut> = {
        let serial_ids = vec![
            fund_output_serial_id,
            offer_change_serial_id,
            accept_change_serial_id,
        ];
        util::discard_dust(
            util::order_by_serial_ids(
                vec![fund_tx_out, offer_change_output, accept_change_output],
                &serial_ids,
            ),
            DUST_LIMIT,
        )
    };

    let input = util::order_by_serial_ids(
        [&offer_inputs[..], &accept_inputs[..]].concat(),
        &[&offer_inputs_serial_ids[..], &accept_inputs_serial_ids[..]].concat(),
    );

    let funding_transaction = Transaction {
        version: TX_VERSION,
        lock_time: lock_time,
        input,
        output,
    };

    return funding_transaction;
}

/// Create a refund transaction
pub fn create_refund_transaction(
    offer_output: TxOut,
    accept_output: TxOut,
    funding_input: TxIn,
    locktime: u32,
) -> Transaction {
    Transaction {
        version: TX_VERSION,
        lock_time: locktime,
        input: vec![funding_input],
        output: vec![offer_output, accept_output],
    }
}

/// Create the multisig redeem script for the funding output
pub fn make_funding_redeemscript(a: &PublicKey, b: &PublicKey) -> Script {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };

    Builder::new()
        .push_opcode(opcodes::all::OP_PUSHNUM_2)
        .push_slice(&first.serialize())
        .push_slice(&second.serialize())
        .push_opcode(opcodes::all::OP_PUSHNUM_2)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script()
}

fn combine_pubkeys(pubkeys: &Vec<PublicKey>) -> Result<PublicKey, Error> {
    if pubkeys.len() < 1 {
        return Err(Error::InvalidArgument);
    }
    let res = pubkeys[0];
    Ok(pubkeys
        .iter()
        .skip(1)
        .try_fold(res, |acc, pk| acc.combine(&pk))?)
}

fn get_oracle_sig_point<C: secp256k1_zkp::Verification>(
    secp: &Secp256k1<C>,
    oracle_info: &OracleInfo,
    msgs: &[Message],
) -> Result<PublicKey, Error> {
    if oracle_info.nonces.len() < msgs.len() {
        return Err(Error::InvalidArgument);
    }

    let sig_points: Vec<PublicKey> = oracle_info
        .nonces
        .iter()
        .zip(msgs.iter())
        .map(|(nonce, msg)| {
            secp_utils::schnorrsig_compute_sig_point(secp, &oracle_info.public_key, nonce, msg)
        })
        .collect::<Result<Vec<PublicKey>, Error>>()?;
    Ok(combine_pubkeys(&sig_points)?)
}

/// Get an adaptor point generated using the given oracle information and messages.
pub fn get_adaptor_point_from_oracle_info<C: Verification>(
    secp: &Secp256k1<C>,
    oracle_infos: &[OracleInfo],
    msgs: &Vec<Vec<Message>>,
) -> Result<PublicKey, Error> {
    if oracle_infos.len() < 1 || msgs.len() < 1 {
        return Err(Error::InvalidArgument);
    }

    let mut oracle_sigpoints = Vec::with_capacity(msgs[0].len());
    for (i, info) in oracle_infos.iter().enumerate() {
        oracle_sigpoints.push(get_oracle_sig_point(secp, &info, &msgs[i])?);
    }
    combine_pubkeys(&oracle_sigpoints)
}

/// Create an adaptor signature for the given cet using the provided adaptor point.
pub fn create_cet_adaptor_sig_from_point<C: secp256k1_zkp::Signing>(
    secp: &secp256k1_zkp::Secp256k1<C>,
    cet: &Transaction,
    adaptor_point: &PublicKey,
    funding_sk: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
) -> Result<EcdsaAdaptorSignature, Error> {
    let sig_hash = util::get_sig_hash_msg(cet, 0, funding_script_pubkey, fund_output_value);

    Ok(secp256k1_zkp::EcdsaAdaptorSignature::encrypt(
        secp,
        &sig_hash,
        funding_sk,
        adaptor_point,
    ))
}

/// Create an adaptor signature for the given cet using the provided oracle infos.
pub fn create_cet_adaptor_sig_from_oracle_info(
    secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    cet: &Transaction,
    oracle_infos: &Vec<OracleInfo>,
    funding_sk: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    msgs: &Vec<Vec<Message>>,
) -> Result<EcdsaAdaptorSignature, Error> {
    let adaptor_point = get_adaptor_point_from_oracle_info(secp, oracle_infos, msgs)?;
    create_cet_adaptor_sig_from_point(
        secp,
        cet,
        &adaptor_point,
        funding_sk,
        funding_script_pubkey,
        fund_output_value,
    )
}

/// Crerate a set of adaptor signatures for the given cet/message pairs.
pub fn create_cet_adaptor_sigs_from_points<C: secp256k1_zkp::Signing>(
    secp: &secp256k1_zkp::Secp256k1<C>,
    inputs: &Vec<(&Transaction, &PublicKey)>,
    funding_sk: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
) -> Result<Vec<EcdsaAdaptorSignature>, Error> {
    inputs
        .iter()
        .map(|(cet, adaptor_point)| {
            create_cet_adaptor_sig_from_point(
                secp,
                cet,
                adaptor_point,
                funding_sk,
                funding_script_pubkey,
                fund_output_value,
            )
        })
        .collect()
}

/// Crerate a set of adaptor signatures for the given cet/message pairs.
pub fn create_cet_adaptor_sigs_from_oracle_info(
    secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    cets: &Vec<Transaction>,
    oracle_infos: &Vec<OracleInfo>,
    funding_sk: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    msgs: &Vec<Vec<Vec<Message>>>,
) -> Result<Vec<EcdsaAdaptorSignature>, Error> {
    if msgs.len() != cets.len() {
        return Err(Error::InvalidArgument);
    }

    cets.iter()
        .zip(msgs.iter())
        .map(|(cet, msg)| {
            create_cet_adaptor_sig_from_oracle_info(
                secp,
                cet,
                oracle_infos,
                funding_sk,
                funding_script_pubkey,
                fund_output_value,
                msg,
            )
        })
        .collect()
}

fn signatures_to_secret(signatures: &Vec<Vec<SchnorrSignature>>) -> Result<SecretKey, Error> {
    let s_values = signatures
        .iter()
        .flatten()
        .map(|x| match secp_utils::schnorrsig_decompose(x) {
            Ok(v) => Ok(v.1),
            Err(err) => Err(err),
        })
        .collect::<Result<Vec<&[u8]>, Error>>()?;
    let mut secret = SecretKey::from_slice(s_values[0])?;
    for s in s_values.iter().skip(1) {
        secret.add_assign(s)?;
    }

    Ok(secret)
}

/// Sign the given cet using own private key, adapt the counter party signature
/// and place both signatures and the funding multi sig script pubkey on the
/// witness stack
pub fn sign_cet<C: secp256k1_zkp::Signing>(
    secp: &secp256k1_zkp::Secp256k1<C>,
    cet: &mut Transaction,
    adaptor_signature: &EcdsaAdaptorSignature,
    oracle_signatures: &Vec<Vec<SchnorrSignature>>,
    funding_sk: &SecretKey,
    other_pk: &PublicKey,
    funding_script_pubkey: &Script,
    fund_output: u64,
) -> Result<(), Error> {
    let adaptor_secret = signatures_to_secret(oracle_signatures)?;
    let adapted_sig = adaptor_signature.decrypt(&adaptor_secret)?;

    util::sign_multi_sig_input(
        secp,
        cet,
        &adapted_sig,
        other_pk,
        funding_sk,
        funding_script_pubkey,
        fund_output,
        0,
    );

    Ok(())
}

/// Verify that a given adaptor signature for a given cet is valid with respect
/// to an adaptor point.
pub fn verify_cet_adaptor_sig_from_point(
    secp: &Secp256k1<secp256k1_zkp::All>,
    adaptor_sig: &EcdsaAdaptorSignature,
    cet: &Transaction,
    adaptor_point: &PublicKey,
    pubkey: &PublicKey,
    funding_script_pubkey: &Script,
    total_collateral: u64,
) -> Result<(), Error> {
    let sig_hash = util::get_sig_hash_msg(cet, 0, funding_script_pubkey, total_collateral);
    adaptor_sig.verify(secp, &sig_hash, &pubkey, &adaptor_point)?;
    Ok(())
}

/// Verify that a given adaptor signature for a given cet is valid with respect
/// to an oracle public key, nonce and a given message.
pub fn verify_cet_adaptor_sig_from_oracle_info(
    secp: &Secp256k1<secp256k1_zkp::All>,
    adaptor_sig: &EcdsaAdaptorSignature,
    cet: &Transaction,
    oracle_infos: &Vec<OracleInfo>,
    pubkey: &PublicKey,
    funding_script_pubkey: &Script,
    total_collateral: u64,
    msgs: &Vec<Vec<Message>>,
) -> Result<(), Error> {
    let adaptor_point = get_adaptor_point_from_oracle_info(secp, oracle_infos, msgs)?;
    verify_cet_adaptor_sig_from_point(
        secp,
        adaptor_sig,
        cet,
        &adaptor_point,
        pubkey,
        funding_script_pubkey,
        total_collateral,
    )
}

/// Verify a signature for a given transaction input.
pub fn verify_tx_input_sig<V: Verification>(
    secp: &Secp256k1<V>,
    signature: &Signature,
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    value: u64,
    pk: &PublicKey,
) -> Result<(), Error> {
    let sig_hash_msg = util::get_sig_hash_msg(tx, input_index, script_pubkey, value);
    secp.verify(&sig_hash_msg, signature, pk)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::script::Script;
    use bitcoin::blockdata::transaction::{OutPoint, SigHashType};
    use bitcoin::consensus::encode::Encodable;
    use secp256k1_zkp::bitcoin_hashes::hex::FromHex;
    use bitcoin::{network::constants::Network, Address, Txid};
    use secp256k1_zkp::{
        rand::{Rng, RngCore},
        schnorrsig::KeyPair,
        PublicKey, Secp256k1, SecretKey, Signing,
    };
    use std::convert::TryInto;
    use std::fmt::Write;
    use std::str::FromStr;
    use util;

    fn create_txin_vec(sequence: u32) -> Vec<TxIn> {
        let mut inputs = Vec::new();
        let txin = TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: sequence,
            witness: Vec::new(),
        };
        inputs.push(txin);
        inputs
    }

    fn create_multi_party_pub_keys() -> (PublicKey, PublicKey) {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let pk = PublicKey::from_secret_key(&secp, &secret_key);
        let pk1 = pk;

        (pk, pk1)
    }

    fn create_test_tx_io() -> (TxOut, TxOut, TxIn) {
        let offer = TxOut {
            value: 1,
            script_pubkey: Script::new(),
        };

        let accept = TxOut {
            value: 2,
            script_pubkey: Script::new(),
        };

        let funding = TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: 3,
            witness: Vec::new(),
        };

        (offer, accept, funding)
    }

    #[test]
    fn create_refund_transaction_test() {
        let (offer, accept, funding) = create_test_tx_io();

        let refund_transaction = create_refund_transaction(offer, accept, funding, 0);
        assert_eq!(2, refund_transaction.version);
        assert_eq!(0, refund_transaction.lock_time);
        assert_eq!(1, refund_transaction.output[0].value);
        assert_eq!(2, refund_transaction.output[1].value);
        assert_eq!(3, refund_transaction.input[0].sequence);
    }

    #[test]
    fn create_funding_transaction_test() {
        let (pk, pk1) = create_multi_party_pub_keys();

        let offer_inputs = create_txin_vec(0);
        let accept_inputs = create_txin_vec(1);

        let change = 1000;

        let total_collateral = 31415;

        let offer_change_output = TxOut {
            value: change,
            script_pubkey: Script::new(),
        };
        let accept_change_output = TxOut {
            value: change,
            script_pubkey: Script::new(),
        };
        let funding_script_pubkey = make_funding_redeemscript(&pk, &pk1);

        let transaction = create_funding_transaction(
            &funding_script_pubkey,
            total_collateral,
            &offer_inputs,
            &[1],
            &accept_inputs,
            &[2],
            offer_change_output,
            0,
            accept_change_output,
            1,
            0,
            0,
        );

        assert_eq!(transaction.input[0].sequence, 0);
        assert_eq!(transaction.input[1].sequence, 1);

        assert_eq!(transaction.output[0].value, total_collateral);
        assert_eq!(transaction.output[1].value, change);
        assert_eq!(transaction.output[2].value, change);
        assert_eq!(transaction.output.len(), 3);
    }

    #[test]
    fn create_funding_transaction_with_outputs_less_than_dust_limit_test() {
        let (pk, pk1) = create_multi_party_pub_keys();

        let offer_inputs = create_txin_vec(0);
        let accept_inputs = create_txin_vec(1);

        let total_collateral = 31415;
        let change = 999;

        let offer_change_output = TxOut {
            value: change,
            script_pubkey: Script::new(),
        };
        let accept_change_output = TxOut {
            value: change,
            script_pubkey: Script::new(),
        };

        let funding_script_pubkey = make_funding_redeemscript(&pk, &pk1);

        let transaction = create_funding_transaction(
            &funding_script_pubkey,
            total_collateral,
            &offer_inputs,
            &[1],
            &accept_inputs,
            &[2],
            offer_change_output,
            0,
            accept_change_output,
            1,
            0,
            0,
        );

        assert_eq!(transaction.output[0].value, total_collateral);
        assert_eq!(transaction.output.len(), 1);
    }

    #[test]
    fn create_funding_transaction_serialized_test() {
        let secp = Secp256k1::new();
        let input_amount = 5000000000;
        let change = 4899999719;
        let total_collateral = 200000312;
        let offer_change_address =
            Address::from_str("bcrt1qlgmznucxpdkp5k3ktsct7eh6qrc4tju7ktjukn").unwrap();
        let accept_change_address =
            Address::from_str("bcrt1qvh2dvgjctwh4z5w7sc93u7h4sug0yrdz2lgpqf").unwrap();

        let offer_change_output = TxOut {
            value: change,
            script_pubkey: offer_change_address.script_pubkey(),
        };

        let accept_change_output = TxOut {
            value: change,
            script_pubkey: accept_change_address.script_pubkey(),
        };

        let offer_input = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "83266d6b22a9babf6ee469b88fd0d3a0c690525f7c903aff22ec8ee44214604f",
                )
                .unwrap(),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: vec![Script::new().to_bytes()],
        };

        let accept_input = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "bc92a22f07ef23c53af343397874b59f5f8c0eb37753af1d1a159a2177d4bb98",
                )
                .unwrap(),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: vec![Script::new().to_bytes()],
        };
        let offer_fund_sk =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let offer_fund_pubkey = PublicKey::from_secret_key(&secp, &offer_fund_sk);
        let accept_fund_sk =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let accept_fund_pubkey = PublicKey::from_secret_key(&secp, &accept_fund_sk);
        let offer_input_sk =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000005")
                .unwrap();
        let accept_input_sk =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000006")
                .unwrap();

        let expected_serialized = "020000000001024F601442E48EEC22FF3A907C5F5290C6A0D3D08FB869E46EBFBAA9226B6D26830000000000FFFFFFFF98BBD477219A151A1DAF5377B30E8C5F9FB574783943F33AC523EF072FA292BC0000000000FFFFFFFF0338C3EB0B000000002200209B984C7BAE3EFDDC3A3F0A20FF81BFE89ED1FE07FF13E562149EE654BED845DBE70F102401000000160014FA3629F3060B6C1A5A365C30BF66FA00F155CB9EE70F10240100000016001465D4D622585BAF5151DE860B1E7AF58710F20DA20247304402207108DE1563AE311F8D4217E1C0C7463386C1A135BE6AF88CBE8D89A3A08D65090220195A2B0140FB9BA83F20CF45AD6EA088BB0C6860C0D4995F1CF1353739CA65A90121022F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4024730440220048716EAEE918AEBCB1BFCFAF7564E78293A7BB0164D9A7844E42FCEB5AE393C022022817D033C9DB19C5BDCADD49B7587A810B6FC2264158A59665ABA8AB298455B012103FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A146029755600000000";

        let funding_script_pubkey =
            make_funding_redeemscript(&offer_fund_pubkey, &accept_fund_pubkey);

        let mut fund_tx = create_funding_transaction(
            &funding_script_pubkey,
            total_collateral,
            &[offer_input],
            &[1],
            &[accept_input],
            &[2],
            offer_change_output,
            0,
            accept_change_output,
            1,
            0,
            0,
        );

        util::sign_p2wpkh_input(
            &secp,
            &offer_input_sk,
            &mut fund_tx,
            0,
            SigHashType::All,
            input_amount,
        );

        util::sign_p2wpkh_input(
            &secp,
            &accept_input_sk,
            &mut fund_tx,
            1,
            SigHashType::All,
            input_amount,
        );

        let mut writer = Vec::new();
        fund_tx.consensus_encode(&mut writer).unwrap();
        let mut serialized = String::new();
        for x in writer {
            let _ = write!(&mut serialized, "{:02X}", x).unwrap();
        }

        assert_eq!(expected_serialized, serialized);
    }

    fn get_p2wpkh_script_pubkey<C: Signing, R: Rng + ?Sized>(
        secp: &Secp256k1<C>,
        rng: &mut R,
    ) -> Script {
        let sk = bitcoin::PrivateKey {
            key: SecretKey::new(rng),
            network: Network::Testnet,
            compressed: true,
        };
        let pk = bitcoin::PublicKey::from_private_key(&secp, &sk);
        Address::p2wpkh(&pk, Network::Testnet)
            .unwrap()
            .script_pubkey()
    }

    fn get_party_params(
        input_amount: u64,
        collateral: u64,
        serial_id: Option<u64>,
    ) -> (PartyParams, SecretKey) {
        let secp = Secp256k1::new();
        let mut rng = secp256k1_zkp::rand::thread_rng();
        let fund_privkey = SecretKey::new(&mut rng);
        let serial_id = serial_id.unwrap_or(1);
        (
            PartyParams {
                fund_pubkey: PublicKey::from_secret_key(&secp, &fund_privkey),
                change_script_pubkey: get_p2wpkh_script_pubkey(&secp, &mut rng),
                change_serial_id: serial_id,
                payout_script_pubkey: get_p2wpkh_script_pubkey(&secp, &mut rng),
                payout_serial_id: serial_id,
                input_amount,
                collateral,
                inputs: vec![TxInputInfo {
                    max_witness_len: 108,
                    redeem_script: Script::new(),
                    outpoint: OutPoint {
                        txid: Txid::from_hex(
                            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
                        )
                        .unwrap(),
                        vout: serial_id as u32,
                    },
                    serial_id: serial_id,
                }],
            },
            fund_privkey,
        )
    }

    fn payouts() -> Vec<Payout> {
        vec![
            Payout {
                offer: 200000000,
                accept: 0,
            },
            Payout {
                offer: 0,
                accept: 200000000,
            },
        ]
    }

    #[test]
    fn get_change_output_and_fees_enough_funds() {
        // Arrange
        let (party_params, _) = get_party_params(100000, 10000, None);

        // Act

        let (change_out, fund_fee, cet_fee) = party_params.get_change_output_and_fees(4).unwrap();

        // Assert
        assert!(change_out.value > 0 && fund_fee > 0 && cet_fee > 0);
    }

    #[test]
    fn get_change_output_and_fees_not_enough_funds() {
        // Arrange
        let (party_params, _) = get_party_params(100000, 100000, None);

        // Act
        let res = party_params.get_change_output_and_fees(4);

        // Assert
        assert!(res.is_err());
    }

    #[test]
    fn create_dlc_transactions_no_error() {
        // Arrange
        let (offer_party_params, _) = get_party_params(1000000000, 100000000, None);
        let (accept_party_params, _) = get_party_params(1000000000, 100000000, None);

        // Act
        let dlc_txs = create_dlc_transactions(
            &offer_party_params,
            &accept_party_params,
            &payouts(),
            100,
            4,
            10,
            10,
            0,
        )
        .unwrap();

        // Assert
        assert_eq!(10, dlc_txs.fund.lock_time);
        assert_eq!(100, dlc_txs.refund.lock_time);
        assert!(dlc_txs.cets.iter().all(|x| x.lock_time == 10));
    }

    #[test]
    fn create_cet_adaptor_sig_is_valid() {
        // Arrange
        let secp = Secp256k1::new();
        let mut rng = secp256k1_zkp::rand::thread_rng();
        let (offer_party_params, offer_fund_sk) = get_party_params(1000000000, 100000000, None);
        let (accept_party_params, accept_fund_sk) = get_party_params(1000000000, 100000000, None);

        let dlc_txs = create_dlc_transactions(
            &offer_party_params,
            &accept_party_params,
            &payouts(),
            100,
            4,
            10,
            10,
            0,
        )
        .unwrap();

        let cets = dlc_txs.cets;
        const NB_ORACLES: usize = 3;
        const NB_OUTCOMES: usize = 2;
        const NB_DIGITS: usize = 20;
        let mut oracle_infos: Vec<OracleInfo> = Vec::with_capacity(NB_ORACLES);
        let mut oracle_sks: Vec<KeyPair> = Vec::with_capacity(NB_ORACLES);
        let mut oracle_sk_nonce: Vec<Vec<[u8; 32]>> = Vec::with_capacity(NB_ORACLES);
        let mut oracle_sigs: Vec<Vec<SchnorrSignature>> = Vec::with_capacity(NB_ORACLES);
        let messages: Vec<Vec<Vec<_>>> =
            (0..NB_OUTCOMES)
                .map(|x| {
                    (0..NB_ORACLES)
                        .map(|y| {
                            (0..NB_DIGITS)
                                .map(|z| {
                                    Message::from_hashed_data::<secp256k1_zkp::bitcoin_hashes::sha256::Hash>(&[
                                        ((y + x + z) as u8).try_into().unwrap(),
                                    ])
                                })
                                .collect()
                        })
                        .collect()
                })
                .collect();

        for i in 0..NB_ORACLES {
            let (oracle_kp, oracle_pubkey) = secp.generate_schnorrsig_keypair(&mut rng);
            let mut nonces: Vec<SchnorrPublicKey> = Vec::with_capacity(NB_DIGITS);
            let mut sk_nonces: Vec<[u8; 32]> = Vec::with_capacity(NB_DIGITS);
            oracle_sigs.push(Vec::with_capacity(NB_DIGITS));
            for j in 0..NB_DIGITS {
                let mut sk_nonce = [0u8; 32];
                rng.fill_bytes(&mut sk_nonce);
                let oracle_r_kp =
                    secp256k1_zkp::schnorrsig::KeyPair::from_seckey_slice(&secp, &sk_nonce)
                        .unwrap();
                let nonce = SchnorrPublicKey::from_keypair(&secp, &oracle_r_kp);
                let sig = secp_utils::schnorrsig_sign_with_nonce(
                    &secp,
                    &messages[0][i][j],
                    &oracle_kp,
                    &sk_nonce,
                );
                oracle_sigs[i].push(sig);
                nonces.push(nonce);
                sk_nonces.push(sk_nonce);
            }
            oracle_infos.push(OracleInfo {
                public_key: oracle_pubkey,
                nonces,
            });
            oracle_sk_nonce.push(sk_nonces);
            oracle_sks.push(oracle_kp);
        }

        let funding_script_pubkey = make_funding_redeemscript(
            &offer_party_params.fund_pubkey,
            &accept_party_params.fund_pubkey,
        );
        let fund_output_value = dlc_txs.fund.output[0].value;

        // Act
        let cet_sigs = create_cet_adaptor_sigs_from_oracle_info(
            &secp,
            &cets,
            &oracle_infos,
            &offer_fund_sk,
            &funding_script_pubkey,
            fund_output_value,
            &messages,
        )
        .unwrap();

        let sign_res = sign_cet(
            &secp,
            &mut cets[0].clone(),
            &cet_sigs[0],
            &oracle_sigs,
            &accept_fund_sk,
            &offer_party_params.fund_pubkey,
            &funding_script_pubkey,
            fund_output_value,
        );

        let adaptor_secret = signatures_to_secret(&oracle_sigs).unwrap();
        let adapted_sig = cet_sigs[0].decrypt(&adaptor_secret).unwrap();

        // Assert
        assert!(cet_sigs
            .iter()
            .enumerate()
            .all(|(i, x)| verify_cet_adaptor_sig_from_oracle_info(
                &secp,
                &x,
                &cets[i],
                &oracle_infos,
                &offer_party_params.fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
                &messages[i],
            )
            .is_ok()));
        sign_res.expect("Error signing CET");
        verify_tx_input_sig(
            &secp,
            &adapted_sig,
            &cets[0],
            0,
            &funding_script_pubkey,
            fund_output_value,
            &offer_party_params.fund_pubkey,
        )
        .expect("Invalid decrypted adaptor signature");
    }

    #[test]
    fn input_output_ordering_test() {
        struct OrderingCase {
            serials: [u64; 3],
            expected_input_order: [usize; 2],
            expected_fund_output_order: [usize; 3],
            expected_payout_order: [usize; 2],
        };

        let cases = vec![
            OrderingCase {
                serials: [0, 1, 2],
                expected_input_order: [0, 1],
                expected_fund_output_order: [0, 1, 2],
                expected_payout_order: [0, 1],
            },
            OrderingCase {
                serials: [1, 0, 2],
                expected_input_order: [0, 1],
                expected_fund_output_order: [1, 0, 2],
                expected_payout_order: [0, 1],
            },
            OrderingCase {
                serials: [2, 0, 1],
                expected_input_order: [0, 1],
                expected_fund_output_order: [2, 0, 1],
                expected_payout_order: [0, 1],
            },
            OrderingCase {
                serials: [2, 1, 0],
                expected_input_order: [1, 0],
                expected_fund_output_order: [2, 1, 0],
                expected_payout_order: [1, 0],
            },
        ];

        for case in cases {
            let (offer_party_params, _) =
                get_party_params(1000000000, 100000000, Some(case.serials[1]));
            let (accept_party_params, _) =
                get_party_params(1000000000, 100000000, Some(case.serials[2]));

            let dlc_txs = create_dlc_transactions(
                &offer_party_params,
                &accept_party_params,
                &vec![Payout {
                    offer: 100000000,
                    accept: 100000000,
                }],
                100,
                4,
                10,
                10,
                case.serials[0],
            )
            .unwrap();

            // Check that fund inputs are in correct order
            assert!(
                dlc_txs.fund.input[case.expected_input_order[0]].previous_output
                    == offer_party_params.inputs[0].outpoint
            );
            assert!(
                dlc_txs.fund.input[case.expected_input_order[1]].previous_output
                    == accept_party_params.inputs[0].outpoint
            );

            // Check that fund output are in correct order
            assert!(
                dlc_txs.fund.output[case.expected_fund_output_order[0]].script_pubkey
                    == dlc_txs.funding_script_pubkey.to_v0_p2wsh()
            );
            assert!(
                dlc_txs.fund.output[case.expected_fund_output_order[1]].script_pubkey
                    == offer_party_params.change_script_pubkey
            );
            assert!(
                dlc_txs.fund.output[case.expected_fund_output_order[2]].script_pubkey
                    == accept_party_params.change_script_pubkey
            );

            // Check payout output ordering
            assert!(
                dlc_txs.cets[0].output[case.expected_payout_order[0]].script_pubkey
                    == offer_party_params.payout_script_pubkey
            );
            assert!(
                dlc_txs.cets[0].output[case.expected_payout_order[1]].script_pubkey
                    == accept_party_params.payout_script_pubkey
            );

            crate::util::get_output_for_script_pubkey(
                &dlc_txs.fund,
                &dlc_txs.funding_script_pubkey.to_v0_p2wsh(),
            )
            .expect("Could not find fund output");
        }
    }
}
