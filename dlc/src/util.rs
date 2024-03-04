//! Utility functions not uniquely related to DLC

use bitcoin::util::sighash::SighashCache;
use bitcoin::{
    blockdata::script::Builder, hash_types::PubkeyHash, util::address::Payload, EcdsaSighashType,
    Script, Transaction, TxOut,
};
use bitcoin::{Sequence, Witness};
use secp256k1_zkp::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey, Signing};

use crate::channel::{BUFFER_TX_WEIGHT, CET_EXTRA_WEIGHT};
use crate::Error;

// Setting the nSequence for every input of a transaction to this value disables
// both RBF and nLockTime usage.
pub(crate) const DISABLE_LOCKTIME: Sequence = Sequence(0xffffffff);
// Setting the nSequence for every input of a transaction to this value disables
// RBF but enables nLockTime usage.
pub(crate) const ENABLE_LOCKTIME: Sequence = Sequence(0xfffffffe);

const MIN_FEE: u64 = 153;

/// Get a BIP143 (https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
/// signature hash with sighash all flag for a segwit transaction input as
/// a Message instance
pub(crate) fn get_sig_hash_msg(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    value: u64,
) -> Result<Message, Error> {
    let sig_hash = SighashCache::new(tx).segwit_signature_hash(
        input_index,
        script_pubkey,
        value,
        EcdsaSighashType::All,
    )?;
    Ok(Message::from_slice(&sig_hash).unwrap())
}

/// Convert a raw signature to DER encoded and append the sighash type, to use
/// a signature in a signature script
pub(crate) fn finalize_sig(sig: &Signature, sig_hash_type: EcdsaSighashType) -> Vec<u8> {
    [
        sig.serialize_der().as_ref(),
        &[sig_hash_type.to_u32() as u8],
    ]
    .concat()
}

/// Generate a signature for a given transaction input using the given secret key.
pub fn get_raw_sig_for_tx_input<C: Signing>(
    secp: &Secp256k1<C>,
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    value: u64,
    sk: &SecretKey,
) -> Result<Signature, Error> {
    let sig_hash_msg = get_sig_hash_msg(tx, input_index, script_pubkey, value)?;
    Ok(secp.sign_ecdsa_low_r(&sig_hash_msg, sk))
}

/// Returns a DER encoded signature with appended sighash for the specified input
/// in the provided transaction (assumes a segwit input)
pub fn get_sig_for_tx_input<C: Signing>(
    secp: &Secp256k1<C>,
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    value: u64,
    sig_hash_type: EcdsaSighashType,
    sk: &SecretKey,
) -> Result<Vec<u8>, Error> {
    let sig = get_raw_sig_for_tx_input(secp, tx, input_index, script_pubkey, value, sk)?;
    Ok(finalize_sig(&sig, sig_hash_type))
}

/// Returns a DER encoded signature with apended sighash for the specified P2WPKH input.
pub fn get_sig_for_p2wpkh_input<C: Signing>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    tx: &Transaction,
    input_index: usize,
    value: u64,
    sig_hash_type: EcdsaSighashType,
) -> Result<Vec<u8>, Error> {
    let script_pubkey = get_pkh_script_pubkey_from_sk(secp, sk);
    get_sig_for_tx_input(
        secp,
        tx,
        input_index,
        &script_pubkey,
        value,
        sig_hash_type,
        sk,
    )
}

/// Computes the required fee for a transaction based on the given weight and fee
/// rate per vbyte.
pub fn tx_weight_to_fee(weight: usize, fee_rate: u64) -> Result<u64, Error> {
    let fee = weight_to_fee(weight, fee_rate)?;

    Ok(u64::max(fee, MIN_FEE))
}

/// Computes the required fee for the given weight in weight units and fee rate in sats per vbyte.
pub fn weight_to_fee(weight: usize, fee_rate: u64) -> Result<u64, Error> {
    let vbytes = f64::ceil((weight as f64) / 4.0) as u64;
    let fee = vbytes
        .checked_mul(fee_rate)
        .ok_or(Error::InvalidArgument(format!(
            "Failed to multiply fee rate: {} to weight",
            fee_rate
        )))?;

    Ok(fee)
}

/// Calculate the base transaction fee for a CET or refund transaction, for the given fee rate.
pub fn cet_or_refund_base_fee(fee_rate: u64) -> Result<u64, Error> {
    let base_weight = crate::CET_BASE_WEIGHT;
    tx_weight_to_fee(base_weight, fee_rate)
}

/// Calculate the extra transaction fees that need to be reserved when opening a DLC channel.
///
/// These fees apply to the entire channel and will need to be divided between the two parties.
pub fn dlc_channel_extra_fee(fee_rate: u64) -> Result<u64, Error> {
    tx_weight_to_fee(BUFFER_TX_WEIGHT + CET_EXTRA_WEIGHT, fee_rate)
}

/// Calculate the fraction of a transaction fee that must be included to pay for the given payout
/// output script pubkey.
///
/// Payout outputs are included in CETs and refund transactions.
pub fn dlc_payout_spk_fee(payout_spk: &Script, fee_rate_sats_per_vb: u64) -> u64 {
    // Numbers come from
    // https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#expected-weight-of-the-contract-execution-or-refund-transaction.

    let value_vb = 8;
    let var_int_vb = 1;

    let payout_spk_vb = payout_spk.len() as u64;

    (value_vb + var_int_vb + payout_spk_vb) * fee_rate_sats_per_vb
}

fn get_pkh_script_pubkey_from_sk<C: Signing>(secp: &Secp256k1<C>, sk: &SecretKey) -> Script {
    use bitcoin::hashes::*;
    let pk = bitcoin::PublicKey {
        compressed: true,
        inner: PublicKey::from_secret_key(secp, sk),
    };
    let mut hash_engine = PubkeyHash::engine();
    pk.write_into(&mut hash_engine)
        .expect("Error writing hash.");
    let pkh = Payload::PubkeyHash(PubkeyHash::from_engine(hash_engine));
    pkh.script_pubkey()
}

/// Create a signature for a p2wpkh transaction input using the provided secret key
/// and places the signature and associated public key on the witness stack.
pub fn sign_p2wpkh_input<C: Signing>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    tx: &mut Transaction,
    input_index: usize,
    sig_hash_type: EcdsaSighashType,
    value: u64,
) -> Result<(), Error> {
    tx.input[input_index].witness =
        get_witness_for_p2wpkh_input(secp, sk, tx, input_index, sig_hash_type, value)?;
    Ok(())
}

/// Generates the witness data for a P2WPKH input using the provided secret key.
pub fn get_witness_for_p2wpkh_input<C: Signing>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    tx: &Transaction,
    input_index: usize,
    sig_hash_type: EcdsaSighashType,
    value: u64,
) -> Result<Witness, Error> {
    let full_sig = get_sig_for_p2wpkh_input(secp, sk, tx, input_index, value, sig_hash_type)?;
    Ok(Witness::from_vec(vec![
        full_sig,
        PublicKey::from_secret_key(secp, sk).serialize().to_vec(),
    ]))
}

/// Generates a signature for a given p2wsh transaction input using the given secret
/// key and info, and places the generated and provided signatures on the input's
/// witness stack, ordering the signatures based on the ordering of the associated
/// public keys.
pub fn sign_multi_sig_input<C: Signing>(
    secp: &Secp256k1<C>,
    transaction: &mut Transaction,
    other_sig: &Signature,
    other_pk: &PublicKey,
    sk: &SecretKey,
    script_pubkey: &Script,
    input_value: u64,
    input_index: usize,
) -> Result<(), Error> {
    let own_sig = get_raw_sig_for_tx_input(
        secp,
        transaction,
        input_index,
        script_pubkey,
        input_value,
        sk,
    )?;

    let own_pk = PublicKey::from_secret_key(secp, sk);

    finalize_multi_sig_input_transaction(
        transaction,
        vec![(*other_pk, *other_sig), (own_pk, own_sig)],
        script_pubkey,
        input_index,
    );

    Ok(())
}

/// Sorts signatures based on the lexicographical order of associated public keys, appends
/// `EcdsaSighashType::All` to each signature, and insert them in the transaction witness for the
/// provided input index, together with the given script pubkey.
pub fn finalize_multi_sig_input_transaction(
    transaction: &mut Transaction,
    mut signature_pubkey_pairs: Vec<(PublicKey, Signature)>,
    script_pubkey: &Script,
    input_index: usize,
) {
    signature_pubkey_pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    let mut signatures = signature_pubkey_pairs
        .into_iter()
        .map(|(_, s)| finalize_sig(&s, EcdsaSighashType::All))
        .collect();
    let mut witness = vec![Vec::new()];
    witness.append(&mut signatures);
    witness.push(script_pubkey.to_bytes());
    transaction.input[input_index].witness = Witness::from_vec(witness);
}

/// Transforms a redeem script for a p2sh-p2w* output to a script signature.
pub(crate) fn redeem_script_to_script_sig(redeem: &Script) -> Script {
    match redeem.len() {
        0 => Script::new(),
        _ => Builder::new().push_slice(redeem.as_bytes()).into_script(),
    }
}

/// Sorts the given inputs in following the order of the ids.
pub(crate) fn order_by_serial_ids<T>(inputs: Vec<T>, ids: &[u64]) -> Vec<T> {
    debug_assert!(inputs.len() == ids.len());
    let mut combined: Vec<(&u64, T)> = ids.iter().zip(inputs).collect();
    combined.sort_by(|a, b| a.0.partial_cmp(b.0).unwrap());
    combined.into_iter().map(|x| x.1).collect()
}

/// Get the vout and TxOut of the first output with a matching `script_pubkey`
/// if any.
pub fn get_output_for_script_pubkey<'a>(
    tx: &'a Transaction,
    script_pubkey: &Script,
) -> Option<(usize, &'a TxOut)> {
    tx.output
        .iter()
        .enumerate()
        .find(|(_, x)| &x.script_pubkey == script_pubkey)
}

/// Filters the outputs that have a value lower than the given `dust_limit`.
pub(crate) fn discard_dust(txs: Vec<TxOut>, dust_limit: u64) -> Vec<TxOut> {
    txs.into_iter().filter(|x| x.value >= dust_limit).collect()
}

pub(crate) fn get_sequence(lock_time: u32) -> Sequence {
    if lock_time == 0 {
        DISABLE_LOCKTIME
    } else {
        ENABLE_LOCKTIME
    }
}

pub(crate) fn compute_var_int_prefix_size(len: usize) -> usize {
    bitcoin::VarInt(len as u64).len()
}

/// Validate that the fee rate is not too high
pub fn validate_fee_rate(fee_rate_per_vb: u64) -> Result<(), Error> {
    if fee_rate_per_vb > 25 * 250 {
        return Err(Error::InvalidArgument(format!("Fee rate: {} greater than 25 * 250", fee_rate_per_vb)));
    }

    Ok(())
}
