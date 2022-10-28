//! Utility functions not uniquely related to DLC

use bitcoin::util::bip143::SigHashCache;
use bitcoin::{
    blockdata::script::Builder, hash_types::PubkeyHash, util::address::Payload, Script,
    SigHashType, Transaction, TxOut,
};
use secp256k1_zkp::{Message, PublicKey, Secp256k1, SecretKey, Signature, Signing};

// Setting the nSequence for every input of a transaction to this value disables
// both RBF and nLockTime usage.
pub(crate) const DISABLE_LOCKTIME: u32 = 0xffffffff;
// Setting the nSequence for every input of a transaction to this value disables
// RBF but enables nLockTime usage.
pub(crate) const ENABLE_LOCKTIME: u32 = 0xfffffffe;

/// Get a BIP143 (https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
/// signature hash with sighash all flag for a segwit transaction input as
/// a Message instance
pub(crate) fn get_sig_hash_msg(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    value: u64,
) -> Message {
    let sig_hash =
        SigHashCache::new(tx).signature_hash(input_index, script_pubkey, value, SigHashType::All);
    Message::from_slice(&sig_hash).unwrap()
}

/// Convert a raw signature to DER encoded and append the sighash type, to use
/// a signature in a signature script
pub(crate) fn finalize_sig(sig: &Signature, sig_hash_type: SigHashType) -> Vec<u8> {
    [
        sig.serialize_der().as_ref(),
        &[sig_hash_type.as_u32() as u8],
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
) -> Signature {
    let sig_hash_msg = get_sig_hash_msg(tx, input_index, script_pubkey, value);
    secp.sign_low_r(&sig_hash_msg, sk)
}

/// Returns a DER encoded signature with appended sighash for the specified input
/// in the provided transaction (assumes a segwit input)
pub fn get_sig_for_tx_input<C: Signing>(
    secp: &Secp256k1<C>,
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &Script,
    value: u64,
    sig_hash_type: SigHashType,
    sk: &SecretKey,
) -> Vec<u8> {
    let sig = get_raw_sig_for_tx_input(secp, tx, input_index, script_pubkey, value, sk);
    finalize_sig(&sig, sig_hash_type)
}

/// Returns a DER encoded signature with apended sighash for the specified P2WPKH input.
pub fn get_sig_for_p2wpkh_input<C: Signing>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    tx: &Transaction,
    input_index: usize,
    value: u64,
    sig_hash_type: SigHashType,
) -> Vec<u8> {
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

pub(crate) fn weight_to_fee(weight: usize, fee_rate: u64) -> u64 {
    (f64::ceil((weight as f64) / 4.0) as u64) * fee_rate
}

fn get_pkh_script_pubkey_from_sk<C: Signing>(secp: &Secp256k1<C>, sk: &SecretKey) -> Script {
    use bitcoin::hashes::*;
    let pk = bitcoin::PublicKey {
        compressed: true,
        key: PublicKey::from_secret_key(secp, sk),
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
    sig_hash_type: SigHashType,
    value: u64,
) {
    tx.input[input_index].witness =
        get_witness_for_p2wpkh_input(secp, sk, tx, input_index, sig_hash_type, value);
}

/// Generates the witness data for a P2WPKH input using the provided secret key.
pub fn get_witness_for_p2wpkh_input<C: Signing>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    tx: &Transaction,
    input_index: usize,
    sig_hash_type: SigHashType,
    value: u64,
) -> Vec<Vec<u8>> {
    let full_sig = get_sig_for_p2wpkh_input(secp, sk, tx, input_index, value, sig_hash_type);
    vec![
        full_sig,
        PublicKey::from_secret_key(secp, sk).serialize().to_vec(),
    ]
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
) {
    let own_sig = get_sig_for_tx_input(
        secp,
        transaction,
        input_index,
        script_pubkey,
        input_value,
        SigHashType::All,
        sk,
    );

    let own_pk = &PublicKey::from_secret_key(secp, sk);

    let other_finalized_sig = finalize_sig(other_sig, SigHashType::All);

    transaction.input[input_index].witness = if own_pk < other_pk {
        vec![
            Vec::new(),
            own_sig,
            other_finalized_sig,
            script_pubkey.to_bytes(),
        ]
    } else {
        vec![
            Vec::new(),
            other_finalized_sig,
            own_sig,
            script_pubkey.to_bytes(),
        ]
    };
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
    let mut combined: Vec<(&u64, T)> = ids.iter().zip(inputs.into_iter()).collect();
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

pub(crate) fn get_sequence(lock_time: u32) -> u32 {
    if lock_time == 0 {
        DISABLE_LOCKTIME
    } else {
        ENABLE_LOCKTIME
    }
}
