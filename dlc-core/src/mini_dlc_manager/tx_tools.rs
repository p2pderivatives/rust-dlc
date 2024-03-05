use bitcoin::{
    address::{WitnessProgram, WitnessVersion},
    script::PushBytesBuf,
    Script, ScriptBuf, Sequence, Transaction, TxOut,
};

use crate::error::FromDlcError;

// Setting the nSequence for every input of a transaction to this value disables
// both RBF and nLockTime usage.
pub(crate) const DISABLE_LOCKTIME: Sequence = Sequence(0xffffffff);
/// Setting the nSequence for every input of a transaction to this value disables
/// RBF but enables nLockTime usage.
pub const ENABLE_LOCKTIME: Sequence = Sequence(0xfffffffe);

/// Minimum value that can be included in a transaction output. Under this value,
/// outputs are discarded
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#change-outputs
pub const DUST_LIMIT: u64 = 1000;

/// The transaction version
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#funding-transaction
pub const TX_VERSION: i32 = 2;

/// The base weight of a fund transaction
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
pub const FUND_TX_BASE_WEIGHT: usize = 214;

/// The weight of a CET excluding payout outputs
/// See: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees
pub const CET_BASE_WEIGHT: usize = 500;

/// The base weight of a transaction input computed as: (outpoint(36) + sequence(4) + scriptPubKeySize(1)) * 4
/// See: <https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees>
pub const TX_INPUT_BASE_WEIGHT: usize = 164;

/// The witness size of a P2WPKH input
/// See: <https://github.com/discreetlogcontracts/dlcspecs/blob/master/Transactions.md#fees>
pub const P2WPKH_WITNESS_SIZE: usize = 107;

/// Transforms a redeem script for a p2sh-p2w* output to a script signature.
pub(crate) fn redeem_script_to_script_sig(redeem: &Script) -> ScriptBuf {
    match redeem.len() {
        0 => ScriptBuf::new(),
        _ => {
            let mut bytes = PushBytesBuf::new();
            bytes.extend_from_slice(redeem.as_bytes()).unwrap();
            ScriptBuf::new_witness_program(&WitnessProgram::new(WitnessVersion::V0, bytes).unwrap())
        }
    }
}

/// Sorts the given inputs in following the order of the ids.
pub fn order_by_serial_ids<T>(inputs: Vec<T>, ids: &[u64]) -> Vec<T> {
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
pub fn discard_dust(txs: Vec<TxOut>, dust_limit: u64) -> Vec<TxOut> {
    txs.into_iter().filter(|x| x.value >= dust_limit).collect()
}

/// nSequence enable or disable locktime
pub fn get_sequence(lock_time: u32) -> Sequence {
    if lock_time == 0 {
        DISABLE_LOCKTIME
    } else {
        ENABLE_LOCKTIME
    }
}

/// Returns the fee for the given weight at given fee rate.
pub fn weight_to_fee(weight: usize, fee_rate: u64) -> Result<u64, FromDlcError> {
    (f64::ceil((weight as f64) / 4.0) as u64)
        .checked_mul(fee_rate)
        .ok_or(FromDlcError::InvalidArgument)
}
