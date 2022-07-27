//!
//!

use bitcoin::{OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::{channel::buffer_descriptor, Error};

use super::{RevokeParams, BUFFER_TX_WEIGHT};

/**
 * Weight of the split transaction:
 * INPUT
 * Overhead -> 10.5 * 4
 * Outpoint -> 36 * 4
 * scriptSigLength -> 1 * 4
 * scriptSig -> 0
 * nSequence -> 4 * 4
 * Witness item count -> 1
 * Witness -> 220
 * OUTPUT (x2):
 *      nValue -> 8 * 4
 *      scriptPubkeyLen -> 1 * 4
 *      scriptPubkey -> 34 * 4
 * TOTAL: 771
*/
pub const SPLIT_TX_WEIGHT: usize = 771;

/**
 * Weight of the ln glue transaction is the same as the buffer transaction.
*/
pub const LN_GLUE_TX_WEIGHT: usize = BUFFER_TX_WEIGHT;

///
pub const DLC_CHANNEL_AND_SPLIT_MIN_WEIGHT: usize = crate::channel::sub_channel::SPLIT_TX_WEIGHT
    + crate::channel::BUFFER_TX_WEIGHT
    + crate::channel::CET_EXTRA_WEIGHT
    + crate::CET_BASE_WEIGHT
    + crate::P2WPKH_WITNESS_SIZE * 2
    + 18;

#[derive(Clone, Debug)]
///
pub struct SplitTx {
    ///
    pub transaction: Transaction,
    ///
    pub output_script: Script,
}

///
pub fn create_split_tx(
    offer_revoke_params: &RevokeParams,
    accept_revoke_params: &RevokeParams,
    fund_tx_outpoint: &OutPoint,
    channel_value: u64,
    dlc_collateral: u64,
    fee_rate_per_vb: u64,
) -> Result<SplitTx, Error> {
    let output_desc = buffer_descriptor(offer_revoke_params, accept_revoke_params);

    let dlc_fee = crate::util::weight_to_fee(
        super::BUFFER_TX_WEIGHT
            + super::CET_EXTRA_WEIGHT
            + crate::CET_BASE_WEIGHT
            + 2 * crate::P2WPKH_WITNESS_SIZE
            + 18,
        fee_rate_per_vb,
    )?;

    let dlc_output_value = dlc_collateral + dlc_fee;

    if dlc_output_value > channel_value + crate::DUST_LIMIT {
        return Err(Error::InvalidArgument);
    }

    let ln_output_value = channel_value
        - dlc_output_value
        - crate::util::weight_to_fee(SPLIT_TX_WEIGHT, fee_rate_per_vb)?;

    let output_values = [ln_output_value, dlc_output_value];

    let output = output_values
        .iter()
        .map(|value| TxOut {
            value: *value,
            script_pubkey: output_desc.script_pubkey(),
        })
        .collect::<Vec<_>>();

    Ok(SplitTx {
        transaction: Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: vec![TxIn {
                previous_output: fund_tx_outpoint.clone(),
                script_sig: Script::default(),
                sequence: Sequence::ZERO,
                witness: Witness::default(),
            }],
            output,
        },
        output_script: output_desc.script_code().unwrap(),
    })
}

///
pub fn create_ln_glue_tx(
    split_tx_outpoint: &OutPoint,
    ln_fund_script: &Script,
    lock_time: PackedLockTime,
    nsequence: Sequence,
    output_value: u64,
) -> Transaction {
    Transaction {
        version: 2,
        lock_time,
        input: {
            vec![TxIn {
                previous_output: split_tx_outpoint.clone(),
                script_sig: Script::default(),
                sequence: nsequence,
                witness: Witness::default(),
            }]
        },
        output: vec![TxOut {
            value: output_value,
            script_pubkey: ln_fund_script.to_v0_p2wsh(),
        }],
    }
}
