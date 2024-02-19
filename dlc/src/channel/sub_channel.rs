//! Module containing utility functions to create transactions for DLC channels embedded in
//! Lightning channels.
//!

use std::collections::HashMap;

use bitcoin::{
    Address, EcdsaSig, OutPoint, PackedLockTime, PublicKey, Script, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use secp256k1_zkp::{PublicKey as SecpPublicKey, Secp256k1, SecretKey, Signing};

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

/// Computes the total amount of fee required for a split transaction plus transactions of a DLC
/// channel.
/// # Errors
/// Returns an error if the given `fee_rate_per_vb` is too large resulting in an overflow during
/// the computation.
pub fn dlc_channel_and_split_fee(fee_rate_per_vb: u64) -> Result<u64, Error> {
    Ok(crate::util::tx_weight_to_fee(
        crate::channel::sub_channel::SPLIT_TX_WEIGHT,
        fee_rate_per_vb,
    )? + crate::util::tx_weight_to_fee(crate::channel::BUFFER_TX_WEIGHT, fee_rate_per_vb)?
        + crate::util::tx_weight_to_fee(
            crate::channel::CET_EXTRA_WEIGHT
                + crate::CET_BASE_WEIGHT
                + crate::P2WPKH_WITNESS_SIZE * 2
                + 18,
            fee_rate_per_vb,
        )?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Structure containing a split transaction and its associated output script.
pub struct SplitTx {
    /// The actual Bitcoin transaction representation.
    pub transaction: Transaction,
    /// The script used to lock the outputs.
    pub output_script: Script,
}

/// Creates a [`SplitTx`] struct from the given parameter.
/// # Errors
/// Returns an error if the given fee rate makes fee computation overflow, or if the given
/// `channel_value` is not enough for the given `dlc_collateral` and fee.
pub fn create_split_tx(
    offer_revoke_params: &RevokeParams,
    accept_revoke_params: &RevokeParams,
    fund_tx_outpoint: &OutPoint,
    channel_value: u64,
    dlc_collateral: u64,
    fee_rate_per_vb: u64,
) -> Result<SplitTx, Error> {
    let output_desc = buffer_descriptor(offer_revoke_params, accept_revoke_params);

    let dlc_fee = crate::util::tx_weight_to_fee(super::BUFFER_TX_WEIGHT, fee_rate_per_vb)?
        + crate::util::tx_weight_to_fee(
            super::CET_EXTRA_WEIGHT + crate::CET_BASE_WEIGHT + 2 * crate::P2WPKH_WITNESS_SIZE + 18,
            fee_rate_per_vb,
        )?;

    let dlc_output_value = dlc_collateral
        .checked_add(dlc_fee)
        .ok_or(Error::InvalidArgument("Failed to checked add dlc fee to dlc collateral".to_string()))?;

    if dlc_output_value
        > channel_value
            .checked_add(crate::DUST_LIMIT)
            .ok_or(Error::InvalidArgument("Failed to checked add dust limit to channel value".to_string()))?
    {
        return Err(Error::InvalidArgument(format!("Dlc output value greater than channel value: {} + dust limit: {}", channel_value, crate::DUST_LIMIT)));
    }

    let ln_output_value = channel_value
        - dlc_output_value
        - crate::util::tx_weight_to_fee(SPLIT_TX_WEIGHT, fee_rate_per_vb)?;

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
                previous_output: *fund_tx_outpoint,
                script_sig: Script::default(),
                sequence: Sequence::ZERO,
                witness: Witness::default(),
            }],
            output,
        },
        output_script: output_desc.script_code().unwrap(),
    })
}

/// Creates a "glue" transaction for the Lightning side of the split channel.
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
                previous_output: *split_tx_outpoint,
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

/// Creates and signs a transaction spending both output of a revoked split transaction that was
/// published on-chain.
pub fn create_and_sign_punish_split_transaction<C: Signing>(
    secp: &Secp256k1<C>,
    offer_params: &RevokeParams,
    accept_params: &RevokeParams,
    own_sk: &SecretKey,
    counter_publish_sk: &SecretKey,
    counter_revoke_sk: &SecretKey,
    prev_tx: &Transaction,
    dest_address: &Address,
    lock_time: u32,
    fee_rate_per_vb: u64,
) -> Result<Transaction, Error> {
    let descriptor = buffer_descriptor(offer_params, accept_params);

    let tx_in = vec![
        TxIn {
            previous_output: OutPoint {
                txid: prev_tx.txid(),
                vout: 0,
            },
            sequence: Sequence::ZERO,
            script_sig: Script::default(),
            witness: Witness::default(),
        },
        TxIn {
            previous_output: OutPoint {
                txid: prev_tx.txid(),
                vout: 1,
            },
            sequence: Sequence::ZERO,
            script_sig: Script::default(),
            witness: Witness::default(),
        },
    ];

    let dest_script_pk_len = dest_address.script_pubkey().len();
    let var_int_prefix_len = crate::util::compute_var_int_prefix_size(dest_script_pk_len);
    let output_weight = super::N_VALUE_WEIGHT + var_int_prefix_len + dest_script_pk_len * 4;
    let tx_fee = crate::util::tx_weight_to_fee(
        super::PUNISH_BUFFER_INPUT_WEIGHT * 2 + output_weight,
        fee_rate_per_vb,
    )?;

    let output_value = prev_tx.output[0].value + prev_tx.output[1].value - tx_fee;

    let mut tx = Transaction {
        version: crate::TX_VERSION,
        lock_time: PackedLockTime(lock_time),
        input: tx_in,
        output: vec![TxOut {
            value: output_value,
            script_pubkey: dest_address.script_pubkey(),
        }],
    };

    for i in 0..2 {
        let mut sigs = HashMap::new();

        for sk in &[&own_sk, &counter_publish_sk, &counter_revoke_sk] {
            let pk = PublicKey {
                inner: SecpPublicKey::from_secret_key(secp, sk),
                compressed: true,
            };

            let pkh = pk.pubkey_hash().as_hash();
            sigs.insert(
                pkh,
                (
                    pk,
                    EcdsaSig::sighash_all(crate::util::get_raw_sig_for_tx_input(
                        secp,
                        &tx,
                        i,
                        &descriptor.script_code()?,
                        prev_tx.output[i].value,
                        sk,
                    )?),
                ),
            );
        }

        descriptor
            .satisfy(&mut tx.input[i], sigs.clone())
            .map_err(|e| Error::InvalidArgument(format!("{e:#}")))?;
    }

    Ok(tx)
}
