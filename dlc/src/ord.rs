//! #
//!

use bitcoin::{OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Witness};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    checked_add, make_funding_redeemscript, DlcTransactions, Error, PartyParams, TX_VERSION,
};

/// Payout information including ordinal assignment.
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OrdPayout {
    /// Whether it should be the offer party that should receive the ordinal.
    pub to_offer: bool,
    /// The payout to the offer party.
    pub offer: u64,
    /// The payout to the accept party.
    pub accept: u64,
}

/// Information about the location of an ordinal in the blockchain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SatPoint {
    /// The outpoint where the ordinal is located.
    pub outpoint: OutPoint,
    /// The offset of the ordinal within the output.
    pub offset: u64,
}

/// Description of the location and value of the UTXO containing an ordinal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct OrdinalUtxo {
    /// The location of the ordinal.
    pub sat_point: SatPoint,
    /// The value of the UTXO.
    pub value: u64,
}

/// Create the set of transactions that make up the DLC contract for a contract including an
/// ordinal as collateral.
pub fn create_dlc_transactions(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    payouts: &[OrdPayout],
    ordinal_utxo: &OrdinalUtxo,
    refund_lock_time: u32,
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    cet_lock_time: u32,
    refund_offer: bool,
    extra_fee: u64,
) -> Result<DlcTransactions, Error> {
    let fund_sequence = crate::util::get_sequence(fund_lock_time);

    let (offer_tx_ins, offer_inputs_serial_ids) =
        offer_params.get_unsigned_tx_inputs_and_serial_ids(fund_sequence);
    let (accept_tx_ins, accept_inputs_serial_ids) =
        accept_params.get_unsigned_tx_inputs_and_serial_ids(fund_sequence);

    let total_collateral = checked_add!(offer_params.collateral, accept_params.collateral)?;

    let (offer_change_output, offer_fund_fee, offer_cet_fee) =
        offer_params.get_change_output_and_fees(fee_rate_per_vb, extra_fee)?;
    let (accept_change_output, accept_fund_fee, accept_cet_fee) =
        accept_params.get_change_output_and_fees(fee_rate_per_vb, extra_fee)?;

    let funding_script_pubkey =
        make_funding_redeemscript(&offer_params.fund_pubkey, &accept_params.fund_pubkey);
    let fund_output_value = checked_add!(
        offer_params.input_amount,
        accept_params.input_amount,
        ordinal_utxo.value
    )? - offer_change_output.value
        - accept_change_output.value
        - offer_fund_fee
        - accept_fund_fee
        - extra_fee;

    assert_eq!(
        total_collateral + offer_cet_fee + accept_cet_fee + extra_fee + ordinal_utxo.value,
        fund_output_value
    );

    assert_eq!(
        offer_params.input_amount + accept_params.input_amount + ordinal_utxo.value,
        fund_output_value
            + offer_change_output.value
            + accept_change_output.value
            + offer_fund_fee
            + accept_fund_fee
            + extra_fee
    );

    // The sort for outputs is stable so we don't need to make sure that the change serial ids of
    // offer and accept are non zero.
    let mut fund_tx = super::create_funding_transaction(
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
        0,
        fund_lock_time,
    );

    fund_tx.input.insert(
        0,
        TxIn {
            previous_output: ordinal_utxo.sat_point.outpoint,
            script_sig: Script::default(),
            sequence: fund_sequence,
            witness: Witness::default(),
        },
    );

    let fund_outpoint = OutPoint {
        txid: fund_tx.txid(),
        vout: crate::util::get_output_for_script_pubkey(
            &fund_tx,
            &funding_script_pubkey.to_v0_p2wsh(),
        )
        .expect("to find the funding script pubkey")
        .0 as u32,
    };
    let (cets, refund_tx) = create_cets_and_refund_tx(
        offer_params,
        accept_params,
        fund_outpoint,
        payouts,
        ordinal_utxo.value,
        refund_offer,
        refund_lock_time,
        cet_lock_time,
        None,
    )?;

    assert_eq!(
        ordinal_utxo.sat_point.outpoint,
        fund_tx.input[0].previous_output
    );

    Ok(DlcTransactions {
        fund: fund_tx,
        cets,
        refund: refund_tx,
        funding_script_pubkey,
    })
}

/// Generates CETs and redung transactions for a contract including an ordinal as part of the
/// collateral. Fails if the outcomes are not well formed.
pub fn create_cets_and_refund_tx(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    prev_outpoint: OutPoint,
    payouts: &[OrdPayout],
    postage: u64,
    refund_offer: bool,
    refund_lock_time: u32,
    cet_lock_time: u32,
    cet_nsequence: Option<Sequence>,
) -> Result<(Vec<Transaction>, Transaction), Error> {
    let total_collateral = crate::checked_add!(offer_params.collateral, accept_params.collateral)?;

    let cet_input = TxIn {
        previous_output: prev_outpoint,
        witness: Witness::default(),
        script_sig: Script::default(),
        sequence: cet_nsequence.unwrap_or_else(|| crate::util::get_sequence(cet_lock_time)),
    };
    let has_proper_outcomes = payouts.iter().all(|o| {
        let total = o.offer.checked_add(o.accept);
        if let Some(total) = total {
            total == total_collateral
        } else {
            false
        }
    });

    if !has_proper_outcomes {
        return Err(Error::InvalidArgument);
    }

    let cets = create_cets(
        &offer_params.payout_script_pubkey,
        &accept_params.payout_script_pubkey,
        payouts,
        postage,
        &cet_input,
        cet_lock_time,
    );

    let offer_refund_output = TxOut {
        value: offer_params.collateral,
        script_pubkey: offer_params.payout_script_pubkey.clone(),
    };

    let accept_refund_output = TxOut {
        value: accept_params.collateral,
        script_pubkey: accept_params.payout_script_pubkey.clone(),
    };

    let refund_input = TxIn {
        previous_output: prev_outpoint,
        witness: Witness::default(),
        script_sig: Script::default(),
        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
    };

    let mut output = if refund_offer {
        vec![offer_refund_output, accept_refund_output]
    } else {
        vec![accept_refund_output, offer_refund_output]
    };
    output = crate::util::discard_dust(output, crate::DUST_LIMIT);
    output[0].value += postage;
    let refund_tx = Transaction {
        version: TX_VERSION,
        lock_time: PackedLockTime(refund_lock_time),
        input: vec![refund_input],
        output,
    };
    Ok((cets, refund_tx))
}

/// Generates the CETs for a contract including an ordinal as part of the collateral.
pub fn create_cets(
    offer_payout_script_pubkey: &Script,
    accept_payout_script_pubkey: &Script,
    payouts: &[OrdPayout],
    postage: u64,
    cet_input: &TxIn,
    cet_lock_time: u32,
) -> Vec<Transaction> {
    let mut cets: Vec<Transaction> = Vec::new();
    for payout in payouts {
        let (offer_payout, accept_payout) = if payout.to_offer {
            (payout.offer + postage, payout.accept)
        } else {
            (payout.offer, payout.accept + postage)
        };
        let offer_output = TxOut {
            value: offer_payout,
            script_pubkey: offer_payout_script_pubkey.clone(),
        };
        let accept_output = TxOut {
            value: accept_payout,
            script_pubkey: accept_payout_script_pubkey.clone(),
        };

        // We use the `to_offer` boolean to order the outputs. If true, we want the offer
        // payout to be first, so convert `!to_offer` to u64 will give 0, and inversely.
        let tx = crate::create_cet(
            offer_output,
            (!payout.to_offer) as u64,
            accept_output,
            payout.to_offer as u64,
            cet_input,
            cet_lock_time,
        );

        // We make sure that the ordinal cannot be spent as fee.
        assert!(tx.output[0].value >= postage);
        cets.push(tx);
    }

    cets
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::hex::FromHex, OutPoint, Txid};

    use crate::DlcTransactions;

    use super::{create_dlc_transactions, OrdPayout, OrdinalUtxo, SatPoint};

    const TOTAL_COLLATERAL: u64 = 20000;

    fn get_ordinal_utxo(value: u64, offset: u64) -> OrdinalUtxo {
        OrdinalUtxo {
            sat_point: SatPoint {
                outpoint: OutPoint {
                    txid: Txid::from_hex(
                        "6df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
                    )
                    .unwrap(),
                    vout: 0,
                },
                offset,
            },
            value,
        }
    }

    fn get_dlc_transactions(
        postage: u64,
        offset: u64,
        serial_ids: Option<(u64, u64)>,
    ) -> DlcTransactions {
        let ordinal_utxo = get_ordinal_utxo(postage, offset);
        let (serial_id1, serial_id2) = serial_ids.map_or((None, None), |(x, y)| (Some(x), Some(y)));
        let (offer_params, _) = crate::tests::get_party_params(100000, 10000, serial_id1);
        let (accept_params, _) = crate::tests::get_party_params(100000, 10000, serial_id2);

        let payouts = vec![OrdPayout {
            to_offer: false,
            offer: TOTAL_COLLATERAL,
            accept: 0,
        }];
        create_dlc_transactions(
            &offer_params,
            &accept_params,
            &payouts,
            &ordinal_utxo,
            0,
            2,
            0,
            0,
            true,
            0,
        )
        .expect("To be able to build transactions")
    }

    #[test]
    fn create_ord_dlc_transactions_test() {
        let dlc_transactions = get_dlc_transactions(10000, 0, None);
        assert_eq!(0, dlc_transactions.get_fund_output_index());
        assert_eq!(10000, dlc_transactions.cets[0].output[0].value);
        assert_eq!(20000, dlc_transactions.refund.output[0].value);
    }

    #[test]
    fn create_ord_dlc_transactions_with_different_postage_test() {
        let dlc_transactions = get_dlc_transactions(25000, 0, None);
        assert_eq!(0, dlc_transactions.get_fund_output_index());
        assert_eq!(25000, dlc_transactions.cets[0].output[0].value);
    }

    #[test]
    fn create_ord_dlc_transactions_with_all_zero_serial_ids_test() {
        let dlc_transactions = get_dlc_transactions(10000, 0, Some((0, 0)));
        assert_eq!(0, dlc_transactions.get_fund_output_index());
        assert_eq!(10000, dlc_transactions.cets[0].output[0].value);
    }
}
