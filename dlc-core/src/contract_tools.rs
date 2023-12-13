use bitcoin::{OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Witness};
use dlc::{checked_add, make_funding_redeemscript, util, DlcTransactions, PartyParams, Payout};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::FromDlcError;

type Error = FromDlcError;

/// Contains the parameters required for creating DLC transactions for a fee
/// collecting party.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct FeePartyParams {
    /// The amount of fee to be paid in funding transaction
    pub change_fee_value: u64,
    /// An address to receive fees in funding
    pub change_script_pubkey: Script,
    /// Id used to order fund outputs
    pub change_serial_id: u64,
}

/// Contains the parameters to add an anchor output
/// to CPFP CET
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct AnchorParams {
    /// The amount of fee to be paid in cet transaction
    pub payout_fee_value: u64,
    /// An address to receive the outcome amount
    pub payout_script_pubkey: Script,
    /// Id used to order CET outputs
    pub payout_serial_id: u64,
}

/// Create the transactions for a DLC contract based on the provided parameters
pub fn create_dlc_transactions(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_party_params: Option<&FeePartyParams>,
    anchors_params: Option<&[AnchorParams]>,
    payouts: &[Payout],
    refund_lock_time: u32,
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    cet_lock_time: u32,
    fund_output_serial_id: u64,
) -> Result<DlcTransactions, Error> {
    let anchors_outputs = anchors_params.map(|a| {
        a.iter()
            .map(|p| TxOut {
                value: p.payout_fee_value,
                script_pubkey: p.payout_script_pubkey.clone(),
            })
            .collect::<Box<[_]>>()
    });

    let anchors_serials_ids =
        anchors_params.map(|a| a.iter().map(|p| p.payout_serial_id).collect::<Box<[_]>>());

    let (fund_tx, funding_script_pubkey) = create_fund_transaction_with_fees(
        offer_params,
        accept_params,
        fee_party_params,
        anchors_outputs.as_deref(),
        fee_rate_per_vb,
        fund_lock_time,
        fund_output_serial_id,
        0,
    )?;
    let fund_outpoint = OutPoint {
        txid: fund_tx.txid(),
        vout: util::get_output_for_script_pubkey(&fund_tx, &funding_script_pubkey.to_v0_p2wsh())
            .expect("to find the funding script pubkey")
            .0 as u32,
    };
    let (cets, refund_tx) = create_cets_and_refund_tx(
        offer_params,
        accept_params,
        anchors_outputs.as_deref(),
        anchors_serials_ids.as_deref(),
        fund_outpoint,
        payouts,
        refund_lock_time,
        cet_lock_time,
        None,
    )?;

    Ok(DlcTransactions {
        fund: fund_tx,
        cets,
        refund: refund_tx,
        funding_script_pubkey,
    })
}

pub(crate) fn create_fund_transaction_with_fees(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_party_params: Option<&FeePartyParams>,
    anchors_outputs: Option<&[TxOut]>,
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    fund_output_serial_id: u64,
    extra_fee: u64,
) -> Result<(Transaction, Script), Error> {
    let total_collateral = checked_add!(offer_params.collateral, accept_params.collateral)?;

    let total_extra_coordinator_fee = fee_party_params
        .map(|p| {
            p.change_fee_value + (fee_rate_per_vb * (9_u64 + p.change_script_pubkey.len() as u64))
        })
        .unwrap_or(0);

    // Emulate ceil function
    let party_coordinator_fee = total_extra_coordinator_fee / 2 + total_extra_coordinator_fee % 2;

    let total_payout_coordinator_fee = match anchors_outputs.as_ref() {
        Some(anchors) => anchors
            .as_ref()
            .iter()
            .map(|p| p.value + (fee_rate_per_vb * (9_u64 + p.script_pubkey.len() as u64)))
            .sum(),
        None => 0,
    };

    let in_payout_coordinator_fee =
        total_payout_coordinator_fee / 2 + total_payout_coordinator_fee % 2;

    let (offer_change_output, offer_fund_fee, offer_cet_fee) = offer_params
        .get_change_output_and_fees(
            fee_rate_per_vb,
            extra_fee + party_coordinator_fee + in_payout_coordinator_fee,
        )
        .map_err(FromDlcError::Dlc)?;
    let (accept_change_output, accept_fund_fee, accept_cet_fee) = accept_params
        .get_change_output_and_fees(
            fee_rate_per_vb,
            extra_fee + party_coordinator_fee + in_payout_coordinator_fee,
        )
        .map_err(FromDlcError::Dlc)?;

    let fund_output_value = checked_add!(offer_params.input_amount, accept_params.input_amount)?
        - offer_change_output.value
        - accept_change_output.value
        - offer_fund_fee
        - accept_fund_fee
        - extra_fee
        - (2 * party_coordinator_fee);

    assert_eq!(
        total_collateral
            + offer_cet_fee
            + accept_cet_fee
            + extra_fee
            + 2 * in_payout_coordinator_fee,
        fund_output_value
    );

    assert_eq!(
        offer_params.input_amount + accept_params.input_amount,
        fund_output_value
            + offer_change_output.value
            + accept_change_output.value
            + offer_fund_fee
            + accept_fund_fee
            + extra_fee
            + (2 * party_coordinator_fee)
    );

    let fund_sequence = util::get_sequence(fund_lock_time);
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
        fee_party_params.map(|p| TxOut {
            value: p.change_fee_value,
            script_pubkey: p.change_script_pubkey.clone(),
        }),
        fee_party_params.map(|p| p.change_fee_value),
        fund_output_serial_id,
        fund_lock_time,
    );

    Ok((fund_tx, funding_script_pubkey))
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
    fee_change_output: Option<TxOut>,
    fee_change_serial_id: Option<u64>,
    fund_output_serial_id: u64,
    lock_time: u32,
) -> Transaction {
    let fund_tx_out = TxOut {
        value: output_amount,
        script_pubkey: funding_script_pubkey.to_v0_p2wsh(),
    };

    let output: Vec<TxOut> = {
        let mut serial_ids = vec![
            fund_output_serial_id,
            offer_change_serial_id,
            accept_change_serial_id,
        ];

        let mut inputs = vec![fund_tx_out, offer_change_output, accept_change_output];

        if let Some(id) = fee_change_serial_id {
            serial_ids.push(id);
        };
        if let Some(o) = fee_change_output {
            inputs.push(o);
        };

        util::discard_dust(
            util::order_by_serial_ids(inputs, &serial_ids),
            dlc::DUST_LIMIT,
        )
    };

    let input = util::order_by_serial_ids(
        [offer_inputs, accept_inputs].concat(),
        &[offer_inputs_serial_ids, accept_inputs_serial_ids].concat(),
    );

    Transaction {
        version: dlc::TX_VERSION,
        lock_time: PackedLockTime(lock_time),
        input,
        output,
    }
}

/// Create the offchain transactions for a DLC contract based on the provided parameters
pub fn create_cets_and_refund_tx(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    anchors_outputs: Option<&[TxOut]>,
    anchors_serials_ids: Option<&[u64]>,
    prev_outpoint: OutPoint,
    payouts: &[Payout],
    refund_lock_time: u32,
    cet_lock_time: u32,
    cet_nsequence: Option<Sequence>,
) -> Result<(Vec<Transaction>, Transaction), Error> {
    let total_collateral = checked_add!(offer_params.collateral, accept_params.collateral)?;

    let has_proper_outcomes = payouts.iter().all(|o| {
        let total = checked_add!(o.offer, o.accept);
        if let Ok(total) = total {
            total == total_collateral
        } else {
            false
        }
    });

    if !has_proper_outcomes {
        return Err(Error::InvalidArgument);
    }

    let cet_input = TxIn {
        previous_output: prev_outpoint,
        witness: Witness::default(),
        script_sig: Script::default(),
        sequence: cet_nsequence.unwrap_or_else(|| util::get_sequence(cet_lock_time)),
    };

    let cets = create_cets(
        &cet_input,
        &offer_params.payout_script_pubkey,
        offer_params.payout_serial_id,
        &accept_params.payout_script_pubkey,
        accept_params.payout_serial_id,
        anchors_outputs,
        anchors_serials_ids,
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

    let refund_input = TxIn {
        previous_output: prev_outpoint,
        witness: Witness::default(),
        script_sig: Script::default(),
        sequence: util::ENABLE_LOCKTIME,
    };

    let refund_tx = create_refund_transaction(
        offer_refund_output,
        offer_params.payout_serial_id,
        accept_refund_ouput,
        accept_params.payout_serial_id,
        anchors_outputs,
        anchors_serials_ids,
        refund_input,
        refund_lock_time,
    );

    Ok((cets, refund_tx))
}

/// Create a contract execution transaction
pub fn create_cet(
    offer_output: TxOut,
    offer_payout_serial_id: u64,
    accept_output: TxOut,
    accept_payout_serial_id: u64,
    anchors_outputs: Option<&[TxOut]>,
    anchors_serials_ids: Option<&[u64]>,
    fund_tx_in: &TxIn,
    lock_time: u32,
) -> Transaction {
    let output: Vec<TxOut> = {
        let mut serial_ids = vec![offer_payout_serial_id, accept_payout_serial_id];

        let mut inputs = vec![offer_output, accept_output];

        if let Some(id) = anchors_serials_ids {
            serial_ids.extend(id);
        };
        if let Some(o) = anchors_outputs {
            inputs.extend(o.iter().cloned());
        };

        util::discard_dust(
            util::order_by_serial_ids(inputs, &serial_ids),
            dlc::DUST_LIMIT,
        )
    };

    Transaction {
        version: dlc::TX_VERSION,
        lock_time: PackedLockTime(lock_time),
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
    anchors_outputs: Option<&[TxOut]>,
    anchors_serials_ids: Option<&[u64]>,
    payouts: &[Payout],
    lock_time: u32,
) -> Vec<Transaction> {
    let mut txs: Vec<Transaction> = Vec::new();
    for payout in payouts {
        let offer_output = TxOut {
            value: payout.offer,
            script_pubkey: offer_payout_script_pubkey.clone(),
        };
        let accept_output = TxOut {
            value: payout.accept,
            script_pubkey: accept_payout_script_pubkey.clone(),
        };
        let tx = create_cet(
            offer_output,
            offer_payout_serial_id,
            accept_output,
            accept_payout_serial_id,
            anchors_outputs,
            anchors_serials_ids,
            fund_tx_input,
            lock_time,
        );

        txs.push(tx);
    }

    txs
}

/// Create a refund transaction
pub fn create_refund_transaction(
    offer_output: TxOut,
    offer_payout_serial_id: u64,
    accept_output: TxOut,
    accept_payout_serial_id: u64,
    anchors_outputs: Option<&[TxOut]>,
    anchors_serials_ids: Option<&[u64]>,
    funding_input: TxIn,
    locktime: u32,
) -> Transaction {
    let output: Vec<TxOut> = {
        let mut serial_ids = vec![offer_payout_serial_id, accept_payout_serial_id];

        let mut inputs = vec![offer_output, accept_output];

        if let Some(id) = anchors_serials_ids {
            serial_ids.extend(id);
        };
        if let Some(o) = anchors_outputs {
            inputs.extend(o.iter().cloned());
        };

        util::discard_dust(
            util::order_by_serial_ids(inputs, &serial_ids),
            dlc::DUST_LIMIT,
        )
    };

    Transaction {
        version: dlc::TX_VERSION,
        lock_time: PackedLockTime(locktime),
        input: vec![funding_input],
        output,
    }
}
