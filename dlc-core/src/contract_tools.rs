use bitcoin::{OutPoint, PackedLockTime, Script, Transaction, TxIn, TxOut};
use dlc::{
    checked_add, create_cets_and_refund_tx, make_funding_redeemscript, util, DlcTransactions,
    PartyParams, Payout,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::FromDlcError;

type Error = FromDlcError;

/// Create the transactions for a DLC contract based on the provided parameters
pub fn create_dlc_transactions(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_party_params: Option<&FeePartyParams>,
    payouts: &[Payout],
    refund_lock_time: u32,
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    cet_lock_time: u32,
    fund_output_serial_id: u64,
) -> Result<DlcTransactions, Error> {
    let (fund_tx, funding_script_pubkey) = create_fund_transaction_with_fees(
        offer_params,
        accept_params,
        fee_party_params,
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
        fund_outpoint,
        payouts,
        refund_lock_time,
        cet_lock_time,
        None,
    )
    .map_err(FromDlcError::Dlc)?;

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
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    fund_output_serial_id: u64,
    extra_fee: u64,
) -> Result<(Transaction, Script), Error> {
    let total_collateral = checked_add!(offer_params.collateral, accept_params.collateral)?;

    let total_extra_coordinator_fee = fee_party_params
        .as_ref()
        .and_then(|p| {
            Some(p.fee_value + (fee_rate_per_vb * (9_u64 + p.fee_script_pubkey.len() as u64)))
        })
        .unwrap_or(0);

    let (offer_change_output, offer_fund_fee, offer_cet_fee) = offer_params
        .get_change_output_and_fees(
            fee_rate_per_vb,
            extra_fee + ((total_extra_coordinator_fee + 2_u64) / 2_u64) as u64 - 1_u64,
        )
        .map_err(FromDlcError::Dlc)?;
    let (accept_change_output, accept_fund_fee, accept_cet_fee) = accept_params
        .get_change_output_and_fees(
            fee_rate_per_vb,
            extra_fee + ((total_extra_coordinator_fee + 2) / 2) - 1,
        )
        .map_err(FromDlcError::Dlc)?;

    let fund_output_value = checked_add!(offer_params.input_amount, accept_params.input_amount)?
        - offer_change_output.value
        - accept_change_output.value
        - offer_fund_fee
        - accept_fund_fee
        - extra_fee;

    assert_eq!(
        total_collateral + offer_cet_fee + accept_cet_fee + extra_fee,
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
        fee_party_params,
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
    fee_party_params: Option<&FeePartyParams>,
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

        if let Some(p) = fee_party_params {
            serial_ids.push(p.fee_serial_id);

            inputs.push(TxOut {
                value: p.fee_value,
                script_pubkey: p.fee_script_pubkey.clone(),
            })
        }

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

/// Contains the parameters required for creating DLC transactions for a fee
/// collecting party.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct FeePartyParams {
    /// An address to receive change
    pub fee_script_pubkey: Script,
    /// Id used to order fund outputs
    pub fee_serial_id: u64,
    /// The collateral put in the contract by the party
    pub fee_value: u64,
}
