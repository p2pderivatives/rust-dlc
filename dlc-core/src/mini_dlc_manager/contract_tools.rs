use super::tx_tools;
use bitcoin::{
    absolute::LockTime, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use dlc::{make_funding_redeemscript, util, DlcTransactions, PartyParams, Payout};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::FromDlcError;

type Error = FromDlcError;

macro_rules! checked_add {
    ($a: expr, $b: expr) => {
        $a.checked_add($b).ok_or(Error::InvalidArgument)
    };
    ($a: expr, $b: expr, $c: expr) => {
        checked_add!(checked_add!($a, $b)?, $c)
    };
    ($a: expr, $b: expr, $c: expr, $d: expr) => {
        checked_add!(checked_add!($a, $b, $c)?, $d)
    };
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
    /// The amount of fee to be paid in funding transaction
    pub change_fee_value: u64,
    /// Id used to order fund outputs
    pub change_serial_id: u64,
    /// An address to receive fees in funding
    pub change_script_pubkey: ScriptBuf,
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
    /// Id used to order CET outputs
    pub payout_serial_id: u64,
    /// An address to receive the outcome amount
    pub payout_script_pubkey: ScriptBuf,
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
) -> Result<(Transaction, ScriptBuf), Error> {
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

    let (offer_change_output, offer_fund_fee, offer_cet_fee) = MyPartyParams(offer_params)
        .get_change_output_and_fees(
            fee_rate_per_vb,
            extra_fee + party_coordinator_fee + in_payout_coordinator_fee,
        )?;
    let (accept_change_output, accept_fund_fee, accept_cet_fee) = MyPartyParams(accept_params)
        .get_change_output_and_fees(
            fee_rate_per_vb,
            extra_fee + party_coordinator_fee + in_payout_coordinator_fee,
        )?;

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

    let fund_sequence = tx_tools::get_sequence(fund_lock_time);
    let (offer_tx_ins, offer_inputs_serial_ids) =
        MyPartyParams(offer_params).get_unsigned_tx_inputs_and_serial_ids(fund_sequence);
    let (accept_tx_ins, accept_inputs_serial_ids) =
        MyPartyParams(accept_params).get_unsigned_tx_inputs_and_serial_ids(fund_sequence);

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
        fee_party_params.map(|p| p.change_serial_id),
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

        tx_tools::discard_dust(
            tx_tools::order_by_serial_ids(inputs, &serial_ids),
            tx_tools::DUST_LIMIT,
        )
    };

    let input = tx_tools::order_by_serial_ids(
        [offer_inputs, accept_inputs].concat(),
        &[offer_inputs_serial_ids, accept_inputs_serial_ids].concat(),
    );

    Transaction {
        version: tx_tools::TX_VERSION,
        lock_time: LockTime::from_consensus(lock_time),
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
        script_sig: ScriptBuf::default(),
        sequence: cet_nsequence.unwrap_or_else(|| tx_tools::get_sequence(cet_lock_time)),
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
        script_sig: ScriptBuf::default(),
        sequence: tx_tools::ENABLE_LOCKTIME,
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

        tx_tools::discard_dust(
            tx_tools::order_by_serial_ids(inputs, &serial_ids),
            tx_tools::DUST_LIMIT,
        )
    };

    Transaction {
        version: tx_tools::TX_VERSION,
        lock_time: LockTime::from_consensus(lock_time),
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
            script_pubkey: offer_payout_script_pubkey.to_owned(),
        };
        let accept_output = TxOut {
            value: payout.accept,
            script_pubkey: accept_payout_script_pubkey.to_owned(),
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

        tx_tools::discard_dust(
            tx_tools::order_by_serial_ids(inputs, &serial_ids),
            tx_tools::DUST_LIMIT,
        )
    };

    Transaction {
        version: tx_tools::TX_VERSION,
        lock_time: LockTime::from_consensus(locktime),
        input: vec![funding_input],
        output,
    }
}

pub(crate) struct MyPartyParams<'a>(&'a PartyParams);

impl<'a> MyPartyParams<'a> {
    /// Returns the change output for a single party as well as the fees that
    /// they are required to pay for the fund transaction and the cet or refund transaction.
    /// The change output value already accounts for the required fees.
    /// If input amount (sum of all input values) is lower than the sum of the collateral
    /// plus the required fees, an error is returned.
    pub(crate) fn get_change_output_and_fees(
        &self,
        fee_rate_per_vb: u64,
        extra_fee: u64,
    ) -> Result<(TxOut, u64, u64), Error> {
        let mut inputs_weight: usize = 0;

        for w in &self.0.inputs {
            let script_weight = tx_tools::redeem_script_to_script_sig(&w.redeem_script)
                .len()
                .checked_mul(4)
                .ok_or(Error::InvalidArgument)?;
            inputs_weight = checked_add!(
                inputs_weight,
                tx_tools::TX_INPUT_BASE_WEIGHT,
                script_weight,
                w.max_witness_len
            )?;
        }

        // Value size + script length var_int + ouput script pubkey size
        let change_size = self.0.change_script_pubkey.len();
        // Change size is scaled by 4 from vBytes to weight units
        let change_weight = change_size.checked_mul(4).ok_or(Error::InvalidArgument)?;

        // Base weight (nLocktime, nVersion, ...) is distributed among parties
        // independently of inputs contributed
        let this_party_fund_base_weight = tx_tools::FUND_TX_BASE_WEIGHT / 2;

        let total_fund_weight = checked_add!(
            this_party_fund_base_weight,
            inputs_weight,
            change_weight,
            36
        )?;
        let fund_fee = tx_tools::weight_to_fee(total_fund_weight, fee_rate_per_vb)?;

        // Base weight (nLocktime, nVersion, funding input ...) is distributed
        // among parties independently of output types
        let this_party_cet_base_weight = tx_tools::CET_BASE_WEIGHT / 2;

        // size of the payout script pubkey scaled by 4 from vBytes to weight units
        let output_spk_weight = self
            .0
            .payout_script_pubkey
            .len()
            .checked_mul(4)
            .ok_or(Error::InvalidArgument)?;
        let total_cet_weight = checked_add!(this_party_cet_base_weight, output_spk_weight)?;
        let cet_or_refund_fee = tx_tools::weight_to_fee(total_cet_weight, fee_rate_per_vb)?;
        let required_input_funds =
            checked_add!(self.0.collateral, fund_fee, cet_or_refund_fee, extra_fee)?;
        if self.0.input_amount < required_input_funds {
            return Err(Error::InvalidArgument);
        }

        let change_output = TxOut {
            value: self.0.input_amount - required_input_funds,
            script_pubkey: self.0.change_script_pubkey.clone(),
        };

        Ok((change_output, fund_fee, cet_or_refund_fee))
    }

    fn get_unsigned_tx_inputs_and_serial_ids(&self, sequence: Sequence) -> (Vec<TxIn>, Vec<u64>) {
        let mut tx_ins = Vec::with_capacity(self.0.inputs.len());
        let mut serial_ids = Vec::with_capacity(self.0.inputs.len());

        for input in &self.0.inputs {
            let tx_in = TxIn {
                previous_output: input.outpoint,
                script_sig: tx_tools::redeem_script_to_script_sig(&input.redeem_script),
                sequence,
                witness: Witness::new(),
            };
            tx_ins.push(tx_in);
            serial_ids.push(input.serial_id);
        }

        (tx_ins, serial_ids)
    }
}
