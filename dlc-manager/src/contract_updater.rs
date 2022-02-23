//! #

use std::ops::Deref;

use bitcoin::{consensus::Decodable, Script, Transaction};
use dlc::{DlcTransactions, PartyParams};
use dlc_messages::{FundingSignature, FundingSignatures, WitnessElement};
use secp256k1_zkp::{All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey, Signature};

use crate::{
    contract::{
        accepted_contract::AcceptedContract, offered_contract::OfferedContract,
        signed_contract::SignedContract, FundingInputInfo,
    },
    error::Error,
    Signer,
};

/// Creates an [`AcceptedContract`] and produces
/// the accepting party's cet adaptor signatures.
pub fn accept_contract(
    secp: &Secp256k1<All>,
    offered_contract: OfferedContract,
    accept_params: PartyParams,
    funding_inputs: Vec<FundingInputInfo>,
    fund_secret_key: &SecretKey,
) -> Result<(AcceptedContract, Vec<EcdsaAdaptorSignature>), crate::Error> {
    let total_collateral = offered_contract.total_collateral;

    let dlc_transactions = dlc::create_dlc_transactions(
        &offered_contract.offer_params,
        &accept_params,
        &offered_contract.contract_info[0].get_payouts(total_collateral),
        offered_contract.contract_timeout,
        offered_contract.fee_rate_per_vb,
        0,
        offered_contract.contract_maturity_bound,
        offered_contract.fund_output_serial_id,
    )?;

    let fund_output_value = dlc_transactions.get_fund_output().value;

    accept_contract_internal(
        secp,
        offered_contract,
        accept_params,
        funding_inputs,
        fund_secret_key,
        fund_output_value,
        None,
        dlc_transactions,
    )
}

pub(crate) fn accept_contract_internal(
    secp: &Secp256k1<All>,
    offered_contract: OfferedContract,
    accept_params: PartyParams,
    funding_inputs: Vec<FundingInputInfo>,
    adaptor_secret_key: &SecretKey,
    input_value: u64,
    input_script_pubkey: Option<Script>,
    dlc_transactions: DlcTransactions,
) -> Result<(AcceptedContract, Vec<EcdsaAdaptorSignature>), crate::Error> {
    let total_collateral = offered_contract.total_collateral;

    let input_script_pubkey =
        input_script_pubkey.unwrap_or_else(|| dlc_transactions.funding_script_pubkey.clone());

    let cet_input = dlc_transactions.cets[0].input[0].clone();
    let (adaptor_info, adaptor_sig) = offered_contract.contract_info[0].get_adaptor_info(
        secp,
        offered_contract.total_collateral,
        adaptor_secret_key,
        &input_script_pubkey,
        input_value,
        &dlc_transactions.cets,
        0,
    )?;
    let mut adaptor_infos = vec![adaptor_info];
    let mut adaptor_sigs = adaptor_sig;

    let DlcTransactions {
        fund,
        mut cets,
        refund,
        funding_script_pubkey,
    } = dlc_transactions;

    for contract_info in offered_contract.contract_info.iter().skip(1) {
        let payouts = contract_info.get_payouts(total_collateral);

        let tmp_cets = dlc::create_cets(
            &cet_input,
            &offered_contract.offer_params.payout_script_pubkey,
            offered_contract.offer_params.payout_serial_id,
            &accept_params.payout_script_pubkey,
            accept_params.payout_serial_id,
            &payouts,
            0,
        );

        let (adaptor_info, adaptor_sig) = contract_info.get_adaptor_info(
            secp,
            offered_contract.total_collateral,
            adaptor_secret_key,
            &input_script_pubkey,
            input_value,
            &tmp_cets,
            adaptor_sigs.len(),
        )?;

        cets.extend(tmp_cets);

        adaptor_infos.push(adaptor_info);
        adaptor_sigs.extend(adaptor_sig);
    }

    let refund_signature = dlc::util::get_raw_sig_for_tx_input(
        secp,
        &refund,
        0,
        &input_script_pubkey,
        input_value,
        adaptor_secret_key,
    );

    let dlc_transactions = DlcTransactions {
        fund,
        cets,
        refund,
        funding_script_pubkey,
    };

    let accepted_contract = AcceptedContract {
        offered_contract,
        adaptor_infos,
        // Drop own adaptor signatures as no point keeping them.
        adaptor_signatures: None,
        accept_params,
        funding_inputs,
        dlc_transactions,
        accept_refund_signature: refund_signature,
    };

    Ok((accepted_contract, adaptor_sigs))
}

/// Verifies the information of the accepting party [`Accept` message](dlc_messages::AcceptDlc),
/// creates a [`SignedContract`], and generates the offering party CET adaptor signatures.
pub fn verify_accepted_and_sign_contract<S: Deref>(
    secp: &Secp256k1<All>,
    offered_contract: &OfferedContract,
    accept_params: PartyParams,
    funding_inputs_info: Vec<FundingInputInfo>,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    signer: S,
) -> Result<(SignedContract, Vec<EcdsaAdaptorSignature>), Error>
where
    S::Target: Signer,
{
    let total_collateral = offered_contract.total_collateral;

    let dlc_transactions = dlc::create_dlc_transactions(
        &offered_contract.offer_params,
        &accept_params,
        &offered_contract.contract_info[0].get_payouts(total_collateral),
        offered_contract.contract_timeout,
        offered_contract.fee_rate_per_vb,
        0,
        offered_contract.contract_maturity_bound,
        offered_contract.fund_output_serial_id,
    )?;
    let fund_output_value = dlc_transactions.get_fund_output().value;
    let fund_privkey =
        signer.get_secret_key_for_pubkey(&offered_contract.offer_params.fund_pubkey)?;
    verify_accepted_and_sign_contract_internal(
        secp,
        offered_contract,
        accept_params,
        funding_inputs_info,
        refund_signature,
        cet_adaptor_signatures,
        fund_output_value,
        &fund_privkey,
        signer,
        None,
        None,
        dlc_transactions,
    )
}

pub(crate) fn verify_accepted_and_sign_contract_internal<S: Deref>(
    secp: &Secp256k1<All>,
    offered_contract: &OfferedContract,
    accept_params: PartyParams,
    funding_inputs_info: Vec<FundingInputInfo>,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    input_value: u64,
    adaptor_secret: &SecretKey,
    signer: S,
    input_script_pubkey: Option<Script>,
    counter_adaptor_pk: Option<PublicKey>,
    dlc_transactions: DlcTransactions,
) -> Result<(SignedContract, Vec<EcdsaAdaptorSignature>), Error>
where
    S::Target: Signer,
{
    let DlcTransactions {
        mut fund,
        mut cets,
        refund,
        funding_script_pubkey,
    } = dlc_transactions;

    let input_script_pubkey = input_script_pubkey.unwrap_or_else(|| funding_script_pubkey.clone());
    let counter_adaptor_pk = counter_adaptor_pk.unwrap_or(accept_params.fund_pubkey);

    dlc::verify_tx_input_sig(
        secp,
        refund_signature,
        &refund,
        0,
        &input_script_pubkey,
        input_value,
        &counter_adaptor_pk,
    )?;

    let (adaptor_info, mut adaptor_index) = offered_contract.contract_info[0]
        .verify_and_get_adaptor_info(
            secp,
            offered_contract.total_collateral,
            &counter_adaptor_pk,
            &input_script_pubkey,
            input_value,
            &cets,
            cet_adaptor_signatures,
            0,
        )?;

    let mut adaptor_infos = vec![adaptor_info];

    let cet_input = cets[0].input[0].clone();

    let total_collateral = offered_contract.offer_params.collateral + accept_params.collateral;

    for contract_info in offered_contract.contract_info.iter().skip(1) {
        let payouts = contract_info.get_payouts(total_collateral);

        let tmp_cets = dlc::create_cets(
            &cet_input,
            &offered_contract.offer_params.payout_script_pubkey,
            offered_contract.offer_params.payout_serial_id,
            &accept_params.payout_script_pubkey,
            accept_params.payout_serial_id,
            &payouts,
            0,
        );

        let (adaptor_info, tmp_adaptor_index) = contract_info.verify_and_get_adaptor_info(
            secp,
            offered_contract.total_collateral,
            &accept_params.fund_pubkey,
            &funding_script_pubkey,
            input_value,
            &tmp_cets,
            cet_adaptor_signatures,
            adaptor_index,
        )?;

        adaptor_index = tmp_adaptor_index;

        cets.extend(tmp_cets);

        adaptor_infos.push(adaptor_info);
    }

    let mut own_signatures: Vec<EcdsaAdaptorSignature> = Vec::new();

    for (contract_info, adaptor_info) in offered_contract
        .contract_info
        .iter()
        .zip(adaptor_infos.iter())
    {
        let sigs = contract_info.get_adaptor_signatures(
            secp,
            adaptor_info,
            adaptor_secret,
            &input_script_pubkey,
            input_value,
            &cets,
        )?;
        own_signatures.extend(sigs);
    }

    let mut input_serial_ids: Vec<_> = offered_contract
        .funding_inputs_info
        .iter()
        .map(|x| x.funding_input.input_serial_id)
        .chain(accept_params.inputs.iter().map(|x| x.serial_id))
        .collect();
    input_serial_ids.sort_unstable();

    // Vec<Witness>
    let witnesses: Vec<Vec<Vec<u8>>> = offered_contract
        .funding_inputs_info
        .iter()
        .map(|x| {
            let input_index = input_serial_ids
                .iter()
                .position(|y| y == &x.funding_input.input_serial_id)
                .ok_or(Error::InvalidState)?;
            let tx = Transaction::consensus_decode(&*x.funding_input.prev_tx).map_err(|_| {
                Error::InvalidParameters(
                    "Could not decode funding input previous tx parameter".to_string(),
                )
            })?;
            let vout = x.funding_input.prev_tx_vout;
            let tx_out = tx.output.get(vout as usize).ok_or_else(|| {
                Error::InvalidParameters(format!("Previous tx output not found at index {}", vout))
            })?;

            // pass wallet instead of privkeys
            signer.sign_tx_input(&mut fund, input_index, tx_out, None)?;

            Ok(fund.input[input_index].witness.clone())
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let funding_signatures: Vec<FundingSignature> = witnesses
        .into_iter()
        .map(|witness| {
            let witness_elements = witness
                .into_iter()
                .map(|z| WitnessElement { witness: z })
                .collect();
            Ok(FundingSignature { witness_elements })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    input_serial_ids.sort_unstable();

    let offer_refund_signature = dlc::util::get_raw_sig_for_tx_input(
        secp,
        &refund,
        0,
        &input_script_pubkey,
        input_value,
        adaptor_secret,
    );

    let dlc_transactions = DlcTransactions {
        fund,
        cets,
        refund,
        funding_script_pubkey,
    };

    let accepted_contract = AcceptedContract {
        offered_contract: offered_contract.clone(),
        accept_params,
        funding_inputs: funding_inputs_info,
        adaptor_infos,
        adaptor_signatures: Some(cet_adaptor_signatures.to_vec()),
        accept_refund_signature: *refund_signature,
        dlc_transactions,
    };

    let signed_contract = SignedContract {
        accepted_contract,
        adaptor_signatures: None,
        offer_refund_signature,
        funding_signatures: FundingSignatures { funding_signatures },
    };

    Ok((signed_contract, own_signatures))
}

/// Verifies the information from the offer party [`Sign` message](dlc_messages::SignDlc),
/// creates the accepting party's [`SignedContract`] and returns it along with the
/// signed fund transaction.
pub fn verify_signed_contract<S: Deref>(
    secp: &Secp256k1<All>,
    accepted_contract: &AcceptedContract,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    funding_signatures: &FundingSignatures,
    input_value: u64,
    input_script_pubkey: Option<Script>,
    counter_adaptor_pk: Option<PublicKey>,
    signer: S,
) -> Result<(SignedContract, Transaction), Error>
where
    S::Target: Signer,
{
    let offered_contract = &accepted_contract.offered_contract;
    let input_script_pubkey = input_script_pubkey.unwrap_or_else(|| {
        accepted_contract
            .dlc_transactions
            .funding_script_pubkey
            .clone()
    });
    let counter_adaptor_pk =
        counter_adaptor_pk.unwrap_or(accepted_contract.offered_contract.offer_params.fund_pubkey);

    dlc::verify_tx_input_sig(
        secp,
        refund_signature,
        &accepted_contract.dlc_transactions.refund,
        0,
        &input_script_pubkey,
        input_value,
        &counter_adaptor_pk,
    )?;

    let mut adaptor_sig_start = 0;

    for (adaptor_info, contract_info) in accepted_contract
        .adaptor_infos
        .iter()
        .zip(offered_contract.contract_info.iter())
    {
        adaptor_sig_start = contract_info.verify_adaptor_info(
            secp,
            &counter_adaptor_pk,
            &input_script_pubkey,
            input_value,
            &accepted_contract.dlc_transactions.cets,
            cet_adaptor_signatures,
            adaptor_sig_start,
            adaptor_info,
        )?;
    }

    let mut input_serials: Vec<_> = offered_contract
        .funding_inputs_info
        .iter()
        .chain(accepted_contract.funding_inputs.iter())
        .map(|x| x.funding_input.input_serial_id)
        .collect();
    input_serials.sort_unstable();

    let mut fund_tx = accepted_contract.dlc_transactions.fund.clone();

    for (funding_input, funding_signatures) in offered_contract
        .funding_inputs_info
        .iter()
        .zip(funding_signatures.funding_signatures.iter())
    {
        let input_index = input_serials
            .iter()
            .position(|x| x == &funding_input.funding_input.input_serial_id)
            .ok_or(Error::InvalidState)?;

        fund_tx.input[input_index].witness = funding_signatures
            .witness_elements
            .iter()
            .map(|x| x.witness.clone())
            .collect();
    }

    for funding_input_info in &accepted_contract.funding_inputs {
        let input_index = input_serials
            .iter()
            .position(|x| x == &funding_input_info.funding_input.input_serial_id)
            .ok_or(Error::InvalidState)?;
        let tx = Transaction::consensus_decode(&*funding_input_info.funding_input.prev_tx)
            .map_err(|_| {
                Error::InvalidParameters(
                    "Could not decode funding input previous tx parameter".to_string(),
                )
            })?;
        let vout = funding_input_info.funding_input.prev_tx_vout;
        let tx_out = tx.output.get(vout as usize).ok_or_else(|| {
            Error::InvalidParameters(format!("Previous tx output not found at index {}", vout))
        })?;

        signer.sign_tx_input(&mut fund_tx, input_index, tx_out, None)?;
    }

    let signed_contract = SignedContract {
        accepted_contract: accepted_contract.clone(),
        adaptor_signatures: Some(cet_adaptor_signatures.to_vec()),
        offer_refund_signature: *refund_signature,
        funding_signatures: funding_signatures.clone(),
    };

    Ok((signed_contract, fund_tx))
}
