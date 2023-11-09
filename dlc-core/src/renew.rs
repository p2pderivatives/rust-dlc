use bitcoin::{Script, Transaction, TxOut};
use dlc::PartyParams;

use secp256k1_zkp::Secp256k1;

use crate::{error::*, ContractParams, SideSign};
use crate::{
    get_dlc_transactions, validate_presigned_with_infos, validate_presigned_without_infos,
};

pub struct RenewInfos {
    pub funding: Transaction,
    pub index_input: u32,
    pub witness_script: Script,
    pub old_funding_output: TxOut,
}

pub fn renew(
    old_contract_params: &ContractParams,
    old_offer_params: &PartyParams,
    old_accept_params: &PartyParams,
    contract_params: &ContractParams,
    offer_side: &SideSign,
    accept_side: &SideSign,
) -> Result<RenewInfos> {
    // Checking that contracts are chained
    let old_dlc_transactions =
        get_dlc_transactions(old_contract_params, old_offer_params, old_accept_params)?;

    let new_dlc_transactions = get_dlc_transactions(
        contract_params,
        offer_side.party_params,
        accept_side.party_params,
    )?;

    let old_funding = old_dlc_transactions.fund;

    let vout_old_dlc = [old_offer_params, old_accept_params]
        .iter()
        .filter(|params| params.change_serial_id < u64::MAX / 2) // Recall: the DLC always has seriald id of u64::MAX/2 in our implementation
        .count() as u32;

    let index_input = new_dlc_transactions
        .fund
        .input
        .iter()
        .position(|input| {
            (&input.previous_output.txid == &old_funding.txid())
                && (input.previous_output.vout == vout_old_dlc)
        })
        .ok_or(FromDlcError::InvalidState(
            "New funding is not using previous DLC",
        ))? as u32;

    // Checking that new contract is genuine
    let secp = Secp256k1::new();
    let adaptor_infos = validate_presigned_without_infos(
        &secp,
        &new_dlc_transactions,
        accept_side.refund_sig,
        accept_side.adaptor_sig,
        &contract_params.contract_info,
        offer_side.party_params,
        accept_side.party_params,
    )?;

    validate_presigned_with_infos(
        &secp,
        &new_dlc_transactions,
        offer_side.refund_sig,
        offer_side.adaptor_sig,
        &contract_params.contract_info,
        &adaptor_infos,
        offer_side.party_params,
    )?;

    let old_funding_output = old_funding
        .output
        .get(vout_old_dlc as usize)
        .expect("a valid bitcoin tx has at least one output");

    Ok(RenewInfos {
        funding: new_dlc_transactions.fund,
        index_input,
        witness_script: old_dlc_transactions.funding_script_pubkey,
        old_funding_output: old_funding_output.clone(),
    })
}
