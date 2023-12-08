use bitcoin::{Script, Transaction};
use dlc::PartyParams;

use dlc::util::get_output_for_script_pubkey;
use secp256k1_zkp::{EcdsaAdaptorSignature, Secp256k1};

use crate::contract_tools::FeePartyParams;
use crate::{error::*, ContractParams, SideSign};
use crate::{
    get_dlc_transactions, validate_presigned_with_infos, validate_presigned_without_infos,
};

pub struct RenewInfos {
    pub funding: Transaction,
    pub index_input: usize,
    pub witness_script: Script,
    pub value: u64,
}

pub fn renew<E: AsRef<[EcdsaAdaptorSignature]>>(
    old_contract_params: &ContractParams,
    old_offer_params: &PartyParams,
    old_accept_params: &PartyParams,
    old_fee_party_params: Option<&FeePartyParams>,
    contract_params: &ContractParams,
    offer_side: &SideSign<E>,
    accept_side: &SideSign<E>,
    fee_party_params: Option<&FeePartyParams>,
) -> Result<RenewInfos> {
    // Checking that contracts are chained
    let old_dlc_transactions = get_dlc_transactions(
        old_contract_params,
        old_offer_params,
        old_accept_params,
        old_fee_party_params,
    )?;

    let new_dlc_transactions = get_dlc_transactions(
        contract_params,
        offer_side.party_params,
        accept_side.party_params,
        fee_party_params,
    )?;

    let old_funding = old_dlc_transactions.fund;

    let vout_old_dlc = get_output_for_script_pubkey(
        &old_funding,
        &old_dlc_transactions.funding_script_pubkey.to_v0_p2wsh(),
    )
    .expect("to find the funding script pubkey")
    .0 as u32;

    let index_input = new_dlc_transactions
        .fund
        .input
        .iter()
        .position(|input| {
            (&input.previous_output.txid == &old_funding.txid())
                && (input.previous_output.vout == vout_old_dlc)
        })
        .ok_or(FromDlcError::InvalidState(format!(
            "New funding is not using previous DLC output ({:?})",
            (&old_funding.txid(), vout_old_dlc)
        )))?;

    // Checking that new contract is genuine
    let secp = Secp256k1::new();
    let (new_dlc_transactions, adaptor_infos) = validate_presigned_without_infos(
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
        accept_side.party_params,
        offer_side.party_params,
    )?;

    let old_funding_output =
        old_funding
            .output
            .get(vout_old_dlc as usize)
            .ok_or(FromDlcError::InvalidState(
                "Malformed funding transaction for old DLC".to_owned(),
            ))?;

    Ok(RenewInfos {
        funding: new_dlc_transactions.fund,
        index_input,
        witness_script: old_dlc_transactions.funding_script_pubkey,
        value: old_funding_output.value,
    })
}
