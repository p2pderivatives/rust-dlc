use dlc::{DlcTransactions, PartyParams};
use dlc_manager::contract::{
    contract_info::ContractInfo, ser::Serializable, signed_contract::SignedContract, AdaptorInfo,
};

use secp256k1_zkp::{ecdsa::Signature, All, EcdsaAdaptorSignature, Secp256k1};
use serde::Serialize;

use crate::{error::*, get_dlc_transactions, validate_presigned_without_infos, SideSign};

pub fn check_all_signed_dlc(
    contract_info: &[ContractInfo],
    offer_side: &SideSign,
    accept_side: &SideSign,
    refund_locktime: u32,
    fee_rate_per_vb: u64,
    cet_locktime: u32,
) -> Result<Vec<u8>> {
    let dlc_transactions = get_dlc_transactions(
        contract_info,
        offer_side.party_params,
        accept_side.party_params,
        refund_locktime,
        fee_rate_per_vb,
        cet_locktime,
    )?;

    let secp = Secp256k1::new();

    let adaptor_infos = validate_presigned_without_infos(
        &secp,
        &dlc_transactions,
        &accept_side.refund_sig,
        &accept_side.adaptor_sig,
        contract_info,
        &offer_side.party_params,
        &accept_side.party_params,
    )?;

    validate_presigned_with_infos(
        &secp,
        &dlc_transactions,
        &offer_side.refund_sig,
        &offer_side.adaptor_sig,
        contract_info,
        &adaptor_infos,
        &offer_side.party_params,
    )?;

    Ok(Serializable::serialize(&dlc_transactions.fund).unwrap())
}

fn validate_presigned_with_infos(
    secp: &Secp256k1<All>,
    dlc_transactions: &DlcTransactions,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    contract_info: &[ContractInfo],
    adaptor_infos: &[AdaptorInfo],
    // own_params: &PartyParams,
    checked_params: &PartyParams,
) -> Result<()> {
    let fund_output_value = dlc_transactions.get_fund_output().value;
    // let total_collateral = own_params.collateral + checked_params.collateral;

    dlc::verify_tx_input_sig(
        secp,
        refund_signature,
        &dlc_transactions.refund,
        0,
        &dlc_transactions.funding_script_pubkey,
        dlc_transactions.get_fund_output().value,
        &checked_params.fund_pubkey,
    )
    .map_err(FromDlcError::Dlc)?;

    let mut adaptor_sig_start = 0;

    for (adaptor_info, contract_info) in adaptor_infos.iter().zip(contract_info.iter()) {
        adaptor_sig_start = contract_info
            .verify_adaptor_info(
                secp,
                &checked_params.fund_pubkey,
                &dlc_transactions.funding_script_pubkey,
                fund_output_value,
                &dlc_transactions.cets,
                &cet_adaptor_signatures,
                adaptor_sig_start,
                adaptor_info,
            )
            .map_err(FromDlcError::Manager)?;
    }

    Ok(())
}
