use bitcoin::Transaction;
use dlc::{DlcTransactions, PartyParams};
use dlc_manager::contract::{contract_info::ContractInfo, AdaptorInfo};

use secp256k1_zkp::{ecdsa::Signature, All, EcdsaAdaptorSignature, Secp256k1};

use crate::{
    error::*, get_dlc_transactions, validate_presigned_with_infos,
    validate_presigned_without_infos, ContractParams, SideSign,
};

pub fn check_all_signed_dlc(
    contract_params: &ContractParams,
    offer_side: &SideSign,
    accept_side: &SideSign,
) -> Result<Transaction> {
    let dlc_transactions = get_dlc_transactions(
        &contract_params,
        offer_side.party_params,
        accept_side.party_params,
    )?;

    let secp = Secp256k1::new();

    let adaptor_infos = validate_presigned_without_infos(
        &secp,
        &dlc_transactions,
        accept_side.refund_sig,
        accept_side.adaptor_sig,
        &contract_params.contract_info,
        offer_side.party_params,
        accept_side.party_params,
    )?;

    validate_presigned_with_infos(
        &secp,
        &dlc_transactions,
        offer_side.refund_sig,
        offer_side.adaptor_sig,
        &contract_params.contract_info,
        &adaptor_infos,
        offer_side.party_params,
    )?;

    Ok(dlc_transactions.fund)
}
