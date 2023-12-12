use bitcoin::Transaction;

use secp256k1_zkp::{EcdsaAdaptorSignature, Secp256k1};

use crate::{
    contract_tools::{AnchorParams, FeePartyParams},
    error::*,
    get_dlc_transactions, validate_presigned_with_infos, validate_presigned_without_infos,
    ContractParams, DlcSide, SideSign,
};

pub fn check_all_signed_dlc<E: AsRef<[EcdsaAdaptorSignature]>>(
    contract_params: &ContractParams,
    offer_side: &SideSign<E>,
    accept_side: &SideSign<E>,
    fee_party_params: Option<&FeePartyParams>,
    anchors_params: Option<&[AnchorParams]>,
) -> Result<Transaction> {
    let dlc_transactions = get_dlc_transactions(
        contract_params,
        offer_side.party_params,
        accept_side.party_params,
        fee_party_params,
        anchors_params,
    )?;

    let secp = Secp256k1::new();

    let (dlc_transactions, adaptor_infos) = validate_presigned_without_infos(
        &secp,
        &dlc_transactions,
        offer_side.refund_sig,
        offer_side.adaptor_sig,
        &contract_params.contract_info,
        offer_side.party_params,
        accept_side.party_params,
        &DlcSide::Offer,
    )?;

    validate_presigned_with_infos(
        &secp,
        &dlc_transactions,
        accept_side.refund_sig,
        accept_side.adaptor_sig,
        &contract_params.contract_info,
        &adaptor_infos,
        offer_side.party_params,
        accept_side.party_params,
        &DlcSide::Accept,
    )?;

    Ok(dlc_transactions.fund)
}
