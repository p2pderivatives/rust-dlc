use dlc::PartyParams;
use dlc_manager::contract::AdaptorInfo;
use secp256k1_zkp::{ecdsa::Signature, EcdsaAdaptorSignature, Secp256k1};

use crate::{
    contract_tools::{AnchorParams, FeePartyParams},
    error::*,
    get_dlc_transactions, validate_presigned_without_infos, ContractParams, DlcSide,
};

pub fn check_signed_dlc<E: AsRef<[EcdsaAdaptorSignature]>>(
    contract_params: &ContractParams,
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_party_params: Option<&FeePartyParams>,
    anchors_params: Option<&[AnchorParams]>,
    adaptor_sig: &[E],
    refund_sig: &Signature,
) -> Result<(Vec<AdaptorInfo>, bool)> {
    let dlc_transactions = get_dlc_transactions(
        contract_params,
        offer_params,
        accept_params,
        fee_party_params,
        anchors_params,
    )?;

    let secp = Secp256k1::new();

    let mut checked_side = DlcSide::Offer;

    let (_, adaptor_infos) = validate_presigned_without_infos(
        &secp,
        &dlc_transactions,
        refund_sig,
        adaptor_sig,
        &contract_params.contract_info,
        offer_params,
        accept_params,
        &checked_side,
    )
    .or_else(|_| {
        checked_side = DlcSide::Accept;
        validate_presigned_without_infos(
            &secp,
            &dlc_transactions,
            refund_sig,
            adaptor_sig,
            &contract_params.contract_info,
            offer_params,
            accept_params,
            &checked_side,
        )
    })?;

    Ok((adaptor_infos, checked_side == DlcSide::Offer))
}
