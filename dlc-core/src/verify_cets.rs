use dlc::PartyParams;
use dlc_manager::contract::AdaptorInfo;
use secp256k1_zkp::{ecdsa::Signature, EcdsaAdaptorSignature, Secp256k1};

use crate::{
    contract_tools::FeePartyParams, error::*, get_dlc_transactions,
    validate_presigned_without_infos, ContractParams,
};

pub fn check_signed_dlc<E: AsRef<[EcdsaAdaptorSignature]>>(
    contract_params: &ContractParams,
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_party_params: Option<&FeePartyParams>,
    adaptor_sig: &[E],
    refund_sig: &Signature,
) -> Result<(Vec<AdaptorInfo>, bool)> {
    let dlc_transactions = get_dlc_transactions(
        contract_params,
        offer_params,
        accept_params,
        fee_party_params,
    )?;

    let cet_adaptor_signatures = &adaptor_sig;

    let secp = Secp256k1::new();

    let mut is_offer = false;

    let (_, adaptor_infos) = validate_presigned_without_infos(
        &secp,
        &dlc_transactions,
        refund_sig,
        cet_adaptor_signatures,
        &contract_params.contract_info,
        offer_params,
        accept_params,
    )
    .or_else(|_| {
        is_offer = true;
        validate_presigned_without_infos(
            &secp,
            &dlc_transactions,
            refund_sig,
            cet_adaptor_signatures,
            &contract_params.contract_info,
            accept_params,
            offer_params,
        )
    })?;

    Ok((adaptor_infos, is_offer))
}
