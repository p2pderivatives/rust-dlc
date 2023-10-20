use dlc::{DlcTransactions, PartyParams};
use dlc_manager::contract::{contract_info::ContractInfo, offered_contract::OfferedContract};
use secp256k1_zkp::{ecdsa::Signature, All, EcdsaAdaptorSignature, Secp256k1};

use crate::{error::*, sign_cets::PartyInfos};

pub fn check_signed_dlc(
    offered_contract: OfferedContract,
    accept_params: PartyInfos,
    adaptor_sig: Vec<EcdsaAdaptorSignature>,
    refund_sig: Signature,
) -> Result<bool> {
    let dlc_transactions = get_dlc_transactions(&offered_contract, &accept_params.party_params)?;

    let cet_adaptor_signatures = &adaptor_sig;

    let secp = Secp256k1::new();

    let mut is_offer = false;

    validate_presigned_without_infos(
        &secp,
        &dlc_transactions,
        &refund_sig,
        &cet_adaptor_signatures,
        &offered_contract.contract_info,
        &offered_contract.offer_params,
        &accept_params.party_params,
    )
    .or_else(|_| {
        is_offer = true;
        validate_presigned_without_infos(
            &secp,
            &dlc_transactions,
            &refund_sig,
            &cet_adaptor_signatures,
            &offered_contract.contract_info,
            &accept_params.party_params,
            &offered_contract.offer_params,
        )
    })?;

    Ok(is_offer)
}

fn validate_presigned_without_infos(
    secp: &Secp256k1<All>,
    dlc_transactions: &DlcTransactions,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    contract_info: &[ContractInfo],
    own_params: &PartyParams,
    checked_params: &PartyParams,
) -> Result<()> {
    let DlcTransactions {
        fund: _,
        mut cets,
        refund,
        funding_script_pubkey,
    } = dlc_transactions.clone();

    dlc::verify_tx_input_sig(
        secp,
        refund_signature,
        &refund,
        0,
        &dlc_transactions.funding_script_pubkey,
        dlc_transactions.get_fund_output().value,
        &checked_params.fund_pubkey,
    )
    .map_err(FromDlcError::Dlc)?;

    let fund_output_value = dlc_transactions.get_fund_output().value;
    let total_collateral = own_params.collateral + checked_params.collateral;

    let (adaptor_info, mut adaptor_index) = contract_info[0]
        .verify_and_get_adaptor_info(
            &secp,
            total_collateral,
            &checked_params.fund_pubkey,
            &funding_script_pubkey,
            fund_output_value,
            &cets,
            &cet_adaptor_signatures,
            0,
        )
        .map_err(FromDlcError::Manager)?;

    let mut adaptor_infos = vec![adaptor_info];

    let cet_input = cets[0].input[0].clone();

    for contract_info in contract_info.iter().skip(1) {
        let payouts: Vec<dlc::Payout> = contract_info
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?;

        let tmp_cets = dlc::create_cets(
            &cet_input,
            &own_params.payout_script_pubkey,
            own_params.payout_serial_id,
            &checked_params.payout_script_pubkey,
            checked_params.payout_serial_id,
            &payouts,
            0,
        );

        let (adaptor_info, tmp_adaptor_index) = contract_info
            .verify_and_get_adaptor_info(
                &secp,
                total_collateral,
                &checked_params.fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
                &tmp_cets,
                &cet_adaptor_signatures,
                adaptor_index,
            )
            .map_err(FromDlcError::Manager)?;

        adaptor_index = tmp_adaptor_index;

        cets.extend(tmp_cets);

        adaptor_infos.push(adaptor_info);
    }
    Ok(())
}

fn get_dlc_transactions(
    offered_contract: &OfferedContract,
    accept_params: &PartyParams,
) -> Result<DlcTransactions> {
    let total_collateral = offered_contract.offer_params.collateral + accept_params.collateral;
    Ok(dlc::create_dlc_transactions(
        &offered_contract.offer_params,
        &accept_params,
        &offered_contract.contract_info[0]
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?,
        offered_contract.refund_locktime,
        offered_contract.fee_rate_per_vb,
        0,
        offered_contract.cet_locktime,
        u64::MAX / 2,
    )
    .map_err(FromDlcError::Dlc)?)
}
