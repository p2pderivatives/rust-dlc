use dlc::{DlcTransactions, PartyParams};
use dlc_manager::contract::{contract_info::ContractInfo, AdaptorInfo};

use secp256k1_zkp::{ecdsa::Signature, All, EcdsaAdaptorSignature, Secp256k1};

pub mod error;
pub mod settlement;
pub mod sign_cets;
pub mod verify_cets;
pub mod verify_contract;

use crate::error::*;

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SideSign<'a> {
    pub party_params: &'a PartyParams,
    pub adaptor_sig: &'a [EcdsaAdaptorSignature],
    pub refund_sig: &'a Signature,
}

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct ContractParams {
    pub contract_info: Vec<ContractInfo>,
    pub refund_locktime: u32,
    pub cet_locktime: u32,
    pub fee_rate_per_vb: u64,
}

fn get_dlc_transactions(
    contract_params: &ContractParams,
    offer_params: &PartyParams,
    accept_params: &PartyParams,
) -> Result<DlcTransactions> {
    let ContractParams {
        contract_info,
        refund_locktime,
        cet_locktime,
        fee_rate_per_vb,
    } = contract_params;

    let total_collateral = offer_params.collateral + accept_params.collateral;
    Ok(dlc::create_dlc_transactions(
        &offer_params,
        &accept_params,
        &contract_info[0]
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?,
        *refund_locktime,
        *fee_rate_per_vb,
        0,
        *cet_locktime,
        u64::MAX / 2,
    )
    .map_err(FromDlcError::Dlc)?)
}

fn validate_presigned_without_infos(
    secp: &Secp256k1<All>,
    dlc_transactions: &DlcTransactions,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    contract_info: &[ContractInfo],
    own_params: &PartyParams,
    checked_params: &PartyParams,
) -> Result<Vec<AdaptorInfo>> {
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
    Ok(adaptor_infos)
}
