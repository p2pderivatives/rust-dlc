use contract_tools::{create_dlc_transactions, FeePartyParams};
use dlc::{DlcTransactions, PartyParams, Payout};
use dlc_manager::contract::{contract_info::ContractInfo, AdaptorInfo};

use secp256k1_zkp::{ecdsa::Signature, All, EcdsaAdaptorSignature, Secp256k1};

pub mod create_contract;
pub mod error;
pub mod renew;
pub mod settlement;
pub mod sign_cets;
pub mod verify_cets;
pub mod verify_contract;

pub mod contract_tools;

use crate::error::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct CetSignatures {
    pub refund_sig: Signature,
    pub adaptor_sig: Box<[EcdsaAdaptorSignature]>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize), serde(rename_all = "camelCase"))]
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
    pub contract_info: Box<[ContractInfo]>,
    pub offer_collateral: u64,
    pub accept_collateral: u64,
    pub refund_locktime: u32,
    pub cet_locktime: u32,
    pub fee_rate_per_vb: u64,
}

fn get_dlc_transactions(
    contract_params: &ContractParams,
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_party_params: Option<&FeePartyParams>,
) -> Result<DlcTransactions> {
    let ContractParams {
        contract_info,
        offer_collateral,
        accept_collateral,
        refund_locktime,
        cet_locktime,
        fee_rate_per_vb,
    } = contract_params;

    (*offer_collateral == offer_params.collateral)
        .then(|| {})
        .ok_or(FromDlcError::InvalidState(
            "Offering party collateral does not match the contract input".to_owned(),
        ))?;
    (*accept_collateral == accept_params.collateral)
        .then(|| {})
        .ok_or(FromDlcError::InvalidState(
            "Accepting party collateral does not match the contract input".to_owned(),
        ))?;

    let total_collateral = offer_params.collateral + accept_params.collateral;
    create_dlc_transactions(
        offer_params,
        accept_params,
        fee_party_params,
        &contract_info[0]
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?,
        *refund_locktime,
        *fee_rate_per_vb,
        0,
        *cet_locktime,
        u64::MAX / 2,
    )
}

fn validate_presigned_without_infos(
    secp: &Secp256k1<All>,
    dlc_transactions: &DlcTransactions,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    contract_info: &[ContractInfo],
    own_params: &PartyParams,
    checked_params: &PartyParams,
) -> Result<(DlcTransactions, Vec<AdaptorInfo>)> {
    let DlcTransactions {
        fund,
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
            secp,
            total_collateral,
            &checked_params.fund_pubkey,
            &funding_script_pubkey,
            fund_output_value,
            &cets,
            cet_adaptor_signatures,
            0,
        )
        .map_err(FromDlcError::Manager)?;

    let mut adaptor_infos = vec![adaptor_info];

    let cet_input = cets[0].input[0].clone();

    for contract_info in contract_info.iter().skip(1) {
        let payouts: Box<[Payout]> = contract_info
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?
            .into_boxed_slice();

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
                secp,
                total_collateral,
                &checked_params.fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
                &tmp_cets,
                cet_adaptor_signatures,
                adaptor_index,
            )
            .map_err(FromDlcError::Manager)?;

        adaptor_index = tmp_adaptor_index;

        cets.extend(tmp_cets);

        adaptor_infos.push(adaptor_info);
    }

    let dlc_transactions = DlcTransactions {
        fund,
        cets,
        refund,
        funding_script_pubkey,
    };
    Ok((dlc_transactions, adaptor_infos))
}

fn validate_presigned_with_infos(
    secp: &Secp256k1<All>,
    dlc_transactions: &DlcTransactions,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    contract_info: &[ContractInfo],
    adaptor_infos: &[AdaptorInfo],
    own_params: &PartyParams,
    checked_params: &PartyParams,
) -> Result<()> {
    let fund_output_value = dlc_transactions.get_fund_output().value;

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

    let total_collateral = own_params.collateral + checked_params.collateral;

    let cet_input = dlc_transactions.cets[0].input[0].clone();

    let mut adaptor_sig_start = 0;

    adaptor_sig_start = contract_info[0]
        .verify_adaptor_info(
            secp,
            &checked_params.fund_pubkey,
            &dlc_transactions.funding_script_pubkey,
            fund_output_value,
            &dlc_transactions.cets,
            cet_adaptor_signatures,
            adaptor_sig_start,
            &adaptor_infos[0],
        )
        .map_err(FromDlcError::Manager)?;

    for (adaptor_info, contract_info) in adaptor_infos.iter().zip(contract_info.iter()).skip(1) {
        let payouts: Box<[Payout]> = contract_info
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?
            .into_boxed_slice();

        let tmp_cets = dlc::create_cets(
            &cet_input,
            &own_params.payout_script_pubkey,
            own_params.payout_serial_id,
            &checked_params.payout_script_pubkey,
            checked_params.payout_serial_id,
            &payouts,
            0,
        );
        adaptor_sig_start = contract_info
            .verify_adaptor_info(
                secp,
                &checked_params.fund_pubkey,
                &dlc_transactions.funding_script_pubkey,
                fund_output_value,
                &tmp_cets,
                cet_adaptor_signatures,
                adaptor_sig_start,
                adaptor_info,
            )
            .map_err(FromDlcError::Manager)?;
    }

    Ok(())
}
