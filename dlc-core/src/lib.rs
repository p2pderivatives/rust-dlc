use bitcoin::TxOut;
use contract_tools::{create_cets, create_dlc_transactions, AnchorParams, FeePartyParams};
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

#[derive(PartialEq)]
enum DlcSide {
    Offer,
    Accept,
}

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
    pub fund_serial_id: u64,
    pub refund_locktime: u32,
    pub cet_locktime: u32,
    pub fee_rate_per_vb: u64,
}

fn get_dlc_transactions(
    contract_params: &ContractParams,
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_party_params: Option<&FeePartyParams>,
    anchors_params: Option<&[AnchorParams]>,
) -> Result<DlcTransactions> {
    let ContractParams {
        contract_info,
        offer_collateral,
        accept_collateral,
        fund_serial_id,
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
        anchors_params,
        &contract_info[0]
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?,
        *refund_locktime,
        *fee_rate_per_vb,
        0,
        *cet_locktime,
        *fund_serial_id,
    )
}

fn validate_presigned_without_infos(
    secp: &Secp256k1<All>,
    dlc_transactions: &DlcTransactions,
    anchors_params: Option<&[AnchorParams]>,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    contract_info: &[ContractInfo],
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    checked_side: &DlcSide,
) -> Result<(DlcTransactions, Vec<AdaptorInfo>)> {
    let DlcTransactions {
        fund,
        mut cets,
        refund,
        funding_script_pubkey,
    } = dlc_transactions.clone();

    let checked_params = match checked_side {
        DlcSide::Offer => &offer_params,
        DlcSide::Accept => &accept_params,
    };

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

    let anchors_outputs = anchors_params.map(|a| {
        a.iter()
            .map(|p| TxOut {
                value: p.payout_fee_value,
                script_pubkey: p.payout_script_pubkey.clone(),
            })
            .collect::<Box<[_]>>()
    });

    let anchors_serials_ids =
        anchors_params.map(|a| a.iter().map(|p| p.payout_serial_id).collect::<Box<[_]>>());

    let fund_output_value = dlc_transactions.get_fund_output().value;
    let total_collateral = offer_params.collateral + accept_params.collateral;

    let (mut adaptor_info, mut adaptor_sig_start) = contract_info[0]
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

        let tmp_cets = create_cets(
            &cet_input,
            &offer_params.payout_script_pubkey,
            offer_params.payout_serial_id,
            &accept_params.payout_script_pubkey,
            accept_params.payout_serial_id,
            anchors_outputs.as_deref(),
            anchors_serials_ids.as_deref(),
            &payouts,
            cets[0].lock_time.0,
        );

        (adaptor_info, adaptor_sig_start) = contract_info
            .verify_and_get_adaptor_info(
                secp,
                total_collateral,
                &checked_params.fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
                &tmp_cets,
                cet_adaptor_signatures,
                adaptor_sig_start,
            )
            .map_err(FromDlcError::Manager)?;

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
    anchors_params: Option<&[AnchorParams]>,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    contract_info: &[ContractInfo],
    adaptor_infos: &[AdaptorInfo],
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    checked_side: &DlcSide,
) -> Result<()> {
    let fund_output_value = dlc_transactions.get_fund_output().value;

    let checked_params = match checked_side {
        DlcSide::Offer => &offer_params,
        DlcSide::Accept => &accept_params,
    };

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

    let anchors_outputs = anchors_params.map(|a| {
        a.iter()
            .map(|p| TxOut {
                value: p.payout_fee_value,
                script_pubkey: p.payout_script_pubkey.clone(),
            })
            .collect::<Box<[_]>>()
    });

    let anchors_serials_ids =
        anchors_params.map(|a| a.iter().map(|p| p.payout_serial_id).collect::<Box<[_]>>());

    let total_collateral = offer_params.collateral + accept_params.collateral;

    let cet_input = dlc_transactions.cets[0].input[0].clone();

    let mut adaptor_sig_start = contract_info[0]
        .verify_adaptor_info(
            secp,
            &checked_params.fund_pubkey,
            &dlc_transactions.funding_script_pubkey,
            fund_output_value,
            &dlc_transactions.cets,
            cet_adaptor_signatures,
            0,
            &adaptor_infos[0],
        )
        .map_err(FromDlcError::Manager)?;

    for (adaptor_info, contract_info) in adaptor_infos.iter().zip(contract_info.iter()).skip(1) {
        let payouts: Box<[Payout]> = contract_info
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?
            .into_boxed_slice();

        let tmp_cets = create_cets(
            &cet_input,
            &offer_params.payout_script_pubkey,
            offer_params.payout_serial_id,
            &accept_params.payout_script_pubkey,
            accept_params.payout_serial_id,
            anchors_outputs.as_deref(),
            anchors_serials_ids.as_deref(),
            &payouts,
            dlc_transactions.cets[0].lock_time.0,
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
