use dlc::{DlcTransactions, PartyParams};
use dlc_manager::contract::{
    contract_info::ContractInfo, ser::Serializable, signed_contract::SignedContract, AdaptorInfo,
};

use secp256k1_zkp::{ecdsa::Signature, All, EcdsaAdaptorSignature, Secp256k1};
use serde::Serialize;

use crate::{error::*, verify_cets::validate_presigned_without_infos};

#[derive(Debug, Serialize)]
pub struct IndexToSign {
    pub index: u32,
    pub amount: u64,
    pub script_pub_key: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct ToSignAndContractInfos {
    pub raw_tx: Vec<u8>,
    pub to_sign_input_infos: Vec<IndexToSign>,
    pub contract_state: Vec<u8>,
}

pub struct SideSign {
    party_params: PartyParams,
    adaptor_sig: Vec<EcdsaAdaptorSignature>,
    refund_sig: Signature,
}

pub fn check_all_signed_dlc(
    contract_info: &[ContractInfo],
    offer_side: &SideSign,
    accept_side: &SideSign,
    refund_locktime: u32,
    fee_rate_per_vb: u64,
    cet_locktime: u32,
) -> Result<Vec<u8>> {
    let total_collateral = offer_side.party_params.collateral + accept_side.party_params.collateral;
    let dlc_transactions = dlc::create_dlc_transactions(
        &offer_side.party_params,
        &accept_side.party_params,
        &contract_info[0]
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?,
        refund_locktime,
        fee_rate_per_vb,
        0,
        cet_locktime,
        u64::MAX / 2,
    )
    .map_err(FromDlcError::Dlc)?;

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
    let DlcTransactions {
        fund: _,
        cets: _,
        refund,
        funding_script_pubkey,
    } = dlc_transactions.clone();

    let fund_output_value = dlc_transactions.get_fund_output().value;
    // let total_collateral = own_params.collateral + checked_params.collateral;

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

    let mut adaptor_sig_start = 0;

    for (adaptor_info, contract_info) in adaptor_infos.iter().zip(contract_info.iter()) {
        adaptor_sig_start = contract_info
            .verify_adaptor_info(
                secp,
                &checked_params.fund_pubkey,
                &funding_script_pubkey,
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
