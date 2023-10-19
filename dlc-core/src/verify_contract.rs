use dlc::{DlcTransactions, PartyParams};
use dlc_manager::contract::{
    contract_info::ContractInfo, ser::Serializable, signed_contract::SignedContract, AdaptorInfo,
};
use dlc_messages::SignDlc;
use secp256k1_zkp::{ecdsa::Signature, All, EcdsaAdaptorSignature, Secp256k1};
use serde::{Deserialize, Serialize};

use crate::error::*;

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

pub fn validate_all_cet(contract: Vec<u8>) -> Result<Vec<u8>> {
    let contract = SignedContract::deserialize(&mut contract.as_slice()).unwrap();

    let secp = Secp256k1::new();

    let dlc_transactions = contract.accepted_contract.dlc_transactions;
    let contract_info = contract.accepted_contract.offered_contract.contract_info;
    let accept_refund_signature = contract.accepted_contract.accept_refund_signature;
    let accept_cet_signatures =
        contract
            .accepted_contract
            .adaptor_signatures
            .ok_or(FromDlcError::InvalidState(
                "No adaptor signature found !".to_owned(),
            ))?;
    let accept_params = contract.accepted_contract.accept_params;
    let offer_refund_signature = contract.offer_refund_signature;
    let offer_cet_signatures = contract
        .adaptor_signatures
        .ok_or(FromDlcError::InvalidState(
            "No adaptor signature found !".to_owned(),
        ))?;
    let offer_params = contract.accepted_contract.offered_contract.offer_params;

    let adaptor_infos = contract.accepted_contract.adaptor_infos;

    validate_presigned_with_infos(
        &secp,
        &dlc_transactions,
        &accept_refund_signature,
        &accept_cet_signatures,
        &contract_info,
        &adaptor_infos,
        &offer_params,
        &accept_params,
    )?;

    validate_presigned_with_infos(
        &secp,
        &dlc_transactions,
        &offer_refund_signature,
        &offer_cet_signatures,
        &contract_info,
        &adaptor_infos,
        &accept_params,
        &offer_params,
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
    own_params: &PartyParams,
    checked_params: &PartyParams,
) -> Result<()> {
    let DlcTransactions {
        fund: _,
        mut cets,
        refund,
        funding_script_pubkey,
    } = dlc_transactions.clone();

    let fund_output_value = dlc_transactions.get_fund_output().value;
    let total_collateral = own_params.collateral + checked_params.collateral;
    let input_value = dlc_transactions.get_fund_output().value;

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
                input_value,
                &dlc_transactions.cets,
                &cet_adaptor_signatures,
                adaptor_sig_start,
                adaptor_info,
            )
            .map_err(FromDlcError::Manager)?;
    }

    Ok(())
}
