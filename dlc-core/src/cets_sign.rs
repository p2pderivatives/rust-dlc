use std::str::FromStr;

use dlc::{DlcTransactions, PartyParams};
use dlc_manager::contract::{
    contract_info::ContractInfo, contract_input::ContractInput, offered_contract::OfferedContract,
    AdaptorInfo, FundingInputInfo,
};
use dlc_messages::{oracle_msgs::OracleAnnouncement, OfferDlc};
use secp256k1_zkp::{
    ecdsa::Signature, All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey,
};
use serde::{Deserialize, Serialize};

use crate::error::*;

#[derive(Clone, Debug, Deserialize)]
pub struct PartyInfos {
    pub party_params: PartyParams,
    pub funding_input_infos: Vec<FundingInputInfo>,
}

#[derive(Debug, Deserialize)]
pub struct DlcInputs {
    pub offer_params: PartyInfos,
    pub accept_params: PartyInfos,
    pub contract_input: ContractInput,
    pub refund_delay: u32,
    pub date_ref: u32,
    pub oracle_announcements: Vec<Vec<OracleAnnouncement>>,
    pub fund_secret_key: SecretKey,
}

#[derive(Debug, Serialize)]
pub struct SignedAndAdaptor {
    pub offered_contract: OfferedContract,
    pub adaptor_sig: Vec<EcdsaAdaptorSignature>,
    pub refund_sig: Signature,
}

pub fn create_signed_CETs(input: DlcInputs) -> Result<SignedAndAdaptor> {
    let offer_params = input.offer_params;
    let accept_params = input.accept_params;
    let contract_input = input.contract_input;
    let refund_delay = input.refund_delay;
    let date_ref = input.date_ref;
    let oracle_announcements = input.oracle_announcements;
    let fund_secret_key = input.fund_secret_key;

    let _ = &contract_input.validate().map_err(FromDlcError::Manager)?;

    let offered_contract: OfferedContract = OfferedContract::new(
        &contract_input,
        oracle_announcements,
        &offer_params.party_params,
        offer_params.funding_input_infos.as_ref(),
        &PublicKey::from_str("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c")
            .expect("is valid"),
        refund_delay,
        date_ref,
    );

    let offer_msg: OfferDlc = (&offered_contract).into();

    let total_collateral = offered_contract.total_collateral;
    let fund_output_serial_id = u64::MAX / 2;
    let contract_info = offered_contract.contract_info.clone();
    let dlc_transactions = dlc::create_dlc_transactions(
        &offer_params.party_params,
        &accept_params.party_params,
        &contract_info[0]
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?,
        offer_msg.refund_locktime,
        offer_msg.fee_rate_per_vb,
        0,
        offer_msg.cet_locktime,
        fund_output_serial_id,
    )
    .map_err(FromDlcError::Dlc)?;

    let secp = Secp256k1::new();

    let fund_public_key = PublicKey::from_secret_key(&secp, &fund_secret_key);

    let (my_party_params, counterparty_params) =
        if offer_params.party_params.fund_pubkey == fund_public_key {
            (offer_params, accept_params)
        } else {
            (accept_params, offer_params)
        };

    let sign_res = sign_cets(
        &secp,
        &dlc_transactions,
        &contract_info,
        &fund_secret_key,
        &my_party_params.party_params,
        &counterparty_params.party_params,
    )?;

    Ok(SignedAndAdaptor {
        offered_contract: offered_contract,
        adaptor_sig: sign_res.1,
        refund_sig: sign_res.2,
    })
}

fn sign_cets(
    secp: &Secp256k1<All>,
    dlc_transactions: &DlcTransactions,
    contract_info: &[ContractInfo],
    adaptor_secret_key: &SecretKey,
    own_params: &PartyParams,
    other_params: &PartyParams,
) -> Result<(Vec<AdaptorInfo>, Vec<EcdsaAdaptorSignature>, Signature)> {
    if PublicKey::from_secret_key(&secp, &adaptor_secret_key) != own_params.fund_pubkey {
        return Err(FromDlcError::Secp(secp256k1_zkp::Error::Upstream(
            secp256k1_zkp::UpstreamError::InvalidPublicKey,
        )));
    };
    let total_collateral = own_params.collateral + other_params.collateral;

    let input_script_pubkey = dlc_transactions.funding_script_pubkey.clone();
    let input_value = dlc_transactions.get_fund_output().value;

    let cet_input = dlc_transactions.cets[0].input[0].clone();

    let (adaptor_info, adaptor_sig) = contract_info[0]
        .get_adaptor_info(
            secp,
            total_collateral,
            adaptor_secret_key,
            &input_script_pubkey,
            input_value,
            &dlc_transactions.cets,
            0,
        )
        .map_err(FromDlcError::Manager)?;
    let mut adaptor_infos = vec![adaptor_info];
    let mut adaptor_sigs = adaptor_sig;

    let DlcTransactions {
        fund,
        cets,
        refund,
        funding_script_pubkey: _,
    } = dlc_transactions;

    let mut cets = cets.clone();

    for contract_info in contract_info.iter().skip(1) {
        let payouts = contract_info
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?;
        let tmp_cets = dlc::create_cets(
            &cet_input,
            &other_params.payout_script_pubkey,
            other_params.payout_serial_id,
            &own_params.payout_script_pubkey,
            own_params.payout_serial_id,
            &payouts,
            0,
        );

        let (adaptor_info, adaptor_sig) = contract_info
            .get_adaptor_info(
                secp,
                total_collateral,
                &adaptor_secret_key,
                &input_script_pubkey,
                input_value,
                &tmp_cets,
                adaptor_sigs.len(),
            )
            .map_err(FromDlcError::Manager)?;

        cets.extend(tmp_cets);

        adaptor_infos.push(adaptor_info);
        adaptor_sigs.extend(adaptor_sig);
    }

    let refund_signature = dlc::util::get_raw_sig_for_tx_input(
        secp,
        refund,
        0,
        &input_script_pubkey,
        input_value,
        &adaptor_secret_key,
    )
    .map_err(FromDlcError::Dlc)?;

    Ok((adaptor_infos, adaptor_sigs, refund_signature))
}
