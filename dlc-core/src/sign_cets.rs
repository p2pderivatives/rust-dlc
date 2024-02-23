use bitcoin::TxOut;
use dlc::{DlcTransactions, PartyParams};
use dlc_manager::contract::{contract_info::ContractInfo, AdaptorInfo};

use secp256k1_zkp::{All, PublicKey, Secp256k1, SecretKey};

use crate::{
    contract_tools::{create_cets, AnchorParams, FeePartyParams},
    error::*,
    get_dlc_transactions, CetSignatures, ContractParams, DlcSide,
};

pub fn sign_cets(
    secp: &Secp256k1<All>,
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_party_params: Option<&FeePartyParams>,
    anchors_params: Option<&[AnchorParams]>,
    contract_params: &ContractParams,
    fund_secret_key: &SecretKey,
) -> Result<CetSignatures> {
    let dlc_transactions = get_dlc_transactions(
        contract_params,
        offer_params,
        accept_params,
        fee_party_params,
        anchors_params,
    )?;

    let fund_public_key = PublicKey::from_secret_key(secp, fund_secret_key);

    let signing_side = match offer_params.fund_pubkey == fund_public_key {
        true => DlcSide::Offer,
        false => DlcSide::Accept,
    };

    let sign_res = sign(
        secp,
        &dlc_transactions,
        anchors_params,
        &contract_params.contract_info,
        fund_secret_key,
        offer_params,
        accept_params,
        &signing_side,
    )?;

    Ok(sign_res.1)
}

fn sign(
    secp: &Secp256k1<All>,
    dlc_transactions: &DlcTransactions,
    anchors_params: Option<&[AnchorParams]>,
    contract_info: &[ContractInfo],
    adaptor_secret_key: &SecretKey,
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    signing_side: &DlcSide,
) -> Result<(Box<[AdaptorInfo]>, CetSignatures)> {
    if signing_side == &DlcSide::Accept
        && PublicKey::from_secret_key(secp, adaptor_secret_key) != accept_params.fund_pubkey
    {
        return Err(FromDlcError::Secp(secp256k1_zkp::Error::Upstream(
            secp256k1_zkp::UpstreamError::InvalidPublicKey,
        )));
    };
    let total_collateral = offer_params.collateral + accept_params.collateral;

    let DlcTransactions {
        fund: _,
        cets,
        refund,
        funding_script_pubkey,
    } = dlc_transactions;

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

    let input_value = dlc_transactions.get_fund_output().value;

    let cet_input = cets[0].input[0].clone();

    let (adaptor_info, adaptor_sig) = contract_info[0]
        .get_adaptor_info(
            secp,
            total_collateral,
            adaptor_secret_key,
            funding_script_pubkey,
            input_value,
            cets,
            0,
        )
        .map_err(FromDlcError::Manager)?;
    let mut adaptor_infos = vec![adaptor_info];
    let mut adaptor_sigs = adaptor_sig;

    for contract_info in contract_info.iter().skip(1) {
        let payouts = contract_info
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?;
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

        let (adaptor_info, adaptor_sig) = contract_info
            .get_adaptor_info(
                secp,
                total_collateral,
                adaptor_secret_key,
                funding_script_pubkey,
                input_value,
                &tmp_cets,
                adaptor_sigs.len(),
            )
            .map_err(FromDlcError::Manager)?;

        adaptor_infos.push(adaptor_info);
        adaptor_sigs.extend(adaptor_sig);
    }

    let refund_signature = dlc::util::get_raw_sig_for_tx_input(
        secp,
        refund,
        0,
        funding_script_pubkey,
        input_value,
        adaptor_secret_key,
    )
    .map_err(FromDlcError::Dlc)?;

    Ok((
        adaptor_infos.into_boxed_slice(),
        CetSignatures {
            refund_sig: refund_signature,
            adaptor_sig: adaptor_sigs.into_boxed_slice(),
        },
    ))
}
