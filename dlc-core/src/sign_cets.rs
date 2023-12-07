use dlc::{DlcTransactions, PartyParams};
use dlc_manager::contract::{contract_info::ContractInfo, AdaptorInfo};

use secp256k1_zkp::{All, PublicKey, Secp256k1, SecretKey};

use crate::{
    contract_tools::FeePartyParams, error::*, get_dlc_transactions, CetSignatures, ContractParams,
};

pub fn sign_cets(
    secp: &Secp256k1<All>,
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    fee_party_params: Option<&FeePartyParams>,
    contract_params: &ContractParams,
    fund_secret_key: &SecretKey,
) -> Result<CetSignatures> {
    let dlc_transactions = get_dlc_transactions(
        contract_params,
        offer_params,
        accept_params,
        fee_party_params,
    )?;

    let fund_public_key = PublicKey::from_secret_key(secp, fund_secret_key);

    let (my_party_params, counterparty_params) = if offer_params.fund_pubkey == fund_public_key {
        (offer_params, accept_params)
    } else {
        (accept_params, offer_params)
    };

    let sign_res = sign(
        secp,
        &dlc_transactions,
        &contract_params.contract_info,
        fund_secret_key,
        my_party_params,
        counterparty_params,
    )?;

    Ok(sign_res.1)
}

fn sign(
    secp: &Secp256k1<All>,
    dlc_transactions: &DlcTransactions,
    contract_info: &[ContractInfo],
    adaptor_secret_key: &SecretKey,
    own_params: &PartyParams,
    other_params: &PartyParams,
) -> Result<(Box<[AdaptorInfo]>, CetSignatures)> {
    if PublicKey::from_secret_key(secp, adaptor_secret_key) != own_params.fund_pubkey {
        return Err(FromDlcError::Secp(secp256k1_zkp::Error::Upstream(
            secp256k1_zkp::UpstreamError::InvalidPublicKey,
        )));
    };
    let total_collateral = own_params.collateral + other_params.collateral;

    let DlcTransactions {
        fund: _,
        cets,
        refund,
        funding_script_pubkey,
    } = dlc_transactions;

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
                adaptor_secret_key,
                funding_script_pubkey,
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
