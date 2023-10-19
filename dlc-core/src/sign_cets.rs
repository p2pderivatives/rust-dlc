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

use crate::error::*;

#[derive(Clone, Debug)]
pub struct PartyInfos {
    pub party_params: PartyParams,
    pub funding_input_infos: Vec<FundingInputInfo>,
}

pub fn sign_cets(
    offer_params: PartyInfos,
    accept_params: PartyInfos,
    contract_input: ContractInput,
    refund_delay: u32,
    date_ref: u32,
    oracle_announcements: Vec<Vec<OracleAnnouncement>>,
    fund_secret_key: SecretKey,
) -> Result<(Vec<EcdsaAdaptorSignature>, Signature)> {
    let _ = &contract_input.validate().map_err(FromDlcError::Manager)?;

    let total_collateral = contract_input.offer_collateral + contract_input.accept_collateral;

    (contract_input.contract_infos.len() == oracle_announcements.len())
        .then_some(())
        .ok_or(Err(FromDlcError::InvalidState(
            "Number of contracts and Oracle Announcement set must match",
        )));

    let latest_maturity = get_latest_maturity_date(&oracle_announcements)?;

    let contract_info = contract_input
        .contract_infos
        .iter()
        .zip(oracle_announcements.into_iter())
        .map(|(x, y)| ContractInfo {
            contract_descriptor: x.contract_descriptor.clone(),
            oracle_announcements: y,
            threshold: x.oracles.threshold as usize,
        })
        .collect::<Vec<ContractInfo>>();

    let fund_output_serial_id = u64::MAX / 2;
    let dlc_transactions = dlc::create_dlc_transactions(
        &offer_params.party_params,
        &accept_params.party_params,
        &contract_info[0]
            .get_payouts(total_collateral)
            .map_err(FromDlcError::Manager)?,
        latest_maturity + refund_delay,
        contract_input.fee_rate,
        0,
        date_ref,
        fund_output_serial_id,
    )
    .map_err(FromDlcError::Dlc)?;

    let secp = Secp256k1::new();

    match contract_info {
        ContractInfo::SingleContractInfo(s) => s.contract_info.oracle_info.validate(secp)?,
        ContractInfo::DisjointContractInfo(d) => {
            if d.contract_infos.len() < 2 {
                return Err(Error::InvalidArgument);
            }

            for c in &d.contract_infos {
                c.oracle_info.validate(secp)?;
            }
        }
    }

    let fund_public_key = PublicKey::from_secret_key(&secp, &fund_secret_key);

    let (my_party_params, counterparty_params) =
        if offer_params.party_params.fund_pubkey == fund_public_key {
            (offer_params, accept_params)
        } else {
            (accept_params, offer_params)
        };

    let sign_res = sign(
        &secp,
        &dlc_transactions,
        &contract_info,
        &fund_secret_key,
        &my_party_params.party_params,
        &counterparty_params.party_params,
    )?;

    Ok((sign_res.1, sign_res.2))
}

fn sign(
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

fn get_latest_maturity_date(announcements: &[Vec<OracleAnnouncement>]) -> Result<u32> {
    announcements
        .iter()
        .flatten()
        .map(|x| x.oracle_event.event_maturity_epoch)
        .max()
        .ok_or_else(|| FromDlcError::InvalidState("Could not find maximum event maturity."))
}