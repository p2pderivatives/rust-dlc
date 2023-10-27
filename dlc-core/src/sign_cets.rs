use dlc::{DlcTransactions, PartyParams};
use dlc_manager::contract::{
    contract_info::ContractInfo, contract_input::ContractInput, AdaptorInfo, FundingInputInfo,
};
use dlc_messages::oracle_msgs::OracleAnnouncement;
use secp256k1_zkp::{
    ecdsa::Signature, All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey,
};

use crate::{error::*, get_dlc_transactions, ContractParams, Signatures};
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct PartyInfos {
    pub party_params: PartyParams,
    pub funding_input_infos: Box<[FundingInputInfo]>,
}

pub fn verify_and_get_contract_params<O: AsRef<[OracleAnnouncement]>>(
    secp: &Secp256k1<All>,
    contract_input: &ContractInput,
    refund_locktime: u32,
    cet_locktime: u32,
    oracle_announcements: &[O],
) -> Result<ContractParams> {
    let _ = &contract_input.validate().map_err(FromDlcError::Manager)?;

    (contract_input.contract_infos.len() == oracle_announcements.len())
        .then_some(())
        .ok_or(FromDlcError::InvalidState(
            "Number of contracts and Oracle Announcement set must match",
        ))?;

    let contract_info = contract_input
        .contract_infos
        .iter()
        .zip(oracle_announcements.into_iter())
        .map(|(x, y)| ContractInfo {
            contract_descriptor: x.contract_descriptor.clone(),
            oracle_announcements: y.as_ref().to_vec(),
            threshold: x.oracles.threshold as usize,
        })
        .collect::<Box<[ContractInfo]>>();

    // Missing check on locktime for refund and contract maturity compared to oracle maturity, cf OfferMsg validate method

    // Maybe some check in validate method of offeredContract too

    for c in contract_info.iter() {
        for o in &c.oracle_announcements {
            o.validate(secp).map_err(|e| FromDlcError::Dlc(e))?
        }
    }

    Ok(ContractParams {
        contract_info: contract_info,
        refund_locktime,
        cet_locktime,
        fee_rate_per_vb: contract_input.fee_rate,
    })
}

pub fn sign_cets<O: AsRef<[OracleAnnouncement]>>(
    secp: &Secp256k1<All>,
    offer_params: &PartyInfos,
    accept_params: &PartyInfos,
    contract_params: &ContractParams,
    fund_secret_key: &SecretKey,
) -> Result<Signatures> {
    let dlc_transactions = get_dlc_transactions(
        &contract_params,
        &offer_params.party_params,
        &accept_params.party_params,
    )?;

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
        &contract_params.contract_info,
        &fund_secret_key,
        &my_party_params.party_params,
        &counterparty_params.party_params,
    )?;

    Ok(Signatures {
        refund_sig: sign_res.2,
        adaptor_sig: sign_res.1,
    })
}

fn sign(
    secp: &Secp256k1<All>,
    dlc_transactions: &DlcTransactions,
    contract_info: &[ContractInfo],
    adaptor_secret_key: &SecretKey,
    own_params: &PartyParams,
    other_params: &PartyParams,
) -> Result<(Box<[AdaptorInfo]>, Box<[EcdsaAdaptorSignature]>, Signature)> {
    if PublicKey::from_secret_key(&secp, &adaptor_secret_key) != own_params.fund_pubkey {
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
                &adaptor_secret_key,
                &funding_script_pubkey,
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
        &funding_script_pubkey,
        input_value,
        &adaptor_secret_key,
    )
    .map_err(FromDlcError::Dlc)?;

    Ok((
        adaptor_infos.into_boxed_slice(),
        adaptor_sigs.into_boxed_slice(),
        refund_signature,
    ))
}
