use dlc_messages::oracle_msgs::OracleAttestation;
use dlc_trie::RangeInfo;
use secp256k1_zkp::{
    schnorr::{self, Signature as SchnorrSignature},
    EcdsaAdaptorSignature, Secp256k1,
};

use bitcoin::{EcdsaSighashType, Script, Transaction, Witness};
use dlc::secp_utils;
use dlc_manager::contract::{contract_info::ContractInfo, AdaptorInfo};
use secp256k1_zkp::{ecdsa::Signature, PublicKey, Scalar, SecretKey};

use crate::{
    contract_tools::FeePartyParams, error::*, get_dlc_transactions,
    validate_presigned_without_infos, ContractParams, DlcSide, SideSign,
};

#[cfg(feature = "serde")]
use serde::Serialize;

pub fn get_refund<E: AsRef<[EcdsaAdaptorSignature]>>(
    contract_params: &ContractParams,
    offer_side: &SideSign<E>,
    accept_side: &SideSign<E>,
    fee_party_params: Option<&FeePartyParams>,
) -> Result<Transaction> {
    let dlc_transactions = get_dlc_transactions(
        contract_params,
        offer_side.party_params,
        accept_side.party_params,
        fee_party_params,
    )?;

    let (refund_sigs_offer, fund_pubkey_offer) =
        (offer_side.refund_sig, &offer_side.party_params.fund_pubkey);

    let (refund_sigs_accept, fund_pubkey_accept) = (
        accept_side.refund_sig,
        &accept_side.party_params.fund_pubkey,
    );

    let mut refund = dlc_transactions.refund;

    sign_multisig_input(
        &mut refund,
        (refund_sigs_offer, fund_pubkey_offer),
        (refund_sigs_accept, fund_pubkey_accept),
        &dlc_transactions.funding_script_pubkey,
    );

    Ok(refund)
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize), serde(rename_all = "camelCase"))]
pub struct AttestationData<'o> {
    pub index: u32,
    pub attestation: &'o OracleAttestation,
}

pub fn get_signed_cet<E: AsRef<[EcdsaAdaptorSignature]>>(
    contract_params: &ContractParams,
    offer_side: &SideSign<E>,
    accept_side: &SideSign<E>,
    fee_party_params: Option<&FeePartyParams>,
    event_id: &str,
    attestations: &[AttestationData],
) -> Result<Transaction> {
    let attestations: Box<[(usize, &OracleAttestation)]> = attestations
        .iter()
        .map(|x| (x.index as usize, x.attestation))
        .collect();

    let dlc_transactions = get_dlc_transactions(
        contract_params,
        offer_side.party_params,
        accept_side.party_params,
        fee_party_params,
    )?;
    let secp = Secp256k1::new();

    let (_, adaptor_infos) = validate_presigned_without_infos(
        &secp,
        &dlc_transactions,
        accept_side.refund_sig,
        accept_side.adaptor_sig,
        &contract_params.contract_info,
        offer_side.party_params,
        accept_side.party_params,
        &DlcSide::Accept,
    )?;

    let (((contract_info, adaptor_info), offer_adaptor_sigs), accept_adaptor_sigs) =
        contract_params
            .contract_info
            .iter()
            .zip(adaptor_infos)
            .zip(offer_side.adaptor_sig)
            .zip(accept_side.adaptor_sig)
            .find(|(((contract_info, _), _), _)| {
                contract_info.oracle_announcements[0]
                    .oracle_event
                    .event_id
                    .as_str()
                    == event_id
            })
            .ok_or(FromDlcError::InvalidArgument)?;

    let total_collateral = offer_side.party_params.collateral + accept_side.party_params.collateral;

    let cet_input = dlc_transactions.cets[0].input[0].clone();

    let payouts = contract_info
        .get_payouts(total_collateral)
        .map_err(FromDlcError::Manager)?
        .into_boxed_slice();

    let tmp_cets = dlc::create_cets(
        &cet_input,
        &offer_side.party_params.payout_script_pubkey,
        offer_side.party_params.payout_serial_id,
        &accept_side.party_params.payout_script_pubkey,
        accept_side.party_params.payout_serial_id,
        &payouts,
        0,
    );

    let (range_info, sigs) =
        get_range_info_and_oracle_sigs(contract_info, &adaptor_info, &attestations)?;
    let mut cet = tmp_cets[range_info.cet_index].clone();

    let (adaptor_sigs_offer, fund_pubkey_offer) = (
        offer_adaptor_sigs.as_ref(),
        &offer_side.party_params.fund_pubkey,
    );

    let (adaptor_sigs_accept, fund_pubkey_accept) = (
        accept_adaptor_sigs.as_ref(),
        &accept_side.party_params.fund_pubkey,
    );

    let adaptor_secret = signatures_to_secret(&sigs)?;

    sign_multisig_input(
        &mut cet,
        (
            &adaptor_sigs_offer[range_info.adaptor_index]
                .decrypt(&adaptor_secret)
                .map_err(FromDlcError::Secp)?,
            fund_pubkey_offer,
        ),
        (
            &adaptor_sigs_accept[range_info.adaptor_index]
                .decrypt(&adaptor_secret)
                .map_err(FromDlcError::Secp)?,
            fund_pubkey_accept,
        ),
        &dlc_transactions.funding_script_pubkey,
    );

    Ok(cet)
}

fn get_range_info_and_oracle_sigs(
    contract_info: &ContractInfo,
    adaptor_info: &AdaptorInfo,
    attestations: &[(usize, &OracleAttestation)],
) -> Result<(RangeInfo, Box<[Vec<schnorr::Signature>]>)> {
    let outcomes = attestations
        .iter()
        .map(|(i, x)| (*i, &x.outcomes))
        .collect::<Vec<(usize, &Vec<String>)>>();
    let info_opt = contract_info.get_range_info_for_outcome(adaptor_info, &outcomes, 0);
    if let Some((sig_infos, range_info)) = info_opt {
        let sigs: Box<[Vec<_>]> = attestations
            .iter()
            .filter_map(|(i, a)| {
                let sig_info = sig_infos.iter().find(|x| x.0 == *i)?;
                Some(a.signatures.iter().take(sig_info.1).cloned().collect())
            })
            .collect();
        return Ok((range_info, sigs));
    }

    Err(FromDlcError::Manager(managerError::InvalidState(
        "Could not find closing info for given outcomes".to_string(),
    )))
}

fn signatures_to_secret(signatures: &[Vec<SchnorrSignature>]) -> Result<SecretKey> {
    let s_values = signatures
        .iter()
        .flatten()
        .map(|x| match secp_utils::schnorrsig_decompose(x) {
            Ok(v) => Ok(v.1),
            Err(err) => Err(FromDlcError::Dlc(err)),
        })
        .collect::<Result<Box<[&[u8]]>>>()?;
    let secret = SecretKey::from_slice(s_values[0])
        .map_err(|e| FromDlcError::Secp(secp256k1_zkp::Error::Upstream(e)))?;

    s_values
        .iter()
        .skip(1)
        .try_fold(secret, |accum, s| -> Result<SecretKey> {
            let sec = SecretKey::from_slice(s)
                .map_err(|e| FromDlcError::Secp(secp256k1_zkp::Error::Upstream(e)))?;
            accum
                .add_tweak(&Scalar::from(sec))
                .map_err(|e| FromDlcError::Secp(secp256k1_zkp::Error::Upstream(e)))
        })
}

fn finalize_sig(sig: &Signature, sig_hash_type: EcdsaSighashType) -> Vec<u8> {
    [
        sig.serialize_der().as_ref(),
        &[sig_hash_type.to_u32() as u8],
    ]
    .concat()
}

fn sign_multisig_input(
    cet: &mut Transaction,
    offer_witness_info: (&Signature, &PublicKey),
    recv_witness_info: (&Signature, &PublicKey),
    script_pubkey: &Script,
) {
    let (sig_offer, pubkey_offer) = offer_witness_info;
    let (sig_recv, pubkey_recv) = recv_witness_info;

    let raw_sig_offer = finalize_sig(sig_offer, bitcoin::EcdsaSighashType::All);
    let raw_sig_recv = finalize_sig(sig_recv, bitcoin::EcdsaSighashType::All);

    cet.input[0].witness = if pubkey_offer < pubkey_recv {
        Witness::from_vec(vec![
            Vec::new(),
            raw_sig_offer,
            raw_sig_recv,
            script_pubkey.to_bytes(),
        ])
    } else {
        Witness::from_vec(vec![
            Vec::new(),
            raw_sig_recv,
            raw_sig_offer,
            script_pubkey.to_bytes(),
        ])
    };
}
