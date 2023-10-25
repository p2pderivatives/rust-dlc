use dlc_manager::contract::ser::Serializable;
use dlc_messages::oracle_msgs::OracleAttestation;
use dlc_trie::RangeInfo;
use secp256k1_zkp::{schnorr::Signature as SchnorrSignature, Secp256k1};

use bitcoin::{EcdsaSighashType, Script, Transaction, Witness};
use dlc::secp_utils;
use dlc_manager::contract::{contract_info::ContractInfo, AdaptorInfo};
use secp256k1_zkp::{ecdsa::Signature, PublicKey, Scalar, SecretKey};

use crate::{
    error::*, get_dlc_transactions, validate_presigned_without_infos, ContractParams, SideSign,
};

#[derive(Clone, Debug, PartialEq)]
pub struct AttestationData {
    pub index: u32,
    pub attestation: OracleAttestation,
}

pub struct ContractSettlement {
    pub contract: Vec<u8>,
    pub attestations: Vec<AttestationData>,
}

pub fn get_signed_cet(
    contract_params: ContractParams,
    offer_side: &SideSign,
    accept_side: &SideSign,
    attestations: Vec<AttestationData>,
) -> Result<Vec<u8>> {
    let attestations: Vec<(usize, OracleAttestation)> = attestations
        .into_iter()
        .map(|x| (x.index as usize, x.attestation.into()))
        .collect();

    let dlc_transactions = get_dlc_transactions(
        &contract_params,
        &offer_side.party_params,
        &accept_side.party_params,
    )?;
    let secp = Secp256k1::new();

    let adaptor_infos = validate_presigned_without_infos(
        &secp,
        &dlc_transactions,
        &accept_side.refund_sig,
        &accept_side.adaptor_sig,
        &contract_params.contract_info,
        &offer_side.party_params,
        &accept_side.party_params,
    )?;
    let (range_info, sigs): (RangeInfo, Vec<Vec<SchnorrSignature>>) =
        get_range_info_and_oracle_sigs(
            &contract_params.contract_info.get(0).unwrap(),
            adaptor_infos.get(0).unwrap(),
            &attestations,
        )?;
    let mut cet = dlc_transactions.cets[range_info.cet_index].clone();

    let (adaptor_sigs_offer, fund_pubkey_offer) = (
        offer_side.adaptor_sig.as_ref(),
        &offer_side.party_params.fund_pubkey,
    );

    let (adaptor_sigs_accept, fund_pubkey_accept) = (
        accept_side.adaptor_sig.as_ref(),
        &accept_side.party_params.fund_pubkey,
    );

    let adaptor_secret = signatures_to_secret(sigs.as_slice())?;

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

    Ok(Serializable::serialize(&cet).unwrap())
}

fn get_range_info_and_oracle_sigs(
    contract_info: &ContractInfo,
    adaptor_info: &AdaptorInfo,
    attestations: &[(usize, OracleAttestation)],
) -> Result<(RangeInfo, Vec<Vec<secp256k1_zkp::schnorr::Signature>>)> {
    let outcomes = attestations
        .iter()
        .map(|(i, x)| (*i, &x.outcomes))
        .collect::<Vec<(usize, &Vec<String>)>>();
    let info_opt = contract_info.get_range_info_for_outcome(adaptor_info, &outcomes, 0);
    if let Some((sig_infos, range_info)) = info_opt {
        let sigs: Vec<Vec<_>> = attestations
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
        .collect::<Result<Vec<&[u8]>>>()?;
    let secret = SecretKey::from_slice(s_values[0])
        .map_err(|e| FromDlcError::Secp(secp256k1_zkp::Error::Upstream(e)))?;

    let result = s_values.iter().skip(1).fold(secret, |accum, s| {
        let sec = SecretKey::from_slice(s).unwrap();
        accum.add_tweak(&Scalar::from(sec)).unwrap()
    });

    Ok(result)
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

pub fn get_refund(
    contract_params: ContractParams,
    offer_side: &SideSign,
    accept_side: &SideSign,
) -> Result<Vec<u8>> {
    let dlc_transactions = get_dlc_transactions(
        &contract_params,
        &offer_side.party_params,
        &accept_side.party_params,
    )?;

    Ok(dlc_transactions.refund.serialize().unwrap())
}
