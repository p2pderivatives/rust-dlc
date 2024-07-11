//! #Utils
use std::ops::Deref;

use bitcoin::{consensus::Encodable, Txid};
use dlc::{PartyParams, TxInputInfo};
use dlc_messages::{
    oracle_msgs::{OracleAnnouncement, OracleAttestation},
    FundingInput,
};
use dlc_trie::RangeInfo;
#[cfg(not(feature = "fuzztarget"))]
use secp256k1_zkp::rand::{thread_rng, Rng, RngCore};
use secp256k1_zkp::{PublicKey, Secp256k1, Signing};

use crate::{
    channel::party_points::PartyBasePoints,
    contract::{contract_info::ContractInfo, AdaptorInfo},
    error::Error,
    Blockchain, ContractSigner, ContractSignerProvider, Wallet,
};

macro_rules! get_object_in_state {
    ($manager: expr, $id: expr, $state: ident, $peer_id: expr, $object_type: ident, $get_call: ident) => {{
        let object = $manager.get_store().$get_call($id)?;
        match object {
            Some(c) => match $peer_id as Option<PublicKey> {
                Some(p) if c.get_counter_party_id() != p => Err(Error::InvalidParameters(format!(
                    "Peer {:02x?} is not involved with {} {:02x?}.",
                    $peer_id,
                    stringify!($object_type),
                    $id
                ))),
                _ => match c {
                    $object_type::$state(s) => Ok(s),
                    _ => Err(Error::InvalidState(format!(
                        "Invalid state {:?} expected {}.",
                        c,
                        stringify!($state),
                    ))),
                },
            },
            None => Err(Error::InvalidParameters(format!(
                "Unknown {} id.",
                stringify!($object_type)
            ))),
        }
    }};
}

pub(crate) use get_object_in_state;

#[cfg(not(feature = "fuzztarget"))]
pub(crate) fn get_new_serial_id() -> u64 {
    thread_rng().next_u64()
}

#[cfg(feature = "fuzztarget")]
pub(crate) fn get_new_serial_id() -> u64 {
    use rand_chacha::rand_core::RngCore;
    use rand_chacha::rand_core::SeedableRng;
    rand_chacha::ChaCha8Rng::from_seed([0u8; 32]).next_u64()
}

#[cfg(not(feature = "fuzztarget"))]
pub(crate) fn get_new_temporary_id() -> [u8; 32] {
    thread_rng().gen::<[u8; 32]>()
}

#[cfg(feature = "fuzztarget")]
pub(crate) fn get_new_temporary_id() -> [u8; 32] {
    use rand_chacha::rand_core::RngCore;
    use rand_chacha::rand_core::SeedableRng;
    let mut res = [0u8; 32];
    rand_chacha::ChaCha8Rng::from_seed([0u8; 32]).fill_bytes(&mut res);
    res
}

pub(crate) fn compute_id(
    fund_tx_id: Txid,
    fund_output_index: u16,
    temporary_id: &[u8; 32],
) -> [u8; 32] {
    let mut res = [0; 32];
    for i in 0..32 {
        res[i] = fund_tx_id[31 - i] ^ temporary_id[i];
    }
    res[30] ^= ((fund_output_index >> 8) & 0xff) as u8;
    res[31] ^= (fund_output_index & 0xff) as u8;
    res
}

pub(crate) fn get_party_params<W: Deref, B: Deref, X: ContractSigner, C: Signing>(
    secp: &Secp256k1<C>,
    own_collateral: u64,
    fee_rate: u64,
    wallet: &W,
    signer: &X,
    blockchain: &B,
) -> Result<(PartyParams, Vec<FundingInput>), Error>
where
    W::Target: Wallet,
    B::Target: Blockchain,
{
    let funding_pubkey = signer.get_public_key(secp)?;

    let payout_addr = wallet.get_new_address()?;
    let payout_spk = payout_addr.script_pubkey();
    let payout_serial_id = get_new_serial_id();
    let change_addr = wallet.get_new_change_address()?;
    let change_spk = change_addr.script_pubkey();
    let change_serial_id = get_new_serial_id();

    // Add base cost of fund tx + CET / 2 and a CET output to the collateral.
    let appr_required_amount =
        own_collateral + get_half_common_fee(fee_rate)? + dlc::util::weight_to_fee(124, fee_rate)?;
    let utxos = wallet.get_utxos_for_amount(appr_required_amount, fee_rate, true)?;

    let mut funding_inputs: Vec<FundingInput> = Vec::new();
    let mut funding_tx_info: Vec<TxInputInfo> = Vec::new();
    let mut total_input = 0;
    for utxo in utxos {
        let prev_tx = blockchain.get_transaction(&utxo.outpoint.txid)?;
        let mut writer = Vec::new();
        prev_tx.consensus_encode(&mut writer)?;
        let prev_tx_vout = utxo.outpoint.vout;
        let sequence = 0xffffffff;
        // TODO(tibo): this assumes P2WPKH with low R
        let max_witness_len = 107;
        let funding_input = FundingInput {
            input_serial_id: get_new_serial_id(),
            prev_tx: writer,
            prev_tx_vout,
            sequence,
            max_witness_len,
            redeem_script: utxo.redeem_script,
        };
        total_input += prev_tx.output[prev_tx_vout as usize].value;
        funding_tx_info.push((&funding_input).into());
        funding_inputs.push(funding_input);
    }

    let party_params = PartyParams {
        fund_pubkey: funding_pubkey,
        change_script_pubkey: change_spk,
        change_serial_id,
        payout_script_pubkey: payout_spk,
        payout_serial_id,
        inputs: funding_tx_info,
        collateral: own_collateral,
        input_amount: total_input,
    };

    Ok((party_params, funding_inputs))
}

pub(crate) fn get_party_base_points<C: Signing, SP: Deref>(
    secp: &Secp256k1<C>,
    signer_provider: &SP,
) -> Result<PartyBasePoints, Error>
where
    SP::Target: ContractSignerProvider,
{
    Ok(PartyBasePoints {
        own_basepoint: PublicKey::from_secret_key(secp, &signer_provider.get_new_secret_key()?),
        publish_basepoint: PublicKey::from_secret_key(secp, &signer_provider.get_new_secret_key()?),
        revocation_basepoint: PublicKey::from_secret_key(
            secp,
            &signer_provider.get_new_secret_key()?,
        ),
    })
}

pub(crate) fn get_half_common_fee(fee_rate: u64) -> Result<u64, Error> {
    let common_fee = dlc::util::get_common_fee(fee_rate)?;
    Ok((common_fee as f64 / 2_f64).ceil() as u64)
}

pub(crate) fn get_range_info_and_oracle_sigs(
    contract_info: &ContractInfo,
    adaptor_info: &AdaptorInfo,
    attestations: &[(usize, OracleAttestation)],
) -> Result<(RangeInfo, Vec<Vec<secp256k1_zkp::schnorr::Signature>>), Error> {
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

    Err(Error::InvalidState(
        "Could not find closing info for given outcomes".to_string(),
    ))
}

pub(crate) fn get_latest_maturity_date(
    announcements: &[Vec<OracleAnnouncement>],
) -> Result<u32, Error> {
    announcements
        .iter()
        .flatten()
        .map(|x| x.oracle_event.event_maturity_epoch)
        .max()
        .ok_or_else(|| {
            Error::InvalidParameters("Could not find maximum event maturity.".to_string())
        })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use dlc_messages::oracle_msgs::{EnumEventDescriptor, EventDescriptor, OracleEvent};
    use secp256k1_zkp::{
        rand::{thread_rng, RngCore},
        schnorr::Signature,
        XOnlyPublicKey,
    };

    use super::*;

    #[test]
    fn id_computation_test() {
        let transaction = bitcoin_test_utils::tx_from_string("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020000ffffffff0101000000000000000000000000");
        let output_index = 1;
        let temporary_id = [34u8; 32];
        let expected_id = bitcoin_test_utils::str_to_hex(
            "81db60dcbef10a2d0cb92cb78400a96ee6a9b6da785d0230bdabf1e18a2d6ffb",
        );

        let id = compute_id(transaction.txid(), output_index, &temporary_id);

        assert_eq!(expected_id, id);
    }

    #[test]
    fn get_latest_maturity_date_test() {
        let mut rand = thread_rng();
        let maturity_dates: Vec<Vec<u32>> = (0..20)
            .map(|_| (0..20).map(|_| rand.next_u32()).collect())
            .collect();
        let announcements: Vec<Vec<_>> = maturity_dates
            .iter()
            .map(|x| x.iter().map(|y| create_announcement(*y)).collect())
            .collect();

        assert_eq!(
            *maturity_dates.iter().flatten().max().unwrap(),
            get_latest_maturity_date(&announcements).expect("to have a latest maturity date.")
        );
    }

    fn create_announcement(maturity: u32) -> OracleAnnouncement {
        let xonly_pk = XOnlyPublicKey::from_str(
            "e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
        )
        .unwrap();

        OracleAnnouncement {
            announcement_signature: Signature::from_str("6470FD1303DDA4FDA717B9837153C24A6EAB377183FC438F939E0ED2B620E9EE5077C4A8B8DCA28963D772A94F5F0DDF598E1C47C137F91933274C7C3EDADCE8").unwrap(),
            oracle_public_key: xonly_pk,
            oracle_event: OracleEvent { oracle_nonces: vec![xonly_pk], event_maturity_epoch: maturity,event_descriptor: EventDescriptor::EnumEvent(EnumEventDescriptor { outcomes: vec!["1".to_string(), "2".to_string()] }), event_id: "01".to_string() },
        }
    }
}
