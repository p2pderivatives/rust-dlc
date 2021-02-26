//! Utility functions not uniquely related to DLC

use super::Error;
use bitcoin::hashes::Hash;
use bitcoin::hashes::*;
use itertools::Itertools;
use secp256k1::{
    schnorrsig::PublicKey as SchnorrPublicKey, Message, PublicKey, Secp256k1, SecretKey,
    Verification,
};

const BIP340_MIDSTATE: [u8; 32] = [
    0x9c, 0xec, 0xba, 0x11, 0x23, 0x92, 0x53, 0x81, 0x11, 0x67, 0x91, 0x12, 0xd1, 0x62, 0x7e, 0x0f,
    0x97, 0xc8, 0x75, 0x50, 0x00, 0x3c, 0xc7, 0x65, 0x90, 0xf6, 0x11, 0x64, 0x33, 0xe9, 0xb6, 0x6a,
];

sha256t_hash_newtype!(
    BIP340Hash,
    BIP340HashTag,
    BIP340_MIDSTATE,
    64,
    doc = "bip340 hash",
    true
);

pub(crate) fn schnorr_pubkey_to_pubkey(
    schnorr_pubkey: &SchnorrPublicKey,
) -> Result<PublicKey, Error> {
    let mut buf = Vec::<u8>::with_capacity(33);
    buf.push(0x02);
    buf.extend(&schnorr_pubkey.serialize());
    Ok(PublicKey::from_slice(&buf)?)
}

pub(crate) fn create_schnorr_hash(
    msg: &Message,
    nonce: &SchnorrPublicKey,
    pubkey: &SchnorrPublicKey,
) -> Vec<u8> {
    let mut buf = Vec::<u8>::new();
    buf.extend(&nonce.serialize());
    buf.extend(&pubkey.serialize());
    buf.extend(msg.as_ref().iter().cloned().collect::<Vec<u8>>());
    BIP340Hash::hash(&buf).into_inner().to_vec()
}

///
pub fn get_oracle_sig_point_batch<C: Verification>(
    secp: &Secp256k1<C>,
    oracle_pubkey: &SchnorrPublicKey,
    nonces: &[SchnorrPublicKey],
    msgs: &[Message],
) -> Result<PublicKey, Error> {
    let hash_sums = add_schnorr_hashes(msgs, nonces, oracle_pubkey)?;
    let nonces_sum = add_schnorr_pubkeys(nonces)?;
    let mut pubkey = schnorr_pubkey_to_pubkey(oracle_pubkey)?;
    pubkey.mul_assign(secp, hash_sums.as_ref())?;
    Ok(pubkey.combine(&nonces_sum)?)
}

///
pub fn get_oracle_sig_points_no_hash_for_nonce(
    oracle_pubkey: &SchnorrPublicKey,
    nonce: &SchnorrPublicKey,
    nb_outcomes: usize,
) -> Result<Vec<PublicKey>, Error> {
    let mut cur = schnorr_pubkey_to_pubkey(nonce)?;
    let oracle_pubkey = schnorr_pubkey_to_pubkey(oracle_pubkey)?;
    let mut sig_points = vec![cur];
    for _ in 1..nb_outcomes {
        cur = cur.combine(&oracle_pubkey)?;
        sig_points.push(cur);
    }

    Ok(sig_points)
}

///
pub fn get_oracle_sig_points_no_hash_for_nonce_pk(
    oracle_pubkey: &PublicKey,
    nonce: &PublicKey,
    nb_outcomes: usize,
) -> Result<Vec<PublicKey>, Error> {
    let mut nonce = nonce.clone();
    let mut sig_points = vec![nonce];
    for _ in 1..nb_outcomes {
        nonce = nonce.combine(oracle_pubkey)?;
        sig_points.push(nonce);
    }

    Ok(sig_points)
}

///
pub fn get_oracle_sig_points_no_hash(
    oracle_pubkey: &SchnorrPublicKey,
    nonces: &Vec<SchnorrPublicKey>,
    nb_outcomes_per_nonce: usize,
) -> Result<Vec<PublicKey>, Error> {
    let nb_nonces = nonces.len();
    let mut nonces_sig_points = Vec::with_capacity(nb_nonces);
    let nb_outcomes = nb_outcomes_per_nonce.pow(nonces.len() as u32);
    let mut res = Vec::with_capacity(nb_outcomes);

    for i in 0..nonces.len() {
        nonces_sig_points.push(get_oracle_sig_points_no_hash_for_nonce(
            oracle_pubkey,
            &nonces[i],
            nb_outcomes_per_nonce,
        )?);
    }

    // compute all possible combinations of outcome sigpoints
    for to_combine in nonces_sig_points.into_iter().multi_cartesian_product() {
        res.push(super::combine_pubkeys(&to_combine)?);
    }

    Ok(res)
}

///
pub fn get_oracle_sig_points_no_hash_pk(
    oracle_pubkey: &PublicKey,
    nonces: &Vec<PublicKey>,
    nb_outcomes_per_nonce: usize,
) -> Result<Vec<PublicKey>, Error> {
    let nb_nonces = nonces.len();
    let mut nonces_sig_points = Vec::with_capacity(nb_nonces);
    let nb_outcomes = nb_outcomes_per_nonce.pow(nonces.len() as u32);
    let mut res = Vec::with_capacity(nb_outcomes);

    for i in 0..nonces.len() {
        nonces_sig_points.push(get_oracle_sig_points_no_hash_for_nonce_pk(
            oracle_pubkey,
            &nonces[i],
            nb_outcomes_per_nonce,
        )?);
    }

    // compute all possible combinations of outcome sigpoints
    for to_combine in nonces_sig_points.into_iter().multi_cartesian_product() {
        res.push(super::combine_pubkeys(&to_combine)?);
    }

    Ok(res)
}

pub(crate) fn add_schnorr_pubkeys(pubkeys: &[SchnorrPublicKey]) -> Result<PublicKey, Error> {
    let first = schnorr_pubkey_to_pubkey(&pubkeys[0])?;

    pubkeys.iter().try_fold(first, |acc, x| {
        let x = schnorr_pubkey_to_pubkey(&x)?;
        acc.combine(&x)?;
        Ok(acc)
    })
}

pub(crate) fn add_schnorr_hashes(
    msgs: &[Message],
    nonces: &[SchnorrPublicKey],
    pubkey: &SchnorrPublicKey,
) -> Result<SecretKey, Error> {
    let first = SecretKey::from_slice(&create_schnorr_hash(&msgs[0], &nonces[0], pubkey))?;

    msgs.iter()
        .zip(nonces.iter())
        .skip(1)
        .try_fold(first, |mut acc, (msg, nonce)| {
            let n = SecretKey::from_slice(&create_schnorr_hash(&msg, &nonce, pubkey))?;
            acc.add_assign(n.as_ref())?;
            Ok(acc)
        })
}
