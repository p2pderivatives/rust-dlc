//! Utility functions not uniquely related to DLC

use super::Error;
use bitcoin::hashes::Hash;
use bitcoin::hashes::*;
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
pub fn get_oracle_sig_point_batch_no_hash<C: Verification>(
    secp: &Secp256k1<C>,
    oracle_pubkey: &SchnorrPublicKey,
    nonces: &[SchnorrPublicKey],
    len: usize,
) -> Result<PublicKey, Error> {
    // compute addition of pubkey for each digit
    let mut pubkey = schnorr_pubkey_to_pubkey(oracle_pubkey)?;
    for _ in 1..len {
        pubkey = pubkey.combine(&pubkey)?;
    }
    // compute sum of nonces
    let nonces_sum = add_schnorr_pubkeys(nonces)?;
    Ok(pubkey.combine(&nonces_sum)?)
}

///
pub fn get_oracle_sig_point_no_hash_factor<C: Verification>(
    secp: &Secp256k1<C>,
    oracle_pubkeys: &[SchnorrPublicKey],
    nonces: &[SchnorrPublicKey],
    len: usize,
) -> Result<PublicKey, Error> {
    let mut sum = Vec::with_capacity(32);
    sum.resize(24, 0);
    sum.extend(&(1..(len as u64 + 1)).sum::<u64>().to_be_bytes());
    let nonces_sum = add_schnorr_pubkeys(nonces)?;
    let mut pubkey = add_schnorr_pubkeys(oracle_pubkeys)?;
    pubkey.mul_assign(secp, &sum)?;
    Ok(pubkey.combine(&nonces_sum)?)
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
