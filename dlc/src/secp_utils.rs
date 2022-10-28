//! Crypto utilities providing necessary DLC specific functions not available in
//! rust-secp256k1 or rust-secp256k1-zkp.

use crate::Error;
use bitcoin::hashes::Hash;
use bitcoin::hashes::*;
use bitcoin::{KeyPair, XOnlyPublicKey};
use secp256k1_zkp::{
    schnorr::Signature as SchnorrSignature, Message, PublicKey, Scalar, Secp256k1, Signing,
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

/// Create a Schnorr signature using the provided nonce instead of generating one.
pub fn schnorrsig_sign_with_nonce<S: Signing>(
    secp: &Secp256k1<S>,
    msg: &Message,
    keypair: &KeyPair,
    nonce: &[u8; 32],
) -> SchnorrSignature {
    secp.sign_schnorr_with_aux_rand(msg, keypair, nonce)
}

/// Compute a signature point for the given public key, nonce and message.
pub fn schnorrsig_compute_sig_point<C: Verification>(
    secp: &Secp256k1<C>,
    pubkey: &XOnlyPublicKey,
    nonce: &XOnlyPublicKey,
    message: &Message,
) -> Result<PublicKey, Error> {
    let hash = create_schnorr_hash(message, nonce, pubkey);
    let pk = schnorr_pubkey_to_pubkey(pubkey)?;
    let scalar = Scalar::from_be_bytes(hash).unwrap();
    let tweaked = pk.mul_tweak(secp, &scalar)?;
    let npk = schnorr_pubkey_to_pubkey(nonce)?;
    Ok(npk.combine(&tweaked)?)
}

/// Decompose a bip340 signature into a nonce and a secret key (as byte array)
pub fn schnorrsig_decompose(
    signature: &SchnorrSignature,
) -> Result<(XOnlyPublicKey, &[u8]), Error> {
    let bytes = signature.as_ref();
    Ok((XOnlyPublicKey::from_slice(&bytes[0..32])?, &bytes[32..64]))
}

fn create_schnorr_hash(msg: &Message, nonce: &XOnlyPublicKey, pubkey: &XOnlyPublicKey) -> [u8; 32] {
    let mut buf = Vec::<u8>::new();
    buf.extend(&nonce.serialize());
    buf.extend(&pubkey.serialize());
    buf.extend(msg.as_ref().to_vec());
    BIP340Hash::hash(&buf).into_inner()
}

fn schnorr_pubkey_to_pubkey(schnorr_pubkey: &XOnlyPublicKey) -> Result<PublicKey, Error> {
    let mut buf = Vec::<u8>::with_capacity(33);
    buf.push(0x02);
    buf.extend(&schnorr_pubkey.serialize());
    Ok(PublicKey::from_slice(&buf)?)
}
