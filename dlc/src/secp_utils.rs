//! Crypto utilities providing necessary DLC specific functions not available in
//! rust-secp256k1 or rust-secp256k1-zkp.

use crate::Error;
use core::ptr;
use secp256k1_sys::{
    types::{c_int, c_uchar, c_void},
    CPtr,
};
use secp256k1_zkp::bitcoin_hashes::Hash;
use secp256k1_zkp::bitcoin_hashes::*;
use secp256k1_zkp::{
    schnorrsig::{KeyPair, PublicKey as SchnorrPublicKey, Signature as SchnorrSignature},
    Message, PublicKey, Secp256k1, Signing, Verification,
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
    unsafe {
        let mut sig = [0u8; secp256k1_zkp::constants::SCHNORRSIG_SIGNATURE_SIZE];
        assert_eq!(
            1,
            secp256k1_sys::secp256k1_schnorrsig_sign(
                *secp.ctx(),
                sig.as_mut_c_ptr(),
                msg.as_c_ptr(),
                keypair.as_ptr(),
                Some(constant_nonce_fn),
                nonce.as_c_ptr() as *const c_void
            )
        );

        SchnorrSignature::from_slice(&sig).unwrap()
    }
}

/// Compute a signature point for the given public key, nonce and message.
pub fn schnorrsig_compute_sig_point<C: Verification>(
    secp: &Secp256k1<C>,
    pubkey: &SchnorrPublicKey,
    nonce: &SchnorrPublicKey,
    message: &Message,
) -> Result<PublicKey, Error> {
    let hash = create_schnorr_hash(message, nonce, pubkey);
    let mut pk = schnorr_pubkey_to_pubkey(pubkey)?;
    pk.mul_assign(secp, &hash)?;
    let npk = schnorr_pubkey_to_pubkey(nonce)?;
    Ok(npk.combine(&pk)?)
}

/// Decompose a bip340 signature into a nonce and a secret key (as byte array)
pub fn schnorrsig_decompose(
    signature: &SchnorrSignature,
) -> Result<(SchnorrPublicKey, &[u8]), Error> {
    let bytes = signature.as_ref();
    Ok((SchnorrPublicKey::from_slice(&bytes[0..32])?, &bytes[32..64]))
}

extern "C" fn constant_nonce_fn(
    nonce32: *mut c_uchar,
    _msg32: *const c_uchar,
    _key32: *const c_uchar,
    _xonly_pk32: *const c_uchar,
    _algo16: *const c_uchar,
    data: *mut c_void,
) -> c_int {
    unsafe {
        ptr::copy_nonoverlapping(data as *const c_uchar, nonce32, 32);
    }
    1
}

fn create_schnorr_hash(
    msg: &Message,
    nonce: &SchnorrPublicKey,
    pubkey: &SchnorrPublicKey,
) -> Vec<u8> {
    let mut buf = Vec::<u8>::new();
    buf.extend(&nonce.serialize());
    buf.extend(&pubkey.serialize());
    buf.extend(msg.as_ref().to_vec());
    BIP340Hash::hash(&buf).into_inner().to_vec()
}

fn schnorr_pubkey_to_pubkey(schnorr_pubkey: &SchnorrPublicKey) -> Result<PublicKey, Error> {
    let mut buf = Vec::<u8>::with_capacity(33);
    buf.push(0x02);
    buf.extend(&schnorr_pubkey.serialize());
    Ok(PublicKey::from_slice(&buf)?)
}
