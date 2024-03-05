//! #

use bitcoin::hashes::HashEngine;
use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
use secp256k1_zkp::{PublicKey, Scalar, Secp256k1, SecretKey};

/// Derives a public key from a `base_point` and a `per_commitment_point` as described in BOLT-3
/// (https://github.com/lightning/bolts/blob/master/03-transactions.md#localpubkey-local_htlcpubkey-remote_htlcpubkey-local_delayedpubkey-and-remote_delayedpubkey-derivation).
///
/// Taken from a previous version of ldk as it was refactored into something less practical to use
/// externally.
pub(crate) fn derive_public_key<T: secp256k1_zkp::Signing>(
    secp_ctx: &Secp256k1<T>,
    per_commitment_point: &PublicKey,
    base_point: &PublicKey,
) -> PublicKey {
    let mut sha = Sha256::engine();
    sha.input(&per_commitment_point.serialize());
    sha.input(&base_point.serialize());
    let res = Sha256::from_engine(sha).to_byte_array();

    let hashkey = PublicKey::from_secret_key(
        secp_ctx,
        &SecretKey::from_slice(&res)
            .expect("Hashes should always be valid keys unless SHA-256 is broken"),
    );
    base_point.combine(&hashkey)
		.expect("Addition only fails if the tweak is the inverse of the key. This is not possible when the tweak contains the hash of the key.")
}

/// Derives a per-commitment-transaction revocation public key from its constituent parts. This is
/// the public equivalent of derive_private_revocation_key - using only public keys to derive a
/// public key instead of private keys.
///
/// Only the cheating participant owns a valid witness to propagate a revoked
/// commitment transaction, thus per_commitment_point always come from cheater
/// and revocation_base_point always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
///
/// Taken from a previous version of ldk as it was refactored into something less practical to use
/// externally.
pub fn derive_public_revocation_key<T: secp256k1_zkp::Verification>(
    secp_ctx: &Secp256k1<T>,
    per_commitment_point: &PublicKey,
    countersignatory_revocation_base_point: &PublicKey,
) -> PublicKey {
    let rev_append_commit_hash_key = {
        let mut sha = Sha256::engine();
        sha.input(&countersignatory_revocation_base_point.serialize());
        sha.input(&per_commitment_point.serialize());

        Sha256::from_engine(sha).to_byte_array()
    };
    let commit_append_rev_hash_key = {
        let mut sha = Sha256::engine();
        sha.input(&per_commitment_point.serialize());
        sha.input(&countersignatory_revocation_base_point.serialize());

        Sha256::from_engine(sha).to_byte_array()
    };

    let countersignatory_contrib = countersignatory_revocation_base_point
        .mul_tweak(
            secp_ctx,
            &Scalar::from_be_bytes(rev_append_commit_hash_key).unwrap(),
        )
        .expect(
            "Multiplying a valid public key by a hash is expected to never fail per secp256k1 docs",
        );
    let broadcaster_contrib = per_commitment_point
        .mul_tweak(
            secp_ctx,
            &Scalar::from_be_bytes(commit_append_rev_hash_key).unwrap(),
        )
        .expect(
            "Multiplying a valid public key by a hash is expected to never fail per secp256k1 docs",
        );
    countersignatory_contrib.combine(&broadcaster_contrib)
		.expect("Addition only fails if the tweak is the inverse of the key. This is not possible when the tweak commits to the key.")
}
