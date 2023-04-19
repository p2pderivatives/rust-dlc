//! # DLC channels use base points used to derive points used to make revocation
//! of states possible. This module contain a structure containing them and methods
//! useful for derivation.

use bitcoin::PublicKey as BitcoinPublicKey;
use dlc::channel::RevokeParams;
use lightning::ln::chan_utils::{derive_public_key, derive_public_revocation_key};
use secp256k1_zkp::{All, PublicKey, Secp256k1, Signing, Verification};

/// Base points used by a party of a DLC channel to derive public and private
/// values necessary for state update throughout the lifetime of the channel.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct PartyBasePoints {
    /// Base point used to derive "own" secrets and points.
    pub own_basepoint: PublicKey,
    /// Base point used to derive revocation secrets and points, revealed when
    /// the state of a channel is revoked.
    pub revocation_basepoint: PublicKey,
    /// Base point used to derive publish secrets and points, used as adaptor
    /// secrets, that get revealed when using the adaptor signature.
    pub publish_basepoint: PublicKey,
}

impl PartyBasePoints {
    /// Creates a new [`PartyBasePoints`] structure filled with the given values.
    pub fn new(
        own_basepoint: PublicKey,
        revocation_basepoint: PublicKey,
        publish_basepoint: PublicKey,
    ) -> Self {
        Self {
            own_basepoint,
            revocation_basepoint,
            publish_basepoint,
        }
    }

    /// Get [`RevokeParams`] from the base points, counter party revocation base
    /// point and the current per update point.
    pub fn get_revokable_params(
        &self,
        secp: &Secp256k1<All>,
        countersignatory_revocation_basepoint: &PublicKey,
        per_update_point: &PublicKey,
    ) -> RevokeParams {
        RevokeParams {
            own_pk: derive_bitcoin_public_key(secp, per_update_point, &self.own_basepoint),
            publish_pk: derive_bitcoin_public_key(secp, per_update_point, &self.publish_basepoint),
            revoke_pk: derive_bitcoin_public_revocation_key(
                secp,
                per_update_point,
                countersignatory_revocation_basepoint,
            ),
        }
    }

    /// Returns an "own" point using the own base point and given per update point.
    pub fn get_own_pk<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        per_update_point: &PublicKey,
    ) -> PublicKey {
        derive_public_key(secp, per_update_point, &self.own_basepoint)
    }

    /// Returns a publish point using the publish base point and given per update point.
    pub fn get_publish_pk<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        per_update_point: &PublicKey,
    ) -> PublicKey {
        derive_public_key(secp, per_update_point, &self.publish_basepoint)
    }

    /// Returns a publish point using the publish base point and given per update point.
    pub fn get_revocation_pk<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        per_update_point: &PublicKey,
    ) -> PublicKey {
        derive_public_key(secp, per_update_point, &self.revocation_basepoint)
    }
}

fn derive_bitcoin_public_key<C: Signing>(
    secp: &Secp256k1<C>,
    per_commitment_point: &PublicKey,
    base_point: &PublicKey,
) -> BitcoinPublicKey {
    let inner = derive_public_key(secp, per_commitment_point, base_point);
    BitcoinPublicKey {
        compressed: true,
        inner,
    }
}

fn derive_bitcoin_public_revocation_key<C: Verification>(
    secp: &Secp256k1<C>,
    per_commitment_point: &PublicKey,
    countersignatory_revocation_base_point: &PublicKey,
) -> BitcoinPublicKey {
    let inner = derive_public_revocation_key(
        secp,
        per_commitment_point,
        countersignatory_revocation_base_point,
    );
    BitcoinPublicKey {
        compressed: true,
        inner,
    }
}
