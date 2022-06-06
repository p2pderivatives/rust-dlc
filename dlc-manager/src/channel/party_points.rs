//! # DLC channels use base points used to derive points used to make revocation
//! of states possible. This module contain a structure containing them and methods
//! useful for derivation.

use bitcoin::PublicKey as BitcoinPublicKey;
use dlc::channel::RevokeParams;
use lightning::ln::chan_utils::{derive_public_key, derive_public_revocation_key};
use secp256k1_zkp::{All, PublicKey, Secp256k1, Signing, Verification};

use crate::error::Error;

/// Base points used by a party of a DLC channel to derive public and private
/// values necessary for state update throughout the lifetime of the channel.
#[derive(Clone, Debug)]
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
    ) -> Result<RevokeParams, Error> {
        Ok(RevokeParams {
            own_pk: derive_bitcoin_public_key(secp, per_update_point, &self.own_basepoint)?,
            publish_pk: derive_bitcoin_public_key(secp, per_update_point, &self.publish_basepoint)?,
            revoke_pk: derive_bitcoin_public_revocation_key(
                secp,
                per_update_point,
                countersignatory_revocation_basepoint,
            )?,
        })
    }

    /// Returns an "own" point using the own base point and given per update point.
    pub fn get_own_pk<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        per_update_point: &PublicKey,
    ) -> Result<PublicKey, Error> {
        let key = derive_public_key(secp, per_update_point, &self.own_basepoint)?;
        Ok(key)
    }

    /// Returns a publish point using the publish base point and given per update point.
    pub fn get_publish_pk<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        per_update_point: &PublicKey,
    ) -> Result<PublicKey, Error> {
        let key = derive_public_key(secp, per_update_point, &self.publish_basepoint)?;
        Ok(key)
    }

    /// Returns a publish point using the publish base point and given per update point.
    pub fn get_revocation_pk<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        per_update_point: &PublicKey,
    ) -> Result<PublicKey, Error> {
        let key = derive_public_key(secp, per_update_point, &self.revocation_basepoint)?;
        Ok(key)
    }
}

fn derive_bitcoin_public_key<C: Signing>(
    secp: &Secp256k1<C>,
    per_commitment_point: &PublicKey,
    base_point: &PublicKey,
) -> Result<BitcoinPublicKey, Error> {
    let key = derive_public_key(secp, per_commitment_point, base_point)
        .map_err(|e| Error::InvalidParameters(format!("Invalid point was given {}", e)))?;
    Ok(BitcoinPublicKey {
        compressed: true,
        key,
    })
}

fn derive_bitcoin_public_revocation_key<C: Verification>(
    secp: &Secp256k1<C>,
    per_commitment_point: &PublicKey,
    countersignatory_revocation_base_point: &PublicKey,
) -> Result<BitcoinPublicKey, Error> {
    let key = derive_public_revocation_key(
        secp,
        per_commitment_point,
        countersignatory_revocation_base_point,
    )
    .map_err(|e| Error::InvalidParameters(format!("Could not derive revocation secret: {}", e)))?;
    Ok(BitcoinPublicKey {
        compressed: true,
        key,
    })
}
