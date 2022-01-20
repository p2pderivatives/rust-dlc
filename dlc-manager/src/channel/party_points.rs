//! #

use dlc::channel::RevokeParams;
use lightning::ln::chan_utils::derive_public_key;
use secp256k1_zkp::{All, PublicKey, Secp256k1, Signing};

use crate::error::Error;

use super::utils::{derive_bitcoin_public_key, derive_bitcoin_public_revocation_key};

///
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct PartyBasePoints {
    ///
    pub own_basepoint: PublicKey,
    ///
    pub revocation_basepoint: PublicKey,
    ///
    pub publish_basepoint: PublicKey,
}

impl PartyBasePoints {
    ///
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

    ///
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

    ///
    pub fn get_own_pk<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        per_update_point: &PublicKey,
    ) -> Result<PublicKey, Error> {
        let key = derive_public_key(secp, per_update_point, &self.own_basepoint)?;
        Ok(key)
    }

    ///
    pub fn get_publish_pk<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        per_update_point: &PublicKey,
    ) -> Result<PublicKey, Error> {
        let key = derive_public_key(secp, per_update_point, &self.publish_basepoint)?;
        Ok(key)
    }

    ///
    pub fn get_revocation_pk<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        per_update_point: &PublicKey,
    ) -> Result<PublicKey, Error> {
        let key = derive_public_key(secp, per_update_point, &self.revocation_basepoint)?;
        Ok(key)
    }
}
