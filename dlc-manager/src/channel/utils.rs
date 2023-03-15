//! #

use bitcoin::PublicKey as BitcoinPublicKey;
use lightning::ln::chan_utils::{derive_public_key, derive_public_revocation_key};
use secp256k1_zkp::{PublicKey, Secp256k1, Signing, Verification};

use crate::error::Error;

pub(crate) fn derive_bitcoin_public_key<C: Signing>(
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

pub(crate) fn derive_bitcoin_public_revocation_key<C: Verification>(
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

/// Generate a temporary contract id for a DLC based on the channel id and the update index of the DLC channel.
pub fn generate_temporary_contract_id(
    channel_id: ChannelId,
    channel_update_idx: u64,
) -> ContractId {
    let mut data = Vec::with_capacity(65);
    data.extend_from_slice(&channel_id);
    data.extend_from_slice(&channel_update_idx.to_be_bytes());
    bitcoin::hashes::sha256::Hash::hash(&data).into_inner()
}
