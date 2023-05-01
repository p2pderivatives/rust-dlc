//! Module containing messages related to DLC on Lightning channels.

use bitcoin::Script;
use secp256k1_zkp::{ecdsa::Signature, EcdsaAdaptorSignature, PublicKey, SecretKey};

use crate::ser_impls::{read_ecdsa_adaptor_signature, write_ecdsa_adaptor_signature};
use crate::{contract_msgs::ContractInfo, CetAdaptorSignatures};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// A message to offer the establishment of a DLC channel within a preexisting Lightning channel.
pub struct SubChannelOffer {
    /// The id of the Lightning channel the message refers to.
    pub channel_id: [u8; 32],
    /// The base point that will be used by the offer party for revocation of the DLC channel
    /// transactions.
    pub revocation_basepoint: PublicKey,
    /// The base point that will be used by the offer party for generating adaptor signatures to
    /// revocable transactions within the DLC channel.
    pub publish_basepoint: PublicKey,
    /// The base point that will be used by the offer party in the 2 of 2 output
    /// of buffer transactions.
    pub own_basepoint: PublicKey,
    /// The point that will be used by the offer party to derive public private key pairs required
    /// for the split transaction.
    pub next_per_split_point: PublicKey,
    /// Information about the contract to be used to setup the DLC channel.
    pub contract_info: ContractInfo,
    /// The base point that will be used by the offer party for revocation of buffer transactions.
    pub channel_revocation_basepoint: PublicKey,
    /// The base point that will be used by the offer party for generating
    /// adaptor signatures to buffer transactions.
    pub channel_publish_basepoint: PublicKey,
    /// The base point that will be used by the offer party in the 2 of 2 output
    /// of buffer transactions.
    pub channel_own_basepoint: PublicKey,
    /// The point that will be used by the offer party to derive public private key pairs required
    /// for the DLC channel.
    pub channel_first_per_update_point: PublicKey,
    /// Script used by the offer party to receive their payout on channel close.
    pub payout_spk: Script,
    /// Serial id used to order CET outputs.
    pub payout_serial_id: u64,
    /// The collateral input by the offer party in the channel.
    pub offer_collateral: u64,
    /// Lock time for the CETs.
    pub cet_locktime: u32,
    /// Lock time for the refund transaction.
    pub refund_locktime: u32,
    /// The nSequence value to use for the CETs.
    pub cet_nsequence: u32,
    /// The fee rate to use for creating the split and DLC channel transactions.
    pub fee_rate_per_vbyte: u64,
}

impl_dlc_writeable!(
    SubChannelOffer, {
    (channel_id, writeable),
    (revocation_basepoint, writeable),
    (publish_basepoint, writeable),
    (own_basepoint, writeable),
    (next_per_split_point, writeable),
    (contract_info, writeable),
    (channel_revocation_basepoint, writeable),
    (channel_publish_basepoint, writeable),
    (channel_own_basepoint, writeable),
    (channel_first_per_update_point, writeable),
    (payout_spk, writeable),
    (payout_serial_id, writeable),
    (offer_collateral, writeable),
    (cet_locktime, writeable),
    (refund_locktime, writeable),
    (cet_nsequence, writeable),
    (fee_rate_per_vbyte, writeable)
    }
);

/// A message to accept an offer to establish a DLC channel within an existing Lightning channel.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SubChannelAccept {
    /// The id of the Lightning channel the message relates to.
    pub channel_id: [u8; 32],
    /// The base point that will be used by the offer party for revocation of the split
    /// transaction.
    pub revocation_basepoint: PublicKey,
    /// The base point that will be used by the offer party for generating
    /// adaptor signatures used to revoke the split transaction.
    pub publish_basepoint: PublicKey,
    /// The base point that will be used by the offer party in the 2 of 2 output
    /// of split transactions.
    pub own_basepoint: PublicKey,
    /// The adaptor signature for the split transaction.
    pub split_adaptor_signature: EcdsaAdaptorSignature,
    /// The signature for the new commit transaction of the Lightning channel.
    pub commit_signature: Signature,
    /// The htlc signatures for the new commit transaction of the Lightning channel.
    pub htlc_signatures: Vec<Signature>,
    /// The first point used to derive public private key pairs used for the split transaction.
    pub first_per_split_point: PublicKey,
    /// The base point that will be used by the offer party for revocation of the DLC channel
    /// buffer transactions.
    pub channel_revocation_basepoint: PublicKey,
    /// The base point that will be used by the offer party for generating
    /// adaptor signatures to buffer transactions within the DLC channel.
    pub channel_publish_basepoint: PublicKey,
    /// The base point that will be used by the offer party in the 2 of 2 output
    /// of buffer transactions within the DLC channel.
    pub channel_own_basepoint: PublicKey,
    /// The adaptor signatures for all CETs generated by the accept party.
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    /// The adaptor signature for the buffer transaction generated by the accept
    /// party.
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    /// The refund signature generated by the accept party.
    pub refund_signature: Signature,
    /// The signature for the glue transaction of the Lightning channel.
    pub ln_glue_signature: Signature,
    /// The point used to derive public private key pairs within the DLC channel.
    pub first_per_update_point: PublicKey,
    /// Script used by the offer party to receive their payout on channel close.
    pub payout_spk: Script,
    /// Serial id used to order CET outputs.
    pub payout_serial_id: u64,
}

impl_dlc_writeable!(
    SubChannelAccept, {
    (channel_id, writeable),
    (revocation_basepoint, writeable),
    (publish_basepoint, writeable),
    (own_basepoint, writeable),
    (split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (commit_signature, writeable),
    (htlc_signatures, writeable),
    (first_per_split_point, writeable),
    (channel_revocation_basepoint, writeable),
    (channel_publish_basepoint, writeable),
    (channel_own_basepoint, writeable),
    (cet_adaptor_signatures, writeable),
    (buffer_adaptor_signature,  {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (refund_signature, writeable),
    (ln_glue_signature, writeable),
    (first_per_update_point, writeable),
    (payout_spk, writeable),
    (payout_serial_id, writeable)
    }
);

/// A message to confirm the establishment of a DLC channel within an existing Lightning channel.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SubChannelConfirm {
    /// The id of the Lightning channel the message relates to.
    pub channel_id: [u8; 32],
    /// The pre-image of the revocation point used for the old commitment transaction.
    pub per_commitment_secret: SecretKey,
    /// The commitment point for the next Lightning commitment transaction.
    pub next_per_commitment_point: PublicKey,
    /// The adaptor signature used for revocation of the split transaction.
    pub split_adaptor_signature: EcdsaAdaptorSignature,
    /// The signature for the new commitment transaction.
    pub commit_signature: Signature,
    /// The htlc signatures for the new commitment transaction.
    pub htlc_signatures: Vec<Signature>,
    /// The adaptor signatures for the DLC channel CETs.
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    /// The adaptor signature for the buffer transaction generated by the offer
    /// party.
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    /// The refund signature generated by the offer party.
    pub refund_signature: Signature,
    /// The signature for the glue transaction of the Lightning channel.
    pub ln_glue_signature: Signature,
}

impl_dlc_writeable!(SubChannelConfirm, {
    (channel_id, writeable),
    (per_commitment_secret, writeable),
    (next_per_commitment_point, writeable),
    (split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (commit_signature, writeable),
    (htlc_signatures, writeable),
    (cet_adaptor_signatures, writeable),
    (buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (refund_signature, writeable),
    (ln_glue_signature, writeable)
});

/// A message to finalize the establishment of a DLC channel within an existing Lightning channel.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SubChannelFinalize {
    /// The id of the Lightning channel the message relates to.
    pub channel_id: [u8; 32],
    /// The pre-image of the revocation point used for the old commitment transaction.
    pub per_commitment_secret: SecretKey,
    /// The commitment point for the next Lightning commitment transaction.
    pub next_per_commitment_point: PublicKey,
}

impl_dlc_writeable!(SubChannelFinalize, {
    (channel_id, writeable),
    (per_commitment_secret, writeable),
    (next_per_commitment_point, writeable)

});

/// A message to offer the collaborative (off-chain) closing of a DLC channel embedded within a
/// Lightning channel.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SubChannelCloseOffer {
    /// The id of the Lightning channel the message relates to.
    pub channel_id: [u8; 32],
    /// The balance proposed to the counter party.
    pub accept_balance: u64,
}

impl_dlc_writeable!(SubChannelCloseOffer, {
    (channel_id, writeable),
    (accept_balance, writeable)
});

/// A message to accept the collaborative closing of a DLC channel embedded within a Lightning
/// channel.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SubChannelCloseAccept {
    /// The id of the Lightning channel the message relates to.
    pub channel_id: [u8; 32],
    /// The signature for the new commitment transaction The signature for the new commitment
    /// transaction.
    pub commit_signature: Signature,
    /// The htlc signatures for the new commitment transactions.
    pub htlc_signatures: Vec<Signature>,
}

impl_dlc_writeable!(SubChannelCloseAccept, {
    (channel_id, writeable),
    (commit_signature, writeable),
    (htlc_signatures, writeable)
});

/// A message to confirm the collaborative closing of a DLC channel embedded within a Lightning
/// channel.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SubChannelCloseConfirm {
    /// The id of the Lightning channel the message relates to.
    pub channel_id: [u8; 32],
    /// The signature for the new commitment transaction The signature for the new commitment
    /// transaction.
    pub commit_signature: Signature,
    /// The htlc signatures for the new commitment transactions.
    pub htlc_signatures: Vec<Signature>,
    /// The pre-image of the split transaction revocation point.
    pub split_revocation_secret: SecretKey,
    /// The pre-image of the commit transaction revocation point.
    pub commit_revocation_secret: SecretKey,
    /// The point to be used for computing the revocation of the next commitment transaction.
    pub next_per_commitment_point: PublicKey,
}

impl_dlc_writeable!(SubChannelCloseConfirm, {
    (channel_id, writeable),
    (commit_signature, writeable),
    (htlc_signatures, writeable),
    (split_revocation_secret, writeable),
    (commit_revocation_secret, writeable),
    (next_per_commitment_point, writeable)
});

/// A message to finalize the collaborative closing of a DLC channel embedded within a  Lightning
/// channel.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SubChannelCloseFinalize {
    /// The id of the Lightning channel the message relates to.
    pub channel_id: [u8; 32],
    /// The pre-image of the split transaction revocation point.
    pub split_revocation_secret: SecretKey,
    /// The pre-image of the commit transaction revocation point.
    pub commit_revocation_secret: SecretKey,
    /// The point to be used for computing the revocation of the next commitment transaction.
    pub next_per_commitment_point: PublicKey,
}

impl_dlc_writeable!(SubChannelCloseFinalize, {
    (channel_id, writeable),
    (split_revocation_secret, writeable),
    (commit_revocation_secret, writeable),
    (next_per_commitment_point, writeable)
});

/// A message to reject an offer to collaboratively close a DLC channel embedded within a Lightning
/// channel.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct Reject {
    /// The id of the Lightning channel the message relates to.
    pub channel_id: [u8; 32],
}

impl_dlc_writeable!(Reject, { (channel_id, writeable) });
