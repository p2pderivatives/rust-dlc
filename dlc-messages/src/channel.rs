//!

use bitcoin::Script;
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::{EcdsaAdaptorSignature, PublicKey, SecretKey, Signature};

use crate::FundingSignatures;
use crate::{
    contract_msgs::ContractInfo,
    ser_impls::{read_ecdsa_adaptor_signature, write_ecdsa_adaptor_signature},
    CetAdaptorSignatures, FundingInput, NegotiationFields,
};

/// Contains information about a party wishing to enter into a DLC with
/// another party. The contained information is sufficient for any other party
/// to create a set of transactions representing the contract and its terms.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct OfferChannel {
    /// The version of the protocol used by the sending peer.
    pub protocol_version: u32,
    /// Indicates options and features selected for the offered contract.
    pub contract_flags: u8,
    /// The identifier of the chain on which the contract takes place.
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    pub chain_hash: [u8; 32],
    /// A random nonce identifying the contract until the fund transaction
    /// is created.
    pub temporary_contract_id: [u8; 32],
    /// A random nonce identifying the channel until the fund transaction is
    /// created.
    pub temporary_channel_id: [u8; 32],
    /// Information about the contract established during channel creation.
    pub contract_info: ContractInfo,
    /// The public key used by the offer party in the 2 of 2 funding output.
    pub funding_pubkey: PublicKey,
    /// The base point that will be used by the offer party for revocation.
    pub revocation_basepoint: PublicKey,
    /// The base point that will be used by the offer party for generating
    /// adaptor signatures to revocable transactions.
    pub publish_basepoint: PublicKey,
    /// The base point that will be used by the offer party in the 2 of 2 output
    /// of buffer transactions.
    pub own_basepoint: PublicKey,
    /// The first per update point of the offer party.
    pub first_per_update_point: PublicKey,
    /// Script used by the offer party to receive their payout on channel close.
    pub payout_spk: Script,
    /// Serial id used to order outputs.
    pub payout_serial_id: u64,
    /// The collateral input by the offer party in the channel.
    pub offer_collateral: u64,
    /// The inputs that the offer party will use to fund the channel.
    pub funding_inputs: Vec<FundingInput>,
    /// The script that the offer party to receive their change.
    pub change_spk: Script,
    /// Serial id used to order outputs.
    pub change_serial_id: u64,
    /// Serial id used to order outputs.
    pub fund_output_serial_id: u64,
    /// The fee rate proposed by the offer party for the channel transactions.
    pub fee_rate_per_vb: u64,
    /// Lock time for the CETs.
    pub cet_locktime: u32,
    /// Lock time for the refund transaction.
    pub refund_locktime: u32,
}

impl_dlc_writeable!(OfferChannel, {
        (protocol_version, writeable),
        (contract_flags, writeable),
        (chain_hash, writeable),
        (temporary_contract_id, writeable),
        (temporary_channel_id, writeable),
        (contract_info, writeable),
        (funding_pubkey, writeable),
        (revocation_basepoint, writeable),
        (publish_basepoint, writeable),
        (own_basepoint, writeable),
        (first_per_update_point, writeable),
        (payout_spk, writeable),
        (payout_serial_id, writeable),
        (offer_collateral, writeable),
        (funding_inputs, vec),
        (change_spk, writeable),
        (change_serial_id, writeable),
        (fund_output_serial_id, writeable),
        (fee_rate_per_vb, writeable),
        (cet_locktime, writeable),
        (refund_locktime, writeable)
});

/// Contains information about a party wishing to accept a DLC offer. The contained
/// information is sufficient for the offering party to re-build the set of
/// transactions representing the contract and its terms, and guarantees the offering
/// party that they can safely provide signatures for their funding input.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct AcceptChannel {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub temporary_channel_id: [u8; 32],
    ///
    pub accept_collateral: u64,
    ///
    pub funding_pubkey: PublicKey,
    ///
    pub revocation_basepoint: PublicKey,
    ///
    pub publish_basepoint: PublicKey,
    ///
    pub own_basepoint: PublicKey,
    ///
    pub first_per_update_point: PublicKey,
    ///
    pub payout_spk: Script,
    ///
    pub payout_serial_id: u64,
    ///
    pub funding_inputs: Vec<FundingInput>,
    ///
    pub change_spk: Script,
    ///
    pub change_serial_id: u64,
    ///
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    ///
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    ///
    pub refund_signature: Signature,
    ///
    pub negotiation_fields: Option<NegotiationFields>,
}

impl_dlc_writeable!(AcceptChannel, {
    (temporary_channel_id, writeable),
    (accept_collateral, writeable),
    (funding_pubkey, writeable),
    (revocation_basepoint, writeable),
    (publish_basepoint, writeable),
    (own_basepoint, writeable),
    (first_per_update_point, writeable),
    (payout_spk, writeable),
    (payout_serial_id, writeable),
    (funding_inputs, vec),
    (change_spk, writeable),
    (change_serial_id, writeable),
    (cet_adaptor_signatures, writeable),
    (buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (refund_signature, writeable),
    (negotiation_fields, option)
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct SignChannel {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub channel_id: [u8; 32],
    ///
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    ///
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    ///
    pub refund_signature: Signature,
    ///
    pub funding_signatures: FundingSignatures,
}

impl_dlc_writeable!(SignChannel, {
    (channel_id, writeable),
    (cet_adaptor_signatures, writeable),
    (buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (refund_signature, writeable),
    (funding_signatures, writeable)
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct SettleChannelOffer {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub channel_id: [u8; 32],
    ///
    pub counter_payout: u64,
    ///
    pub next_per_update_point: PublicKey,
}

impl_dlc_writeable!(SettleChannelOffer, {
    (channel_id, writeable),
    (counter_payout, writeable),
    (next_per_update_point, writeable)
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct SettleChannelAccept {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub channel_id: [u8; 32],
    ///
    pub next_per_update_point: PublicKey,
    ///
    pub settle_adaptor_signature: EcdsaAdaptorSignature,
}

impl_dlc_writeable!(SettleChannelAccept, {
    (channel_id, writeable),
    (next_per_update_point, writeable),
    (settle_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature})
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct SettleChannelConfirm {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub channel_id: [u8; 32],
    ///
    pub prev_per_update_secret: SecretKey,
    ///
    pub settle_adaptor_signature: EcdsaAdaptorSignature,
}

impl_dlc_writeable!(SettleChannelConfirm, {
    (channel_id, writeable),
    (prev_per_update_secret, writeable),
    (settle_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature})
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct SettleChannelFinalize {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub channel_id: [u8; 32],
    ///
    pub prev_per_update_secret: SecretKey,
}

impl_dlc_writeable!(SettleChannelFinalize, {
    (channel_id, writeable),
    (prev_per_update_secret, writeable)
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct RenewChannelOffer {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub channel_id: [u8; 32],
    ///
    pub temporary_contract_id: [u8; 32],
    ///
    pub counter_payout: u64,
    ///
    pub next_per_update_point: PublicKey,
    ///
    pub contract_info: ContractInfo,
    ///
    pub contract_maturity_bound: u32,
    ///
    pub contract_timeout: u32,
}

impl_dlc_writeable!(RenewChannelOffer, {
    (channel_id, writeable),
    (temporary_contract_id, writeable),
    (counter_payout, writeable),
    (next_per_update_point, writeable),
    (contract_info, writeable),
    (contract_maturity_bound, writeable),
    (contract_timeout, writeable)
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct RenewChannelAccept {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub channel_id: [u8; 32],
    ///
    pub next_per_update_point: PublicKey,
    ///
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    ///
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    ///
    pub refund_signature: Signature,
}

impl_dlc_writeable!(RenewChannelAccept, {
    (channel_id, writeable),
    (next_per_update_point, writeable),
    (buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (cet_adaptor_signatures, writeable),
    (refund_signature, writeable)
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct RenewChannelConfirm {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub channel_id: [u8; 32],
    ///
    pub per_update_secret: SecretKey,
    ///
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    ///
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    ///
    pub refund_signature: Signature,
}

impl_dlc_writeable!(RenewChannelConfirm, {
    (channel_id, writeable),
    (per_update_secret, writeable),
    (buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (cet_adaptor_signatures, writeable),
    (refund_signature, writeable)
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct RenewChannelFinalize {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub channel_id: [u8; 32],
    ///
    pub per_update_secret: SecretKey,
}

impl_dlc_writeable!(RenewChannelFinalize, {
    (channel_id, writeable),
    (per_update_secret, writeable)
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct CollaborativeCloseOffer {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    ///
    pub channel_id: [u8; 32],
    ///
    pub counter_payout: u64,
    ///
    pub close_signature: Signature,
}

impl_dlc_writeable!(CollaborativeCloseOffer, {
    (channel_id, writeable),
    (counter_payout, writeable),
    (close_signature, writeable)
});
