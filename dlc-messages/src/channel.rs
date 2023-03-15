//! Contains messages used for the establishment and update of DLC channels.

use bitcoin::Script;
use dlc::Error;
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::{
    ecdsa::Signature, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey, Verification,
};

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
    /// The nSequence value to use for the CETs.
    pub cet_nsequence: u32,
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
        (refund_locktime, writeable),
        (cet_nsequence, writeable)
});

impl OfferChannel {
    /// Returns whether the message satisfies validity requirements.
    pub fn validate<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        min_timeout_interval: u32,
        max_timeout_interval: u32,
        min_cet_nsequence: u32,
        max_cet_nsequence: u32,
    ) -> Result<(), Error> {
        let closest_maturity_date = self.contract_info.get_closest_maturity_date();
        let valid_dates = self.cet_locktime <= closest_maturity_date
            && closest_maturity_date + min_timeout_interval <= self.refund_locktime
            && self.refund_locktime <= closest_maturity_date + max_timeout_interval
            && self.cet_nsequence >= min_cet_nsequence
            && self.cet_nsequence <= max_cet_nsequence;
        if !valid_dates {
            return Err(Error::InvalidArgument);
        }

        match &self.contract_info {
            ContractInfo::SingleContractInfo(s) => s.contract_info.oracle_info.validate(secp)?,
            ContractInfo::DisjointContractInfo(d) => {
                for c in &d.contract_infos {
                    c.oracle_info.validate(secp)?;
                }
            }
        }

        Ok(())
    }
}

/// Contains information about a party wishing to accept a DLC offer. The contained
/// information is sufficient for the offering party to re-build the set of
/// transactions representing the contract and its terms, and guarantees the offering
/// party that they can safely provide signatures for their funding input.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// The temporary id of the channel.
    pub temporary_channel_id: [u8; 32],
    /// The collateral input by the accept party.
    pub accept_collateral: u64,
    /// The [`PublicKey`] used for the fund output by the accept party.
    pub funding_pubkey: PublicKey,
    /// The [`PublicKey`] used for deriving revocation points by the accept party.
    pub revocation_basepoint: PublicKey,
    /// The [`PublicKey`] used for deriving publish points by the accept party.
    pub publish_basepoint: PublicKey,
    /// The [`PublicKey`] used for deriving own points by the accept party.
    pub own_basepoint: PublicKey,
    /// The initial per update point used by the accept party.
    pub first_per_update_point: PublicKey,
    /// The script pubkey for the accept party to receive their payout.
    pub payout_spk: Script,
    /// The serial id of the payout output used to order transaction outputs.
    pub payout_serial_id: u64,
    /// The set of inputs used by the accept party to fund the channel.
    pub funding_inputs: Vec<FundingInput>,
    /// The script pubkey used by the accept party to receive back their change.
    pub change_spk: Script,
    /// The serial id of the change output used to order transaction outputs.
    pub change_serial_id: u64,
    /// The adaptor signatures for all CETs generated by the accept party.
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    /// The adaptor signature for the buffer transaction generated by the accept
    /// party.
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    /// The refund signature generated by the accept party.
    pub refund_signature: Signature,
    /// Fields used to negotiate parameters with the counter party.
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Message used to finalize the setup of a DLC channel.
pub struct SignChannel {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
    /// The adaptor signatures for all CETs generated by the offer party.
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    /// The adaptor signature for the buffer transaction generated by the offer
    /// party.
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    /// The refund signature generated by the offer party.
    pub refund_signature: Signature,
    /// The signatures for the offer party's inputs.
    pub funding_signatures: FundingSignatures,
}

impl_dlc_writeable!(SignChannel, {
    (channel_id, writeable),
    (cet_adaptor_signatures, writeable),
    (buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (refund_signature, writeable),
    (funding_signatures, writeable)
});

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Message used to offer a settlement of the channel by on of the parties.
pub struct SettleOffer {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
    /// The payout offered to the receiving party.
    pub counter_payout: u64,
    /// The per update point to be used by the sending party to setup the next
    /// channel state.
    pub next_per_update_point: PublicKey,
}

impl_dlc_writeable!(SettleOffer, {
    (channel_id, writeable),
    (counter_payout, writeable),
    (next_per_update_point, writeable)
});

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Message used to accept a previously received settlement offer.
pub struct SettleAccept {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
    /// The per update point to be used by the sending party to setup the next
    /// channel state.
    pub next_per_update_point: PublicKey,
    /// The adaptor signature for the settle transaction generated by the sending
    /// party.
    pub settle_adaptor_signature: EcdsaAdaptorSignature,
}

impl_dlc_writeable!(SettleAccept, {
    (channel_id, writeable),
    (next_per_update_point, writeable),
    (settle_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature})
});

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Message used to confirm the settlement of a channel.
pub struct SettleConfirm {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
    /// The pre-image of the per update point used by the sending party during
    /// the establishment of the previous channel state.
    pub prev_per_update_secret: SecretKey,
    /// The adaptor signature for the settlement transaction generated by the
    /// sending party.
    pub settle_adaptor_signature: EcdsaAdaptorSignature,
}

impl_dlc_writeable!(SettleConfirm, {
    (channel_id, writeable),
    (prev_per_update_secret, writeable),
    (settle_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature})
});

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Message used to finalize the settlement of a channel.
pub struct SettleFinalize {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
    /// The pre-image of the per update point used by the sending party during
    /// the establishment of the previous channel state.
    pub prev_per_update_secret: SecretKey,
}

impl_dlc_writeable!(SettleFinalize, {
    (channel_id, writeable),
    (prev_per_update_secret, writeable)
});

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Message used to offer to establish a new contract within the channel.
pub struct RenewOffer {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
    /// The proposed payout for the receiving party for the previous channel
    /// state.
    pub counter_payout: u64,
    /// The per update point to be used by the sending party to setup the next
    /// channel state.
    pub next_per_update_point: PublicKey,
    /// Information about the offered contract.
    pub contract_info: ContractInfo,
    /// Lock time for the CETs.
    pub cet_locktime: u32,
    /// Lock time for the refund transaction.
    pub refund_locktime: u32,
    /// The nSequence value to use for the CETs.
    pub cet_nsequence: u32,
}

impl_dlc_writeable!(RenewOffer, {
    (channel_id, writeable),
    (counter_payout, writeable),
    (next_per_update_point, writeable),
    (contract_info, writeable),
    (cet_locktime, writeable),
    (refund_locktime, writeable),
    (cet_nsequence, writeable)
});

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Message used to accept the establishment of a new contract within a channel.
pub struct RenewAccept {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
    /// The per update point to be used by the sending party to setup the next
    /// channel state.
    pub next_per_update_point: PublicKey,
    /// The adaptor signature for the buffer transaction generated by the offer
    /// party.
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    /// The adaptor signatures for all CETs generated by the offer party.
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    /// The refund signature generated by the offer party.
    pub refund_signature: Signature,
}

impl_dlc_writeable!(RenewAccept, {
    (channel_id, writeable),
    (next_per_update_point, writeable),
    (buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (cet_adaptor_signatures, writeable),
    (refund_signature, writeable)
});

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Message used to confirm the establishment of a new contract within a channel.
pub struct RenewConfirm {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
    /// The pre image of the per update point used by the sending party to setup
    /// the previous channel state.
    pub per_update_secret: SecretKey,
    /// The adaptor signature for the buffer transaction generated by the offer
    /// party.
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    /// The adaptor signatures for all CETs generated by the offer party.
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    /// The refund signature generated by the offer party.
    pub refund_signature: Signature,
}

impl_dlc_writeable!(RenewConfirm, {
    (channel_id, writeable),
    (per_update_secret, writeable),
    (buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (cet_adaptor_signatures, writeable),
    (refund_signature, writeable)
});

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Message used to finalize the establishment of a new contract within a channel.
pub struct RenewFinalize {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
    /// The pre image of the per update point used by the sending party to setup
    /// the previous channel state.
    pub per_update_secret: SecretKey,
}

impl_dlc_writeable!(RenewFinalize, {
    (channel_id, writeable),
    (per_update_secret, writeable)
});

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// Message used to offer to collaboratively close a channel.
pub struct CollaborativeCloseOffer {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
    /// The proposed payout for the receiving party to close the channel with.
    pub counter_payout: u64,
    /// The signature of the sending party for the closing transaction.
    pub close_signature: Signature,
}

impl_dlc_writeable!(CollaborativeCloseOffer, {
    (channel_id, writeable),
    (counter_payout, writeable),
    (close_signature, writeable)
});

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]

/// Message used to reject an received offer.
pub struct Reject {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    /// The id of the channel referred to by the message.
    pub channel_id: [u8; 32],
}

impl_dlc_writeable!(Reject, { (channel_id, writeable) });
