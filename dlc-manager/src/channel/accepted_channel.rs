//! # Structure and methods for channels that have been accepted.

use bitcoin::{Script, Transaction};
use dlc_messages::channel::AcceptChannel;
use secp256k1_zkp::{EcdsaAdaptorSignature, PublicKey};

use crate::{contract::accepted_contract::AcceptedContract, ContractId, DlcChannelId, ReferenceId};

use super::party_points::PartyBasePoints;

/// A [`super::Channel`] is in `Accepted` state when the accept party
/// accepts the [`super::offered_channel::OfferedChannel`].
#[derive(Clone, Debug)]
pub struct AcceptedChannel {
    /// The [`secp256k1_zkp::PublicKey`] of the node of the offer party.
    pub counter_party: PublicKey,
    /// The id of the initial contract in the channel.
    pub accepted_contract_id: ContractId,
    /// The set of [`super::party_points::PartyBasePoints`] that will be used by
    /// the offer party throughout the lifetime of the channel.
    pub offer_base_points: PartyBasePoints,
    /// The set of [`super::party_points::PartyBasePoints`] that will be used by
    /// the accept party throughout the lifetime of the channel.
    pub accept_base_points: PartyBasePoints,
    /// The initial per update point of the offer party.
    pub offer_per_update_point: PublicKey,
    /// The initial per update point of the accept party.
    pub accept_per_update_point: PublicKey,
    /// The buffer transaction for the initial contract in the channel.
    pub buffer_transaction: Transaction,
    /// The script pubkey of the buffer transaction output.
    pub buffer_script_pubkey: Script,
    /// The temporary id of the channel.
    pub temporary_channel_id: DlcChannelId,
    /// The actual id of the channel.
    pub channel_id: DlcChannelId,
    /// The image of the per update seed used by the accept party.
    pub accept_per_update_seed: PublicKey,
    /// The accept party adaptor signature for the buffer transaction.
    pub accept_buffer_adaptor_signature: EcdsaAdaptorSignature,
    /// The reference id set by the api user.
    pub reference_id: Option<ReferenceId>
}

impl AcceptedChannel {
    pub(crate) fn get_accept_channel_msg(
        &self,
        contract: &AcceptedContract,
        buffer_adaptor_signature: &EcdsaAdaptorSignature,
        cet_adaptor_signatures: &[EcdsaAdaptorSignature],
        reference_id: Option<ReferenceId>,
    ) -> AcceptChannel {
        AcceptChannel {
            temporary_channel_id: self.temporary_channel_id,
            accept_collateral: contract.accept_params.collateral,
            funding_pubkey: contract.accept_params.fund_pubkey,
            payout_spk: contract.accept_params.payout_script_pubkey.clone(),
            payout_serial_id: contract.accept_params.payout_serial_id,
            funding_inputs: contract.funding_inputs.iter().map(|x| x.into()).collect(),
            change_spk: contract.accept_params.change_script_pubkey.clone(),
            change_serial_id: contract.accept_params.change_serial_id,
            cet_adaptor_signatures: cet_adaptor_signatures.into(),
            refund_signature: contract.accept_refund_signature,
            negotiation_fields: None,
            revocation_basepoint: self.accept_base_points.revocation_basepoint,
            publish_basepoint: self.accept_base_points.publish_basepoint,
            own_basepoint: self.accept_base_points.own_basepoint,
            first_per_update_point: self.accept_per_update_point,
            buffer_adaptor_signature: *buffer_adaptor_signature,
            reference_id
        }
    }
}
