//! # A channel is offered when an offer was made or received. This module contains
//! the model for it and method for working with it.

use dlc::PartyParams;
use dlc_messages::channel::OfferChannel;
// use dlc_messages::channel::OfferChannel;
use secp256k1_zkp::PublicKey;

use crate::{
    contract::offered_contract::OfferedContract, conversion_utils::get_tx_input_infos,
    error::Error, ChannelId, ContractId,
};

use super::party_points::PartyBasePoints;

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
/// A DLC channel for which an [`dlc_messages::channel::OfferChannel`] message
/// was sent or received.
pub struct OfferedChannel {
    /// The temporary [`crate::ContractId`] of the contract that was offered for
    /// channel setup.
    pub offered_contract_id: ContractId,
    /// The temporary [`crate::ChannelId`] of the channel.
    pub temporary_channel_id: ChannelId,
    /// The set of base points that the offer party will use during the lifetime
    /// of the channel.
    pub party_points: PartyBasePoints,
    /// The per update point for the initial establishment of the channel.
    pub per_update_point: PublicKey,
    /// The image of the seed used by the offer party to derive all per update
    /// points (Will be `None` on the accept party side.)
    pub offer_per_update_seed: Option<PublicKey>,
    /// Whether the local party is the offer party or not.
    pub is_offer_party: bool,
    /// The [`secp256k1_zkp::PublicKey`] of the counter party's node.
    pub counter_party: PublicKey,
    /// The nSequence value to use for the CETs.
    pub cet_nsequence: u32,
}

impl OfferedChannel {
    pub(crate) fn get_offer_channel_msg(&self, offered_contract: &OfferedContract) -> OfferChannel {
        let party_points = &self.party_points;
        OfferChannel {
            protocol_version: crate::conversion_utils::PROTOCOL_VERSION,
            contract_flags: 0,
            chain_hash: crate::conversion_utils::BITCOIN_CHAINHASH,
            temporary_contract_id: offered_contract.id,
            temporary_channel_id: self.temporary_channel_id,
            contract_info: offered_contract.into(),
            funding_pubkey: offered_contract.offer_params.fund_pubkey,
            revocation_basepoint: party_points.revocation_basepoint,
            publish_basepoint: party_points.publish_basepoint,
            own_basepoint: party_points.own_basepoint,
            first_per_update_point: self.per_update_point,
            payout_spk: offered_contract.offer_params.payout_script_pubkey.clone(),
            payout_serial_id: offered_contract.offer_params.payout_serial_id,
            offer_collateral: offered_contract.offer_params.collateral,
            funding_inputs: offered_contract
                .funding_inputs_info
                .iter()
                .map(|x| x.into())
                .collect(),
            change_spk: offered_contract.offer_params.change_script_pubkey.clone(),
            change_serial_id: offered_contract.offer_params.change_serial_id,
            cet_locktime: offered_contract.cet_locktime,
            refund_locktime: offered_contract.refund_locktime,
            fee_rate_per_vb: offered_contract.fee_rate_per_vb,
            fund_output_serial_id: offered_contract.fund_output_serial_id,
            cet_nsequence: crate::manager::CET_NSEQUENCE,
        }
    }

    /// Creates an [`OfferedChannel`] and [`crate::contract::offered_contract::OfferedContract`]
    /// from an [`dlc_messages::channel::OfferChannel`] message. Fails if the
    /// transactions provided for funding cannot be decoded or the UTXO information
    /// are invalid, or if the contract information is invalid.
    pub fn from_offer_channel(
        offer_channel: &OfferChannel,
        counter_party: PublicKey,
    ) -> Result<(OfferedChannel, OfferedContract), Error> {
        let channel = OfferedChannel {
            offered_contract_id: offer_channel.temporary_contract_id,
            temporary_channel_id: offer_channel.temporary_channel_id,
            party_points: PartyBasePoints {
                own_basepoint: offer_channel.own_basepoint,
                revocation_basepoint: offer_channel.revocation_basepoint,
                publish_basepoint: offer_channel.publish_basepoint,
            },
            per_update_point: offer_channel.first_per_update_point,
            offer_per_update_seed: None,
            is_offer_party: false,
            counter_party,
            cet_nsequence: offer_channel.cet_nsequence,
        };

        let (inputs, input_amount) = get_tx_input_infos(&offer_channel.funding_inputs)?;

        let contract = OfferedContract {
            id: offer_channel.temporary_contract_id,
            is_offer_party: false,
            contract_info: crate::conversion_utils::get_contract_info_and_announcements(
                &offer_channel.contract_info,
            )?,
            counter_party,
            offer_params: PartyParams {
                fund_pubkey: offer_channel.funding_pubkey,
                change_script_pubkey: offer_channel.change_spk.clone(),
                change_serial_id: offer_channel.change_serial_id,
                payout_script_pubkey: offer_channel.payout_spk.clone(),
                payout_serial_id: offer_channel.payout_serial_id,
                collateral: offer_channel.offer_collateral,
                inputs,
                input_amount,
            },
            cet_locktime: offer_channel.cet_locktime,
            refund_locktime: offer_channel.refund_locktime,
            fee_rate_per_vb: offer_channel.fee_rate_per_vb,
            fund_output_serial_id: offer_channel.fund_output_serial_id,
            funding_inputs_info: offer_channel
                .funding_inputs
                .iter()
                .map(|x| x.into())
                .collect(),
            total_collateral: offer_channel.contract_info.get_total_collateral(),
            fee_percentage_denominator: 0,
            fee_address: "".to_string(),
        };

        Ok((channel, contract))
    }
}
