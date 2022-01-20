//! #

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
///
pub struct OfferedChannel {
    ///
    pub offered_contract_id: ContractId,
    ///
    pub temporary_channel_id: ChannelId,
    ///
    pub party_points: PartyBasePoints,
    ///
    pub per_update_point: PublicKey,
    ///
    pub offer_per_update_seed: Option<PublicKey>,
    ///
    pub is_offer_party: bool,
    ///
    pub counter_party: PublicKey,
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
            cet_locktime: offered_contract.contract_maturity_bound,
            refund_locktime: offered_contract.contract_timeout,
            fee_rate_per_vb: offered_contract.fee_rate_per_vb,
            fund_output_serial_id: offered_contract.fund_output_serial_id,
        }
    }

    ///
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
            contract_maturity_bound: offer_channel.cet_locktime,
            contract_timeout: offer_channel.refund_locktime,
            fee_rate_per_vb: offer_channel.fee_rate_per_vb,
            fund_output_serial_id: offer_channel.fund_output_serial_id,
            funding_inputs_info: offer_channel
                .funding_inputs
                .iter()
                .map(|x| x.into())
                .collect(),
            total_collateral: offer_channel.contract_info.get_total_collateral(),
        };

        Ok((channel, contract))
    }
}
