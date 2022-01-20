//! #

use bitcoin::{Script, Transaction};
use dlc_messages::{channel::AcceptChannel, CetAdaptorSignature, CetAdaptorSignatures};
// use dlc_messages::{channel::AcceptChannel, CetAdaptorSignature, CetAdaptorSignatures};
use secp256k1_zkp::{EcdsaAdaptorSignature, PublicKey};

use crate::{contract::accepted_contract::AcceptedContract, ChannelId, ContractId};

use super::party_points::PartyBasePoints;

///
#[derive(Clone, Debug)]
pub struct AcceptedChannel {
    ///
    pub counter_party: PublicKey,
    ///
    pub accepted_contract_id: ContractId,
    ///
    pub offer_base_points: PartyBasePoints,
    ///
    pub accept_base_points: PartyBasePoints,
    ///
    pub offer_per_update_point: PublicKey,
    ///
    pub accept_per_update_point: PublicKey,
    ///
    pub buffer_transaction: Transaction,
    ///
    pub buffer_script_pubkey: Script,
    ///
    pub temporary_channel_id: ChannelId,
    ///
    pub channel_id: ChannelId,
    ///
    pub accept_per_update_seed: PublicKey,
    ///
    pub accept_buffer_adaptor_signature: EcdsaAdaptorSignature,
}

impl AcceptedChannel {
    pub(crate) fn get_accept_channel_msg(
        &self,
        contract: &AcceptedContract,
        buffer_adaptor_signature: &EcdsaAdaptorSignature,
        cet_adaptor_signatures: &[EcdsaAdaptorSignature],
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
            cet_adaptor_signatures: CetAdaptorSignatures {
                ecdsa_adaptor_signatures: cet_adaptor_signatures
                    .iter()
                    .map::<CetAdaptorSignature, _>(|x| CetAdaptorSignature { signature: *x })
                    .collect(),
            },
            refund_signature: contract.accept_refund_signature,
            negotiation_fields: None,
            revocation_basepoint: self.accept_base_points.revocation_basepoint,
            publish_basepoint: self.accept_base_points.publish_basepoint,
            own_basepoint: self.accept_base_points.own_basepoint,
            first_per_update_point: self.accept_per_update_point,
            buffer_adaptor_signature: *buffer_adaptor_signature,
        }
    }
}
