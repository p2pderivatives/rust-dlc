//! #SignedContract

use crate::ChannelId;

use super::accepted_contract::AcceptedContract;
use dlc_messages::CetAdaptorSignature;
use dlc_messages::CetAdaptorSignatures;
use dlc_messages::FundingSignatures;
use dlc_messages::SignDlc;
use secp256k1_zkp::EcdsaAdaptorSignature;
use secp256k1_zkp::Signature;

/// Contain information about a contract that was fully signed.
#[derive(Clone)]
pub struct SignedContract {
    /// The accepted contract that was signed.
    pub accepted_contract: AcceptedContract,
    /// The adaptor signatures of the offering party (None if offering party).
    pub adaptor_signatures: Option<Vec<EcdsaAdaptorSignature>>,
    /// The refund signature of the offering party.
    pub offer_refund_signature: Signature,
    /// The signatures for the funding inputs of the offering party.
    pub funding_signatures: FundingSignatures,
    ///
    pub channel_id: Option<ChannelId>,
}

impl SignedContract {
    pub(crate) fn get_sign_dlc(
        &self,
        cet_adaptor_signatures: Vec<EcdsaAdaptorSignature>,
    ) -> SignDlc {
        let contract_id = self.accepted_contract.get_contract_id();

        SignDlc {
            contract_id,
            cet_adaptor_signatures: CetAdaptorSignatures {
                ecdsa_adaptor_signatures: cet_adaptor_signatures
                    .into_iter()
                    .map(|x| CetAdaptorSignature { signature: x })
                    .collect(),
            },
            refund_signature: self.offer_refund_signature,
            funding_signatures: self.funding_signatures.clone(),
        }
    }
}
