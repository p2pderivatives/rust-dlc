//! #SignedContract

use super::accepted_contract::AcceptedContract;
use dlc_messages::FundingSignatures;
use secp256k1::ecdsa_adaptor::{AdaptorProof, AdaptorSignature};
use secp256k1::Signature;

/// Contain information about a contract that was fully signed.
#[derive(Clone)]
pub struct SignedContract {
    /// The accepted contract that was signed.
    pub accepted_contract: AcceptedContract,
    /// The adaptor signatures of the offering party (None if offering party).
    pub adaptor_signatures: Option<Vec<(AdaptorSignature, AdaptorProof)>>,
    /// The refund signature of the offering party.
    pub offer_refund_signature: Signature,
    /// The signatures for the funding inputs of the offering party.
    pub funding_signatures: FundingSignatures,
}
