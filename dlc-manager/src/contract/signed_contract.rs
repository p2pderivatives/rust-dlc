//! #SignedContract

use crate::conversion_utils::PROTOCOL_VERSION;

use super::accepted_contract::AcceptedContract;
use dlc_messages::FundingSignatures;
use dlc_messages::SignDlc;

/// Contain information about a contract that was fully signed.
#[derive(Clone)]
pub struct SignedContract {
    /// The accepted contract that was signed.
    pub accepted_contract: AcceptedContract,
    /// The signatures for the funding inputs of the offering party.
    pub funding_signatures: FundingSignatures,
}

impl SignedContract {
    pub(crate) fn get_sign_dlc(&self) -> SignDlc {
        let contract_id = self.accepted_contract.get_contract_id();

        SignDlc {
            protocol_version: PROTOCOL_VERSION,
            contract_id,
            funding_signatures: self.funding_signatures.clone(),
        }
    }
}
