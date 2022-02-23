//! Module containing structures and functions related to contracts.

use crate::ContractId;
use bitcoin::{Address, Transaction};
use dlc_messages::{oracle_msgs::OracleAttestation, AcceptDlc, FundingInput, SignDlc};
use dlc_trie::multi_oracle_trie::MultiOracleTrie;
use dlc_trie::multi_oracle_trie_with_diff::MultiOracleTrieWithDiff;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use signed_contract::SignedContract;

pub mod accepted_contract;
pub mod contract_info;
pub mod contract_input;
pub mod enum_descriptor;
pub mod numerical_descriptor;
pub mod offered_contract;
pub mod ser;
pub mod signed_contract;
pub(crate) mod utils;

#[derive(Clone)]
/// Enum representing the possible states of a DLC.
pub enum Contract {
    /// Initial state where a contract is being proposed.
    Offered(offered_contract::OfferedContract),
    /// A contract that was accepted.
    Accepted(accepted_contract::AcceptedContract),
    /// A contract for which signatures have been produced.
    Signed(signed_contract::SignedContract),
    /// A contract whose funding transaction was included in the blockchain.
    Confirmed(signed_contract::SignedContract),
    /// A contract for which a CET was broadcast.
    Closed(ClosedContract),
    /// A contract whose refund transaction was broadcast.
    Refunded(signed_contract::SignedContract),
    /// A contract that failed when verifying information from an accept message.
    FailedAccept(FailedAcceptContract),
    /// A contract that failed when verifying information from a sign message.
    FailedSign(FailedSignContract),
}

impl std::fmt::Debug for Contract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            Contract::Offered(_) => "offered",
            Contract::Accepted(_) => "accepted",
            Contract::Signed(_) => "signed",
            Contract::Confirmed(_) => "confirmed",
            Contract::Closed(_) => "closed",
            Contract::Refunded(_) => "refunded",
            Contract::FailedAccept(_) => "failed accept",
            Contract::FailedSign(_) => "failed sign",
        };
        f.debug_struct("Contract").field("state", &state).finish()
    }
}

impl Contract {
    /// Get the id of a contract. Returns the temporary contract id for offered
    /// and failed accept contracts.
    pub fn get_id(&self) -> ContractId {
        match self {
            Contract::Offered(o) => o.id,
            Contract::Accepted(o) => o.get_contract_id(),
            Contract::Signed(o) | Contract::Confirmed(o) | Contract::Refunded(o) => {
                o.accepted_contract.get_contract_id()
            }
            Contract::FailedAccept(c) => c.offered_contract.id,
            Contract::FailedSign(c) => c.accepted_contract.get_contract_id(),
            Contract::Closed(c) => c.signed_contract.accepted_contract.get_contract_id(),
        }
    }

    /// Returns the temporary contract id of a contract.
    pub fn get_temporary_id(&self) -> ContractId {
        match self {
            Contract::Offered(o) => o.id,
            Contract::Accepted(o) => o.offered_contract.id,
            Contract::Signed(o) | Contract::Confirmed(o) | Contract::Refunded(o) => {
                o.accepted_contract.offered_contract.id
            }
            Contract::FailedAccept(c) => c.offered_contract.id,
            Contract::FailedSign(c) => c.accepted_contract.offered_contract.id,
            Contract::Closed(c) => c.signed_contract.accepted_contract.offered_contract.id,
        }
    }
}

/// Information about a funding input.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct FundingInputInfo {
    /// The funding input as used in messages.
    pub funding_input: FundingInput,
    /// The address corresponding to the input if it belongs to us.
    pub address: Option<Address>,
}

/// Information about a contract that failed while verifying an accept message.
#[derive(Clone)]
pub struct FailedAcceptContract {
    /// The offered contract that was accepted.
    pub offered_contract: offered_contract::OfferedContract,
    /// The received accept message.
    pub accept_message: AcceptDlc,
    /// The error message that was generated.
    pub error_message: String,
}

/// Information about a contract that failed while verifying a sign message.
#[derive(Clone)]
pub struct FailedSignContract {
    /// The accepted contract that was signed.
    pub accepted_contract: accepted_contract::AcceptedContract,
    /// The sign message that was received.
    pub sign_message: SignDlc,
    /// The error message that was generated.
    pub error_message: String,
}

#[derive(Clone)]
/// Information about a contract that was closed by broadcasting a CET.
pub struct ClosedContract {
    /// The signed contract that was closed.
    pub signed_contract: SignedContract,
    /// The attestations that were used to decrypt the broadcast CET.
    pub attestations: Vec<OracleAttestation>,
    /// The signed version of the CET that was broadcast.
    pub signed_cet: Transaction,
}

/// Information about the adaptor signatures and the CET for which they are
/// valid.
#[derive(Clone)]
pub enum AdaptorInfo {
    /// For enumeration outcome DLC, no special information needs to be kept.
    Enum,
    /// For numerical outcome DLC, a trie is used to store the information.
    Numerical(MultiOracleTrie),
    /// For numerical outcome DLC where oracles are allowed to diverge to some
    /// extent in the outcome value, a trie of trie is used to store the information.
    NumericalWithDifference(MultiOracleTrieWithDiff),
}

/// The descriptor of a contract.
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum ContractDescriptor {
    /// Case for enumeration outcome DLC.
    Enum(enum_descriptor::EnumDescriptor),
    /// Case for numerical outcome DLC.
    Numerical(numerical_descriptor::NumericalDescriptor),
}

impl ContractDescriptor {
    /// Get the parameters on allowed divergence between oracle if any.
    pub fn get_oracle_params(&self) -> Option<numerical_descriptor::DifferenceParams> {
        match self {
            ContractDescriptor::Enum(_) => None,
            ContractDescriptor::Numerical(n) => n.difference_params.clone(),
        }
    }
}
