//! Module containing structures and functions related to contracts.

use crate::error::Error;
use crate::ContractId;
use bitcoin::{Address, Transaction};
use dlc_messages::{
    oracle_msgs::{EventDescriptor, OracleAnnouncement, OracleAttestation},
    AcceptDlc, FundingInput, SignDlc,
};
use dlc_trie::multi_oracle_trie::MultiOracleTrie;
use dlc_trie::multi_oracle_trie_with_diff::MultiOracleTrieWithDiff;
use secp256k1_zkp::PublicKey;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use signed_contract::SignedContract;

use self::utils::unordered_equal;

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
    /// A contract for which a CET was broadcasted, but not neccesarily confirmed to blockchain
    PreClosed(PreClosedContract),
    /// A contract for which a CET was confirmed to blockchain
    Closed(ClosedContract),
    /// A contract whose refund transaction was broadcast.
    Refunded(signed_contract::SignedContract),
    /// A contract that failed when verifying information from an accept message.
    FailedAccept(FailedAcceptContract),
    /// A contract that failed when verifying information from a sign message.
    FailedSign(FailedSignContract),
    /// A contract that was rejected by the party to whom it was offered.
    Rejected(offered_contract::OfferedContract),
}

impl std::fmt::Debug for Contract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            Contract::Offered(_) => "offered",
            Contract::Accepted(_) => "accepted",
            Contract::Signed(_) => "signed",
            Contract::Confirmed(_) => "confirmed",
            Contract::PreClosed(_) => "pre-closed",
            Contract::Closed(_) => "closed",
            Contract::Refunded(_) => "refunded",
            Contract::FailedAccept(_) => "failed accept",
            Contract::FailedSign(_) => "failed sign",
            Contract::Rejected(_) => "rejected",
        };
        f.debug_struct("Contract").field("state", &state).finish()
    }
}

impl Contract {
    /// Get the id of a contract. Returns the temporary contract id for offered
    /// and failed accept contracts.
    pub fn get_id(&self) -> ContractId {
        match self {
            Contract::Offered(o) | Contract::Rejected(o) => o.id,
            Contract::Accepted(o) => o.get_contract_id(),
            Contract::Signed(o) | Contract::Confirmed(o) | Contract::Refunded(o) => {
                o.accepted_contract.get_contract_id()
            }
            Contract::FailedAccept(c) => c.offered_contract.id,
            Contract::FailedSign(c) => c.accepted_contract.get_contract_id(),
            Contract::PreClosed(c) => c.signed_contract.accepted_contract.get_contract_id(),
            Contract::Closed(c) => c.contract_id,
        }
    }

    /// Returns the temporary contract id of a contract.
    pub fn get_temporary_id(&self) -> ContractId {
        match self {
            Contract::Offered(o) | Contract::Rejected(o) => o.id,
            Contract::Accepted(o) => o.offered_contract.id,
            Contract::Signed(o) | Contract::Confirmed(o) | Contract::Refunded(o) => {
                o.accepted_contract.offered_contract.id
            }
            Contract::FailedAccept(c) => c.offered_contract.id,
            Contract::FailedSign(c) => c.accepted_contract.offered_contract.id,
            Contract::PreClosed(c) => c.signed_contract.accepted_contract.offered_contract.id,
            Contract::Closed(c) => c.temporary_contract_id,
        }
    }

    /// Returns the public key of the counter party's node.
    pub fn get_counter_party_id(&self) -> PublicKey {
        match self {
            Contract::Offered(o) | Contract::Rejected(o) => o.counter_party,
            Contract::Accepted(a) => a.offered_contract.counter_party,
            Contract::Signed(s) | Contract::Confirmed(s) | Contract::Refunded(s) => {
                s.accepted_contract.offered_contract.counter_party
            }
            Contract::PreClosed(c) => {
                c.signed_contract
                    .accepted_contract
                    .offered_contract
                    .counter_party
            }
            Contract::Closed(c) => c.counter_party_id,
            Contract::FailedAccept(f) => f.offered_contract.counter_party,
            Contract::FailedSign(f) => f.accepted_contract.offered_contract.counter_party,
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

/// Information about a contract that is almost closed by a broadcasted, but not confirmed CET.
#[derive(Clone)]
pub struct PreClosedContract {
    /// The signed contract that was closed.
    pub signed_contract: SignedContract,
    /// The attestations that were used to decrypt the broadcast CET.
    pub attestations: Option<Vec<OracleAttestation>>,
    /// The signed version of the CET that was broadcast.
    pub signed_cet: Transaction,
}

/// Information about a contract that was closed by a CET that was confirmed on the blockchain.
#[derive(Clone)]
pub struct ClosedContract {
    /// The attestations that were used to decrypt the broadcast CET.
    pub attestations: Option<Vec<OracleAttestation>>,
    /// The signed version of the CET that was broadcast.
    pub signed_cet: Option<Transaction>,
    /// The id of the contract
    pub contract_id: ContractId,
    /// The temporary id of the contract.
    pub temporary_contract_id: ContractId,
    /// The public key of the counter-party's node.
    pub counter_party_id: PublicKey,
    /// The profit and loss for the given contract
    pub pnl: i64,
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

    /// Validate that all possible outcomes that can be attested by the oracle(s)
    /// have a single associated payout.
    pub fn validate(
        &self,
        announcements: &Vec<OracleAnnouncement>,
    ) -> Result<(), crate::error::Error> {
        let first = announcements
            .first()
            .expect("to have at least one element.");
        match &first.oracle_event.event_descriptor {
            EventDescriptor::EnumEvent(ee) => {
                for announcement in announcements {
                    match &announcement.oracle_event.event_descriptor {
                        EventDescriptor::EnumEvent(enum_desc) => {
                            if !unordered_equal(&ee.outcomes, &enum_desc.outcomes) {
                                return Err(Error::InvalidParameters(
                                    "Oracles don't have same enum outcomes.".to_string(),
                                ));
                            }
                        }
                        _ => {
                            return Err(Error::InvalidParameters(
                                "Expected enum event descriptor.".to_string(),
                            ))
                        }
                    }
                }
                match self {
                    ContractDescriptor::Enum(ed) => ed.validate(ee),
                    _ => Err(Error::InvalidParameters(
                        "Event descriptor from contract and oracle differ.".to_string(),
                    )),
                }
            }
            EventDescriptor::DigitDecompositionEvent(_) => match self {
                ContractDescriptor::Numerical(n) => {
                    let min_nb_digits = n.oracle_numeric_infos.get_min_nb_digits();
                    let max_value = n
                        .oracle_numeric_infos
                        .base
                        .checked_pow(min_nb_digits as u32)
                        .ok_or_else(|| {
                            Error::InvalidParameters("Could not compute max value".to_string())
                        })?;
                    n.validate((max_value - 1) as u64)
                }
                _ => Err(Error::InvalidParameters(
                    "Event descriptor from contract and oracle differ.".to_string(),
                )),
            },
        }
    }
}
