//! # Module containing structures and methods for working with DLC channels.

use bitcoin::{hashes::Hash, Transaction, Txid};
use dlc_messages::channel::{AcceptChannel, SignChannel};
use secp256k1_zkp::PublicKey;

use crate::{ChannelId, ContractId};

use self::{
    accepted_channel::AcceptedChannel, offered_channel::OfferedChannel,
    signed_channel::SignedChannel,
};

pub mod accepted_channel;
pub mod offered_channel;
pub mod party_points;
pub mod ser;
pub mod signed_channel;
mod utils;

/// Enumeration containing the possible state a DLC channel can be in.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Channel {
    /// A channel that has been offered.
    Offered(OfferedChannel),
    /// A channel that has been accepted.
    Accepted(AcceptedChannel),
    /// A channel whose fund outputs have been signed by the offer party.
    Signed(SignedChannel),
    /// A channel that failed when validating an
    /// [`dlc_messages::channel::AcceptChannel`] message.
    FailedAccept(FailedAccept),
    /// A channel that failed when validating an
    /// [`dlc_messages::channel::SignChannel`] message.
    FailedSign(FailedSign),
    /// A [`OfferedChannel`] that got rejected by the counterparty.
    Cancelled(OfferedChannel),
    /// A [`Channel`] is in `Closing` state when the local party
    /// has broadcast a buffer transaction and is waiting to finalize the
    /// closing of the channel by broadcasting a CET.
    Closing(ClosingChannel),
    /// A [`Channel`] is in `Closed` state when it was force closed by
    /// the local party.
    Closed(ClosedChannel),
    /// A [`Channel`] is in `CounterClosed` state when it was force
    /// closed by the counter party.
    CounterClosed(ClosedChannel),
    /// A [`Channel`] is in `ClosedPunished` state when the local
    /// party broadcast a punishment transaction in response to the counter
    /// party broadcasting a settle or buffer transaction for a revoked channel
    /// state.
    ClosedPunished(ClosedPunishedChannel),
    /// A [`SignedChannel`] is in `CollaborativelyClosed` state when it was
    /// collaboratively closed.
    CollaborativelyClosed(ClosedChannel),
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            Channel::Offered(_) => "offered",
            Channel::Accepted(_) => "accepted",
            Channel::Signed(_) => "signed",
            Channel::FailedAccept(_) => "failed accept",
            Channel::FailedSign(_) => "failed sign",
            Channel::Cancelled(_) => "cancelled",
            Channel::Closing(_) => "closing",
            Channel::Closed(_) => "closed",
            Channel::CounterClosed(_) => "counter closed",
            Channel::ClosedPunished(_) => "closed punished",
            Channel::CollaborativelyClosed(_) => "collaboratively closed",
        };
        f.debug_struct("Contract").field("state", &state).finish()
    }
}

impl Channel {
    /// Returns the public key of the counter party's node.
    pub fn get_counter_party_id(&self) -> PublicKey {
        match self {
            Channel::Offered(o) => o.counter_party,
            Channel::Accepted(a) => a.counter_party,
            Channel::Signed(s) => s.counter_party,
            Channel::FailedAccept(f) => f.counter_party,
            Channel::FailedSign(f) => f.counter_party,
            Channel::Cancelled(o) => o.counter_party,
            Channel::Closing(c) => c.counter_party,
            Channel::Closed(c) | Channel::CounterClosed(c) | Channel::CollaborativelyClosed(c) => {
                c.counter_party
            }
            Channel::ClosedPunished(c) => c.counter_party,
        }
    }
}

/// A channel that failed when validating an
/// [`dlc_messages::channel::AcceptChannel`] message.
#[derive(Clone)]
pub struct FailedAccept {
    /// The [`secp256k1_zkp::PublicKey`] of the counter party.
    pub counter_party: PublicKey,
    /// The temporary [`crate::ChannelId`] of the channel.
    pub temporary_channel_id: ChannelId,
    /// An message describing the error encountered while validating the
    /// [`dlc_messages::channel::AcceptChannel`] message.
    pub error_message: String,
    /// The [`dlc_messages::channel::AcceptChannel`] that was received.
    pub accept_message: AcceptChannel,
}

/// A channel that failed when validating an
/// [`dlc_messages::channel::SignChannel`] message.
#[derive(Clone)]
pub struct FailedSign {
    /// The [`secp256k1_zkp::PublicKey`] of the counter party.
    pub counter_party: PublicKey,
    /// The [`crate::ChannelId`] of the channel.
    pub channel_id: ChannelId,
    /// An message describing the error encountered while validating the
    /// [`dlc_messages::channel::SignChannel`] message.
    pub error_message: String,
    /// The [`dlc_messages::channel::SignChannel`] that was received.
    pub sign_message: SignChannel,
}

#[derive(Clone)]
/// A channel is closing when its buffer transaction was broadcast or detected on chain.
pub struct ClosingChannel {
    /// The [`secp256k1_zkp::PublicKey`] of the counter party.
    pub counter_party: PublicKey,
    /// The temporary [`crate::ChannelId`] of the channel.
    pub temporary_channel_id: ChannelId,
    /// The [`crate::ChannelId`] for the channel.
    pub channel_id: ChannelId,
    /// The previous state the channel was before being closed, if that state was the `Signed` one,
    /// otherwise is `None`.
    pub rollback_state: Option<SignedChannel>,
    /// The buffer transaction that was broadcast.
    pub buffer_transaction: Transaction,
    /// The [`crate::ContractId`] of the contract that was used to close
    /// the channel.
    pub contract_id: ContractId,
    /// Whether the local party initiated the closing of the channel.
    pub is_closer: bool,
}

#[derive(Clone)]
/// A channel is closed when its buffer transaction has been spent.
pub struct ClosedChannel {
    /// The [`secp256k1_zkp::PublicKey`] of the counter party.
    pub counter_party: PublicKey,
    /// The temporary [`crate::ChannelId`] of the channel.
    pub temporary_channel_id: ChannelId,
    /// The [`crate::ChannelId`] for the channel.
    pub channel_id: ChannelId,
}

#[derive(Clone)]
/// A channel is closed punished when the counter party broadcast a revoked transaction triggering
/// the broadcast of a punishment transaction by the local party.
pub struct ClosedPunishedChannel {
    /// The [`secp256k1_zkp::PublicKey`] of the counter party.
    pub counter_party: PublicKey,
    /// The temporary [`crate::ChannelId`] of the channel.
    pub temporary_channel_id: ChannelId,
    /// The [`crate::ChannelId`] for the channel.
    pub channel_id: ChannelId,
    /// The transaction id of the punishment transaction that was broadcast.
    pub punish_txid: Txid,
}

impl Channel {
    /// Returns the temporary [`crate::ChannelId`] for the channel.
    pub fn get_temporary_id(&self) -> ChannelId {
        match self {
            Channel::Offered(o) => o.temporary_channel_id,
            Channel::Accepted(a) => a.temporary_channel_id,
            Channel::Signed(s) => s.temporary_channel_id,
            Channel::FailedAccept(f) => f.temporary_channel_id,
            Channel::Closed(c) | Channel::CounterClosed(c) | Channel::CollaborativelyClosed(c) => {
                c.temporary_channel_id
            }
            Channel::ClosedPunished(c) => c.temporary_channel_id,
            _ => unimplemented!(),
        }
    }

    /// Returns the [`crate::ChannelId`] for the channel.
    pub fn get_id(&self) -> ChannelId {
        match self {
            Channel::Offered(o) => o.temporary_channel_id,
            Channel::Accepted(a) => a.channel_id,
            Channel::Signed(s) => s.channel_id,
            Channel::FailedAccept(f) => f.temporary_channel_id,
            Channel::FailedSign(f) => f.channel_id,
            Channel::Closing(c) => c.channel_id,
            Channel::Closed(c) | Channel::CounterClosed(c) | Channel::CollaborativelyClosed(c) => {
                c.channel_id
            }
            Channel::ClosedPunished(c) => c.channel_id,
            Channel::Cancelled(c) => c.temporary_channel_id,
        }
    }

    /// Returns the contract id associated with the channel if in a state where a contract is set.
    pub fn get_contract_id(&self) -> Option<ContractId> {
        match self {
            Channel::Offered(o) => Some(o.offered_contract_id),
            Channel::Accepted(a) => Some(a.accepted_contract_id),
            Channel::Signed(s) => s.get_contract_id(),
            Channel::FailedAccept(_) => None,
            Channel::FailedSign(_) => None,
            _ => None,
        }
    }
}

/// Generate a temporary contract id for a DLC based on the channel id and the update index of the DLC channel.
pub fn generate_temporary_contract_id(
    channel_id: ChannelId,
    channel_update_idx: u64,
) -> ContractId {
    let mut data = Vec::with_capacity(65);
    data.extend_from_slice(&channel_id);
    data.extend_from_slice(&channel_update_idx.to_be_bytes());
    bitcoin::hashes::sha256::Hash::hash(&data).to_byte_array()
}
