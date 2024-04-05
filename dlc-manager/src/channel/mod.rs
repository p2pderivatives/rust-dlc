//! # Module containing structures and methods for working with DLC channels.

use dlc_messages::channel::{AcceptChannel, SignChannel};
use secp256k1_zkp::PublicKey;

use crate::ChannelId;

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

impl Channel {
    /// Returns the temporary [`crate::ChannelId`] for the channel.
    pub fn get_temporary_id(&self) -> ChannelId {
        match self {
            Channel::Offered(o) => o.temporary_channel_id,
            Channel::Accepted(a) => a.temporary_channel_id,
            Channel::Signed(s) => s.temporary_channel_id,
            Channel::FailedAccept(f) => f.temporary_channel_id,
            Channel::Cancelled(o) => o.temporary_channel_id,
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
            Channel::Cancelled(o) => o.temporary_channel_id,
        }
    }
}
