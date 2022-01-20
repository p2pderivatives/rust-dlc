//! #

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
pub(crate) mod utils;

///
#[derive(Clone)]
pub enum Channel {
    ///
    Offered(OfferedChannel),
    ///
    Accepted(AcceptedChannel),
    ///
    Signed(SignedChannel),
    ///
    FailedAccept(FailedAccept),
    ///
    FailedSign(FailedSign),
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            Channel::Offered(_) => "offered",
            Channel::Accepted(_) => "accepted",
            Channel::Signed(_) => "signed",
            Channel::FailedAccept(_) => "failed accept",
            Channel::FailedSign(_) => "failed sign",
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
        }
    }
}

// pub(crate) enum ChannelError {
//     Close(String),
//     Ignore(String),
// }

///
#[derive(Clone)]
pub struct FailedAccept {
    ///
    pub counter_party: PublicKey,
    ///
    pub temporary_channel_id: ChannelId,
    ///
    pub error_message: String,
    ///
    pub accept_message: AcceptChannel,
}

///
#[derive(Clone)]
pub struct FailedSign {
    ///
    pub counter_party: PublicKey,
    ///
    pub channel_id: ChannelId,
    ///
    pub error_message: String,
    ///
    pub sign_message: SignChannel,
}

impl Channel {
    ///
    pub fn get_temporary_id(&self) -> ChannelId {
        match self {
            Channel::Offered(o) => o.temporary_channel_id,
            Channel::Accepted(a) => a.temporary_channel_id,
            Channel::Signed(s) => s.temporary_channel_id,
            Channel::FailedAccept(f) => f.temporary_channel_id,
            _ => unimplemented!(),
        }
    }

    ///
    pub fn get_id(&self) -> ChannelId {
        match self {
            Channel::Offered(o) => o.temporary_channel_id,
            Channel::Accepted(a) => a.channel_id,
            Channel::Signed(s) => s.channel_id,
            Channel::FailedAccept(f) => f.temporary_channel_id,
            Channel::FailedSign(f) => f.channel_id,
        }
    }
}
