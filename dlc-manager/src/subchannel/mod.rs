//! # Module containing structures and methods for working with DLC channels embedded in Lightning
//! channels.

use std::ops::Deref;

use bitcoin::{hashes::Hash, OutPoint, Script, Transaction, Txid};
use dlc::channel::sub_channel::SplitTx;
use lightning::{
    chain::{
        chaininterface::{BroadcasterInterface, FeeEstimator},
        keysinterface::KeysInterface,
    },
    ln::{
        chan_utils::CounterpartyCommitmentSecrets,
        channelmanager::{ChannelDetails, ChannelManager},
        msgs::{CommitmentSigned, RevokeAndACK},
    },
    util::logger::Logger,
};
use secp256k1_zkp::{ecdsa::Signature, EcdsaAdaptorSignature, PublicKey, SecretKey};

use crate::{channel::party_points::PartyBasePoints, error::Error, ChannelId, ContractId};

pub mod ser;

#[derive(Clone)]
/// Contains information about a DLC channel embedded within a Lightning Network Channel.
pub struct SubChannel {
    /// The index for the channel.
    pub channel_id: ChannelId,
    /// The [`secp256k1_zkp::PublicKey`] of the counter party's node.
    pub counter_party: PublicKey,
    /// The update index of the sub channel.
    pub update_idx: u64,
    /// The state of the sub channel.
    pub state: SubChannelState,
    /// The image of the seed used by the local party to derive all per update
    /// points (Will be `None` on the accept party side before the sub channel is accepted.)
    pub per_split_seed: Option<PublicKey>,
    /// The current fee rate to be used to create transactions.
    pub fee_rate_per_vb: u64,
    /// The points used by the local party to derive revocation secrets for the split transaction.
    pub own_base_points: PartyBasePoints,
    /// The points used by the remote party to derive revocation secrets for the split transaction.
    pub counter_base_points: Option<PartyBasePoints>,
    /// The value of the original funding output.
    pub fund_value_satoshis: u64,
    /// The locking script of the original funding output.
    pub original_funding_redeemscript: Script,
    /// Whether the local party is the one who offered the sub channel.
    pub is_offer: bool,
    /// The public key used by the local party for the funding output script.
    pub own_fund_pk: PublicKey,
    /// The public key used by the remote party for the funding output script.
    pub counter_fund_pk: PublicKey,
    /// The revocation secrets from the remote party for already revoked split transactions.
    pub counter_party_secrets: CounterpartyCommitmentSecrets,
}

impl std::fmt::Debug for SubChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubChannel")
            .field("channel_id", &self.channel_id)
            .field("state", &self.state)
            .finish()
    }
}

impl SubChannel {
    /// Return the channel ID of the DLC channel at given index if in a state where such a channel
    /// is supposed to exist.
    pub fn get_dlc_channel_id(&self, index: u8) -> Option<ChannelId> {
        let temporary_channel_id =
            generate_temporary_channel_id(self.channel_id, self.update_idx, index);
        match &self.state {
            SubChannelState::Offered(_) => Some(temporary_channel_id),
            SubChannelState::Accepted(a) => Some(a.get_dlc_channel_id(temporary_channel_id, index)),
            SubChannelState::Signed(s) => Some(s.get_dlc_channel_id(temporary_channel_id, index)),
            SubChannelState::Closing(c) => Some(
                c.signed_sub_channel
                    .get_dlc_channel_id(temporary_channel_id, index),
            ),
            SubChannelState::CloseOffered(c) => Some(
                c.signed_subchannel
                    .get_dlc_channel_id(temporary_channel_id, index),
            ),
            SubChannelState::CloseAccepted(c) => Some(
                c.signed_subchannel
                    .get_dlc_channel_id(temporary_channel_id, index),
            ),
            SubChannelState::CloseConfirmed(c) => Some(
                c.signed_subchannel
                    .get_dlc_channel_id(temporary_channel_id, index),
            ),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
/// Represents the state of a [`SubChannel`].
pub enum SubChannelState {
    /// The sub channel was offered (sent or received).
    Offered(OfferedSubChannel),
    /// The sub channel was accepted.
    Accepted(AcceptedSubChannel),
    /// The sub channel transactions have been signed.
    Signed(SignedSubChannel),
    /// The sub channel is closing.
    Closing(ClosingSubChannel),
    /// The sub channel has been closed on chain by the local party.
    OnChainClosed,
    /// The sub channel has been closed on chain by the remote party.
    CounterOnChainClosed,
    /// An offer to collaboratively close the sub channel has been made.
    CloseOffered(CloseOfferedSubChannel),
    /// An offer to collaboratively close the sub channel was accepted.
    CloseAccepted(CloseAcceptedSubChannel),
    /// An offer to collaboratively close the sub channel was confirmed.
    CloseConfirmed(CloseConfirmedSubChannel),
    /// The sub channel was closed off chain (reverted to a regular LN channel).
    OffChainClosed,
    /// The sub channel was closed by broadcasting a punishment transaction.
    ClosedPunished(Txid),
}

#[derive(Debug, Clone)]
/// Information about an offer to set up a sub channel.
pub struct OfferedSubChannel {
    /// The current per update point of the local party.
    pub per_split_point: PublicKey,
}

#[derive(Debug, Clone)]
/// Information about a sub channel that is in the accepted state.
pub struct AcceptedSubChannel {
    /// The current per split point of the offer party.
    pub offer_per_split_point: PublicKey,
    /// The current per split point of the accept party.
    pub accept_per_split_point: PublicKey,
    /// The adaptor signature of the accepting party for the split transaction.
    pub accept_split_adaptor_signature: EcdsaAdaptorSignature,
    /// Information about the split transaction for the sub channel.
    pub split_tx: SplitTx,
    /// Glue transaction that bridges the split transaction to the Lightning sub channel.
    pub ln_glue_transaction: Transaction,
}

impl AcceptedSubChannel {
    fn get_dlc_channel_id(&self, temporary_channel_id: ChannelId, channel_idx: u8) -> ChannelId {
        crate::utils::compute_id(
            self.split_tx.transaction.txid(),
            channel_idx as u16 + 1,
            &temporary_channel_id,
        )
    }
}

#[derive(Debug, Clone)]
/// Information about a sub channel whose transactions have been signed.
pub struct SignedSubChannel {
    /// The current per split point of the local party.
    pub own_per_split_point: PublicKey,
    /// The current per split point of the remote party.
    pub counter_per_split_point: PublicKey,
    /// Adaptor signature of the local party for the split transaction.
    pub own_split_adaptor_signature: EcdsaAdaptorSignature,
    /// Adaptor signature of the remote party for the split transaction.
    pub counter_split_adaptor_signature: EcdsaAdaptorSignature,
    /// Information about the split transaction for the sub channel.
    pub split_tx: SplitTx,
    /// Glue transaction that bridges the split transaction to the Lightning sub channel.
    pub ln_glue_transaction: Transaction,
    /// Signature of the remote party for the glue transaction.
    pub counter_glue_signature: Signature,
}

impl SignedSubChannel {
    fn get_dlc_channel_id(&self, temporary_channel_id: ChannelId, channel_idx: u8) -> ChannelId {
        crate::utils::compute_id(
            self.split_tx.transaction.txid(),
            channel_idx as u16 + 1,
            &temporary_channel_id,
        )
    }
}

#[derive(Debug, Clone)]
/// Information about an offer to collaboratively close a sub channel.
pub struct CloseOfferedSubChannel {
    /// The signed sub channel for which the offer was made.
    pub signed_subchannel: SignedSubChannel,
    /// The proposed balance of the offer party for the DLC sub channel.
    pub offer_balance: u64,
    /// The proposed balance of the accpet party for the DLC sub channel.
    pub accept_balance: u64,
}

#[derive(Debug, Clone)]
/// Information about an offer to collaboratively close a sub channel that was accepted.
pub struct CloseAcceptedSubChannel {
    /// The signed sub channel for which the offer was made.
    pub signed_subchannel: SignedSubChannel,
    /// The balance of the local party for the DLC sub channel.
    pub own_balance: u64,
}

#[derive(Debug, Clone)]
/// Information about an offer to collaboratively close a sub channel that was confirmed.
pub struct CloseConfirmedSubChannel {
    /// The signed sub channel for which the offer was made.
    pub signed_subchannel: SignedSubChannel,
    /// The balance of the local party for the DLC sub channel.
    pub own_balance: u64,
}

/// Information about a sub channel that is in the process of being unilateraly closed.
#[derive(Debug, Clone)]
pub struct ClosingSubChannel {
    /// The signed sub channel that is being closed.
    pub signed_sub_channel: SignedSubChannel,
}

/// Provides the ability to access and update Lightning Network channels.
pub trait LNChannelManager {
    /// Returns the details of the channel with given `channel_id` if found.
    fn get_channel_details(&self, channel_id: &ChannelId) -> Option<ChannelDetails>;
    /// Updates the funding output for the channel and returns the [`CommitmentSigned`] message
    /// with signatures for the updated commitment transaction and HTLCs.
    fn get_updated_funding_outpoint_commitment_signed(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
        funding_outpoint: &OutPoint,
        channel_value_satoshis: u64,
        value_to_self_msat: u64,
    ) -> Result<CommitmentSigned, Error>;
    /// Provides commitment transaction and HTLCs signatures and returns a [`RevokeAndACK`]
    /// message.
    fn on_commitment_signed_get_raa(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
        commitment_signature: &Signature,
        htlc_signatures: &[Signature],
    ) -> Result<RevokeAndACK, Error>;

    /// Provides and verify a [`RevokeAndACK`] message.
    fn revoke_and_ack(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
        revoke_and_ack: &RevokeAndACK,
    ) -> Result<(), Error>;

    /// Gives the ability to access the funding secret key within the provided callback.
    fn sign_with_fund_key_cb<F>(&self, channel_id: &[u8; 32], cb: &mut F)
    where
        F: FnMut(&SecretKey);

    /// Force close the channel with given `channel_id` and `counter_party_node_id`.
    fn force_close_channel(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
    ) -> Result<(), Error>;
}

impl<M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> LNChannelManager
    for ChannelManager<M, T, K, F, L>
where
    M::Target: lightning::chain::Watch<<K::Target as KeysInterface>::Signer>,
    T::Target: BroadcasterInterface,
    K::Target: KeysInterface,
    F::Target: FeeEstimator,
    L::Target: Logger,
{
    fn get_channel_details(&self, channel_id: &ChannelId) -> Option<ChannelDetails> {
        let channel_details = self.list_channels();
        let res = channel_details
            .iter()
            .find(|x| &x.channel_id == channel_id)?;
        Some(res.clone())
    }

    fn get_updated_funding_outpoint_commitment_signed(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
        funding_outpoint: &OutPoint,
        channel_value_satoshis: u64,
        value_to_self_msat: u64,
    ) -> Result<CommitmentSigned, Error> {
        self.get_updated_funding_outpoint_commitment_signed(
            channel_id,
            counter_party_node_id,
            &lightning::chain::transaction::OutPoint {
                txid: funding_outpoint.txid,
                index: funding_outpoint.vout as u16,
            },
            channel_value_satoshis,
            value_to_self_msat,
        )
        .map_err(|e| Error::InvalidParameters(format!("{e:?}")))
    }

    fn on_commitment_signed_get_raa(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
        commitment_signature: &Signature,
        htlc_signatures: &[Signature],
    ) -> Result<RevokeAndACK, Error> {
        self.on_commitment_signed_get_raa(
            channel_id,
            counter_party_node_id,
            commitment_signature,
            htlc_signatures,
        )
        .map_err(|e| Error::InvalidParameters(format!("{e:?}")))
    }

    fn revoke_and_ack(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
        revoke_and_ack: &RevokeAndACK,
    ) -> Result<(), Error> {
        self.revoke_and_ack_commitment(channel_id, counter_party_node_id, revoke_and_ack)
            .map_err(|e| Error::InvalidParameters(format!("{e:?}")))
    }

    fn sign_with_fund_key_cb<SF>(&self, channel_id: &[u8; 32], cb: &mut SF)
    where
        SF: FnMut(&SecretKey),
    {
        self.sign_with_fund_key_callback(channel_id, cb)
            .map_err(|e| Error::InvalidParameters(format!("{e:?}")))
            .unwrap();
    }

    fn force_close_channel(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
    ) -> Result<(), Error> {
        self.force_close_broadcasting_latest_txn(channel_id, counter_party_node_id)
            .map_err(|e| Error::InvalidParameters(format!("{e:?}")))
    }
}

/// Generate a temporary channel id for a DLC channel based on the LN channel id, the update index of the
/// split transaction and the index of the DLC channel within the sub channel.
pub fn generate_temporary_channel_id(
    channel_id: ChannelId,
    split_update_idx: u64,
    channel_index: u8,
) -> ContractId {
    let mut data = Vec::with_capacity(65);
    data.extend_from_slice(&channel_id);
    data.extend_from_slice(&split_update_idx.to_be_bytes());
    data.extend_from_slice(&channel_index.to_be_bytes());
    bitcoin::hashes::sha256::Hash::hash(&data).into_inner()
}
