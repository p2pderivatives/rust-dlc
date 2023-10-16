//! # Module containing structures and methods for working with DLC channels embedded in Lightning
//! channels.

use std::{fmt::Display, ops::Deref};

use bitcoin::{hashes::Hash, OutPoint, Script, Transaction, Txid};
use dlc::channel::sub_channel::SplitTx;
use lightning::{
    chain::{
        chaininterface::{BroadcasterInterface, FeeEstimator},
        chainmonitor::ChainMonitor,
        Watch,
    },
    ln::{
        chan_utils::CounterpartyCommitmentSecrets,
        channelmanager::{ChannelDetails, ChannelLock, ChannelManager},
        msgs::{ChannelMessageHandler, CommitmentSigned, RevokeAndACK},
    },
    routing::router::Router,
    sign::{EntropySource, NodeSigner, SignerProvider, WriteableEcdsaChannelSigner},
    util::{errors::APIError, logger::Logger},
};
use secp256k1_zkp::{ecdsa::Signature, EcdsaAdaptorSignature, PublicKey, SecretKey};

use crate::{channel::party_points::PartyBasePoints, error::Error, ChannelId, ContractId};

pub mod ser;

#[derive(Clone, PartialEq, Eq)]
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
    /// The id used to derive the keys for the Lightning channel.
    pub channel_keys_id: [u8; 32],
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
            SubChannelState::Confirmed(s) => {
                Some(s.get_dlc_channel_id(temporary_channel_id, index))
            }
            SubChannelState::Signed(s) | SubChannelState::Finalized(s) => {
                Some(s.get_dlc_channel_id(temporary_channel_id, index))
            }
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

    /// Return the flag associated with the state of the sub channel, or `None` if the state is not
    /// relevant for reestablishment.
    pub(crate) fn get_reestablish_flag(&self) -> Option<u8> {
        match self.state {
            SubChannelState::Offered(_) => Some(ReestablishFlag::Offered as u8),
            SubChannelState::Accepted(_) => Some(ReestablishFlag::Accepted as u8),
            SubChannelState::Confirmed(_) => Some(ReestablishFlag::Confirmed as u8),
            SubChannelState::Finalized(_) => Some(ReestablishFlag::Finalized as u8),
            SubChannelState::Signed(_) => Some(ReestablishFlag::Signed as u8),
            SubChannelState::CloseOffered(_) => Some(ReestablishFlag::CloseOffered as u8),
            SubChannelState::CloseAccepted(_) => Some(ReestablishFlag::CloseAccepted as u8),
            SubChannelState::CloseConfirmed(_) => Some(ReestablishFlag::CloseConfirmed as u8),
            SubChannelState::OffChainClosed => Some(ReestablishFlag::OffChainClosed as u8),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Represents the state of a [`SubChannel`].
pub enum SubChannelState {
    /// The sub channel was offered (sent or received).
    Offered(OfferedSubChannel),
    /// The sub channel was accepted.
    Accepted(AcceptedSubChannel),
    /// An offer to establish a sub channel was rejected.
    Rejected,
    /// The sub channel was confirmed.
    Confirmed(ConfirmedSubChannel),
    /// The sub channel transactions have been signed, awaiting revocation of the previous
    /// commitment transaction.
    Finalized(SignedSubChannel),
    /// The sub channel transactions have been signed and the previous commitment transaction
    /// revoked.
    Signed(SignedSubChannel),

    /// An offer to collaboratively close the sub channel has been made.
    CloseOffered(CloseOfferedSubChannel),
    /// An offer to collaboratively close the sub channel was accepted.
    CloseAccepted(CloseAcceptedSubChannel),
    /// An offer to collaboratively close the sub channel was confirmed.
    CloseConfirmed(CloseConfirmedSubChannel),
    /// The sub channel was closed off chain (reverted to a regular LN channel).
    OffChainClosed,

    /// The sub channel is closing.
    Closing(ClosingSubChannel),
    /// The sub channel has been closed on chain by the local party.
    OnChainClosed,
    /// The sub channel has been closed on chain by the remote party.
    CounterOnChainClosed,
    /// The sub channel was closed by broadcasting a punishment transaction.
    ClosedPunished(Txid),
}

impl Display for SubChannelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubChannelState::Offered(_) => write!(f, "Offered"),
            SubChannelState::Accepted(_) => write!(f, "Accepted"),
            SubChannelState::Confirmed(_) => write!(f, "Confirmed"),
            SubChannelState::Finalized(_) => write!(f, "Finalized"),
            SubChannelState::Signed(_) => write!(f, "Signed"),
            SubChannelState::Closing(_) => write!(f, "Closing"),
            SubChannelState::OnChainClosed => write!(f, "OnChainClosed"),
            SubChannelState::CounterOnChainClosed => write!(f, "CounterOnChainClosed"),
            SubChannelState::CloseOffered(_) => write!(f, "CloseOffered"),
            SubChannelState::CloseAccepted(_) => write!(f, "CloseAccepted"),
            SubChannelState::CloseConfirmed(_) => write!(f, "CloseConfirmed"),
            SubChannelState::OffChainClosed => write!(f, "OffChainClosed"),
            SubChannelState::ClosedPunished(_) => write!(f, "ClosedPunished"),
            SubChannelState::Rejected => write!(f, "Rejected"),
        }
    }
}

/// Flags associated with states that must be communicated to the remote node during
/// reestablishment.
#[repr(u8)]
pub(crate) enum ReestablishFlag {
    Offered = 1,
    Accepted = 2,
    Confirmed = 3,
    Finalized = 4,
    Signed = 5,
    CloseOffered = 6,
    CloseAccepted = 7,
    CloseConfirmed = 8,
    OffChainClosed = 9,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Information about an offer to set up a sub channel.
pub struct OfferedSubChannel {
    /// The current per update point of the local party.
    pub per_split_point: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Information about a sub channel that is in the accepted state.
pub struct AcceptedSubChannel {
    /// The current per split point of the offer party.
    pub offer_per_split_point: PublicKey,
    /// The current per split point of the accept party.
    pub accept_per_split_point: PublicKey,
    /// Information about the split transaction for the sub channel.
    pub split_tx: SplitTx,
    /// Glue transaction that bridges the split transaction to the Lightning sub channel.
    pub ln_glue_transaction: Transaction,
    /// Information used to facilitate the rollback of a channel split.
    pub ln_rollback: LnRollBackInfo,
    /// Commitment transactions of the previous Lightning channel state to broadcast in
    /// order to force close the Lightning channel (in the `Accepted` state, the funding outpoint
    /// has already been updated but we don't have the signatures required to force close the split
    /// channel yet, so we need to keep the previous commitment transaction(s) to be able to force
    /// close).
    pub commitment_transactions: Vec<bitcoin::Transaction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Holds information used to facilitate the rollback of a channel split.
pub struct LnRollBackInfo {
    /// The original value of the channel.
    pub channel_value_satoshis: u64,
    /// The original `value_to_self_msat` of the LN channel.
    pub value_to_self_msat: u64,
    /// The original funding outpoint
    pub funding_outpoint: lightning::chain::transaction::OutPoint,
}

impl From<&ChannelDetails> for LnRollBackInfo {
    fn from(value: &ChannelDetails) -> Self {
        Self {
            channel_value_satoshis: value.channel_value_satoshis,
            value_to_self_msat: value.balance_msat,
            funding_outpoint: value
                .funding_txo
                .expect("to have a defined funding outpoint"),
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// Information about a sub channel offered by the local party whose transactions have been signed,
/// but whose previous commitment transaction has not been revoked yet.
pub struct ConfirmedSubChannel {
    /// The current per split point of the local party.
    pub own_per_split_point: PublicKey,
    /// The current per split point of the remote party.
    pub counter_per_split_point: PublicKey,
    /// Adaptor signature of the local party for the split transaction.
    pub own_split_adaptor_signature: EcdsaAdaptorSignature,
    /// Information about the split transaction for the sub channel.
    pub split_tx: SplitTx,
    /// Glue transaction that bridges the split transaction to the Lightning sub channel.
    pub ln_glue_transaction: Transaction,
    /// Signature of the remote party for the glue transaction.
    pub counter_glue_signature: Signature,
    /// The secret to revoke the previous commitment transaction of the LN channel.
    pub prev_commitment_secret: SecretKey,
    /// The image of the next commitment point to be used to build a commitment transaction.
    pub next_per_commitment_point: PublicKey,
    /// Information used to facilitate the rollback of a channel split.
    pub ln_rollback: LnRollBackInfo,
    /// Commitment transactions of the previous Lightning channel state to broadcast in
    /// order to force close the Lightning channel (in the `Confirmed` state, the funding outpoint
    /// has already been updated but we don't have the signatures required to force close the split
    /// channel yet, so we need to keep the previous commitment transaction(s) to be able to force
    /// close).
    pub commitment_transactions: Vec<bitcoin::Transaction>,
}

impl ConfirmedSubChannel {
    fn get_dlc_channel_id(&self, temporary_channel_id: ChannelId, channel_idx: u8) -> ChannelId {
        crate::utils::compute_id(
            self.split_tx.transaction.txid(),
            channel_idx as u16 + 1,
            &temporary_channel_id,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Information used to facilitate the rollback of a channel split.
    pub ln_rollback: LnRollBackInfo,
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// Information about an offer to collaboratively close a sub channel.
pub struct CloseOfferedSubChannel {
    /// The signed sub channel for which the offer was made.
    pub signed_subchannel: SignedSubChannel,
    /// The proposed balance of the offer party for the DLC sub channel.
    pub offer_balance: u64,
    /// The proposed balance of the accpet party for the DLC sub channel.
    pub accept_balance: u64,
    /// Indicates if the local party is the one who made the offer.
    pub is_offer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Information about an offer to collaboratively close a sub channel that was accepted.
pub struct CloseAcceptedSubChannel {
    /// The signed sub channel for which the offer was made.
    pub signed_subchannel: SignedSubChannel,
    /// The balance of the local party for the DLC sub channel.
    pub own_balance: u64,
    /// The balance of the remote party for the DLC sub channel.
    pub counter_balance: u64,
    /// Rollback information about the split channel
    pub ln_rollback: LnRollBackInfo,
    /// Commitment transactions of the Lightning channel in the previous split state to use in
    /// order to force close the Lightning channel (in the `CloseAccepted` state, the funding outpoint
    /// has already been updated to remove the split transaction but we don't have the signature
    /// for the new commitment transaction yet so we need to keep the commitment transaction from
    /// the previous state to be able to force close).
    pub commitment_transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Information about an offer to collaboratively close a sub channel that was confirmed.
pub struct CloseConfirmedSubChannel {
    /// The signed sub channel for which the offer was made.
    pub signed_subchannel: SignedSubChannel,
    /// The balance of the local party for the DLC sub channel.
    pub own_balance: u64,
    /// The balance of the remote party for the DLC sub channel.
    pub counter_balance: u64,
    /// Rollback information about the split channel
    pub ln_rollback: LnRollBackInfo,
    /// Whether to check for LN secret (to deal with reestblishments)
    pub check_ln_secret: bool,
    /// Commitment transactions of the Lightning channel in the previous split state to use in
    /// order to force close the Lightning channel (in the `CloseConfirmed` state, the funding outpoint
    /// has already been updated to remove the split transaction but we don't have the signature
    /// for the new commitment transaction yet so we need to keep the commitment transaction from
    /// the previous state to be able to force close).
    pub commitment_transactions: Vec<Transaction>,
}

/// Information about a sub channel that is in the process of being unilateraly closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosingSubChannel {
    /// The signed sub channel that is being closed.
    pub signed_sub_channel: SignedSubChannel,
    /// Whether the local party initiated the closing.
    pub is_initiator: bool,
    /// Commitment transactions to use to close the lightning side of the split channel for cases
    /// where the LDK `ChannelManager` has been updated to a state which would prevent it to
    /// properly force close, like when we are force closing during establishment or off chain
    /// closing of a split channel.
    pub commitment_transactions: Option<Vec<Transaction>>,
}

/// Provides the ability to access and update Lightning Network channels.
pub trait LNChannelManager<SP>: ChannelMessageHandler
where
    SP: lightning::sign::ChannelSigner,
{
    /// Returns the details of the channel with given `channel_id` if found.
    fn get_channel_details(&self, channel_id: &ChannelId) -> Option<ChannelDetails>;
    /// Enable executing the provided callback while holding the lock of the channel with provided
    /// id, making sure that the channel is in a useable state and that a connection is established
    /// with the peer.
    fn with_useable_channel_lock<F, T>(
        &self,
        channel_id: &ChannelId,
        counter_party_node_id: &PublicKey,
        commit_tx_number: Option<u64>,
        cb: F,
    ) -> Result<T, APIError>
    where
        F: FnOnce(&mut ChannelLock<SP>) -> Result<T, APIError>;
    /// Enable executing the provided callback while holding the lock of the channel without
    /// checking the channel state or peer connection status.
    fn with_channel_lock_no_check<F, T>(
        &self,
        channel_id: &ChannelId,
        counter_party_node_id: &PublicKey,
        cb: F,
    ) -> Result<T, APIError>
    where
        F: FnOnce(&mut ChannelLock<SP>) -> Result<T, APIError>;
    /// Updates the funding output for the channel and returns the [`CommitmentSigned`] message
    /// with signatures for the updated commitment transaction and HTLCs.
    fn get_updated_funding_outpoint_commitment_signed(
        &self,
        channel_lock: &mut ChannelLock<SP>,
        funding_outpoint: &OutPoint,
        channel_value_satoshis: u64,
        value_to_self_msat: u64,
    ) -> Result<(CommitmentSigned, u64), APIError>;
    /// Provides commitment transaction and HTLCs signatures and returns a [`RevokeAndACK`]
    /// message.
    fn on_commitment_signed_get_raa(
        &self,
        channel_lock: &mut ChannelLock<SP>,
        commitment_signature: &Signature,
        htlc_signatures: &[Signature],
    ) -> Result<RevokeAndACK, APIError>;

    /// Provides and verify a [`RevokeAndACK`] message.
    fn revoke_and_ack(
        &self,
        channel_lock: &mut ChannelLock<SP>,
        revoke_and_ack: &RevokeAndACK,
    ) -> Result<(), APIError>;

    /// Force close the channel with given `channel_id` and `counter_party_node_id`.
    fn force_close_channel(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
    ) -> Result<(), Error>;

    /// Set the funding outpoint to the given one and sets the channel values to the given
    /// ones.
    fn set_funding_outpoint(
        &self,
        channel_lock: &mut ChannelLock<SP>,
        funding_outpoint: &lightning::chain::transaction::OutPoint,
        channel_value_satoshis: u64,
        value_to_self_msat: u64,
    );
}

/// Provides methods to interact with a `ChainMonitor` for a Lightning channel (in particular the
/// one from LDK).
pub trait LNChainMonitor {
    /// Gets the latest commitment transactions and HTLC transactions that can be used to close the
    /// channel.
    fn get_latest_holder_commitment_txn(
        &self,
        funding_txo: &lightning::chain::transaction::OutPoint,
    ) -> Result<Vec<Transaction>, Error>;

    /// Updates the funding transaction output of the channel monitor associated with the channel
    /// specified by `old_funding_txo`.
    fn update_channel_funding_txo(
        &self,
        old_funding_txo: &lightning::chain::transaction::OutPoint,
        new_funding_txo: &lightning::chain::transaction::OutPoint,
        channel_value_satoshis: u64,
    ) -> Result<(), Error>;
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, K: Deref, F: Deref, R: Deref, L: Deref>
    LNChannelManager<<K::Target as SignerProvider>::Signer>
    for ChannelManager<M, T, ES, NS, K, F, R, L>
where
    M::Target: lightning::chain::Watch<<K::Target as SignerProvider>::Signer>,
    T::Target: BroadcasterInterface,
    ES::Target: EntropySource,
    NS::Target: NodeSigner,
    K::Target: SignerProvider,
    F::Target: FeeEstimator,
    R::Target: Router,
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
        channel_lock: &mut ChannelLock<<K::Target as SignerProvider>::Signer>,
        funding_outpoint: &OutPoint,
        channel_value_satoshis: u64,
        value_to_self_msat: u64,
    ) -> Result<(CommitmentSigned, u64), APIError> {
        self.get_updated_funding_outpoint_commitment_signed(
            channel_lock,
            &lightning::chain::transaction::OutPoint {
                txid: funding_outpoint.txid,
                index: funding_outpoint.vout as u16,
            },
            channel_value_satoshis,
            value_to_self_msat,
        )
    }

    fn on_commitment_signed_get_raa(
        &self,
        channel_lock: &mut ChannelLock<<K::Target as SignerProvider>::Signer>,
        commitment_signature: &Signature,
        htlc_signatures: &[Signature],
    ) -> Result<RevokeAndACK, APIError> {
        self.on_commitment_signed_get_raa(channel_lock, commitment_signature, htlc_signatures)
    }

    fn revoke_and_ack(
        &self,
        channel_lock: &mut ChannelLock<<K::Target as SignerProvider>::Signer>,
        revoke_and_ack: &RevokeAndACK,
    ) -> Result<(), APIError> {
        self.revoke_and_ack_commitment(channel_lock, revoke_and_ack)
    }

    fn force_close_channel(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
    ) -> Result<(), Error> {
        self.force_close_broadcasting_latest_txn(channel_id, counter_party_node_id)
            .map_err(|e| Error::InvalidParameters(format!("{e:?}")))
    }

    fn set_funding_outpoint(
        &self,
        channel_lock: &mut ChannelLock<<K::Target as SignerProvider>::Signer>,
        funding_outpoint: &lightning::chain::transaction::OutPoint,
        channel_value_satoshis: u64,
        value_to_self_msat: u64,
    ) {
        self.set_funding_outpoint(
            channel_lock,
            funding_outpoint,
            channel_value_satoshis,
            value_to_self_msat,
        );
    }

    fn with_useable_channel_lock<C, RV>(
        &self,
        channel_id: &ChannelId,
        counter_party_node_id: &PublicKey,
        commit_tx_number: Option<u64>,
        cb: C,
    ) -> Result<RV, APIError>
    where
        C: FnOnce(
            &mut ChannelLock<<<K as Deref>::Target as SignerProvider>::Signer>,
        ) -> Result<RV, APIError>,
    {
        self.with_useable_channel_lock(channel_id, counter_party_node_id, commit_tx_number, cb)
    }

    fn with_channel_lock_no_check<C, RV>(
        &self,
        channel_id: &ChannelId,
        counter_party_node_id: &PublicKey,
        cb: C,
    ) -> Result<RV, APIError>
    where
        C: FnOnce(
            &mut ChannelLock<<<K as Deref>::Target as SignerProvider>::Signer>,
        ) -> Result<RV, APIError>,
    {
        self.with_channel_lock_no_check(channel_id, counter_party_node_id, cb)
    }
}

impl<
        ChannelSigner: WriteableEcdsaChannelSigner,
        C: Deref,
        T: Deref,
        F: Deref,
        L: Deref,
        P: Deref,
    > LNChainMonitor for ChainMonitor<ChannelSigner, C, T, F, L, P>
where
    C::Target: lightning::chain::Filter,
    T::Target: BroadcasterInterface,
    F::Target: FeeEstimator,
    L::Target: Logger,
    P::Target: lightning::chain::chainmonitor::Persist<ChannelSigner>,
{
    fn get_latest_holder_commitment_txn(
        &self,
        funding_txo: &lightning::chain::transaction::OutPoint,
    ) -> Result<Vec<Transaction>, Error> {
        self.get_latest_holder_commitment_txn(funding_txo)
            .map_err(|e| {
                Error::InvalidParameters(format!("Could not get channel monitor: {:?}", e))
            })
    }

    fn update_channel_funding_txo(
        &self,
        old_funding_txo: &lightning::chain::transaction::OutPoint,
        new_funding_txo: &lightning::chain::transaction::OutPoint,
        channel_value_satoshis: u64,
    ) -> Result<(), Error> {
        match Watch::update_channel_funding_txo(
            self,
            *old_funding_txo,
            *new_funding_txo,
            channel_value_satoshis,
        ) {
            lightning::chain::ChannelMonitorUpdateStatus::Completed => Ok(()),
            s => Err(Error::InvalidState(format!(
                "Unexpected channel monitor status {:?}",
                s
            ))),
        }
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

/// Trait to be implemented by a signing component providing the ability to sign LN/DLC split
/// transactions. It is required that the signer's keys are identical to the ones used for the
/// original Lightning channel.
pub trait LnDlcChannelSigner {
    /// Get the signature for the split transaction using the LN channel holder funding secret key.
    fn get_holder_split_tx_signature(
        &self,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
        split_tx: &Transaction,
        original_funding_redeemscript: &Script,
        original_channel_value_satoshis: u64,
    ) -> Result<Signature, Error>;

    /// Get an adaptor signature for the split transaction using the LN channel holder funding
    /// secret key as the signing key, and the remote party publish public key as adaptor key.
    fn get_holder_split_tx_adaptor_signature(
        &self,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
        split_tx: &Transaction,
        original_channel_value_satoshis: u64,
        original_funding_redeemscript: &Script,
        other_publish_key: &PublicKey,
    ) -> Result<EcdsaAdaptorSignature, Error>;
}

/// Generates `Signer` that are able to sign split transaction for LN/DLC channels.
pub trait LnDlcSignerProvider<Signer: LnDlcChannelSigner> {
    /// Derives the private key material backing a `Signer`.
    ///
    /// To derive a new `Signer`, the same `channel_keys_id` and `channel_value_satoshis` parameter
    /// that were provided to generate the LDK `ChannelSigner` shoud be passed, and the
    /// implementation should derive the same key values.
    fn derive_ln_dlc_channel_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id: [u8; 32],
    ) -> Signer;
}
