//!
//!
//!
use std::{ops::Deref, sync::Mutex};

use bitcoin::{OutPoint, PackedLockTime, Script, Sequence, Transaction, Txid};
use dlc::channel::{
    get_tx_adaptor_signature,
    sub_channel::{SplitTx, LN_GLUE_TX_WEIGHT},
};
use dlc_messages::{
    channel::{AcceptChannel, OfferChannel},
    oracle_msgs::OracleAnnouncement,
    ser_impls::{read_ecdsa_adaptor_signature, write_ecdsa_adaptor_signature},
    sub_channel::{
        SubChannelAccept, SubChannelCloseAccept, SubChannelCloseConfirm, SubChannelCloseFinalize,
        SubChannelCloseOffer, SubChannelConfirm, SubChannelFinalize, SubChannelMessage,
        SubChannelOffer,
    },
    FundingSignatures,
};
use lightning::{
    chain::{
        chaininterface::{BroadcasterInterface, FeeEstimator},
        keysinterface::{KeysInterface, Sign},
    },
    ln::{
        chan_utils::{
            build_commitment_secret, derive_private_key, derive_private_revocation_key,
            CounterpartyCommitmentSecrets,
        },
        channelmanager::{ChannelDetails, ChannelManager},
        msgs::{CommitmentSigned, DecodeError, RevokeAndACK},
    },
    util::logger::Logger,
    util::ser::{Readable, Writeable, Writer},
};
use secp256k1_zkp::{
    ecdsa::Signature, All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey,
};

use crate::{
    chain_monitor::{ChainMonitor, ChannelInfo, RevokedTxType, TxType},
    channel::Channel,
    channel::{offered_channel::OfferedChannel, party_points::PartyBasePoints},
    channel_updater::{
        self, FundingInfo, SubChannelSignInfo, SubChannelSignVerifyInfo, SubChannelVerifyInfo,
    },
    contract::{contract_input::ContractInput, Contract},
    custom_signer::CustomSigner,
    error::Error,
    manager::{get_channel_in_state, get_contract_in_state, Manager},
    Blockchain, ChannelId, Oracle, Signer, Storage, Time, Wallet,
};

const INITIAL_SPLIT_NUMBER: u64 = (1 << 48) - 1;

#[macro_export]
///
macro_rules! get_sub_channel_in_state {
    ($manager: ident, $channel_id: expr, $state: ident, $peer_id: expr) => {{
        match $manager.store.get_sub_channel($channel_id)? {
            Some(sub_channel) => {
                if let Some(p) = $peer_id as Option<PublicKey> {
                    if sub_channel.counter_party != p {
                        return Err(Error::InvalidParameters(format!(
                            "Peer {:02x?} is not involved with {} {:02x?}.",
                            $peer_id,
                            stringify!($object_type),
                            $channel_id
                        )));
                    }
                }
                if let SubChannelState::$state(s) = sub_channel.state.clone() {
                    Ok((sub_channel, s))
                } else {
                    Err(Error::InvalidState(format!(
                        "Expected {} state but got {:?}",
                        stringify!($state),
                        &sub_channel.state,
                    )))
                }
            }
            None => Err(Error::InvalidParameters(format!(
                "Unknown {} id.",
                stringify!($object_type)
            ))),
        }
    }};
}

#[derive(Clone)]
///
pub struct SubChannel {
    /// The index for the channel.
    pub channel_id: ChannelId,
    /// The [`secp256k1_zkp::PublicKey`] of the counter party's node.
    pub counter_party: PublicKey,
    /// The update index of the sub channel.
    pub update_idx: u64,
    /// The sub channel state.
    pub state: SubChannelState,
    /// The image of the seed used by the local party to derive all per update
    /// points (Will be `None` on the accept party side.)
    pub per_split_seed: Option<PublicKey>,
    /// The current fee rate to be used to create transactions.
    pub fee_rate_per_vb: u64,
    ///
    pub own_base_points: PartyBasePoints,
    ///
    pub counter_base_points: Option<PartyBasePoints>,
    ///
    pub fund_value_satoshis: u64,
    ///
    pub original_funding_redeemscript: Script,
    ///
    pub is_offer: bool,
    ///
    pub own_fund_pk: PublicKey,
    ///
    pub counter_fund_pk: PublicKey,

    counter_party_secrets: CounterpartyCommitmentSecrets,
}

impl_dlc_writeable!(SubChannel, {
    (channel_id, writeable),
    (counter_party, writeable),
    (update_idx, writeable),
    (state, writeable),
    (per_split_seed, option),
    (fee_rate_per_vb, writeable),
    (own_base_points, writeable),
    (counter_base_points, option),
    (fund_value_satoshis, writeable),
    (original_funding_redeemscript, writeable),
    (is_offer, writeable),
    (own_fund_pk, writeable),
    (counter_fund_pk, writeable),
    (counter_party_secrets, writeable)
});

impl std::fmt::Debug for SubChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubChannel")
            .field("channel_id", &self.channel_id)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug, Clone)]
///
pub enum SubChannelState {
    ///
    Offered(OfferedSubChannel),
    ///
    Accepted(AcceptedSubChannel),
    ///
    Signed(SignedSubChannel),
    ///
    Closing(ClosingSubChannel),
    ///
    OnChainClosed,
    ///
    CounterOnChainClosed,
    ///
    CloseOffered(CloseOfferedSubChannel),
    ///
    CloseAccepted(CloseAcceptedSubChannel),
    ///
    CloseConfirmed(CloseConfirmedSubChannel),
    ///
    OffChainClosed,
    ///
    ClosedPunished(Txid),
}

impl_dlc_writeable_enum!(SubChannelState,
    (0, Offered),
    (1, Accepted),
    (2, Signed),
    (3, Closing),
    (4, CloseOffered),
    (5, CloseAccepted),
    (6, CloseConfirmed),
    (7, ClosedPunished)
    ;;;
    (8, OnChainClosed),
    (9, CounterOnChainClosed),
    (10, OffChainClosed)
);

///
pub trait LNChannelManager<Signer: Sign> {
    ///
    fn get_channel_details(&self, channel_id: &ChannelId) -> Option<ChannelDetails>;
    ///
    fn get_updated_funding_outpoint_commitment_signed(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
        funding_outpoint: &OutPoint,
        channel_value_satoshis: u64,
        value_to_self_msat: u64,
    ) -> Result<CommitmentSigned, Error>;
    ///
    fn on_commitment_signed_get_raa(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
        commitment_signature: &Signature,
        htlc_signatures: &[Signature],
    ) -> Result<RevokeAndACK, Error>;

    ///
    fn revoke_and_ack(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
        revoke_and_ack: &RevokeAndACK,
    ) -> Result<(), Error>;

    ///
    fn sign_with_fund_key_cb<F>(&self, channel_id: &[u8; 32], cb: &mut F)
    where
        F: FnMut(&SecretKey);

    ///
    fn force_close_channel(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
    ) -> Result<(), Error>;
}

impl<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref> LNChannelManager<Signer>
    for ChannelManager<M, T, K, F, L>
where
    M::Target: lightning::chain::Watch<Signer>,
    T::Target: BroadcasterInterface,
    K::Target: KeysInterface<Signer = Signer>,
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
        .map_err(|e| Error::InvalidParameters(format!("{:?}", e)))
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
        .map_err(|e| Error::InvalidParameters(format!("{:?}", e)))
    }

    fn revoke_and_ack(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
        revoke_and_ack: &RevokeAndACK,
    ) -> Result<(), Error> {
        self.revoke_and_ack_commitment(channel_id, counter_party_node_id, revoke_and_ack)
            .map_err(|e| Error::InvalidParameters(format!("{:?}", e)))
    }

    fn sign_with_fund_key_cb<SF>(&self, channel_id: &[u8; 32], cb: &mut SF)
    where
        SF: FnMut(&SecretKey),
    {
        self.sign_with_fund_key_callback(channel_id, cb)
            .map_err(|e| Error::InvalidParameters(format!("{:?}", e)))
            .unwrap();
    }

    fn force_close_channel(
        &self,
        channel_id: &[u8; 32],
        counter_party_node_id: &PublicKey,
    ) -> Result<(), Error> {
        self.force_close_broadcasting_latest_txn(channel_id, counter_party_node_id)
            .map_err(|e| Error::InvalidParameters(format!("{:?}", e)))
    }
}

#[derive(Debug, Clone)]
///
pub struct OfferedSubChannel {
    /// The current per update point of the local party.
    pub per_split_point: PublicKey,
}

impl_dlc_writeable!(OfferedSubChannel, { (per_split_point, writeable) });

#[derive(Debug, Clone)]
///
pub struct AcceptedSubChannel {
    /// The current per split point of the offer party.
    pub offer_per_split_point: PublicKey,
    /// The current per split point of the accept party.
    pub accept_per_split_point: PublicKey,
    ///
    pub accept_split_adaptor_signature: EcdsaAdaptorSignature,
    ///
    pub split_tx: SplitTx,
    ///
    pub ln_glue_transaction: Transaction,
}

impl_dlc_writeable_external!(SplitTx, split_tx, {(transaction, writeable), (output_script, writeable)});

impl_dlc_writeable!(AcceptedSubChannel, {
    (offer_per_split_point, writeable),
    (accept_per_split_point, writeable),
    (accept_split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (split_tx, {cb_writeable, split_tx::write, split_tx::read}),
    (ln_glue_transaction, writeable)
});

#[derive(Debug, Clone)]
///
pub struct SignedSubChannel {
    /// The current per split point of the local party.
    pub own_per_split_point: PublicKey,
    /// The current per split point of the remote party.
    pub counter_per_split_point: PublicKey,
    ///
    pub own_split_adaptor_signature: EcdsaAdaptorSignature,
    ///
    pub counter_split_adaptor_signature: EcdsaAdaptorSignature,
    ///
    pub split_tx: SplitTx,
    ///
    pub ln_glue_transaction: Transaction,
    ///
    pub counter_glue_signature: Signature,
}

impl_dlc_writeable!(SignedSubChannel, {
    (own_per_split_point, writeable),
    (counter_per_split_point, writeable),
    (own_split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (counter_split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (split_tx, {cb_writeable, split_tx::write, split_tx::read}),
    (ln_glue_transaction, writeable),
    (counter_glue_signature, writeable)
});

#[derive(Debug, Clone)]
///
pub struct CloseOfferedSubChannel {
    ///
    pub signed_subchannel: SignedSubChannel,
    ///
    pub offer_balance: u64,
    ///
    pub accept_balance: u64,
}

impl_dlc_writeable!(CloseOfferedSubChannel, {
    (signed_subchannel, writeable),
    (offer_balance, writeable),
    (accept_balance, writeable)
});

#[derive(Debug, Clone)]
///
pub struct CloseAcceptedSubChannel {
    ///
    pub signed_subchannel: SignedSubChannel,
}

impl_dlc_writeable!(CloseAcceptedSubChannel, { (signed_subchannel, writeable) });

#[derive(Debug, Clone)]
///
pub struct CloseConfirmedSubChannel {
    ///
    pub signed_subchannel: SignedSubChannel,
}

impl_dlc_writeable!(CloseConfirmedSubChannel, { (signed_subchannel, writeable) });

///
#[derive(Debug, Clone)]
pub struct ClosingSubChannel {
    ///
    pub signed_sub_channel: SignedSubChannel,
}

impl_dlc_writeable!(ClosingSubChannel, { (signed_sub_channel, writeable) });

///
pub struct SubChannelManager<
    W: Deref,
    M: Deref,
    S: Deref,
    B: Deref,
    O: Deref,
    T: Deref,
    F: Deref,
    D: Deref<Target = Manager<W, B, S, O, T, F>>,
> where
    W::Target: Wallet,
    M::Target: LNChannelManager<CustomSigner>,
    S::Target: Storage,
    B::Target: Blockchain,
    O::Target: Oracle,
    T::Target: Time,
    F::Target: FeeEstimator,
{
    secp: Secp256k1<All>,
    wallet: W,
    ln_channel_manager: M,
    store: S,
    blockchain: B,
    dlc_channel_manager: D,
    fee_estimator: F,
    chain_monitor: Mutex<ChainMonitor>,
}

impl<
        W: Deref,
        M: Deref,
        S: Deref,
        B: Deref,
        O: Deref,
        T: Deref,
        F: Deref,
        D: Deref<Target = Manager<W, B, S, O, T, F>>,
    > SubChannelManager<W, M, S, B, O, T, F, D>
where
    W::Target: Wallet,
    M::Target: LNChannelManager<CustomSigner>,
    S::Target: Storage,
    B::Target: Blockchain,
    O::Target: Oracle,
    T::Target: Time,
    F::Target: FeeEstimator,
{
    ///
    pub fn new(
        secp: Secp256k1<All>,
        wallet: W,
        ln_channel_manager: M,
        store: S,
        blockchain: B,
        dlc_channel_manager: D,
        fee_estimator: F,
        init_height: u64,
    ) -> Self {
        SubChannelManager {
            secp,
            wallet,
            ln_channel_manager,
            store,
            blockchain,
            dlc_channel_manager,
            fee_estimator,
            chain_monitor: Mutex::new(ChainMonitor::new(init_height)),
        }
    }
}

impl<
        W: Deref,
        M: Deref,
        S: Deref,
        B: Deref,
        O: Deref,
        T: Deref,
        F: Deref,
        D: Deref<Target = Manager<W, B, S, O, T, F>>,
    > SubChannelManager<W, M, S, B, O, T, F, D>
where
    W::Target: Wallet,
    M::Target: LNChannelManager<CustomSigner>,
    S::Target: Storage,
    B::Target: Blockchain,
    O::Target: Oracle,
    T::Target: Time,
    F::Target: FeeEstimator,
{
    ///
    pub fn on_sub_channel_message(
        &self,
        msg: &SubChannelMessage,
        sender: &PublicKey,
    ) -> Result<Option<SubChannelMessage>, Error> {
        match msg {
            SubChannelMessage::Request(req) => {
                self.on_subchannel_offer(req, sender)?;
                Ok(None)
            }
            SubChannelMessage::Accept(a) => {
                let res = self.on_subchannel_accept(a, sender)?;
                Ok(Some(SubChannelMessage::Confirm(res)))
            }
            SubChannelMessage::Confirm(c) => {
                let res = self.on_subchannel_confirm(c, sender)?;
                Ok(Some(SubChannelMessage::Finalize(res)))
            }
            SubChannelMessage::Finalize(f) => {
                self.on_sub_channel_finalize(f, sender)?;
                Ok(None)
            }
            SubChannelMessage::CloseOffer(o) => {
                self.on_sub_channel_close_offer(o, sender)?;
                Ok(None)
            }
            SubChannelMessage::CloseAccept(a) => {
                let res = self.on_sub_channel_close_accept(a, sender)?;
                Ok(Some(SubChannelMessage::CloseConfirm(res)))
            }
            SubChannelMessage::CloseConfirm(c) => {
                let res = self.on_sub_channel_close_confirm(c, sender)?;
                Ok(Some(SubChannelMessage::CloseFinalize(res)))
            }
            SubChannelMessage::CloseFinalize(f) => {
                self.on_sub_channel_close_finalize(f, sender)?;
                Ok(None)
            }
            SubChannelMessage::CloseReject(_) => todo!(),
        }
    }

    ///
    pub fn offer_sub_channel(
        &self,
        channel_id: &[u8; 32],
        contract_input: &ContractInput,
        oracle_announcements: &[Vec<OracleAnnouncement>],
    ) -> Result<SubChannelOffer, Error> {
        // TODO(tibo): deal with already split channel
        let channel_details = self
            .ln_channel_manager
            .get_channel_details(channel_id)
            .ok_or_else(|| {
                Error::InvalidParameters(format!("Unknown LN channel {channel_id:02x?}"))
            })?;

        let sub_channel =
            match self.store.get_sub_channel(channel_details.channel_id)? {
                Some(mut s) => match s.state {
                    SubChannelState::OffChainClosed => {
                        s.is_offer = true;
                        s.update_idx -= 1;
                        Some(s)
                    }
                    _ => return Err(Error::InvalidState(
                        "Received sub channel offer but a non closed sub channel already exists"
                            .to_string(),
                    )),
                },
                None => None,
            };

        validate_and_get_ln_values_per_party(
            &channel_details,
            contract_input.offer_collateral,
            contract_input.accept_collateral,
            contract_input.fee_rate,
            true,
        )?;

        let (per_split_seed, update_idx) = match &sub_channel {
            None => (self.wallet.get_new_secret_key()?, INITIAL_SPLIT_NUMBER),
            Some(s) => {
                let pub_seed = s.per_split_seed.expect("Should have a per split seed.");
                let sec_seed = self.wallet.get_secret_key_for_pubkey(&pub_seed)?;
                (sec_seed, s.update_idx)
            }
        };
        let per_split_secret = SecretKey::from_slice(&build_commitment_secret(
            per_split_seed.as_ref(),
            update_idx,
        ))
        .expect("a valid secret key.");

        let next_per_split_point = PublicKey::from_secret_key(&self.secp, &per_split_secret);
        let per_split_seed_pk = PublicKey::from_secret_key(&self.secp, &per_split_seed);
        let party_base_points = crate::utils::get_party_base_points(&self.secp, &self.wallet)?;

        let (mut offered_channel, mut offered_contract) = crate::channel_updater::offer_channel(
            &self.secp,
            contract_input,
            &channel_details.counterparty.node_id,
            oracle_announcements,
            crate::manager::CET_NSEQUENCE,
            crate::manager::REFUND_DELAY,
            &self.wallet,
            &self.blockchain,
            true,
        )?;

        // TODO(tibo): refactor properly.
        offered_contract.offer_params.inputs = Vec::new();
        offered_contract.funding_inputs_info = Vec::new();

        offered_channel.temporary_channel_id = *channel_id;

        let msg = SubChannelOffer {
            channel_id: channel_details.channel_id,
            next_per_split_point,
            revocation_basepoint: party_base_points.revocation_basepoint,
            publish_basepoint: party_base_points.publish_basepoint,
            own_basepoint: party_base_points.own_basepoint,
            channel_own_basepoint: offered_channel.party_points.own_basepoint,
            channel_publish_basepoint: offered_channel.party_points.publish_basepoint,
            channel_revocation_basepoint: offered_channel.party_points.revocation_basepoint,
            contract_info: (&offered_contract).into(),
            channel_first_per_update_point: offered_channel.per_update_point,
            payout_spk: offered_contract.offer_params.payout_script_pubkey.clone(),
            payout_serial_id: offered_contract.offer_params.payout_serial_id,
            offer_collateral: offered_contract.offer_params.collateral,
            cet_locktime: offered_contract.contract_maturity_bound,
            refund_locktime: offered_contract.contract_timeout,
            cet_nsequence: crate::manager::CET_NSEQUENCE,
            fee_rate_per_vbyte: contract_input.fee_rate,
        };

        let offered_state = OfferedSubChannel {
            per_split_point: next_per_split_point,
        };

        let sub_channel = match sub_channel {
            Some(mut s) => {
                s.state = SubChannelState::Offered(offered_state);
                s
            }
            None => SubChannel {
                channel_id: channel_details.channel_id,
                counter_party: channel_details.counterparty.node_id,
                per_split_seed: Some(per_split_seed_pk),
                fee_rate_per_vb: contract_input.fee_rate,
                is_offer: true,
                update_idx: INITIAL_SPLIT_NUMBER,
                state: SubChannelState::Offered(offered_state),
                counter_party_secrets: CounterpartyCommitmentSecrets::new(),
                own_base_points: party_base_points,
                counter_base_points: None,
                fund_value_satoshis: channel_details.channel_value_satoshis,
                original_funding_redeemscript: channel_details.funding_redeemscript.unwrap(),
                own_fund_pk: channel_details.holder_funding_pubkey,
                counter_fund_pk: channel_details.counter_funding_pubkey,
            },
        };

        self.store.upsert_channel(
            Channel::Offered(offered_channel),
            Some(Contract::Offered(offered_contract)),
        )?;
        self.store.upsert_sub_channel(&sub_channel)?;

        Ok(msg)
    }

    ///
    pub fn accept_sub_channel(
        &self,
        channel_id: &ChannelId,
    ) -> Result<(PublicKey, SubChannelAccept), Error> {
        let (mut offered_sub_channel, state) =
            get_sub_channel_in_state!(self, *channel_id, Offered, None as Option<PublicKey>)?;

        let per_split_seed = self.wallet.get_new_secret_key()?;
        let per_split_secret = SecretKey::from_slice(&build_commitment_secret(
            per_split_seed.as_ref(),
            offered_sub_channel.update_idx,
        ))
        .expect("a valid secret key.");

        offered_sub_channel.per_split_seed =
            Some(PublicKey::from_secret_key(&self.secp, &per_split_seed));

        let next_per_split_point = PublicKey::from_secret_key(&self.secp, &per_split_secret);

        let channel_details = self
            .ln_channel_manager
            .get_channel_details(channel_id)
            .ok_or_else(|| {
                Error::InvalidParameters(format!("Unknown LN channel {channel_id:02x?}"))
            })?;

        let offered_channel =
            get_channel_in_state!(self, channel_id, Offered, None as Option<PublicKey>)?;

        let offered_contract = get_contract_in_state!(
            self,
            &offered_channel.offered_contract_id,
            Offered,
            None as Option<PublicKey>
        )?;

        // Revalidate in case channel capacity has changed since receiving the offer.
        let (own_to_self_msat, _counter_to_self_msat) = validate_and_get_ln_values_per_party(
            &channel_details,
            offered_contract.total_collateral - offered_contract.offer_params.collateral,
            offered_contract.offer_params.collateral,
            offered_contract.fee_rate_per_vb,
            false,
        )?;

        let funding_redeemscript = channel_details
            .funding_redeemscript
            .as_ref()
            .unwrap()
            .clone();

        let funding_txo = channel_details
            .funding_txo
            .expect("to have a funding tx output");

        let offer_revoke_params = offered_sub_channel
            .counter_base_points
            .as_ref()
            .expect("to have counter base points")
            .get_revokable_params(
                &self.secp,
                &offered_sub_channel.own_base_points.revocation_basepoint,
                &state.per_split_point,
            )?;

        let accept_revoke_params = offered_sub_channel.own_base_points.get_revokable_params(
            &self.secp,
            &offered_sub_channel
                .counter_base_points
                .as_ref()
                .expect("to have counter base points")
                .revocation_basepoint,
            &next_per_split_point,
        )?;

        let own_base_secret_key = self
            .wallet
            .get_secret_key_for_pubkey(&offered_sub_channel.own_base_points.own_basepoint)?;
        let own_secret_key =
            derive_private_key(&self.secp, &next_per_split_point, &own_base_secret_key)
                .expect("to get a valid secret.");

        let split_tx = dlc::channel::sub_channel::create_split_tx(
            &offer_revoke_params,
            &accept_revoke_params,
            &OutPoint {
                txid: funding_txo.txid,
                vout: funding_txo.index as u32,
            },
            channel_details.channel_value_satoshis,
            offered_contract.total_collateral,
            offered_contract.fee_rate_per_vb,
        )?;

        let ln_output_value = split_tx.transaction.output[0].value;

        let mut split_tx_adaptor_signature = None;
        self.ln_channel_manager
            .sign_with_fund_key_cb(channel_id, &mut |sk| {
                split_tx_adaptor_signature = Some(
                    get_tx_adaptor_signature(
                        &self.secp,
                        &split_tx.transaction,
                        channel_details.channel_value_satoshis,
                        &funding_redeemscript,
                        sk,
                        &offer_revoke_params.publish_pk.inner,
                    )
                    .unwrap(),
                );
            });

        let split_tx_adaptor_signature = split_tx_adaptor_signature.unwrap();

        let glue_tx_output_value = ln_output_value
            - dlc::util::weight_to_fee(LN_GLUE_TX_WEIGHT, offered_contract.fee_rate_per_vb);

        let ln_glue_tx = dlc::channel::sub_channel::create_ln_glue_tx(
            &OutPoint {
                txid: split_tx.transaction.txid(),
                vout: 0,
            },
            &funding_redeemscript,
            PackedLockTime::ZERO,
            Sequence(crate::manager::CET_NSEQUENCE),
            glue_tx_output_value,
        );

        let commitment_signed = self
            .ln_channel_manager
            .get_updated_funding_outpoint_commitment_signed(
                channel_id,
                &offered_sub_channel.counter_party,
                &OutPoint {
                    txid: ln_glue_tx.txid(),
                    vout: 0,
                },
                glue_tx_output_value,
                own_to_self_msat,
            )?;

        let sub_channel_info = SubChannelSignInfo {
            funding_info: FundingInfo {
                funding_tx: split_tx.transaction.clone(),
                funding_script_pubkey: split_tx.output_script.clone(),
                funding_input_value: split_tx.transaction.output[1].value,
            },
            own_adaptor_sk: own_secret_key,
        };
        let (mut accepted_channel, mut accepted_contract, accept_channel) =
            channel_updater::accept_channel_offer_internal(
                &self.secp,
                &offered_channel,
                &offered_contract,
                &self.wallet,
                &self.blockchain,
                Some(sub_channel_info),
            )?;

        let ln_glue_signature = dlc::util::get_raw_sig_for_tx_input(
            &self.secp,
            &ln_glue_tx,
            0,
            &split_tx.output_script,
            ln_output_value,
            &own_secret_key,
        )?;

        // TODO(tibo): refactor properly.
        accepted_contract.accept_params.inputs = Vec::new();
        accepted_contract.funding_inputs = Vec::new();
        accepted_channel.channel_id = offered_sub_channel.channel_id;

        let msg = SubChannelAccept {
            channel_id: *channel_id,
            split_adaptor_signature: split_tx_adaptor_signature,
            first_per_split_point: next_per_split_point,
            revocation_basepoint: offered_sub_channel.own_base_points.revocation_basepoint,
            publish_basepoint: offered_sub_channel.own_base_points.publish_basepoint,
            own_basepoint: offered_sub_channel.own_base_points.own_basepoint,
            commit_signature: commitment_signed.signature,
            htlc_signatures: commitment_signed.htlc_signatures,
            channel_revocation_basepoint: accept_channel.revocation_basepoint,
            channel_publish_basepoint: accept_channel.publish_basepoint,
            channel_own_basepoint: accept_channel.own_basepoint,
            cet_adaptor_signatures: accept_channel.cet_adaptor_signatures,
            buffer_adaptor_signature: accept_channel.buffer_adaptor_signature,
            refund_signature: accept_channel.refund_signature,
            first_per_update_point: accept_channel.first_per_update_point,
            payout_spk: accept_channel.payout_spk,
            payout_serial_id: accept_channel.payout_serial_id,
            ln_glue_signature,
        };

        let accepted_sub_channel = AcceptedSubChannel {
            offer_per_split_point: state.per_split_point,
            accept_per_split_point: next_per_split_point,
            accept_split_adaptor_signature: split_tx_adaptor_signature,
            split_tx,
            ln_glue_transaction: ln_glue_tx,
        };

        offered_sub_channel.state = SubChannelState::Accepted(accepted_sub_channel);

        self.store.upsert_channel(
            Channel::Accepted(accepted_channel),
            Some(Contract::Accepted(accepted_contract)),
        )?;
        self.store.upsert_sub_channel(&offered_sub_channel)?;

        Ok((offered_sub_channel.counter_party, msg))
    }

    ///
    pub fn initiate_force_close_sub_channel(&self, channel_id: &ChannelId) -> Result<(), Error> {
        let (mut signed, state) =
            get_sub_channel_in_state!(self, *channel_id, Signed, None::<PublicKey>)?;

        let channel_details = self
            .ln_channel_manager
            .get_channel_details(channel_id)
            .unwrap();

        let publish_base_secret = self
            .wallet
            .get_secret_key_for_pubkey(&signed.own_base_points.publish_basepoint)?;

        let publish_sk =
            derive_private_key(&self.secp, &state.own_per_split_point, &publish_base_secret)
                .expect("to be able to derive the publish secret");

        let counter_split_signature = state.counter_split_adaptor_signature.decrypt(&publish_sk)?;

        let mut split_tx = state.split_tx.transaction.clone();

        let mut own_sig = None;

        self.ln_channel_manager
            .sign_with_fund_key_cb(channel_id, &mut |fund_sk| {
                own_sig = Some(
                    dlc::util::get_raw_sig_for_tx_input(
                        &self.secp,
                        &split_tx,
                        0,
                        &signed.original_funding_redeemscript,
                        signed.fund_value_satoshis,
                        fund_sk,
                    )
                    .unwrap(),
                );
                dlc::util::sign_multi_sig_input(
                    &self.secp,
                    &mut split_tx,
                    &counter_split_signature,
                    &channel_details.counter_funding_pubkey,
                    fund_sk,
                    &signed.original_funding_redeemscript,
                    signed.fund_value_satoshis,
                    0,
                )
                .unwrap();
            });

        dlc::verify_tx_input_sig(
            &self.secp,
            &own_sig.unwrap(),
            &split_tx,
            0,
            &signed.original_funding_redeemscript,
            signed.fund_value_satoshis,
            &channel_details.holder_funding_pubkey,
        )
        .unwrap();

        self.blockchain.send_transaction(&split_tx)?;

        let closing_sub_channel = ClosingSubChannel {
            signed_sub_channel: state,
        };

        signed.state = SubChannelState::Closing(closing_sub_channel);

        self.store.upsert_sub_channel(&signed)?;

        Ok(())
    }

    ///
    pub fn finalize_force_close_sub_channels(&self, channel_id: &ChannelId) -> Result<(), Error> {
        let (closing, state) =
            get_sub_channel_in_state!(self, *channel_id, Closing, None::<PublicKey>)?;

        let split_tx_confs = self
            .blockchain
            .get_transaction_confirmations(&state.signed_sub_channel.split_tx.transaction.txid())?;

        if split_tx_confs < crate::manager::CET_NSEQUENCE {
            return Err(Error::InvalidState(format!(
                "NSequence hasn't elapsed yet, need {} more blocks",
                crate::manager::CET_NSEQUENCE - split_tx_confs
            )));
        }

        let signed_sub_channel = &state.signed_sub_channel;
        let counter_party = closing.counter_party;
        let mut glue_tx = state.signed_sub_channel.ln_glue_transaction.clone();

        let own_revoke_params = closing.own_base_points.get_revokable_params(
            &self.secp,
            &closing
                .counter_base_points
                .as_ref()
                .expect("to have counter base points")
                .revocation_basepoint,
            &signed_sub_channel.own_per_split_point,
        )?;

        let counter_revoke_params = closing
            .counter_base_points
            .as_ref()
            .expect("to have counter base points")
            .get_revokable_params(
                &self.secp,
                &closing.own_base_points.revocation_basepoint,
                &signed_sub_channel.counter_per_split_point,
            )?;

        let (offer_params, accept_params) = if closing.is_offer {
            (&own_revoke_params, &counter_revoke_params)
        } else {
            (&counter_revoke_params, &own_revoke_params)
        };

        let own_base_secret_key = self
            .wallet
            .get_secret_key_for_pubkey(&closing.own_base_points.own_basepoint)?;
        let own_secret_key = derive_private_key(
            &self.secp,
            &signed_sub_channel.own_per_split_point,
            &own_base_secret_key,
        )
        .expect("to be able to derive own secret.");

        let own_signature = dlc::util::get_raw_sig_for_tx_input(
            &self.secp,
            &glue_tx,
            0,
            &signed_sub_channel.split_tx.output_script,
            signed_sub_channel.split_tx.transaction.output[0].value,
            &own_secret_key,
        )?;

        dlc::channel::satisfy_buffer_descriptor(
            &mut glue_tx,
            offer_params,
            accept_params,
            &own_revoke_params.own_pk.inner,
            &own_signature,
            &counter_revoke_params.own_pk,
            &signed_sub_channel.counter_glue_signature,
        )?;

        self.blockchain.send_transaction(&glue_tx)?;

        self.dlc_channel_manager
            .force_close_sub_channel(channel_id, (closing, &state))?;

        self.ln_channel_manager
            .force_close_channel(channel_id, &counter_party)?;

        Ok(())
    }

    ///
    pub fn offer_subchannel_close(
        &self,
        channel_id: &ChannelId,
        accept_balance: u64,
    ) -> Result<(SubChannelCloseOffer, PublicKey), Error> {
        let (mut signed_subchannel, state) =
            get_sub_channel_in_state!(self, *channel_id, Signed, None::<PublicKey>)?;

        let dlc_channel = get_channel_in_state!(self, channel_id, Signed, None::<PublicKey>)?;

        let offer_balance = match dlc_channel.state {
            crate::channel::signed_channel::SignedChannelState::Established {
                total_collateral,
                ..
            } => {
                if total_collateral < accept_balance {
                    return Err(Error::InvalidParameters(
                        "Accept balance must be smaller than total collateral in DLC channel."
                            .to_string(),
                    ));
                }

                total_collateral - accept_balance
            }
            crate::channel::signed_channel::SignedChannelState::Settled {
                counter_payout,
                own_payout,
                ..
            } => {
                if accept_balance != counter_payout {
                    return Err(Error::InvalidParameters("Accept balance must be equal to the counter payout when DLC channel is settled.".to_string()));
                }

                own_payout
            }
            _ => {
                return Err(Error::InvalidState(
                    "Can only close subchannel that are established or settled".to_string(),
                ));
            }
        };

        let close_offer = SubChannelCloseOffer {
            channel_id: *channel_id,
            accept_balance,
        };

        let counter_party = signed_subchannel.counter_party;
        let close_offered_subchannel = CloseOfferedSubChannel {
            signed_subchannel: state,
            offer_balance,
            accept_balance,
        };

        signed_subchannel.state = SubChannelState::CloseOffered(close_offered_subchannel);

        self.store.upsert_sub_channel(&signed_subchannel)?;

        Ok((close_offer, counter_party))
    }

    ///
    pub fn accept_subchannel_close_offer(
        &self,
        channel_id: &ChannelId,
    ) -> Result<(SubChannelCloseAccept, PublicKey), Error> {
        let (mut sub_channel, state) =
            get_sub_channel_in_state!(self, *channel_id, CloseOffered, None::<PublicKey>)?;

        let dlc_channel = get_channel_in_state!(self, channel_id, Signed, None::<PublicKey>)?;

        let total_collateral =
            dlc_channel.own_params.collateral + dlc_channel.counter_params.collateral;

        debug_assert_eq!(state.accept_balance + state.offer_balance, total_collateral);

        let channel_details = self
            .ln_channel_manager
            .get_channel_details(channel_id)
            .ok_or_else(|| Error::InvalidParameters(format!("Unknown channel {:?}", channel_id)))?;

        let (offer_fees, accept_fees) = per_party_fee(sub_channel.fee_rate_per_vb);

        let ln_own_balance_msats = channel_details.outbound_capacity_msat
            + channel_details.unspendable_punishment_reserve.unwrap() * 1000
            + accept_fees * 1000
            + state.accept_balance * 1000;

        let _ln_counter_balance = channel_details.inbound_capacity_msat
            + channel_details.counterparty.unspendable_punishment_reserve * 1000
            + offer_fees * 1000
            + state.offer_balance * 1000;

        let fund_value = sub_channel.fund_value_satoshis;

        let commitment_signed = self
            .ln_channel_manager
            .get_updated_funding_outpoint_commitment_signed(
                channel_id,
                &sub_channel.counter_party,
                &state.signed_subchannel.split_tx.transaction.input[0].previous_output,
                fund_value,
                ln_own_balance_msats,
            )?;

        let close_accept = SubChannelCloseAccept {
            channel_id: *channel_id,
            commit_signature: commitment_signed.signature,
            htlc_signatures: commitment_signed.htlc_signatures,
        };

        let close_accepted_subchannel = CloseAcceptedSubChannel {
            signed_subchannel: state.signed_subchannel,
        };

        sub_channel.state = SubChannelState::CloseAccepted(close_accepted_subchannel);

        self.store.upsert_sub_channel(&sub_channel)?;

        Ok((close_accept, sub_channel.counter_party))
    }

    fn on_subchannel_offer(
        &self,
        sub_channel_offer: &SubChannelOffer,
        counter_party: &PublicKey,
    ) -> Result<(), Error> {
        let channel_details = self
            .ln_channel_manager
            .get_channel_details(&sub_channel_offer.channel_id)
            .ok_or_else(|| {
                Error::InvalidParameters(format!(
                    "Unknown channel {:02x?}",
                    sub_channel_offer.channel_id
                ))
            })?;

        let sub_channel =
            match self.store.get_sub_channel(channel_details.channel_id)? {
                Some(mut s) => match s.state {
                    SubChannelState::OffChainClosed => {
                        s.is_offer = false;
                        s.update_idx -= 1;
                        Some(s)
                    }
                    _ => return Err(Error::InvalidState(
                        "Received sub channel offer but a non closed sub channel already exists"
                            .to_string(),
                    )),
                },
                None => None,
            };

        validate_and_get_ln_values_per_party(
            &channel_details,
            sub_channel_offer.contract_info.get_total_collateral()
                - sub_channel_offer.offer_collateral,
            sub_channel_offer.offer_collateral,
            sub_channel_offer.fee_rate_per_vbyte,
            false,
        )?;

        // TODO(tibo): validate subchannel is valid wrt current channel conditions.

        let offered_sub_channel = OfferedSubChannel {
            per_split_point: sub_channel_offer.next_per_split_point,
        };

        let offer_channel = OfferChannel {
            protocol_version: 0, //unused
            contract_flags: 0,   //unused
            chain_hash: [0; 32], //unused
            temporary_contract_id: channel_details.channel_id,
            temporary_channel_id: channel_details.channel_id,
            contract_info: sub_channel_offer.contract_info.clone(),
            // THIS IS INCORRECT!!! SHOULD BE KEY FROM SPLIT TX
            funding_pubkey: channel_details.holder_funding_pubkey,
            revocation_basepoint: sub_channel_offer.channel_revocation_basepoint,
            publish_basepoint: sub_channel_offer.channel_publish_basepoint,
            own_basepoint: sub_channel_offer.channel_own_basepoint,
            first_per_update_point: sub_channel_offer.channel_first_per_update_point,
            payout_spk: sub_channel_offer.payout_spk.clone(),
            payout_serial_id: sub_channel_offer.payout_serial_id,
            offer_collateral: sub_channel_offer.offer_collateral,
            funding_inputs: vec![],
            change_spk: Script::default(),
            change_serial_id: 0,
            fund_output_serial_id: 0,
            fee_rate_per_vb: sub_channel_offer.fee_rate_per_vbyte,
            cet_locktime: sub_channel_offer.cet_locktime,
            refund_locktime: sub_channel_offer.refund_locktime,
            cet_nsequence: sub_channel_offer.cet_nsequence,
        };

        let (offered_channel, offered_contract) =
            OfferedChannel::from_offer_channel(&offer_channel, *counter_party)?;

        let party_base_points = crate::utils::get_party_base_points(&self.secp, &self.wallet)?;
        let counter_base_points = Some(PartyBasePoints {
            own_basepoint: sub_channel_offer.own_basepoint,
            revocation_basepoint: sub_channel_offer.revocation_basepoint,
            publish_basepoint: sub_channel_offer.publish_basepoint,
        });

        let sub_channel = match sub_channel {
            Some(mut s) => {
                s.state = SubChannelState::Offered(offered_sub_channel);
                s
            }
            None => SubChannel {
                channel_id: channel_details.channel_id,
                counter_party: channel_details.counterparty.node_id,
                per_split_seed: None,
                fee_rate_per_vb: offered_contract.fee_rate_per_vb,
                is_offer: false,
                update_idx: INITIAL_SPLIT_NUMBER,
                state: SubChannelState::Offered(offered_sub_channel),
                counter_party_secrets: CounterpartyCommitmentSecrets::new(),
                own_base_points: party_base_points,
                counter_base_points,
                fund_value_satoshis: channel_details.channel_value_satoshis,
                original_funding_redeemscript: channel_details.funding_redeemscript.unwrap(),
                own_fund_pk: channel_details.holder_funding_pubkey,
                counter_fund_pk: channel_details.counter_funding_pubkey,
            },
        };

        self.store.upsert_channel(
            Channel::Offered(offered_channel),
            Some(Contract::Offered(offered_contract)),
        )?;
        self.store.upsert_sub_channel(&sub_channel)?;

        Ok(())
    }

    fn on_subchannel_accept(
        &self,
        sub_channel_accept: &SubChannelAccept,
        counter_party: &PublicKey,
    ) -> Result<SubChannelConfirm, Error> {
        let (mut offered_sub_channel, state) = get_sub_channel_in_state!(
            self,
            sub_channel_accept.channel_id,
            Offered,
            Some(*counter_party)
        )?;

        let channel_details = self
            .ln_channel_manager
            .get_channel_details(&sub_channel_accept.channel_id)
            .ok_or_else(|| {
                Error::InvalidParameters(format!(
                    "Unknown LN channel {:02x?}",
                    sub_channel_accept.channel_id
                ))
            })?;

        let offer_revoke_params = offered_sub_channel.own_base_points.get_revokable_params(
            &self.secp,
            &sub_channel_accept.revocation_basepoint,
            &state.per_split_point,
        )?;

        let accept_points = PartyBasePoints {
            own_basepoint: sub_channel_accept.own_basepoint,
            revocation_basepoint: sub_channel_accept.revocation_basepoint,
            publish_basepoint: sub_channel_accept.publish_basepoint,
        };

        let accept_revoke_params = accept_points.get_revokable_params(
            &self.secp,
            &offered_sub_channel.own_base_points.revocation_basepoint,
            &sub_channel_accept.first_per_split_point,
        )?;

        let funding_txo = channel_details.funding_txo.expect("to have a funding txo");
        let funding_outpoint = OutPoint {
            txid: funding_txo.txid,
            vout: funding_txo.index as u32,
        };
        let funding_redeemscript = channel_details
            .funding_redeemscript
            .as_ref()
            .unwrap()
            .clone();

        let offered_channel = get_channel_in_state!(
            self,
            &channel_details.channel_id,
            Offered,
            None as Option<PublicKey>
        )?;

        let offered_contract = get_contract_in_state!(
            self,
            &offered_channel.offered_contract_id,
            Offered,
            None as Option<PublicKey>
        )?;

        let (own_to_self_value_msat, _) = validate_and_get_ln_values_per_party(
            &channel_details,
            offered_contract.total_collateral - offered_contract.offer_params.collateral,
            offered_contract.offer_params.collateral,
            offered_contract.fee_rate_per_vb,
            true,
        )?;

        let split_tx = dlc::channel::sub_channel::create_split_tx(
            &offer_revoke_params,
            &accept_revoke_params,
            &funding_outpoint,
            channel_details.channel_value_satoshis,
            offered_contract.total_collateral,
            offered_contract.fee_rate_per_vb,
        )?;

        let ln_output_value = split_tx.transaction.output[0].value;

        dlc::channel::verify_tx_adaptor_signature(
            &self.secp,
            &split_tx.transaction,
            channel_details.channel_value_satoshis,
            &funding_redeemscript,
            &channel_details.counter_funding_pubkey,
            &offer_revoke_params.publish_pk.inner,
            &sub_channel_accept.split_adaptor_signature,
        )?;

        let channel_id = &channel_details.channel_id;
        let mut split_tx_adaptor_signature = None;
        self.ln_channel_manager
            .sign_with_fund_key_cb(channel_id, &mut |sk| {
                split_tx_adaptor_signature = Some(
                    get_tx_adaptor_signature(
                        &self.secp,
                        &split_tx.transaction,
                        channel_details.channel_value_satoshis,
                        &funding_redeemscript,
                        sk,
                        &accept_revoke_params.publish_pk.inner,
                    )
                    .unwrap(),
                );
            });

        let split_tx_adaptor_signature = split_tx_adaptor_signature.unwrap();

        let own_base_secret_key = self
            .wallet
            .get_secret_key_for_pubkey(&offered_sub_channel.own_base_points.own_basepoint)?;
        let own_secret_key =
            derive_private_key(&self.secp, &state.per_split_point, &own_base_secret_key)
                .expect("to get a valid secret.");

        let glue_tx_output_value = ln_output_value
            - dlc::util::weight_to_fee(LN_GLUE_TX_WEIGHT, offered_contract.fee_rate_per_vb);

        let ln_glue_tx = dlc::channel::sub_channel::create_ln_glue_tx(
            &OutPoint {
                txid: split_tx.transaction.txid(),
                vout: 0,
            },
            &funding_redeemscript,
            PackedLockTime::ZERO,
            Sequence(crate::manager::CET_NSEQUENCE),
            glue_tx_output_value,
        );

        let commitment_signed = self
            .ln_channel_manager
            .get_updated_funding_outpoint_commitment_signed(
                &sub_channel_accept.channel_id,
                counter_party,
                &OutPoint {
                    txid: ln_glue_tx.txid(),
                    vout: 0,
                },
                glue_tx_output_value,
                own_to_self_value_msat,
            )?;

        let revoke_and_ack = self.ln_channel_manager.on_commitment_signed_get_raa(
            &sub_channel_accept.channel_id,
            counter_party,
            &sub_channel_accept.commit_signature,
            &sub_channel_accept.htlc_signatures,
        )?;

        let accept_channel = AcceptChannel {
            temporary_channel_id: channel_details.channel_id,
            accept_collateral: offered_contract.total_collateral
                - offered_contract.offer_params.collateral,
            funding_pubkey: channel_details.holder_funding_pubkey,
            revocation_basepoint: sub_channel_accept.channel_revocation_basepoint,
            publish_basepoint: sub_channel_accept.channel_publish_basepoint,
            own_basepoint: sub_channel_accept.channel_own_basepoint,
            first_per_update_point: sub_channel_accept.first_per_update_point,
            payout_serial_id: sub_channel_accept.payout_serial_id,
            funding_inputs: vec![],
            change_spk: Script::default(),
            change_serial_id: 0,
            cet_adaptor_signatures: sub_channel_accept.cet_adaptor_signatures.clone(),
            buffer_adaptor_signature: sub_channel_accept.buffer_adaptor_signature,
            refund_signature: sub_channel_accept.refund_signature,
            negotiation_fields: None,
            payout_spk: sub_channel_accept.payout_spk.clone(),
        };

        let sub_channel_info = SubChannelSignVerifyInfo {
            funding_info: FundingInfo {
                funding_tx: split_tx.transaction.clone(),
                funding_script_pubkey: split_tx.output_script.clone(),
                funding_input_value: split_tx.transaction.output[1].value,
            },
            own_adaptor_sk: own_secret_key,
            counter_adaptor_pk: accept_revoke_params.own_pk.inner,
        };

        let (mut signed_channel, signed_contract, sign_channel) =
            crate::channel_updater::verify_and_sign_accepted_channel_internal(
                &self.secp,
                &offered_channel,
                &offered_contract,
                &accept_channel,
                //TODO(tibo): this should be parameterizable.
                crate::manager::CET_NSEQUENCE,
                &self.wallet,
                Some(sub_channel_info),
            )?;

        // TODO(tibo): consider having separate ids to enable multiple DLC channels.
        signed_channel.channel_id = sub_channel_accept.channel_id;

        dlc::verify_tx_input_sig(
            &self.secp,
            &sub_channel_accept.ln_glue_signature,
            &ln_glue_tx,
            0,
            &split_tx.output_script,
            ln_output_value,
            &accept_revoke_params.own_pk.inner,
        )?;

        let ln_glue_signature = dlc::util::get_raw_sig_for_tx_input(
            &self.secp,
            &ln_glue_tx,
            0,
            &split_tx.output_script,
            ln_output_value,
            &own_secret_key,
        )?;

        let msg = SubChannelConfirm {
            channel_id: sub_channel_accept.channel_id,
            per_commitment_secret: SecretKey::from_slice(&revoke_and_ack.per_commitment_secret)
                .expect("a valid secret key"),
            next_per_commitment_point: revoke_and_ack.next_per_commitment_point,
            split_adaptor_signature: split_tx_adaptor_signature,
            commit_signature: commitment_signed.signature,
            htlc_signatures: commitment_signed.htlc_signatures,
            cet_adaptor_signatures: sign_channel.cet_adaptor_signatures,
            buffer_adaptor_signature: sign_channel.buffer_adaptor_signature,
            refund_signature: sign_channel.refund_signature,
            ln_glue_signature,
        };

        let signed_sub_channel = SignedSubChannel {
            own_per_split_point: state.per_split_point,
            counter_per_split_point: sub_channel_accept.first_per_split_point,
            own_split_adaptor_signature: split_tx_adaptor_signature,
            counter_split_adaptor_signature: sub_channel_accept.split_adaptor_signature,
            split_tx,
            counter_glue_signature: sub_channel_accept.ln_glue_signature,
            ln_glue_transaction: ln_glue_tx,
        };

        offered_sub_channel.counter_base_points = Some(accept_points);

        offered_sub_channel.state = SubChannelState::Signed(signed_sub_channel);

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Signed(signed_contract)),
        )?;
        self.store.upsert_sub_channel(&offered_sub_channel)?;

        Ok(msg)
    }

    fn on_subchannel_confirm(
        &self,
        sub_channel_confirm: &SubChannelConfirm,
        counter_party: &PublicKey,
    ) -> Result<SubChannelFinalize, Error> {
        let (mut accepted_sub_channel, state) = get_sub_channel_in_state!(
            self,
            sub_channel_confirm.channel_id,
            Accepted,
            Some(*counter_party)
        )?;

        let raa = RevokeAndACK {
            channel_id: sub_channel_confirm.channel_id,
            per_commitment_secret: *sub_channel_confirm.per_commitment_secret.as_ref(),
            next_per_commitment_point: sub_channel_confirm.next_per_commitment_point,
        };

        let channel_details = self
            .ln_channel_manager
            .get_channel_details(&sub_channel_confirm.channel_id)
            .ok_or_else(|| {
                Error::InvalidParameters(format!(
                    "Unknown LN channel {:02x?}",
                    sub_channel_confirm.channel_id
                ))
            })?;

        let accept_revoke_params = accepted_sub_channel.own_base_points.get_revokable_params(
            &self.secp,
            &accepted_sub_channel
                .counter_base_points
                .as_ref()
                .expect("to have counter base points")
                .revocation_basepoint,
            &state.accept_per_split_point,
        )?;

        let funding_redeemscript = &accepted_sub_channel.original_funding_redeemscript;

        dlc::channel::verify_tx_adaptor_signature(
            &self.secp,
            &state.split_tx.transaction,
            accepted_sub_channel.fund_value_satoshis,
            funding_redeemscript,
            &channel_details.counter_funding_pubkey,
            &accept_revoke_params.publish_pk.inner,
            &sub_channel_confirm.split_adaptor_signature,
        )?;

        self.ln_channel_manager.revoke_and_ack(
            &sub_channel_confirm.channel_id,
            counter_party,
            &raa,
        )?;

        let revoke_and_ack = self.ln_channel_manager.on_commitment_signed_get_raa(
            &sub_channel_confirm.channel_id,
            counter_party,
            &sub_channel_confirm.commit_signature,
            &sub_channel_confirm.htlc_signatures,
        )?;

        let accepted_channel = get_channel_in_state!(
            self,
            &sub_channel_confirm.channel_id,
            Accepted,
            Some(*counter_party)
        )?;

        let accepted_contract = get_contract_in_state!(
            self,
            &accepted_channel.accepted_contract_id,
            Accepted,
            Some(*counter_party)
        )?;

        let sign_channel = dlc_messages::channel::SignChannel {
            channel_id: sub_channel_confirm.channel_id,
            cet_adaptor_signatures: sub_channel_confirm.cet_adaptor_signatures.clone(),
            buffer_adaptor_signature: sub_channel_confirm.buffer_adaptor_signature,
            refund_signature: sub_channel_confirm.refund_signature,
            funding_signatures: FundingSignatures {
                funding_signatures: vec![],
            },
        };

        let offer_revoke_params = accepted_sub_channel
            .counter_base_points
            .as_ref()
            .expect("to have counter base points")
            .get_revokable_params(
                &self.secp,
                &accepted_sub_channel.own_base_points.revocation_basepoint,
                &state.offer_per_split_point,
            )?;

        let sub_channel_info = SubChannelVerifyInfo {
            funding_info: FundingInfo {
                funding_tx: state.split_tx.transaction.clone(),
                funding_script_pubkey: state.split_tx.output_script.clone(),
                funding_input_value: state.split_tx.transaction.output[1].value,
            },
            counter_adaptor_pk: offer_revoke_params.own_pk.inner,
        };

        let (signed_channel, signed_contract) = channel_updater::verify_signed_channel_internal(
            &self.secp,
            &accepted_channel,
            &accepted_contract,
            &sign_channel,
            &self.wallet,
            Some(sub_channel_info),
        )?;

        let signed_sub_channel = SignedSubChannel {
            own_per_split_point: state.accept_per_split_point,
            counter_per_split_point: state.offer_per_split_point,
            own_split_adaptor_signature: state.accept_split_adaptor_signature,
            counter_split_adaptor_signature: sub_channel_confirm.split_adaptor_signature,
            split_tx: state.split_tx.clone(),
            counter_glue_signature: sub_channel_confirm.ln_glue_signature,
            ln_glue_transaction: state.ln_glue_transaction,
        };

        let msg = SubChannelFinalize {
            channel_id: sub_channel_confirm.channel_id,
            per_commitment_secret: SecretKey::from_slice(&revoke_and_ack.per_commitment_secret)
                .expect("a valid secret key"),
            next_per_commitment_point: revoke_and_ack.next_per_commitment_point,
        };

        accepted_sub_channel.state = SubChannelState::Signed(signed_sub_channel);

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Confirmed(signed_contract)),
        )?;
        self.store.upsert_sub_channel(&accepted_sub_channel)?;

        Ok(msg)
    }

    fn on_sub_channel_finalize(
        &self,
        sub_channel_finalize: &SubChannelFinalize,
        counter_party: &PublicKey,
    ) -> Result<(), Error> {
        let channel = get_channel_in_state!(
            self,
            &sub_channel_finalize.channel_id,
            Signed,
            Some(*counter_party)
        )?;
        let contract = get_contract_in_state!(
            self,
            &channel
                .get_contract_id()
                .ok_or_else(|| Error::InvalidState(
                    "No contract id in on_sub_channel_finalize".to_string()
                ))?,
            Signed,
            Some(*counter_party)
        )?;
        let raa = RevokeAndACK {
            channel_id: sub_channel_finalize.channel_id,
            per_commitment_secret: sub_channel_finalize.per_commitment_secret.secret_bytes(),
            next_per_commitment_point: sub_channel_finalize.next_per_commitment_point,
        };
        self.ln_channel_manager.revoke_and_ack(
            &sub_channel_finalize.channel_id,
            counter_party,
            &raa,
        )?;

        self.store.upsert_channel(
            Channel::Signed(channel),
            Some(Contract::Confirmed(contract)),
        )?;

        Ok(())
    }

    fn on_sub_channel_close_offer(
        &self,
        offer: &SubChannelCloseOffer,
        counter_party: &PublicKey,
    ) -> Result<(), Error> {
        let (mut sub_channel, state) =
            get_sub_channel_in_state!(self, offer.channel_id, Signed, Some(*counter_party))?;

        let dlc_channel =
            get_channel_in_state!(self, &offer.channel_id, Signed, None::<PublicKey>)?;

        let offer_balance = match dlc_channel.state {
            crate::channel::signed_channel::SignedChannelState::Established {
                total_collateral,
                ..
            } => {
                if total_collateral < offer.accept_balance {
                    return Err(Error::InvalidParameters(
                        "Accept balance must be smaller than total collateral in DLC channel."
                            .to_string(),
                    ));
                }

                total_collateral - offer.accept_balance
            }
            crate::channel::signed_channel::SignedChannelState::Settled {
                own_payout,
                counter_payout,
                ..
            } => {
                if offer.accept_balance != own_payout {
                    return Err(Error::InvalidParameters(
                        "Accept balance must be equal to own payout when DLC channel is settled."
                            .to_string(),
                    ));
                }

                counter_payout
            }
            _ => {
                return Err(Error::InvalidState(
                    "Can only close subchannel that are established or settled".to_string(),
                ));
            }
        };

        let updated = CloseOfferedSubChannel {
            signed_subchannel: state,
            offer_balance,
            accept_balance: offer.accept_balance,
        };

        sub_channel.state = SubChannelState::CloseOffered(updated);

        self.store.upsert_sub_channel(&sub_channel)?;

        Ok(())
    }

    fn on_sub_channel_close_accept(
        &self,
        accept: &SubChannelCloseAccept,
        counter_party: &PublicKey,
    ) -> Result<SubChannelCloseConfirm, Error> {
        let (mut sub_channel, state) =
            get_sub_channel_in_state!(self, accept.channel_id, CloseOffered, Some(*counter_party))?;

        let channel_details = self
            .ln_channel_manager
            .get_channel_details(&accept.channel_id)
            .ok_or_else(|| {
                Error::InvalidParameters(format!("Unknown channel {:?}", accept.channel_id))
            })?;

        let (offer_fees, accept_fees) = per_party_fee(sub_channel.fee_rate_per_vb);
        let ln_own_balance_msats = channel_details.outbound_capacity_msat
            + channel_details.unspendable_punishment_reserve.unwrap_or(0) * 1000
            + offer_fees * 1000
            + state.offer_balance * 1000;

        let _ln_counter_balance = channel_details.inbound_capacity_msat
            + channel_details.counterparty.unspendable_punishment_reserve * 1000
            + accept_fees * 1000
            + state.accept_balance * 1000;

        let fund_value = sub_channel.fund_value_satoshis;

        let commitment_signed = self
            .ln_channel_manager
            .get_updated_funding_outpoint_commitment_signed(
                &sub_channel.channel_id,
                &sub_channel.counter_party,
                &state.signed_subchannel.split_tx.transaction.input[0].previous_output,
                fund_value,
                ln_own_balance_msats,
            )?;

        let raa = self.ln_channel_manager.on_commitment_signed_get_raa(
            &sub_channel.channel_id,
            counter_party,
            &accept.commit_signature,
            &accept.htlc_signatures,
        )?;

        let per_split_seed = self.wallet.get_secret_key_for_pubkey(
            &sub_channel
                .per_split_seed
                .expect("to have a per split seed"),
        )?;

        let per_split_secret = SecretKey::from_slice(&build_commitment_secret(
            per_split_seed.as_ref(),
            sub_channel.update_idx,
        ))?;

        let close_confirm = SubChannelCloseConfirm {
            channel_id: accept.channel_id,
            commit_signature: commitment_signed.signature,
            htlc_signatures: commitment_signed.htlc_signatures,
            split_revocation_secret: per_split_secret,
            commit_revocation_secret: SecretKey::from_slice(&raa.per_commitment_secret)
                .expect("a valid secret key"),
            next_per_commitment_point: raa.next_per_commitment_point,
        };

        self.chain_monitor.lock().unwrap().add_tx(
            state.signed_subchannel.split_tx.transaction.txid(),
            ChannelInfo {
                channel_id: sub_channel.channel_id,
                tx_type: TxType::Revoked {
                    update_idx: sub_channel.update_idx,
                    own_adaptor_signature: state.signed_subchannel.own_split_adaptor_signature,
                    is_offer: sub_channel.is_offer,
                    revoked_tx_type: RevokedTxType::Split,
                },
            },
        );

        let updated_channel = CloseConfirmedSubChannel {
            signed_subchannel: state.signed_subchannel,
        };

        sub_channel.state = SubChannelState::CloseConfirmed(updated_channel);

        self.store.upsert_sub_channel(&sub_channel)?;

        Ok(close_confirm)
    }

    fn on_sub_channel_close_confirm(
        &self,
        confirm: &SubChannelCloseConfirm,
        counter_party: &PublicKey,
    ) -> Result<SubChannelCloseFinalize, Error> {
        let (mut sub_channel, state) = get_sub_channel_in_state!(
            self,
            confirm.channel_id,
            CloseAccepted,
            Some(*counter_party)
        )?;

        sub_channel
            .counter_party_secrets
            .provide_secret(
                sub_channel.update_idx,
                *confirm.split_revocation_secret.as_ref(),
            )
            .map_err(|_| Error::InvalidParameters("Invalid split revocation secret".to_string()))?;

        debug_assert_eq!(
            PublicKey::from_secret_key(&self.secp, &confirm.split_revocation_secret),
            state.signed_subchannel.counter_per_split_point
        );

        let raa = RevokeAndACK {
            channel_id: confirm.channel_id,
            per_commitment_secret: *confirm.commit_revocation_secret.as_ref(),
            next_per_commitment_point: confirm.next_per_commitment_point,
        };

        self.ln_channel_manager
            .revoke_and_ack(&confirm.channel_id, counter_party, &raa)?;

        let own_raa = self.ln_channel_manager.on_commitment_signed_get_raa(
            &sub_channel.channel_id,
            counter_party,
            &confirm.commit_signature,
            &confirm.htlc_signatures,
        )?;

        let per_split_seed = self.wallet.get_secret_key_for_pubkey(
            &sub_channel
                .per_split_seed
                .expect("to have a per split seed"),
        )?;

        let per_split_secret = derive_private_key(
            &self.secp,
            &state.signed_subchannel.own_per_split_point,
            &per_split_seed,
        )?;

        let finalize = SubChannelCloseFinalize {
            channel_id: confirm.channel_id,
            split_revocation_secret: per_split_secret,
            commit_revocation_secret: SecretKey::from_slice(&own_raa.per_commitment_secret)
                .expect("a valid secret key"),
            next_per_commitment_point: own_raa.next_per_commitment_point,
        };

        self.chain_monitor.lock().unwrap().add_tx(
            state.signed_subchannel.split_tx.transaction.txid(),
            ChannelInfo {
                channel_id: sub_channel.channel_id,
                tx_type: TxType::Revoked {
                    update_idx: sub_channel.update_idx,
                    own_adaptor_signature: state.signed_subchannel.own_split_adaptor_signature,
                    is_offer: sub_channel.is_offer,
                    revoked_tx_type: RevokedTxType::Split,
                },
            },
        );

        sub_channel.state = SubChannelState::OffChainClosed;

        self.store.upsert_sub_channel(&sub_channel)?;

        Ok(finalize)
    }

    fn on_sub_channel_close_finalize(
        &self,
        finalize: &SubChannelCloseFinalize,
        counter_party: &PublicKey,
    ) -> Result<(), Error> {
        let (mut sub_channel, _) = get_sub_channel_in_state!(
            self,
            finalize.channel_id,
            CloseConfirmed,
            Some(*counter_party)
        )?;

        sub_channel
            .counter_party_secrets
            .provide_secret(
                sub_channel.update_idx,
                *finalize.split_revocation_secret.as_ref(),
            )
            .map_err(|_| Error::InvalidParameters("Invalid split revocation secret".to_string()))?;

        let revoke_and_ack = RevokeAndACK {
            channel_id: finalize.channel_id,
            per_commitment_secret: *finalize.commit_revocation_secret.as_ref(),
            next_per_commitment_point: finalize.next_per_commitment_point,
        };

        self.ln_channel_manager.revoke_and_ack(
            &finalize.channel_id,
            counter_party,
            &revoke_and_ack,
        )?;

        sub_channel.state = SubChannelState::OffChainClosed;

        self.store.upsert_sub_channel(&sub_channel)?;

        Ok(())
    }

    ///
    pub fn check_for_watched_tx(&self) -> Result<(), Error> {
        let cur_height = self.blockchain.get_blockchain_height()?;
        let last_height = self.chain_monitor.lock().unwrap().last_height;

        if cur_height < last_height {
            return Err(Error::InvalidState(
                "Current height is lower than last height.".to_string(),
            ));
        }

        //todo(tibo): check and deal with reorgs.

        for height in last_height + 1..=cur_height {
            let block = self.blockchain.get_block_at_height(height)?;

            let watch_res = self
                .chain_monitor
                .lock()
                .unwrap()
                .process_block(&block, height);

            for (tx, channel_info) in watch_res {
                let mut sub_channel = match self.store.get_sub_channel(channel_info.channel_id)? {
                    None => {
                        log::error!("Unknown channel {:?}", channel_info.channel_id);
                        continue;
                    }
                    Some(s) => s,
                };

                if let TxType::Current = channel_info.tx_type {
                    // TODO(tibo): should only considered closed after some confirmations.
                    // Ideally should save previous state, and maybe restore in
                    // case of reorg, though if the counter party has sent the
                    // tx to close the channel it is unlikely that the tx will
                    // not be part of a future block.
                    sub_channel.state = SubChannelState::CounterOnChainClosed;
                    self.store.upsert_sub_channel(&sub_channel)?;
                    continue;
                } else if let TxType::Revoked {
                    update_idx,
                    own_adaptor_signature,
                    is_offer,
                    revoked_tx_type,
                } = channel_info.tx_type
                {
                    let secret = sub_channel
                        .counter_party_secrets
                        .get_secret(update_idx)
                        .expect("to be able to retrieve the per update secret");
                    let counter_per_update_secret = SecretKey::from_slice(&secret)
                        .expect("to be able to parse the counter per update secret.");

                    let per_update_seed_pk = sub_channel
                        .per_split_seed
                        .expect("to have a per split seed");

                    let per_update_seed_sk =
                        self.wallet.get_secret_key_for_pubkey(&per_update_seed_pk)?;

                    let per_update_secret = SecretKey::from_slice(&build_commitment_secret(
                        per_update_seed_sk.as_ref(),
                        update_idx,
                    ))
                    .expect("a valid secret key.");

                    let per_update_point =
                        PublicKey::from_secret_key(&self.secp, &per_update_secret);

                    let own_revocation_params = sub_channel.own_base_points.get_revokable_params(
                        &self.secp,
                        &sub_channel
                            .counter_base_points
                            .as_ref()
                            .expect("to have counter base points")
                            .revocation_basepoint,
                        &per_update_point,
                    )?;

                    let counter_per_update_point =
                        PublicKey::from_secret_key(&self.secp, &counter_per_update_secret);

                    let base_own_sk = self
                        .wallet
                        .get_secret_key_for_pubkey(&sub_channel.own_base_points.own_basepoint)?;

                    let own_sk = derive_private_key(&self.secp, &per_update_point, &base_own_sk)?;

                    let counter_revocation_params = sub_channel
                        .counter_base_points
                        .as_ref()
                        .expect("to have counter base points")
                        .get_revokable_params(
                            &self.secp,
                            &sub_channel.own_base_points.revocation_basepoint,
                            &counter_per_update_point,
                        )?;

                    let witness = if sub_channel.own_fund_pk < sub_channel.counter_fund_pk {
                        tx.input[0].witness.to_vec().remove(1)
                    } else {
                        tx.input[0].witness.to_vec().remove(2)
                    };

                    let sig_data = witness
                        .iter()
                        .take(witness.len() - 1)
                        .cloned()
                        .collect::<Vec<_>>();
                    let own_sig = Signature::from_der(&sig_data)?;

                    let counter_sk = own_adaptor_signature.recover(
                        &self.secp,
                        &own_sig,
                        &counter_revocation_params.publish_pk.inner,
                    )?;

                    let own_revocation_base_secret = &self.wallet.get_secret_key_for_pubkey(
                        &sub_channel.own_base_points.revocation_basepoint,
                    )?;

                    let counter_revocation_sk = derive_private_revocation_key(
                        &self.secp,
                        &counter_per_update_secret,
                        own_revocation_base_secret,
                    )?;

                    let (offer_params, accept_params) = if is_offer {
                        (&own_revocation_params, &counter_revocation_params)
                    } else {
                        (&counter_revocation_params, &own_revocation_params)
                    };

                    let fee_rate_per_vb: u64 = (self.fee_estimator.get_est_sat_per_1000_weight(
                        lightning::chain::chaininterface::ConfirmationTarget::HighPriority,
                    ) / 250)
                        .into();

                    let signed_tx = match revoked_tx_type {
                        RevokedTxType::Split => {
                            dlc::channel::sub_channel::create_and_sign_punish_split_transaction(
                                &self.secp,
                                offer_params,
                                accept_params,
                                &own_sk,
                                &counter_sk,
                                &counter_revocation_sk,
                                &tx,
                                &self.wallet.get_new_address()?,
                                0,
                                fee_rate_per_vb,
                            )?
                        }
                        _ => panic!("Sub channel manager should only deal with split tx"),
                    };

                    self.blockchain.send_transaction(&signed_tx)?;

                    sub_channel.state = SubChannelState::ClosedPunished(signed_tx.txid());

                    self.store.upsert_sub_channel(&sub_channel)?;
                } else if let TxType::CollaborativeClose = channel_info.tx_type {
                    todo!();
                    // signed_channel.state = SignedChannelState::CollaborativelyClosed;
                    // self.store
                    //     .upsert_channel(Channel::Signed(signed_channel), None)?;
                }
            }

            self.chain_monitor
                .lock()
                .unwrap()
                .increment_height(&block.block_hash());
        }

        Ok(())
    }
}

fn validate_and_get_ln_values_per_party(
    channel_details: &ChannelDetails,
    own_collateral: u64,
    counter_collateral: u64,
    fee_rate: u64,
    is_offer: bool,
) -> Result<(u64, u64), Error> {
    let (offer_fees, accept_fees) = per_party_fee(fee_rate);
    let (own_fees, counter_fees) = if is_offer {
        (offer_fees, accept_fees)
    } else {
        (accept_fees, offer_fees)
    };

    let own_reserve_msat = channel_details.unspendable_punishment_reserve.unwrap_or(0) * 1000;
    let counter_reserve_msat = channel_details.counterparty.unspendable_punishment_reserve * 1000;

    let own_value_to_self_msat = (channel_details.outbound_capacity_msat + own_reserve_msat)
        .checked_sub((own_collateral + own_fees) * 1000)
        .ok_or_else(|| {
            Error::InvalidParameters(format!(
                "Not enough outbound capacity to establish given contract. Want {} but have {}",
                (own_collateral + own_fees) * 1000,
                channel_details.outbound_capacity_msat + own_reserve_msat
            ))
        })?;
    // TODO(tibo): find better ways to validate amounts + take into account increased fees.
    if own_value_to_self_msat < dlc::DUST_LIMIT * 1000 {
        return Err(Error::InvalidParameters(format!(
            "Not enough outbound capacity to establish given contract. Want {} but have {}",
            dlc::DUST_LIMIT * 1000,
            own_value_to_self_msat
        )));
    }

    let counter_value_to_self_msat = (channel_details.inbound_capacity_msat + counter_reserve_msat)
        .checked_sub((counter_collateral + counter_fees) * 1000)
        .ok_or_else(|| {
            Error::InvalidParameters(format!(
                "Not enough inbound capacity to establish given contract. Want {} but have {}",
                (counter_collateral + counter_fees) * 1000,
                channel_details.inbound_capacity_msat + counter_reserve_msat
            ))
        })?;
    // TODO(tibo): find better ways to validate amounts + take into account increased fees.
    if counter_value_to_self_msat < dlc::DUST_LIMIT * 1000 {
        return Err(Error::InvalidParameters(format!(
            "Not enough inbound capacity to establish given contract. Want {} but have {}",
            dlc::DUST_LIMIT * 1000,
            counter_value_to_self_msat
        )));
    }

    Ok((own_value_to_self_msat, counter_value_to_self_msat))
}

// Return fees for offer and accept parties (in that order). Offer pays 1 more
// if total fee is not even.
fn per_party_fee(fee_rate: u64) -> (u64, u64) {
    let total_fee = (dlc::channel::sub_channel::dlc_channel_and_split_fee(fee_rate)
        + dlc::util::weight_to_fee(LN_GLUE_TX_WEIGHT, fee_rate)) as f64;
    (
        (total_fee / 2.0).ceil() as u64,
        (total_fee / 2.0).floor() as u64,
    )
}
