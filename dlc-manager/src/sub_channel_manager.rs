//!
//!
//!
use std::ops::Deref;

use bitcoin::{OutPoint, PackedLockTime, Script, Sequence, Transaction};
use dlc::channel::{
    get_tx_adaptor_signature,
    sub_channel::{SplitTx, LN_GLUE_TX_WEIGHT},
};
use dlc_messages::{
    channel::{AcceptChannel, OfferChannel},
    oracle_msgs::OracleAnnouncement,
    ser_impls::{read_ecdsa_adaptor_signature, write_ecdsa_adaptor_signature},
    sub_channel::{
        SubChannelAccept, SubChannelConfirm, SubChannelFinalize, SubChannelMessage, SubChannelOffer,
    },
    FundingSignatures,
};
use lightning::{
    chain::{
        chaininterface::{BroadcasterInterface, FeeEstimator},
        keysinterface::{KeysInterface, Sign},
    },
    ln::{
        chan_utils::{build_commitment_secret, derive_private_key},
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
        get_object_in_state!(
            $manager,
            $channel_id,
            $state,
            $peer_id,
            SubChannel,
            get_sub_channel
        )
    }};
}

#[derive(Debug, Clone)]
///
pub enum SubChannel {
    ///
    Offered(OfferedSubChannel),
    ///
    Accepted(AcceptedSubChannel),
    ///
    Signed(SignedSubChannel),
    ///
    Closing(ClosingSubChannel),
}

impl SubChannel {
    ///
    pub fn get_counter_party_id(&self) -> PublicKey {
        match self {
            SubChannel::Offered(o) => o.counter_party,
            SubChannel::Accepted(a) => a.counter_party,
            SubChannel::Signed(s) => s.counter_party,
            SubChannel::Closing(s) => s.signed_sub_channel.counter_party,
        }
    }

    /// Return the id associated with the sub-channel.
    pub fn get_id(&self) -> ChannelId {
        match self {
            SubChannel::Offered(o) => o.channel_id,
            SubChannel::Accepted(a) => a.channel_id,
            SubChannel::Signed(s) => s.channel_id,
            SubChannel::Closing(c) => c.signed_sub_channel.channel_id,
        }
    }
}

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
    /// The  for the channel.
    pub channel_id: ChannelId,
    /// The [`secp256k1_zkp::PublicKey`] of the counter party's node.
    pub counter_party: PublicKey,
    ///
    pub party_base_points: PartyBasePoints,
    /// The current per update point of the local party.
    pub per_split_point: PublicKey,
    /// The image of the seed used by the local party to derive all per update
    /// points (Will be `None` on the accept party side.)
    pub per_split_seed: Option<PublicKey>,
    /// The current fee rate to be used to create transactions.
    pub fee_rate_per_vb: u64,
    ///
    pub is_offer: bool,
}

impl_dlc_writeable!(OfferedSubChannel, {
    (channel_id, writeable),
    (counter_party, writeable),
    (party_base_points, writeable),
    (per_split_point, writeable),
    (per_split_seed, writeable),
    (fee_rate_per_vb, writeable),
    (is_offer, writeable)
});

#[derive(Debug, Clone)]
///
pub struct AcceptedSubChannel {
    /// The  for the channel.
    pub channel_id: ChannelId,
    /// The [`secp256k1_zkp::PublicKey`] of the counter party's node.
    pub counter_party: PublicKey,
    /// The current per update point of the offer party.
    pub offer_per_split_point: PublicKey,
    /// The current per update point of the accept party.
    pub accept_per_split_point: PublicKey,
    ///
    pub offer_base_points: PartyBasePoints,
    ///
    pub accept_base_points: PartyBasePoints,
    ///
    pub accept_split_adaptor_signature: EcdsaAdaptorSignature,
    /// The image of the seed used by the local party to derive all per update
    /// points (Will be `None` on the accept party side.)
    pub per_split_seed: PublicKey,
    ///
    pub split_tx: SplitTx,
    ///
    pub is_offer: bool,
    ///
    pub fund_value_satoshis: u64,
    ///
    pub original_funding_redeemscript: Script,
    ///
    pub ln_glue_transaction: Transaction,
}

impl_dlc_writeable_external!(SplitTx, split_tx, {(transaction, writeable), (output_script, writeable)});

impl_dlc_writeable!(AcceptedSubChannel, {
    (channel_id, writeable),
    (counter_party, writeable),
    (offer_per_split_point, writeable),
    (accept_per_split_point, writeable),
    (offer_base_points, writeable),
    (accept_base_points, writeable),
    (accept_split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (per_split_seed, writeable),
    (split_tx, {cb_writeable, split_tx::write, split_tx::read}),
    (is_offer, writeable),
    (fund_value_satoshis, writeable),
    (original_funding_redeemscript, writeable),
    (ln_glue_transaction, writeable)
});

#[derive(Debug, Clone)]
///
pub struct SignedSubChannel {
    /// The id for the channel.
    pub channel_id: ChannelId,
    /// The [`secp256k1_zkp::PublicKey`] of the counter party's node.
    pub counter_party: PublicKey,
    /// The current per split point of the local party.
    pub own_per_split_point: PublicKey,
    /// The current per split point of the remote party.
    pub counter_per_split_point: PublicKey,
    ///
    pub own_points: PartyBasePoints,
    ///
    pub counter_points: PartyBasePoints,
    ///
    pub own_split_adaptor_signature: EcdsaAdaptorSignature,
    ///
    pub counter_split_adaptor_signature: EcdsaAdaptorSignature,
    /// The image of the seed used by the local party to derive all per update
    /// points (Will be `None` on the accept party side.)
    pub per_split_seed: PublicKey,
    ///
    pub split_tx: SplitTx,
    ///
    pub is_offer: bool,
    ///
    pub fund_value_satoshis: u64,
    ///
    pub original_funding_redeemscript: Script,
    ///
    pub ln_glue_transaction: Transaction,
    ///
    pub counter_glue_signature: Signature,
}

impl_dlc_writeable!(SignedSubChannel, {
    (channel_id, writeable),
    (counter_party, writeable),
    (own_per_split_point, writeable),
    (counter_per_split_point, writeable),
    (own_points, writeable),
    (counter_points, writeable),
    (own_split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (counter_split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (per_split_seed, writeable),
    (split_tx, {cb_writeable, split_tx::write, split_tx::read}),
    (is_offer, writeable),
    (fund_value_satoshis, writeable),
    (original_funding_redeemscript, writeable),
    (ln_glue_transaction, writeable),
    (counter_glue_signature, writeable)
});

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
    time: T,
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
        time: T,
    ) -> Self {
        SubChannelManager {
            secp,
            wallet,
            ln_channel_manager,
            store,
            blockchain,
            dlc_channel_manager,
            time,
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
                return Ok(None);
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
            .ok_or(Error::InvalidParameters(format!(
                "Unknown LN channel {:02x?}",
                channel_id
            )))?;

        validate_and_get_ln_values_per_party(
            &channel_details,
            contract_input.offer_collateral,
            contract_input.accept_collateral,
            contract_input.fee_rate,
        )?;

        let per_split_seed = self.wallet.get_new_secret_key()?;
        let per_split_secret = SecretKey::from_slice(&build_commitment_secret(
            per_split_seed.as_ref(),
            INITIAL_SPLIT_NUMBER,
        ))
        .expect("a valid secret key.");

        let next_per_split_point = PublicKey::from_secret_key(&self.secp, &per_split_secret);
        let per_split_seed_pk = PublicKey::from_secret_key(&self.secp, &per_split_seed);
        let party_base_points = crate::utils::get_party_base_points(&self.secp, &self.wallet)?;

        let (mut offered_channel, mut offered_contract) = crate::channel_updater::offer_channel(
            &self.secp,
            contract_input,
            &channel_details.counterparty.node_id,
            &oracle_announcements,
            crate::manager::CET_NSEQUENCE,
            crate::manager::REFUND_DELAY,
            &self.wallet,
            &self.blockchain,
            &self.time,
            true,
        )?;

        // TODO(tibo): refactor properly.
        offered_contract.offer_params.inputs = Vec::new();
        offered_contract.funding_inputs_info = Vec::new();

        offered_channel.temporary_channel_id = channel_id.clone();

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
            cet_locktime: offered_contract.cet_locktime,
            refund_locktime: offered_contract.refund_locktime,
            cet_nsequence: crate::manager::CET_NSEQUENCE,
            fee_rate_per_vbyte: contract_input.fee_rate,
        };

        let offered_sub_channel = OfferedSubChannel {
            channel_id: channel_details.channel_id,
            counter_party: channel_details.counterparty.node_id,
            per_split_point: next_per_split_point,
            per_split_seed: Some(per_split_seed_pk),
            fee_rate_per_vb: contract_input.fee_rate,
            is_offer: false,
            party_base_points,
        };

        self.store
            .upsert_sub_channel(&SubChannel::Offered(offered_sub_channel))?;
        self.store.upsert_channel(
            Channel::Offered(offered_channel),
            Some(Contract::Offered(offered_contract)),
        )?;

        Ok(msg)
    }

    ///
    pub fn accept_sub_channel(
        &self,
        channel_id: &ChannelId,
    ) -> Result<(PublicKey, SubChannelAccept), Error> {
        let offered_sub_channel =
            get_sub_channel_in_state!(self, *channel_id, Offered, None as Option<PublicKey>)?;

        let per_split_seed = self.wallet.get_new_secret_key()?;
        let per_split_secret = SecretKey::from_slice(&build_commitment_secret(
            per_split_seed.as_ref(),
            INITIAL_SPLIT_NUMBER,
        ))
        .expect("a valid secret key.");

        let next_per_split_point = PublicKey::from_secret_key(&self.secp, &per_split_secret);
        let per_split_seed_pk = PublicKey::from_secret_key(&self.secp, &per_split_seed);

        let channel_details = self
            .ln_channel_manager
            .get_channel_details(channel_id)
            .ok_or(Error::InvalidParameters(format!(
                "Unknown LN channel {:02x?}",
                channel_id
            )))?;

        let fund_value_satoshis = channel_details.channel_value_satoshis;

        let offered_channel =
            get_channel_in_state!(self, channel_id, Offered, None as Option<PublicKey>)?;

        let offered_contract = get_contract_in_state!(
            self,
            &offered_channel.offered_contract_id,
            Offered,
            None as Option<PublicKey>
        )?;

        // Revalidate in case channel capacity has changed since receiving the offer.
        let (own_to_self_msat, counter_to_self_msat) = validate_and_get_ln_values_per_party(
            &channel_details,
            offered_contract.total_collateral - offered_contract.offer_params.collateral,
            offered_contract.offer_params.collateral,
            offered_contract.fee_rate_per_vb,
        )?;

        let funding_redeemscript = channel_details
            .funding_redeemscript
            .as_ref()
            .unwrap()
            .clone();

        let funding_txo = channel_details
            .funding_txo
            .expect("to have a funding tx output");

        let accept_points = crate::utils::get_party_base_points(&self.secp, &self.wallet)?;

        let offer_revoke_params = offered_sub_channel.party_base_points.get_revokable_params(
            &self.secp,
            &accept_points.revocation_basepoint,
            &offered_sub_channel.per_split_point,
        );

        let accept_revoke_params = accept_points.get_revokable_params(
            &self.secp,
            &offered_sub_channel.party_base_points.revocation_basepoint,
            &next_per_split_point,
        );

        let own_base_secret_key = self
            .wallet
            .get_secret_key_for_pubkey(&accept_points.own_basepoint)?;
        let own_secret_key =
            derive_private_key(&self.secp, &next_per_split_point, &own_base_secret_key);

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

        debug_assert_eq!(
            (channel_details.channel_value_satoshis) * 1000,
            channel_details.inbound_capacity_msat
                + channel_details.outbound_capacity_msat
                + channel_details.unspendable_punishment_reserve.unwrap_or(0) * 1000
                + channel_details.counterparty.unspendable_punishment_reserve * 1000
        );

        // TODO(tibo): remove or fix this assert to work with msat properly (div instead of mul)
        debug_assert_eq!(
            ln_output_value * 1000,
            own_to_self_msat
                + counter_to_self_msat
                + dlc::util::weight_to_fee(LN_GLUE_TX_WEIGHT, offered_contract.fee_rate_per_vb)?
                    * 1000
        );

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
            - dlc::util::weight_to_fee(LN_GLUE_TX_WEIGHT, offered_contract.fee_rate_per_vb)?;

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
            revocation_basepoint: accept_points.revocation_basepoint,
            publish_basepoint: accept_points.publish_basepoint,
            own_basepoint: accept_points.own_basepoint,
            commit_signature: commitment_signed.signature,
            htlc_signatures: commitment_signed.htlc_signatures.clone(),
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
            channel_id: *channel_id,
            counter_party: offered_sub_channel.counter_party,
            offer_per_split_point: offered_sub_channel.per_split_point,
            accept_per_split_point: next_per_split_point,
            accept_split_adaptor_signature: split_tx_adaptor_signature,
            per_split_seed: per_split_seed_pk,
            split_tx,
            offer_base_points: offered_sub_channel.party_base_points,
            accept_base_points: accept_points,
            is_offer: false,
            fund_value_satoshis,
            original_funding_redeemscript: funding_redeemscript,
            ln_glue_transaction: ln_glue_tx,
        };

        self.store
            .upsert_sub_channel(&SubChannel::Accepted(accepted_sub_channel))?;
        self.store.upsert_channel(
            Channel::Accepted(accepted_channel),
            Some(Contract::Accepted(accepted_contract)),
        )?;

        Ok((offered_sub_channel.counter_party, msg))
    }

    ///
    pub fn initiate_force_close_sub_channels(&self, channel_id: &ChannelId) -> Result<(), Error> {
        let signed = get_sub_channel_in_state!(self, *channel_id, Signed, None::<PublicKey>)?;

        let channel_details = self
            .ln_channel_manager
            .get_channel_details(channel_id)
            .unwrap();

        let publish_base_secret = self
            .wallet
            .get_secret_key_for_pubkey(&signed.own_points.publish_basepoint)?;

        let publish_sk = derive_private_key(
            &self.secp,
            &signed.own_per_split_point,
            &publish_base_secret,
        );

        let counter_split_signature = signed
            .counter_split_adaptor_signature
            .decrypt(&publish_sk)?;

        let mut split_tx = signed.split_tx.transaction.clone();

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
                        &fund_sk,
                    )
                    .unwrap(),
                );
                dlc::util::sign_multi_sig_input(
                    &self.secp,
                    &mut split_tx,
                    &counter_split_signature,
                    &channel_details.counter_funding_pubkey,
                    &fund_sk,
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
            signed_sub_channel: signed,
        };

        self.store
            .upsert_sub_channel(&SubChannel::Closing(closing_sub_channel))?;

        Ok(())
    }

    ///
    pub fn finalize_force_close_sub_channels(&self, channel_id: &ChannelId) -> Result<(), Error> {
        let closing = get_sub_channel_in_state!(self, *channel_id, Closing, None::<PublicKey>)?;

        let split_tx_confs = self.blockchain.get_transaction_confirmations(
            &closing.signed_sub_channel.split_tx.transaction.txid(),
        )?;

        if split_tx_confs < crate::manager::CET_NSEQUENCE {
            return Err(Error::InvalidState(format!(
                "NSequence hasn't elapsed yet, need {} more blocks",
                crate::manager::CET_NSEQUENCE - split_tx_confs
            )));
        }

        let signed_sub_channel = &closing.signed_sub_channel;
        let counter_party = closing.signed_sub_channel.counter_party;
        let mut glue_tx = closing.signed_sub_channel.ln_glue_transaction.clone();

        let own_revoke_params = signed_sub_channel.own_points.get_revokable_params(
            &self.secp,
            &signed_sub_channel.counter_points.revocation_basepoint,
            &signed_sub_channel.own_per_split_point,
        );

        let counter_revoke_params = signed_sub_channel.counter_points.get_revokable_params(
            &self.secp,
            &signed_sub_channel.own_points.revocation_basepoint,
            &signed_sub_channel.counter_per_split_point,
        );

        let (offer_params, accept_params) = if signed_sub_channel.is_offer {
            (&own_revoke_params, &counter_revoke_params)
        } else {
            (&counter_revoke_params, &own_revoke_params)
        };

        let own_base_secret_key = self
            .wallet
            .get_secret_key_for_pubkey(&signed_sub_channel.own_points.own_basepoint)?;
        let own_secret_key = derive_private_key(
            &self.secp,
            &signed_sub_channel.own_per_split_point,
            &own_base_secret_key,
        );

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
            .force_close_sub_channel(channel_id, closing)?;

        self.ln_channel_manager
            .force_close_channel(channel_id, &counter_party)?;

        Ok(())
    }

    fn on_subchannel_offer(
        &self,
        sub_channel_offer: &SubChannelOffer,
        counter_party: &PublicKey,
    ) -> Result<(), Error> {
        let channel_details = self
            .ln_channel_manager
            .get_channel_details(&sub_channel_offer.channel_id)
            .ok_or(Error::InvalidParameters(format!(
                "Unknown channel {:02x?}",
                sub_channel_offer.channel_id
            )))?;

        validate_and_get_ln_values_per_party(
            &channel_details,
            sub_channel_offer.contract_info.get_total_collateral()
                - sub_channel_offer.offer_collateral,
            sub_channel_offer.offer_collateral,
            sub_channel_offer.fee_rate_per_vbyte,
        )?;

        // TODO(tibo): validate subchannel is valid wrt current channel conditions.

        let offered_sub_channel = OfferedSubChannel {
            is_offer: false,
            channel_id: sub_channel_offer.channel_id,
            counter_party: *counter_party,
            per_split_point: sub_channel_offer.next_per_split_point,
            per_split_seed: None,
            fee_rate_per_vb: sub_channel_offer.fee_rate_per_vbyte,
            party_base_points: PartyBasePoints {
                own_basepoint: sub_channel_offer.own_basepoint,
                revocation_basepoint: sub_channel_offer.revocation_basepoint,
                publish_basepoint: sub_channel_offer.publish_basepoint,
            },
        };

        let offer_channel = OfferChannel {
            protocol_version: 0, //unused
            contract_flags: 0,   //unused
            chain_hash: [0; 32], //unused
            temporary_contract_id: offered_sub_channel.channel_id,
            temporary_channel_id: offered_sub_channel.channel_id,
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
            fee_rate_per_vb: offered_sub_channel.fee_rate_per_vb,
            cet_locktime: sub_channel_offer.cet_locktime,
            refund_locktime: sub_channel_offer.refund_locktime,
            cet_nsequence: sub_channel_offer.cet_nsequence,
        };

        let (offered_channel, offered_contract) =
            OfferedChannel::from_offer_channel(&offer_channel, *counter_party)?;

        self.store
            .upsert_sub_channel(&SubChannel::Offered(offered_sub_channel))?;
        self.store.upsert_channel(
            Channel::Offered(offered_channel),
            Some(Contract::Offered(offered_contract)),
        )?;

        Ok(())
    }

    fn on_subchannel_accept(
        &self,
        sub_channel_accept: &SubChannelAccept,
        counter_party: &PublicKey,
    ) -> Result<SubChannelConfirm, Error> {
        let offered_sub_channel = get_sub_channel_in_state!(
            self,
            sub_channel_accept.channel_id,
            Offered,
            Some(*counter_party)
        )?;

        let channel_details = self
            .ln_channel_manager
            .get_channel_details(&sub_channel_accept.channel_id)
            .ok_or(Error::InvalidParameters(format!(
                "Unknown LN channel {:02x?}",
                sub_channel_accept.channel_id
            )))?;

        let fund_value_satoshis = channel_details.channel_value_satoshis;

        let offer_revoke_params = offered_sub_channel.party_base_points.get_revokable_params(
            &self.secp,
            &sub_channel_accept.revocation_basepoint,
            &offered_sub_channel.per_split_point,
        );

        let accept_points = PartyBasePoints {
            own_basepoint: sub_channel_accept.own_basepoint,
            revocation_basepoint: sub_channel_accept.revocation_basepoint,
            publish_basepoint: sub_channel_accept.publish_basepoint,
        };

        let accept_revoke_params = accept_points.get_revokable_params(
            &self.secp,
            &offered_sub_channel.party_base_points.revocation_basepoint,
            &sub_channel_accept.first_per_split_point,
        );

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
            .get_secret_key_for_pubkey(&offered_sub_channel.party_base_points.own_basepoint)?;
        let own_secret_key = derive_private_key(
            &self.secp,
            &offered_sub_channel.per_split_point,
            &own_base_secret_key,
        );

        let glue_tx_output_value = ln_output_value
            - dlc::util::weight_to_fee(LN_GLUE_TX_WEIGHT, offered_contract.fee_rate_per_vb)?;

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

        // TODO(tibo): consider having separate ids.
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
            per_split_secret: SecretKey::from_slice(&revoke_and_ack.per_commitment_secret)
                .expect("a valid secret key"),
            next_per_commitment_point: revoke_and_ack.next_per_commitment_point,
            split_adaptor_signature: split_tx_adaptor_signature,
            commit_signature: commitment_signed.signature,
            htlc_signatures: commitment_signed.htlc_signatures.clone(),
            cet_adaptor_signatures: sign_channel.cet_adaptor_signatures,
            buffer_adaptor_signature: sign_channel.buffer_adaptor_signature,
            refund_signature: sign_channel.refund_signature,
            ln_glue_signature,
        };

        let signed_sub_channel = SignedSubChannel {
            channel_id: sub_channel_accept.channel_id,
            counter_party: *counter_party,
            own_per_split_point: offered_sub_channel.per_split_point,
            counter_per_split_point: sub_channel_accept.first_per_split_point,
            own_points: offered_sub_channel.party_base_points.clone(),
            counter_points: accept_points,
            own_split_adaptor_signature: split_tx_adaptor_signature,
            counter_split_adaptor_signature: sub_channel_accept.split_adaptor_signature,
            per_split_seed: offered_sub_channel
                .per_split_seed
                .expect("to have a per split seed"),
            split_tx,
            is_offer: true,
            fund_value_satoshis,
            original_funding_redeemscript: funding_redeemscript,
            counter_glue_signature: sub_channel_accept.ln_glue_signature,
            ln_glue_transaction: ln_glue_tx,
        };

        self.store
            .upsert_sub_channel(&SubChannel::Signed(signed_sub_channel))?;
        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Signed(signed_contract)),
        )?;

        Ok(msg)
    }

    fn on_subchannel_confirm(
        &self,
        sub_channel_confirm: &SubChannelConfirm,
        counter_party: &PublicKey,
    ) -> Result<SubChannelFinalize, Error> {
        let accepted_sub_channel = get_sub_channel_in_state!(
            self,
            sub_channel_confirm.channel_id,
            Accepted,
            Some(*counter_party)
        )?;

        let raa = RevokeAndACK {
            channel_id: sub_channel_confirm.channel_id,
            per_commitment_secret: sub_channel_confirm.per_split_secret.as_ref().clone(),
            next_per_commitment_point: sub_channel_confirm.next_per_commitment_point,
        };

        let channel_details = self
            .ln_channel_manager
            .get_channel_details(&sub_channel_confirm.channel_id)
            .ok_or(Error::InvalidParameters(format!(
                "Unknown LN channel {:02x?}",
                sub_channel_confirm.channel_id
            )))?;

        let accept_revoke_params = accepted_sub_channel
            .accept_base_points
            .get_revokable_params(
                &self.secp,
                &accepted_sub_channel.offer_base_points.revocation_basepoint,
                &accepted_sub_channel.accept_per_split_point,
            );

        let funding_redeemscript = &accepted_sub_channel.original_funding_redeemscript;

        dlc::channel::verify_tx_adaptor_signature(
            &self.secp,
            &accepted_sub_channel.split_tx.transaction,
            accepted_sub_channel.fund_value_satoshis,
            &funding_redeemscript,
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

        let offer_revoke_params = accepted_sub_channel.offer_base_points.get_revokable_params(
            &self.secp,
            &accepted_sub_channel.accept_base_points.revocation_basepoint,
            &accepted_sub_channel.offer_per_split_point,
        );

        let sub_channel_info = SubChannelVerifyInfo {
            funding_info: FundingInfo {
                funding_tx: accepted_sub_channel.split_tx.transaction.clone(),
                funding_script_pubkey: accepted_sub_channel.split_tx.output_script.clone(),
                funding_input_value: accepted_sub_channel.split_tx.transaction.output[1].value,
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
            channel_id: accepted_sub_channel.channel_id,
            counter_party: *counter_party,
            own_per_split_point: accepted_sub_channel.accept_per_split_point,
            counter_per_split_point: accepted_sub_channel.offer_per_split_point,
            own_points: accepted_sub_channel.accept_base_points,
            counter_points: accepted_sub_channel.offer_base_points,
            own_split_adaptor_signature: accepted_sub_channel.accept_split_adaptor_signature,
            counter_split_adaptor_signature: sub_channel_confirm.split_adaptor_signature,
            per_split_seed: accepted_sub_channel.per_split_seed,
            split_tx: accepted_sub_channel.split_tx.clone(),
            is_offer: false,
            fund_value_satoshis: accepted_sub_channel.fund_value_satoshis,
            original_funding_redeemscript: accepted_sub_channel.original_funding_redeemscript,
            counter_glue_signature: sub_channel_confirm.ln_glue_signature,
            ln_glue_transaction: accepted_sub_channel.ln_glue_transaction.clone(),
        };

        let msg = SubChannelFinalize {
            channel_id: sub_channel_confirm.channel_id,
            per_split_secret: SecretKey::from_slice(&revoke_and_ack.per_commitment_secret)
                .expect("a valid secret key"),
            next_per_commitment_point: revoke_and_ack.next_per_commitment_point,
        };

        self.store
            .upsert_sub_channel(&SubChannel::Signed(signed_sub_channel))?;
        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Confirmed(signed_contract)),
        )?;

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
            Some(counter_party.clone())
        )?;
        let contract = get_contract_in_state!(
            self,
            &channel.get_contract_id().ok_or(Error::InvalidState(
                "No contract id in on_sub_channel_finalize".to_string()
            ))?,
            Signed,
            Some(counter_party.clone())
        )?;
        let raa = RevokeAndACK {
            channel_id: sub_channel_finalize.channel_id,
            per_commitment_secret: sub_channel_finalize.per_split_secret.secret_bytes(),
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
}

fn validate_and_get_ln_values_per_party(
    channel_details: &ChannelDetails,
    own_collateral: u64,
    counter_collateral: u64,
    fee_rate: u64,
) -> Result<(u64, u64), Error> {
    let total_fee = dlc::util::weight_to_fee(
        dlc::channel::sub_channel::DLC_CHANNEL_AND_SPLIT_MIN_WEIGHT + LN_GLUE_TX_WEIGHT,
        fee_rate,
    )? as f64;
    let per_party_fee = (total_fee / 2.0) as u64;

    let own_reserve_msat = channel_details.unspendable_punishment_reserve.unwrap_or(0) * 1000;
    let counter_reserve_msat = channel_details.counterparty.unspendable_punishment_reserve * 1000;

    let own_value_to_self_msat = (channel_details.outbound_capacity_msat + own_reserve_msat)
        .checked_sub((own_collateral + per_party_fee) * 1000)
        .ok_or(Error::InvalidParameters(format!(
            "Not enough outbound capacity to establish given contract. Want {} but have {}",
            (own_collateral + per_party_fee) * 1000,
            channel_details.outbound_capacity_msat + own_reserve_msat
        )))?;
    // TODO(tibo): find better ways to validate amounts + take into account increased fees.
    if own_value_to_self_msat < dlc::DUST_LIMIT * 1000 {
        return Err(Error::InvalidParameters(format!(
            "Not enough outbound capacity to establish given contract. Want {} but have {}",
            dlc::DUST_LIMIT * 1000,
            own_value_to_self_msat
        )));
    }

    let counter_value_to_self_msat = (channel_details.inbound_capacity_msat + counter_reserve_msat)
        .checked_sub((counter_collateral + per_party_fee) * 1000)
        .ok_or(Error::InvalidParameters(format!(
            "Not enough inbound capacity to establish given contract. Want {} but have {}",
            (counter_collateral + per_party_fee) * 1000,
            channel_details.inbound_capacity_msat + counter_reserve_msat
        )))?;
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
