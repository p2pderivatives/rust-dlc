//! #Manager a component to create and update DLCs.

use super::{Blockchain, Oracle, Storage, Time, Wallet};
use crate::chain_monitor::{ChainMonitor, ChannelInfo, RevokedTxType, TxType};
use crate::channel::offered_channel::OfferedChannel;
use crate::channel::signed_channel::{SignedChannel, SignedChannelState, SignedChannelStateType};
use crate::channel::Channel;
use crate::channel_updater::get_signed_channel_state;
use crate::channel_updater::verify_signed_channel;
use crate::contract::{
    accepted_contract::AcceptedContract, contract_info::ContractInfo,
    contract_input::ContractInput, contract_input::OracleInput, offered_contract::OfferedContract,
    signed_contract::SignedContract, AdaptorInfo, ClosedContract, Contract, FailedAcceptContract,
    FailedSignContract, PreClosedContract,
};
use crate::contract_updater::{accept_contract, verify_accepted_and_sign_contract};
use crate::error::Error;
use crate::Signer;
use crate::{ChannelId, ContractId};
use bitcoin::Address;
use bitcoin::Transaction;
use dlc_messages::channel::{
    AcceptChannel, CollaborativeCloseOffer, OfferChannel, Reject, RenewAccept, RenewConfirm,
    RenewFinalize, RenewOffer, SettleAccept, SettleConfirm, SettleFinalize, SettleOffer,
    SignChannel,
};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::{AcceptDlc, Message as DlcMessage, OfferDlc, SignDlc};
use lightning::chain::chaininterface::FeeEstimator;
use lightning::ln::chan_utils::{
    build_commitment_secret, derive_private_key, derive_private_revocation_key,
};
use log::{error, warn};
use secp256k1_zkp::XOnlyPublicKey;
use secp256k1_zkp::{ecdsa::Signature, All, PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;
use std::ops::Deref;
use std::string::ToString;

/// The number of confirmations required before moving the the confirmed state.
pub const NB_CONFIRMATIONS: u32 = 6;
/// The delay to set the refund value to.
pub const REFUND_DELAY: u32 = 86400 * 7;
/// The nSequence value used for CETs in DLC channels
pub const CET_NSEQUENCE: u32 = 288;
/// Timeout in seconds when waiting for a peer's reply, after which a DLC channel
/// is forced closed.
pub const PEER_TIMEOUT: u64 = 3600;

type ClosableContractInfo<'a> = Option<(
    &'a ContractInfo,
    &'a AdaptorInfo,
    Vec<(usize, OracleAttestation)>,
)>;

/// Used to create and update DLCs.
pub struct Manager<W: Deref, B: Deref, S: Deref, O: Deref, T: Deref, F: Deref>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
    F::Target: FeeEstimator,
{
    oracles: HashMap<XOnlyPublicKey, O>,
    wallet: W,
    blockchain: B,
    store: S,
    secp: Secp256k1<All>,
    chain_monitor: ChainMonitor,
    time: T,
    fee_estimator: F,
}

macro_rules! get_object_in_state {
    ($manager: ident, $id: expr, $state: ident, $peer_id: expr, $object_type: ident, $get_call: ident) => {{
        let object = $manager.store.$get_call($id)?;
        match object {
            Some(c) => {
                if let Some(p) = $peer_id as Option<PublicKey> {
                    if c.get_counter_party_id() != p {
                        return Err(Error::InvalidParameters(format!(
                            "Peer {:02x?} is not involved with contract {:02x?}.",
                            $peer_id, $id
                        )));
                    }
                }
                match c {
                    $object_type::$state(s) => Ok(s),
                    _ => Err(Error::InvalidState(format!(
                        "Invalid state {:?} expected {}.",
                        c,
                        stringify!($state),
                    ))),
                }
            }
            None => Err(Error::InvalidParameters(format!(
                "Unknown {} id.",
                stringify!($object_type)
            ))),
        }
    }};
}

macro_rules! get_contract_in_state {
    ($manager: ident, $contract_id: expr, $state: ident, $peer_id: expr) => {{
        get_object_in_state!(
            $manager,
            $contract_id,
            $state,
            $peer_id,
            Contract,
            get_contract
        )
    }};
}

macro_rules! get_channel_in_state {
    ($manager: ident, $channel_id: expr, $state: ident, $peer_id: expr) => {{
        get_object_in_state!(
            $manager,
            $channel_id,
            $state,
            $peer_id,
            Channel,
            get_channel
        )
    }};
}

macro_rules! get_signed_channel_rollback_state {
    ($signed_channel: ident, $state: ident, $($field: ident),*) => {{
       match $signed_channel.roll_back_state.as_ref() {
           Some(SignedChannelState::$state{$($field,)* ..}) => Ok(($($field,)*)),
           _ => Err(Error::InvalidState(format!("Expected rollback state {} got {:?}", stringify!($state), $signed_channel.state))),
        }
    }};
}

macro_rules! check_for_timed_out_channels {
    ($manager: ident, $state: ident) => {
        let channels = $manager
            .store
            .get_signed_channels(Some(SignedChannelStateType::$state))?;

        for channel in channels {
            if let SignedChannelState::$state { timeout, .. } = channel.state {
                let is_timed_out = timeout < $manager.time.unix_time_now();
                if is_timed_out {
                    match $manager.force_close_channel_internal(channel) {
                        Err(e) => error!("Error force closing channel {}", e),
                        _ => {}
                    }
                }
            }
        }
    };
}

impl<W: Deref, B: Deref, S: Deref, O: Deref, T: Deref, F: Deref> Manager<W, B, S, O, T, F>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
    F::Target: FeeEstimator,
{
    /// Create a new Manager struct.
    pub fn new(
        wallet: W,
        blockchain: B,
        store: S,
        oracles: HashMap<XOnlyPublicKey, O>,
        time: T,
        fee_estimator: F,
    ) -> Result<Self, Error> {
        let init_height = blockchain.get_blockchain_height()?;
        let chain_monitor = store
            .get_chain_monitor()?
            .unwrap_or(ChainMonitor::new(init_height));

        Ok(Manager {
            secp: secp256k1_zkp::Secp256k1::new(),
            wallet,
            blockchain,
            store,
            oracles,
            time,
            fee_estimator,
            chain_monitor,
        })
    }

    /// Get the store from the Manager to access contracts.
    pub fn get_store(&self) -> &S {
        &self.store
    }

    #[doc(hidden)]
    pub fn get_mut_store(&mut self) -> &mut S {
        &mut self.store
    }

    /// Function called to pass a DlcMessage to the Manager.
    pub fn on_dlc_message(
        &mut self,
        msg: &DlcMessage,
        counter_party: PublicKey,
    ) -> Result<Option<DlcMessage>, Error> {
        match msg {
            DlcMessage::Offer(o) => {
                self.on_offer_message(o, counter_party)?;
                Ok(None)
            }
            DlcMessage::Accept(a) => Ok(Some(self.on_accept_message(a, &counter_party)?)),
            DlcMessage::Sign(s) => {
                self.on_sign_message(s, &counter_party)?;
                Ok(None)
            }
            DlcMessage::OfferChannel(o) => {
                self.on_offer_channel(o, counter_party)?;
                Ok(None)
            }
            DlcMessage::AcceptChannel(a) => Ok(Some(DlcMessage::SignChannel(
                self.on_accept_channel(a, &counter_party)?,
            ))),
            DlcMessage::SignChannel(s) => {
                self.on_sign_channel(s, &counter_party)?;
                Ok(None)
            }
            DlcMessage::SettleOffer(s) => match self.on_settle_offer(s, &counter_party)? {
                Some(msg) => Ok(Some(DlcMessage::Reject(msg))),
                None => Ok(None),
            },
            DlcMessage::SettleAccept(s) => Ok(Some(DlcMessage::SettleConfirm(
                self.on_settle_accept(s, &counter_party)?,
            ))),
            DlcMessage::SettleConfirm(s) => Ok(Some(DlcMessage::SettleFinalize(
                self.on_settle_confirm(s, &counter_party)?,
            ))),
            DlcMessage::SettleFinalize(s) => {
                self.on_settle_finalize(s, &counter_party)?;
                Ok(None)
            }
            DlcMessage::RenewOffer(r) => match self.on_renew_offer(r, &counter_party)? {
                Some(msg) => Ok(Some(DlcMessage::Reject(msg))),
                None => Ok(None),
            },
            DlcMessage::RenewAccept(r) => Ok(Some(DlcMessage::RenewConfirm(
                self.on_renew_accept(r, &counter_party)?,
            ))),
            DlcMessage::RenewConfirm(r) => Ok(Some(DlcMessage::RenewFinalize(
                self.on_renew_confirm(r, &counter_party)?,
            ))),
            DlcMessage::RenewFinalize(r) => {
                self.on_renew_finalize(r, &counter_party)?;
                Ok(None)
            }
            DlcMessage::CollaborativeCloseOffer(c) => {
                self.on_collaborative_close_offer(c, &counter_party)?;
                Ok(None)
            }
            DlcMessage::Reject(r) => {
                self.on_reject(r, &counter_party)?;
                Ok(None)
            }
        }
    }

    /// Function called to create a new DLC. The offered contract will be stored
    /// and an OfferDlc message returned.
    pub fn send_offer(
        &mut self,
        contract_input: &ContractInput,
        counter_party: PublicKey,
    ) -> Result<OfferDlc, Error> {
        contract_input.validate()?;

        let oracle_announcements = contract_input
            .contract_infos
            .iter()
            .map(|x| self.get_oracle_announcements(&x.oracles))
            .collect::<Result<Vec<_>, Error>>()?;

        let (offered_contract, offer_msg) = crate::contract_updater::offer_contract(
            &self.secp,
            contract_input,
            oracle_announcements,
            REFUND_DELAY,
            &counter_party,
            &self.wallet,
            &self.blockchain,
            &self.time,
        )?;

        offered_contract.validate()?;

        self.store.create_contract(&offered_contract)?;

        Ok(offer_msg)
    }

    /// Function to call to accept a DLC for which an offer was received.
    pub fn accept_contract_offer(
        &mut self,
        contract_id: &ContractId,
    ) -> Result<(ContractId, PublicKey, AcceptDlc), Error> {
        let offered_contract =
            get_contract_in_state!(self, contract_id, Offered, None as Option<PublicKey>)?;

        let counter_party = offered_contract.counter_party;

        let (accepted_contract, accept_msg) = accept_contract(
            &self.secp,
            &offered_contract,
            &self.wallet,
            &self.blockchain,
        )?;

        self.wallet.import_address(&Address::p2wsh(
            &accepted_contract.dlc_transactions.funding_script_pubkey,
            self.blockchain.get_network()?,
        ))?;

        let contract_id = accepted_contract.get_contract_id();

        self.store
            .update_contract(&Contract::Accepted(accepted_contract))?;

        Ok((contract_id, counter_party, accept_msg))
    }

    /// Function to call to check the state of the currently executing DLCs and
    /// update them if possible.
    pub fn periodic_check(&mut self) -> Result<(), Error> {
        self.check_signed_contracts()?;
        self.check_confirmed_contracts()?;
        self.check_preclosed_contracts()?;
        self.channel_checks()?;

        Ok(())
    }

    fn on_offer_message(
        &mut self,
        offered_message: &OfferDlc,
        counter_party: PublicKey,
    ) -> Result<(), Error> {
        offered_message.validate(&self.secp, REFUND_DELAY, REFUND_DELAY * 2)?;
        let contract: OfferedContract =
            OfferedContract::try_from_offer_dlc(offered_message, counter_party)?;
        contract.validate()?;

        if self.store.get_contract(&contract.id)?.is_some() {
            return Err(Error::InvalidParameters(
                "Contract with identical id already exists".to_string(),
            ));
        }

        self.store.create_contract(&contract)?;

        Ok(())
    }

    fn on_accept_message(
        &mut self,
        accept_msg: &AcceptDlc,
        counter_party: &PublicKey,
    ) -> Result<DlcMessage, Error> {
        let offered_contract = get_contract_in_state!(
            self,
            &accept_msg.temporary_contract_id,
            Offered,
            Some(*counter_party)
        )?;

        let (signed_contract, signed_msg) = match verify_accepted_and_sign_contract(
            &self.secp,
            &offered_contract,
            accept_msg,
            &self.wallet,
        ) {
            Ok(contract) => contract,
            Err(e) => return self.accept_fail_on_error(offered_contract, accept_msg.clone(), e),
        };

        self.wallet.import_address(&Address::p2wsh(
            &signed_contract
                .accepted_contract
                .dlc_transactions
                .funding_script_pubkey,
            self.blockchain.get_network()?,
        ))?;

        self.store
            .update_contract(&Contract::Signed(signed_contract))?;

        Ok(DlcMessage::Sign(signed_msg))
    }

    fn on_sign_message(
        &mut self,
        sign_message: &SignDlc,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let accepted_contract =
            get_contract_in_state!(self, &sign_message.contract_id, Accepted, Some(*peer_id))?;

        let (signed_contract, fund_tx) = match crate::contract_updater::verify_signed_contract(
            &self.secp,
            &accepted_contract,
            sign_message,
            &self.wallet,
        ) {
            Ok(contract) => contract,
            Err(e) => return self.sign_fail_on_error(accepted_contract, sign_message.clone(), e),
        };

        self.store
            .update_contract(&Contract::Signed(signed_contract))?;

        self.blockchain.send_transaction(&fund_tx)?;

        Ok(())
    }

    fn get_oracle_announcements(
        &self,
        oracle_inputs: &OracleInput,
    ) -> Result<Vec<OracleAnnouncement>, Error> {
        let mut announcements = Vec::new();
        for pubkey in &oracle_inputs.public_keys {
            let oracle = self
                .oracles
                .get(pubkey)
                .ok_or_else(|| Error::InvalidParameters("Unknown oracle public key".to_string()))?;
            announcements.push(oracle.get_announcement(&oracle_inputs.event_id)?.clone());
        }

        Ok(announcements)
    }

    fn sign_fail_on_error<R>(
        &mut self,
        accepted_contract: AcceptedContract,
        sign_message: SignDlc,
        e: Error,
    ) -> Result<R, Error> {
        error!("Error in on_sign {}", e);
        self.store
            .update_contract(&Contract::FailedSign(FailedSignContract {
                accepted_contract,
                sign_message,
                error_message: e.to_string(),
            }))?;
        Err(e)
    }

    fn accept_fail_on_error<R>(
        &mut self,
        offered_contract: OfferedContract,
        accept_message: AcceptDlc,
        e: Error,
    ) -> Result<R, Error> {
        error!("Error in on_accept {}", e);
        self.store
            .update_contract(&Contract::FailedAccept(FailedAcceptContract {
                offered_contract,
                accept_message,
                error_message: e.to_string(),
            }))?;
        Err(e)
    }

    fn check_signed_contract(&mut self, contract: &SignedContract) -> Result<(), Error> {
        let confirmations = self.blockchain.get_transaction_confirmations(
            &contract.accepted_contract.dlc_transactions.fund.txid(),
        )?;
        if confirmations >= NB_CONFIRMATIONS {
            self.store
                .update_contract(&Contract::Confirmed(contract.clone()))?;
        }
        Ok(())
    }

    fn check_signed_contracts(&mut self) -> Result<(), Error> {
        for c in self.store.get_signed_contracts()? {
            if let Err(e) = self.check_signed_contract(&c) {
                error!(
                    "Error checking confirmed contract {}: {}",
                    c.accepted_contract.get_contract_id_string(),
                    e
                )
            }
        }

        Ok(())
    }

    fn check_confirmed_contracts(&mut self) -> Result<(), Error> {
        for c in self.store.get_confirmed_contracts()? {
            // Confirmed contracts from channel are processed in channel specific methods.
            if c.channel_id.is_some() {
                continue;
            }
            if let Err(e) = self.check_confirmed_contract(&c) {
                error!(
                    "Error checking confirmed contract {}: {}",
                    c.accepted_contract.get_contract_id_string(),
                    e
                )
            }
        }

        Ok(())
    }

    fn get_closable_contract_info<'a>(
        &'a self,
        contract: &'a SignedContract,
    ) -> ClosableContractInfo<'a> {
        let contract_infos = &contract.accepted_contract.offered_contract.contract_info;
        let adaptor_infos = &contract.accepted_contract.adaptor_infos;
        for (contract_info, adaptor_info) in contract_infos.iter().zip(adaptor_infos.iter()) {
            let matured: Vec<_> = contract_info
                .oracle_announcements
                .iter()
                .filter(|x| {
                    (x.oracle_event.event_maturity_epoch as u64) <= self.time.unix_time_now()
                })
                .enumerate()
                .collect();
            if matured.len() >= contract_info.threshold {
                let attestations: Vec<_> = matured
                    .iter()
                    .filter_map(|(i, announcement)| {
                        let oracle = self.oracles.get(&announcement.oracle_public_key)?;
                        Some((
                            *i,
                            oracle
                                .get_attestation(&announcement.oracle_event.event_id)
                                .ok()?,
                        ))
                    })
                    .collect();
                if attestations.len() >= contract_info.threshold {
                    return Some((contract_info, adaptor_info, attestations));
                }
            }
        }
        None
    }

    fn check_confirmed_contract(&mut self, contract: &SignedContract) -> Result<(), Error> {
        let closable_contract_info = self.get_closable_contract_info(contract);
        if let Some((contract_info, adaptor_info, attestations)) = closable_contract_info {
            let cet = crate::contract_updater::get_signed_cet(
                &self.secp,
                contract,
                contract_info,
                adaptor_info,
                &attestations,
                &self.wallet,
            )?;
            match self.close_contract(
                contract,
                cet,
                attestations.iter().map(|x| x.1.clone()).collect(),
            ) {
                Ok(closed_contract) => {
                    self.store.update_contract(&closed_contract)?;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Failed to close contract {}: {}",
                        contract.accepted_contract.get_contract_id_string(),
                        e
                    );
                    return Err(e);
                }
            }
        }

        self.check_refund(contract)?;

        Ok(())
    }

    fn check_preclosed_contracts(&mut self) -> Result<(), Error> {
        for c in self.store.get_preclosed_contracts()? {
            if let Err(e) = self.check_preclosed_contract(&c) {
                error!(
                    "Error checking pre-closed contract {}: {}",
                    c.signed_contract.accepted_contract.get_contract_id_string(),
                    e
                )
            }
        }

        Ok(())
    }

    fn check_preclosed_contract(&mut self, contract: &PreClosedContract) -> Result<(), Error> {
        let broadcasted_txid = contract.signed_cet.txid();
        let confirmations = self
            .blockchain
            .get_transaction_confirmations(&broadcasted_txid)?;
        if confirmations >= NB_CONFIRMATIONS {
            let closed_contract = ClosedContract {
                attestations: contract.attestations.clone(),
                signed_cet: Some(contract.signed_cet.clone()),
                contract_id: contract.signed_contract.accepted_contract.get_contract_id(),
                temporary_contract_id: contract
                    .signed_contract
                    .accepted_contract
                    .offered_contract
                    .id,
                counter_party_id: contract
                    .signed_contract
                    .accepted_contract
                    .offered_contract
                    .counter_party,
                pnl: contract
                    .signed_contract
                    .accepted_contract
                    .compute_pnl(&contract.signed_cet),
            };
            self.store
                .update_contract(&Contract::Closed(closed_contract))?;
        }

        Ok(())
    }

    fn close_contract(
        &mut self,
        contract: &SignedContract,
        signed_cet: Transaction,
        attestations: Vec<OracleAttestation>,
    ) -> Result<Contract, Error> {
        let confirmations = self
            .blockchain
            .get_transaction_confirmations(&signed_cet.txid())?;

        if confirmations < 1 {
            // TODO(tibo): if this fails because another tx is already in
            // mempool or blockchain, we might have been cheated. There is
            // not much to be done apart from possibly extracting a fraud
            // proof but ideally it should be handled.
            self.blockchain.send_transaction(&signed_cet)?;

            let preclosed_contract = PreClosedContract {
                signed_contract: contract.clone(),
                attestations: Some(attestations),
                signed_cet,
            };

            return Ok(Contract::PreClosed(preclosed_contract));
        } else if confirmations < NB_CONFIRMATIONS {
            let preclosed_contract = PreClosedContract {
                signed_contract: contract.clone(),
                attestations: Some(attestations),
                signed_cet,
            };

            return Ok(Contract::PreClosed(preclosed_contract));
        }

        let closed_contract = ClosedContract {
            attestations: Some(attestations.to_vec()),
            pnl: contract.accepted_contract.compute_pnl(&signed_cet),
            signed_cet: Some(signed_cet),
            contract_id: contract.accepted_contract.get_contract_id(),
            temporary_contract_id: contract.accepted_contract.offered_contract.id,
            counter_party_id: contract.accepted_contract.offered_contract.counter_party,
        };

        Ok(Contract::Closed(closed_contract))
    }

    fn check_refund(&mut self, contract: &SignedContract) -> Result<(), Error> {
        // TODO(tibo): should check for confirmation of refund before updating state
        if contract
            .accepted_contract
            .dlc_transactions
            .refund
            .lock_time
            .0 as u64
            <= self.time.unix_time_now()
        {
            let accepted_contract = &contract.accepted_contract;
            let refund = accepted_contract.dlc_transactions.refund.clone();
            let confirmations = self
                .blockchain
                .get_transaction_confirmations(&refund.txid())?;
            if confirmations == 0 {
                let refund =
                    crate::contract_updater::get_signed_refund(&self.secp, contract, &self.wallet)?;
                self.blockchain.send_transaction(&refund)?;
            }

            self.store
                .update_contract(&Contract::Refunded(contract.clone()))?;
        }

        Ok(())
    }
}

impl<W: Deref, B: Deref, S: Deref, O: Deref, T: Deref, F: Deref> Manager<W, B, S, O, T, F>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
    F::Target: FeeEstimator,
{
    /// Create a new channel offer and return the [`dlc_messages::channel::OfferChannel`]
    /// message to be sent to the `counter_party`.
    pub fn offer_channel(
        &mut self,
        contract_input: &ContractInput,
        counter_party: PublicKey,
    ) -> Result<OfferChannel, Error> {
        let oracle_announcements = contract_input
            .contract_infos
            .iter()
            .map(|x| self.get_oracle_announcements(&x.oracles))
            .collect::<Result<Vec<_>, Error>>()?;

        let (offered_channel, offered_contract) = crate::channel_updater::offer_channel(
            &self.secp,
            contract_input,
            &counter_party,
            &oracle_announcements,
            CET_NSEQUENCE,
            REFUND_DELAY,
            &self.wallet,
            &self.blockchain,
            &self.time,
        )?;

        let msg = offered_channel.get_offer_channel_msg(&offered_contract);

        self.store.upsert_channel(
            Channel::Offered(offered_channel),
            Some(Contract::Offered(offered_contract)),
        )?;

        Ok(msg)
    }

    /// Accept a channel that was offered. Returns the [`dlc_messages::channel::AcceptChannel`]
    /// message to be sent, the updated [`crate::ChannelId`] and [`crate::ContractId`],
    /// as well as the public key of the offering node.
    pub fn accept_channel(
        &mut self,
        channel_id: &ChannelId,
    ) -> Result<(AcceptChannel, ChannelId, ContractId, PublicKey), Error> {
        let offered_channel =
            get_channel_in_state!(self, channel_id, Offered, None as Option<PublicKey>)?;

        if offered_channel.is_offer_party {
            return Err(Error::InvalidState(
                "Cannot accept channel initiated by us.".to_string(),
            ));
        }

        let offered_contract = get_contract_in_state!(
            self,
            &offered_channel.offered_contract_id,
            Offered,
            None as Option<PublicKey>
        )?;

        let (accepted_channel, accepted_contract, accept_channel) =
            crate::channel_updater::accept_channel_offer(
                &self.secp,
                &offered_channel,
                &offered_contract,
                &self.wallet,
                &self.blockchain,
            )?;

        self.wallet.import_address(&Address::p2wsh(
            &accepted_contract.dlc_transactions.funding_script_pubkey,
            self.blockchain.get_network()?,
        ))?;

        let channel_id = accepted_channel.channel_id;
        let contract_id = accepted_contract.get_contract_id();
        let counter_party = accepted_contract.offered_contract.counter_party;

        self.store.upsert_channel(
            Channel::Accepted(accepted_channel),
            Some(Contract::Accepted(accepted_contract)),
        )?;

        Ok((accept_channel, channel_id, contract_id, counter_party))
    }

    /// Force close the channel with given [`crate::ChannelId`].
    pub fn force_close_channel(&mut self, channel_id: &ChannelId) -> Result<(), Error> {
        let channel = get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        self.force_close_channel_internal(channel)
    }

    /// Offer to settle the balance of a channel so that the counter party gets
    /// `counter_payout`. Returns the [`dlc_messages::channel::SettleChannelOffer`]
    /// message to be sent and the public key of the counter party node.
    pub fn settle_offer(
        &mut self,
        channel_id: &ChannelId,
        counter_payout: u64,
    ) -> Result<(SettleOffer, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let msg = crate::channel_updater::settle_channel_offer(
            &self.secp,
            &mut signed_channel,
            counter_payout,
            PEER_TIMEOUT,
            &self.wallet,
            &self.time,
        )?;

        let counter_party = signed_channel.counter_party;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok((msg, counter_party))
    }

    /// Accept a settlement offer, returning the [`SettleAccept`] message to be
    /// sent to the node with the returned [`PublicKey`] id.
    pub fn accept_settle_offer(
        &mut self,
        channel_id: &ChannelId,
    ) -> Result<(SettleAccept, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let msg = crate::channel_updater::settle_channel_accept(
            &self.secp,
            &mut signed_channel,
            CET_NSEQUENCE,
            0,
            PEER_TIMEOUT,
            &self.wallet,
            &self.time,
        )?;

        let counter_party = signed_channel.counter_party;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok((msg, counter_party))
    }

    /// Returns a [`RenewOffer`] message as well as the [`PublicKey`] of the
    /// counter party's node to offer the establishment of a new contract in the
    /// channel.
    pub fn renew_offer(
        &mut self,
        channel_id: &ChannelId,
        counter_payout: u64,
        contract_input: &ContractInput,
    ) -> Result<(RenewOffer, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let oracle_announcements = contract_input
            .contract_infos
            .iter()
            .map(|x| self.get_oracle_announcements(&x.oracles))
            .collect::<Result<Vec<_>, Error>>()?;

        let (msg, offered_contract) = crate::channel_updater::renew_offer(
            &self.secp,
            &mut signed_channel,
            contract_input,
            oracle_announcements,
            counter_payout,
            REFUND_DELAY,
            PEER_TIMEOUT,
            CET_NSEQUENCE,
            &self.wallet,
            &self.time,
        )?;

        let counter_party = offered_contract.counter_party;

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Offered(offered_contract)),
        )?;

        Ok((msg, counter_party))
    }

    /// Accept an offer to renew the contract in the channel. Returns the
    /// [`RenewAccept`] message to be sent to the peer with the returned
    /// [`PublicKey`] as node id.
    pub fn accept_renew_offer(
        &mut self,
        channel_id: &ChannelId,
    ) -> Result<(RenewAccept, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;
        let offered_contract_id = signed_channel.get_contract_id().ok_or_else(|| {
            Error::InvalidState("Expected to have a contract id but did not.".to_string())
        })?;

        let offered_contract = get_contract_in_state!(
            self,
            &offered_contract_id,
            Offered,
            None as Option<PublicKey>
        )?;

        let (accepted_contract, msg) = crate::channel_updater::accept_channel_renewal(
            &self.secp,
            &mut signed_channel,
            &offered_contract,
            CET_NSEQUENCE,
            PEER_TIMEOUT,
            &self.wallet,
            &self.time,
        )?;

        let counter_party = signed_channel.counter_party;

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Accepted(accepted_contract)),
        )?;

        Ok((msg, counter_party))
    }

    /// Reject an offer to renew the contract in the channel. Returns the
    /// [`Reject`] message to be sent to the peer with the returned
    /// [`PublicKey`] node id.
    pub fn reject_renew_offer(
        &mut self,
        channel_id: &ChannelId,
    ) -> Result<(Reject, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;
        let offered_contract_id = signed_channel.get_contract_id().ok_or_else(|| {
            Error::InvalidState(
                "Expected to be in a state with an associated contract id but was not.".to_string(),
            )
        })?;

        let offered_contract = get_contract_in_state!(
            self,
            &offered_contract_id,
            Offered,
            None as Option<PublicKey>
        )?;

        let reject_msg = crate::channel_updater::reject_renew_offer(&mut signed_channel)?;

        let counter_party = signed_channel.counter_party;

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Rejected(offered_contract)),
        )?;

        Ok((reject_msg, counter_party))
    }

    /// Returns a [`Reject`] message to be sent to the counter party of the
    /// channel to inform them that the local party does not wish to accept the
    /// proposed settle offer.
    pub fn reject_settle_offer(
        &mut self,
        channel_id: &ChannelId,
    ) -> Result<(Reject, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let msg = crate::channel_updater::reject_settle_offer(&mut signed_channel)?;

        let counter_party = signed_channel.counter_party;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok((msg, counter_party))
    }

    /// Returns a [`CollaborativeCloseOffer`] message to be sent to the counter
    /// party of the channel and update the state of the channel. Note that the
    /// channel will be forced closed after a timeout if the counter party does
    /// not broadcast the close transaction.
    pub fn offer_collaborative_close(
        &mut self,
        channel_id: &ChannelId,
        counter_payout: u64,
    ) -> Result<CollaborativeCloseOffer, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let (msg, close_tx) = crate::channel_updater::offer_collaborative_close(
            &self.secp,
            &mut signed_channel,
            counter_payout,
            &self.wallet,
            &self.time,
        )?;

        self.chain_monitor.add_tx(
            close_tx.txid(),
            ChannelInfo {
                channel_id: *channel_id,
                tx_type: TxType::CollaborativeClose,
            },
        );

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;
        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(msg)
    }

    /// Accept an offer to collaboratively close the channel. The close transaction
    /// will be broadcast and the state of the channel updated.
    pub fn accept_collaborative_close(&mut self, channel_id: &ChannelId) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let closed_contract = if let Some(SignedChannelState::Established {
            signed_contract_id,
            is_offer,
            ..
        }) = &signed_channel.roll_back_state
        {
            let counter_payout = get_signed_channel_state!(
                signed_channel,
                CollaborativeCloseOffered,
                counter_payout
            )?;
            let contract =
                get_contract_in_state!(self, signed_contract_id, Confirmed, None::<PublicKey>)?;
            let own_collateral = if *is_offer {
                contract
                    .accepted_contract
                    .offered_contract
                    .offer_params
                    .collateral
            } else {
                contract.accepted_contract.accept_params.collateral
            };
            let pnl = own_collateral as i64 - counter_payout as i64;
            Some(ClosedContract {
                attestations: None,
                signed_cet: None,
                contract_id: *signed_contract_id,
                temporary_contract_id: contract.accepted_contract.offered_contract.id,
                counter_party_id: signed_channel.counter_party,
                pnl,
            })
        } else {
            None
        };

        let close_tx = crate::channel_updater::accept_collaborative_close_offer(
            &self.secp,
            &mut signed_channel,
            &self.wallet,
        )?;

        self.blockchain.send_transaction(&close_tx)?;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        if let Some(closed_contract) = closed_contract {
            self.store
                .update_contract(&Contract::Closed(closed_contract))?;
        }

        Ok(())
    }

    fn try_finalize_closing_established_channel(
        &mut self,
        mut signed_channel: SignedChannel,
    ) -> Result<(), Error> {
        let (buffer_tx, signed_cet, contract_id, attestations) = get_signed_channel_state!(
            signed_channel,
            Closing,
            buffer_transaction,
            signed_cet,
            contract_id,
            attestations
        )?;

        if self
            .blockchain
            .get_transaction_confirmations(&buffer_tx.txid())?
            > CET_NSEQUENCE
        {
            let confirmed_contract =
                get_contract_in_state!(self, &contract_id, Confirmed, None as Option<PublicKey>)?;

            let closed_contract =
                self.close_contract(&confirmed_contract, signed_cet, attestations)?;

            signed_channel.state = SignedChannelState::Closed;

            self.store
                .upsert_channel(Channel::Signed(signed_channel), Some(closed_contract))?;
        }

        Ok(())
    }

    fn on_offer_channel(
        &mut self,
        offer_channel: &OfferChannel,
        counter_party: PublicKey,
    ) -> Result<(), Error> {
        offer_channel.validate(
            &self.secp,
            REFUND_DELAY,
            REFUND_DELAY * 2,
            CET_NSEQUENCE,
            CET_NSEQUENCE * 2,
        )?;

        let (channel, contract) = OfferedChannel::from_offer_channel(offer_channel, counter_party)?;

        contract.validate()?;

        if self
            .store
            .get_channel(&channel.temporary_channel_id)?
            .is_some()
        {
            return Err(Error::InvalidParameters(
                "Channel with identical idea already in store".to_string(),
            ));
        }

        self.store
            .upsert_channel(Channel::Offered(channel), Some(Contract::Offered(contract)))?;

        Ok(())
    }

    fn on_accept_channel(
        &mut self,
        accept_channel: &AcceptChannel,
        peer_id: &PublicKey,
    ) -> Result<SignChannel, Error> {
        let offered_channel = get_channel_in_state!(
            self,
            &accept_channel.temporary_channel_id,
            Offered,
            Some(*peer_id)
        )?;
        let offered_contract = get_contract_in_state!(
            self,
            &offered_channel.offered_contract_id,
            Offered,
            Some(*peer_id)
        )?;

        let (signed_channel, signed_contract, sign_channel) = {
            let res = crate::channel_updater::verify_and_sign_accepted_channel(
                &self.secp,
                &offered_channel,
                &offered_contract,
                accept_channel,
                //TODO(tibo): this should be parameterizable.
                CET_NSEQUENCE,
                &self.wallet,
            );

            match res {
                Ok(res) => res,
                Err(e) => {
                    let channel = crate::channel::FailedAccept {
                        temporary_channel_id: accept_channel.temporary_channel_id,
                        error_message: format!("Error validating accept channel: {}", e),
                        accept_message: accept_channel.clone(),
                        counter_party: *peer_id,
                    };
                    self.store
                        .upsert_channel(Channel::FailedAccept(channel), None)?;
                    return Err(e);
                }
            }
        };

        self.wallet.import_address(&Address::p2wsh(
            &signed_contract
                .accepted_contract
                .dlc_transactions
                .funding_script_pubkey,
            self.blockchain.get_network()?,
        ))?;

        if let SignedChannelState::Established {
            buffer_transaction, ..
        } = &signed_channel.state
        {
            self.chain_monitor.add_tx(
                buffer_transaction.txid(),
                ChannelInfo {
                    channel_id: signed_channel.channel_id,
                    tx_type: TxType::Current,
                },
            );
        } else {
            unreachable!();
        }

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Signed(signed_contract)),
        )?;

        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(sign_channel)
    }

    fn on_sign_channel(
        &mut self,
        sign_channel: &SignChannel,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let accepted_channel =
            get_channel_in_state!(self, &sign_channel.channel_id, Accepted, Some(*peer_id))?;
        let accepted_contract = get_contract_in_state!(
            self,
            &accepted_channel.accepted_contract_id,
            Accepted,
            Some(*peer_id)
        )?;

        let (signed_channel, signed_contract) = {
            let res = verify_signed_channel(
                &self.secp,
                &accepted_channel,
                &accepted_contract,
                sign_channel,
                &self.wallet,
            );

            match res {
                Ok(res) => res,
                Err(e) => {
                    let channel = crate::channel::FailedSign {
                        channel_id: sign_channel.channel_id,
                        error_message: format!("Error validating accept channel: {}", e),
                        sign_message: sign_channel.clone(),
                        counter_party: *peer_id,
                    };
                    self.store
                        .upsert_channel(Channel::FailedSign(channel), None)?;
                    return Err(e);
                }
            }
        };

        if let SignedChannelState::Established {
            buffer_transaction, ..
        } = &signed_channel.state
        {
            self.chain_monitor.add_tx(
                buffer_transaction.txid(),
                ChannelInfo {
                    channel_id: signed_channel.channel_id,
                    tx_type: TxType::Current,
                },
            );
        } else {
            unreachable!();
        }

        self.blockchain.send_transaction(&signed_channel.fund_tx)?;

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Signed(signed_contract)),
        )?;
        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(())
    }

    fn on_settle_offer(
        &mut self,
        settle_offer: &SettleOffer,
        peer_id: &PublicKey,
    ) -> Result<Option<Reject>, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &settle_offer.channel_id, Signed, Some(*peer_id))?;

        if let SignedChannelState::SettledOffered { .. } = signed_channel.state {
            return Ok(Some(Reject {
                channel_id: settle_offer.channel_id,
            }));
        }

        crate::channel_updater::on_settle_offer(&mut signed_channel, settle_offer)?;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(None)
    }

    fn on_settle_accept(
        &mut self,
        settle_accept: &SettleAccept,
        peer_id: &PublicKey,
    ) -> Result<SettleConfirm, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &settle_accept.channel_id, Signed, Some(*peer_id))?;

        let msg = crate::channel_updater::settle_channel_confirm(
            &self.secp,
            &mut signed_channel,
            settle_accept,
            CET_NSEQUENCE,
            0,
            PEER_TIMEOUT,
            &self.wallet,
            &self.time,
        )?;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(msg)
    }

    fn on_settle_confirm(
        &mut self,
        settle_confirm: &SettleConfirm,
        peer_id: &PublicKey,
    ) -> Result<SettleFinalize, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &settle_confirm.channel_id, Signed, Some(*peer_id))?;
        let own_payout = get_signed_channel_state!(signed_channel, SettledAccepted, own_payout)?;
        let (prev_buffer_tx, own_buffer_adaptor_signature, is_offer, signed_contract_id) = get_signed_channel_rollback_state!(
            signed_channel,
            Established,
            buffer_transaction,
            own_buffer_adaptor_signature,
            is_offer,
            signed_contract_id
        )?;

        let prev_buffer_txid = prev_buffer_tx.txid();
        let own_buffer_adaptor_signature = *own_buffer_adaptor_signature;
        let is_offer = *is_offer;
        let signed_contract_id = *signed_contract_id;

        let msg = crate::channel_updater::settle_channel_finalize(
            &self.secp,
            &mut signed_channel,
            settle_confirm,
            &self.wallet,
        )?;

        self.chain_monitor.add_tx(
            prev_buffer_txid,
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type: TxType::Revoked {
                    update_idx: signed_channel.update_idx + 1,
                    own_adaptor_signature: own_buffer_adaptor_signature,
                    is_offer,
                    revoked_tx_type: RevokedTxType::Buffer,
                },
            },
        );

        let contract =
            get_contract_in_state!(self, &signed_contract_id, Confirmed, None::<PublicKey>)?;

        let own_collateral = if contract.accepted_contract.offered_contract.is_offer_party {
            contract
                .accepted_contract
                .offered_contract
                .offer_params
                .collateral
        } else {
            contract.accepted_contract.accept_params.collateral
        };

        let closed_contract = Contract::Closed(ClosedContract {
            attestations: None,
            signed_cet: None,
            contract_id: signed_contract_id,
            temporary_contract_id: contract.accepted_contract.offered_contract.id,
            counter_party_id: signed_channel.counter_party,
            pnl: (own_collateral as i64) - (own_payout as i64),
        });

        self.store
            .upsert_channel(Channel::Signed(signed_channel), Some(closed_contract))?;
        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(msg)
    }

    fn on_settle_finalize(
        &mut self,
        settle_finalize: &SettleFinalize,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &settle_finalize.channel_id, Signed, Some(*peer_id))?;
        let own_payout = get_signed_channel_state!(signed_channel, SettledConfirmed, own_payout)?;
        let (buffer_tx, own_buffer_adaptor_signature, is_offer, signed_contract_id) = get_signed_channel_rollback_state!(
            signed_channel,
            Established,
            buffer_transaction,
            own_buffer_adaptor_signature,
            is_offer,
            signed_contract_id
        )?;

        let own_buffer_adaptor_signature = *own_buffer_adaptor_signature;
        let is_offer = *is_offer;
        let buffer_txid = buffer_tx.txid();
        let signed_contract_id = *signed_contract_id;

        crate::channel_updater::settle_channel_on_finalize(
            &self.secp,
            &mut signed_channel,
            settle_finalize,
        )?;

        self.chain_monitor.add_tx(
            buffer_txid,
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type: TxType::Revoked {
                    update_idx: signed_channel.update_idx + 1,
                    own_adaptor_signature: own_buffer_adaptor_signature,
                    is_offer,
                    revoked_tx_type: RevokedTxType::Buffer,
                },
            },
        );

        let contract =
            get_contract_in_state!(self, &signed_contract_id, Confirmed, None::<PublicKey>)?;

        let own_collateral = if contract.accepted_contract.offered_contract.is_offer_party {
            contract
                .accepted_contract
                .offered_contract
                .offer_params
                .collateral
        } else {
            contract.accepted_contract.accept_params.collateral
        };

        let closed_contract = Contract::Closed(ClosedContract {
            attestations: None,
            signed_cet: None,
            contract_id: signed_contract_id,
            temporary_contract_id: contract.accepted_contract.offered_contract.id,
            counter_party_id: signed_channel.counter_party,
            pnl: (own_collateral as i64) - (own_payout as i64),
        });

        self.store
            .upsert_channel(Channel::Signed(signed_channel), Some(closed_contract))?;
        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(())
    }

    fn on_renew_offer(
        &mut self,
        renew_offer: &RenewOffer,
        peer_id: &PublicKey,
    ) -> Result<Option<Reject>, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_offer.channel_id, Signed, Some(*peer_id))?;

        // Received a renew offer when we already sent one, we reject it.
        if let SignedChannelState::RenewOffered { is_offer, .. } = signed_channel.state {
            if is_offer {
                return Ok(Some(Reject {
                    channel_id: renew_offer.channel_id,
                }));
            }
        }

        let offered_contract =
            crate::channel_updater::on_renew_offer(&mut signed_channel, renew_offer)?;

        self.store.create_contract(&offered_contract)?;
        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(None)
    }

    fn on_renew_accept(
        &mut self,
        renew_accept: &RenewAccept,
        peer_id: &PublicKey,
    ) -> Result<RenewConfirm, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_accept.channel_id, Signed, Some(*peer_id))?;
        let offered_contract_id = signed_channel.get_contract_id().ok_or_else(|| {
            Error::InvalidState(
                "Expected to be in a state with an associated contract id but was not.".to_string(),
            )
        })?;

        let offered_contract =
            get_contract_in_state!(self, &offered_contract_id, Offered, Some(*peer_id))?;

        let (signed_contract, msg) = crate::channel_updater::verify_renew_accept_and_confirm(
            &self.secp,
            renew_accept,
            &mut signed_channel,
            &offered_contract,
            CET_NSEQUENCE,
            PEER_TIMEOUT,
            &self.wallet,
            &self.time,
        )?;

        // Directly confirmed as we're in a channel the fund tx is already confirmed.
        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Confirmed(signed_contract)),
        )?;

        Ok(msg)
    }

    fn on_renew_confirm(
        &mut self,
        renew_confirm: &RenewConfirm,
        peer_id: &PublicKey,
    ) -> Result<RenewFinalize, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_confirm.channel_id, Signed, Some(*peer_id))?;
        let contract_id = signed_channel.get_contract_id().ok_or_else(|| {
            Error::InvalidState(
                "Expected to be in a state with an associated contract id but was not.".to_string(),
            )
        })?;

        let (tx_type, prev_tx_id, closed_contract) = match signed_channel
            .roll_back_state
            .as_ref()
            .expect("to have a rollback state")
        {
            SignedChannelState::Established {
                own_buffer_adaptor_signature,
                buffer_transaction,
                signed_contract_id,
                ..
            } => {
                let contract =
                    get_contract_in_state!(self, signed_contract_id, Confirmed, None::<PublicKey>)?;
                let own_collateral = if contract.accepted_contract.offered_contract.is_offer_party {
                    contract
                        .accepted_contract
                        .offered_contract
                        .offer_params
                        .collateral
                } else {
                    contract.accepted_contract.accept_params.collateral
                };
                let pnl = (contract.accepted_contract.offered_contract.total_collateral as i64)
                    - (own_collateral as i64);
                let closed_contract = Contract::Closed(ClosedContract {
                    attestations: None,
                    signed_cet: None,
                    contract_id: *signed_contract_id,
                    temporary_contract_id: contract.accepted_contract.offered_contract.id,
                    counter_party_id: signed_channel.counter_party,
                    pnl,
                });
                (
                    TxType::Revoked {
                        update_idx: signed_channel.update_idx,
                        own_adaptor_signature: *own_buffer_adaptor_signature,
                        is_offer: false,
                        revoked_tx_type: RevokedTxType::Buffer,
                    },
                    buffer_transaction.txid(),
                    Some(closed_contract),
                )
            }
            SignedChannelState::Settled {
                settle_tx,
                own_settle_adaptor_signature,
                ..
            } => (
                TxType::Revoked {
                    update_idx: signed_channel.update_idx,
                    own_adaptor_signature: *own_settle_adaptor_signature,
                    is_offer: false,
                    revoked_tx_type: RevokedTxType::Settle,
                },
                settle_tx.txid(),
                None,
            ),
            s => {
                return Err(Error::InvalidState(format!(
                    "Expected rollback state Established or Revoked but found {:?}",
                    s
                )))
            }
        };

        let accepted_contract =
            get_contract_in_state!(self, &contract_id, Accepted, Some(*peer_id))?;

        let (signed_contract, msg) = crate::channel_updater::verify_renew_confirm_and_finalize(
            &self.secp,
            &mut signed_channel,
            &accepted_contract,
            renew_confirm,
            &self.wallet,
        )?;

        self.chain_monitor.add_tx(
            prev_tx_id,
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type,
            },
        );

        let buffer_tx =
            get_signed_channel_state!(signed_channel, Established, ref buffer_transaction)?;

        self.chain_monitor.add_tx(
            buffer_tx.txid(),
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type: TxType::Current,
            },
        );

        // Directly confirmed as we're in a channel the fund tx is already confirmed.
        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Confirmed(signed_contract)),
        )?;

        self.store.persist_chain_monitor(&self.chain_monitor)?;

        if let Some(closed_contract) = closed_contract {
            self.store.update_contract(&closed_contract)?;
        }

        Ok(msg)
    }

    fn on_renew_finalize(
        &mut self,
        renew_finalize: &RenewFinalize,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_finalize.channel_id, Signed, Some(*peer_id))?;

        let (tx_type, prev_tx_id, closed_contract) = match signed_channel
            .roll_back_state
            .as_ref()
            .expect("to have a rollback state")
        {
            SignedChannelState::Established {
                own_buffer_adaptor_signature,
                buffer_transaction,
                signed_contract_id,
                ..
            } => {
                let contract =
                    get_contract_in_state!(self, signed_contract_id, Confirmed, None::<PublicKey>)?;
                let own_collateral = if contract.accepted_contract.offered_contract.is_offer_party {
                    contract
                        .accepted_contract
                        .offered_contract
                        .offer_params
                        .collateral
                } else {
                    contract.accepted_contract.accept_params.collateral
                };
                let pnl = (contract.accepted_contract.offered_contract.total_collateral as i64)
                    - (own_collateral as i64);
                let closed_contract = Contract::Closed(ClosedContract {
                    attestations: None,
                    signed_cet: None,
                    contract_id: *signed_contract_id,
                    temporary_contract_id: contract.accepted_contract.offered_contract.id,
                    counter_party_id: signed_channel.counter_party,
                    pnl,
                });
                (
                    TxType::Revoked {
                        update_idx: signed_channel.update_idx,
                        own_adaptor_signature: *own_buffer_adaptor_signature,
                        is_offer: false,
                        revoked_tx_type: RevokedTxType::Buffer,
                    },
                    buffer_transaction.txid(),
                    Some(closed_contract),
                )
            }
            SignedChannelState::Settled {
                settle_tx,
                own_settle_adaptor_signature,
                ..
            } => (
                TxType::Revoked {
                    update_idx: signed_channel.update_idx,
                    own_adaptor_signature: *own_settle_adaptor_signature,
                    is_offer: false,
                    revoked_tx_type: RevokedTxType::Settle,
                },
                settle_tx.txid(),
                None,
            ),
            s => {
                return Err(Error::InvalidState(format!(
                    "Expected rollback state of Established or Settled but was {:?}",
                    s
                )))
            }
        };

        crate::channel_updater::renew_channel_on_finalize(&mut signed_channel, renew_finalize)?;

        self.chain_monitor.add_tx(
            prev_tx_id,
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type,
            },
        );

        let buffer_tx =
            get_signed_channel_state!(signed_channel, Established, ref buffer_transaction)?;

        self.chain_monitor.add_tx(
            buffer_tx.txid(),
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type: TxType::Current,
            },
        );

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;
        self.store.persist_chain_monitor(&self.chain_monitor)?;

        if let Some(closed_contract) = closed_contract {
            self.store.update_contract(&closed_contract)?;
        }

        Ok(())
    }

    fn on_collaborative_close_offer(
        &mut self,
        close_offer: &CollaborativeCloseOffer,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &close_offer.channel_id, Signed, Some(*peer_id))?;

        crate::channel_updater::on_collaborative_close_offer(
            &mut signed_channel,
            close_offer,
            PEER_TIMEOUT,
            &self.time,
        )?;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(())
    }

    fn on_reject(&mut self, reject: &Reject, counter_party: &PublicKey) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &reject.channel_id, Signed, Some(*counter_party))?;

        crate::channel_updater::on_reject(&mut signed_channel)?;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;
        Ok(())
    }

    fn channel_checks(&mut self) -> Result<(), Error> {
        let established_closing_channels = self
            .store
            .get_signed_channels(Some(SignedChannelStateType::Closing))?;

        for channel in established_closing_channels {
            if let Err(e) = self.try_finalize_closing_established_channel(channel) {
                error!("Error trying to close established channel: {}", e);
            }
        }

        if let Err(e) = self.check_for_timed_out_channels() {
            error!("Error checking timed out channels {}", e);
        }
        self.check_for_watched_tx()
    }

    fn check_for_timed_out_channels(&mut self) -> Result<(), Error> {
        check_for_timed_out_channels!(self, RenewOffered);
        check_for_timed_out_channels!(self, RenewAccepted);
        check_for_timed_out_channels!(self, RenewConfirmed);
        check_for_timed_out_channels!(self, SettledOffered);
        check_for_timed_out_channels!(self, SettledAccepted);
        check_for_timed_out_channels!(self, SettledConfirmed);

        Ok(())
    }

    fn check_for_watched_tx(&mut self) -> Result<(), Error> {
        let cur_height = self.blockchain.get_blockchain_height()?;
        let last_height = self.chain_monitor.last_height;

        if cur_height < last_height {
            return Err(Error::InvalidState(
                "Current height is lower than last height.".to_string(),
            ));
        }

        //todo(tibo): check and deal with reorgs.

        for height in last_height + 1..cur_height {
            let block = self.blockchain.get_block_at_height(height)?;

            let watch_res = self.chain_monitor.process_block(&block, height);

            for (tx, channel_info) in watch_res {
                let mut signed_channel = match get_channel_in_state!(
                    self,
                    &channel_info.channel_id,
                    Signed,
                    None as Option<PublicKey>
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        error!(
                            "Could not retrieve channel {:?}: {}",
                            channel_info.channel_id, e
                        );
                        continue;
                    }
                };

                if let TxType::Current = channel_info.tx_type {
                    // TODO(tibo): should only considered closed after some confirmations.
                    // Ideally should save previous state, and maybe restore in
                    // case of reorg, though if the counter party has sent the
                    // tx to close the channel it is unlikely that the tx will
                    // not be part of a future block.
                    let contract = if let Some(contract_id) = signed_channel.get_contract_id() {
                        let contract_opt = self.store.get_contract(&contract_id)?;
                        if let Some(contract) = contract_opt {
                            match contract {
                                Contract::Confirmed(c) => {
                                    Some(Contract::PreClosed(PreClosedContract {
                                        signed_contract: c,
                                        attestations: None,
                                        signed_cet: tx.clone(),
                                    }))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    signed_channel.state = SignedChannelState::CounterClosed;
                    self.store
                        .upsert_channel(Channel::Signed(signed_channel), contract)?;
                    continue;
                } else if let TxType::Revoked {
                    update_idx,
                    own_adaptor_signature,
                    is_offer,
                    revoked_tx_type,
                } = channel_info.tx_type
                {
                    let secret = signed_channel
                        .counter_party_commitment_secrets
                        .get_secret(update_idx)
                        .expect("to be able to retrieve the per update secret");
                    let counter_per_update_secret = SecretKey::from_slice(&secret)
                        .expect("to be able to parse the counter per update secret.");

                    let per_update_seed_pk = signed_channel.own_per_update_seed;

                    let per_update_seed_sk =
                        self.wallet.get_secret_key_for_pubkey(&per_update_seed_pk)?;

                    let per_update_secret = SecretKey::from_slice(&build_commitment_secret(
                        per_update_seed_sk.as_ref(),
                        update_idx,
                    ))
                    .expect("a valid secret key.");

                    let per_update_point =
                        PublicKey::from_secret_key(&self.secp, &per_update_secret);

                    let own_revocation_params = signed_channel.own_points.get_revokable_params(
                        &self.secp,
                        &signed_channel.counter_points.revocation_basepoint,
                        &per_update_point,
                    );

                    let counter_per_update_point =
                        PublicKey::from_secret_key(&self.secp, &counter_per_update_secret);

                    let base_own_sk = self
                        .wallet
                        .get_secret_key_for_pubkey(&signed_channel.own_points.own_basepoint)?;

                    let own_sk = derive_private_key(&self.secp, &per_update_point, &base_own_sk);

                    let counter_revocation_params =
                        signed_channel.counter_points.get_revokable_params(
                            &self.secp,
                            &signed_channel.own_points.revocation_basepoint,
                            &counter_per_update_point,
                        );

                    let witness = if signed_channel.own_params.fund_pubkey
                        < signed_channel.counter_params.fund_pubkey
                    {
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
                        &signed_channel.own_points.revocation_basepoint,
                    )?;

                    let counter_revocation_sk = derive_private_revocation_key(
                        &self.secp,
                        &counter_per_update_secret,
                        own_revocation_base_secret,
                    );

                    let (offer_params, accept_params) = if is_offer {
                        (&own_revocation_params, &counter_revocation_params)
                    } else {
                        (&counter_revocation_params, &own_revocation_params)
                    };

                    let fee_rate_per_vb: u64 = (self.fee_estimator.get_est_sat_per_1000_weight(
                        lightning::chain::chaininterface::ConfirmationTarget::OnChainSweep,
                    ) / 250)
                        .into();

                    let signed_tx = match revoked_tx_type {
                        RevokedTxType::Buffer => {
                            dlc::channel::create_and_sign_punish_buffer_transaction(
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
                        RevokedTxType::Settle => {
                            dlc::channel::create_and_sign_punish_settle_transaction(
                                &self.secp,
                                offer_params,
                                accept_params,
                                &own_sk,
                                &counter_sk,
                                &counter_revocation_sk,
                                &tx,
                                &self.wallet.get_new_address()?,
                                CET_NSEQUENCE,
                                0,
                                fee_rate_per_vb,
                                is_offer,
                            )?
                        }
                    };

                    self.blockchain.send_transaction(&signed_tx)?;

                    signed_channel.state = SignedChannelState::ClosedPunished {
                        punishment_txid: signed_tx.txid(),
                    };

                    self.store
                        .upsert_channel(Channel::Signed(signed_channel), None)?;
                } else if let TxType::CollaborativeClose = channel_info.tx_type {
                    if let Some(SignedChannelState::Established {
                        signed_contract_id,
                        is_offer,
                        ..
                    }) = signed_channel.roll_back_state
                    {
                        let counter_payout = get_signed_channel_state!(
                            signed_channel,
                            CollaborativeCloseOffered,
                            counter_payout
                        )?;
                        let contract = get_contract_in_state!(
                            self,
                            &signed_contract_id,
                            Confirmed,
                            None::<PublicKey>
                        )?;
                        let own_payout =
                            contract.accepted_contract.offered_contract.total_collateral
                                - counter_payout;
                        let own_collateral = if is_offer {
                            contract
                                .accepted_contract
                                .offered_contract
                                .offer_params
                                .collateral
                        } else {
                            contract.accepted_contract.accept_params.collateral
                        };
                        let pnl = (own_collateral as i64) - (own_payout as i64);

                        let closed_contract = ClosedContract {
                            attestations: None,
                            signed_cet: None,
                            contract_id: signed_contract_id,
                            temporary_contract_id: contract.accepted_contract.offered_contract.id,
                            counter_party_id: signed_channel.counter_party,
                            pnl,
                        };
                        self.store
                            .update_contract(&Contract::Closed(closed_contract))?;
                    }
                    signed_channel.state = SignedChannelState::CollaborativelyClosed;
                    self.store
                        .upsert_channel(Channel::Signed(signed_channel), None)?;
                }
            }

            self.chain_monitor.increment_height(&block.block_hash());
        }

        Ok(())
    }

    fn force_close_channel_internal(&mut self, mut channel: SignedChannel) -> Result<(), Error> {
        match channel.state {
            SignedChannelState::Established { .. } => {
                self.initiate_unilateral_close_established_channel(channel)
            }
            SignedChannelState::Settled { .. } => self.close_settled_channel(channel),
            SignedChannelState::SettledOffered { .. }
            | SignedChannelState::SettledReceived { .. }
            | SignedChannelState::SettledAccepted { .. }
            | SignedChannelState::SettledConfirmed { .. }
            | SignedChannelState::RenewOffered { .. }
            | SignedChannelState::RenewAccepted { .. }
            | SignedChannelState::RenewConfirmed { .. }
            | SignedChannelState::CollaborativeCloseOffered { .. } => {
                channel.state = channel
                    .roll_back_state
                    .take()
                    .expect("to have a rollback state");
                self.force_close_channel_internal(channel)
            }
            SignedChannelState::Closing { .. } => Err(Error::InvalidState(
                "Channel is already closing.".to_string(),
            )),
            SignedChannelState::Closed
            | SignedChannelState::CounterClosed
            | SignedChannelState::CollaborativelyClosed
            | SignedChannelState::ClosedPunished { .. } => {
                Err(Error::InvalidState("Channel already closed.".to_string()))
            }
        }
    }

    /// Initiate the unilateral closing of a channel that has been established.
    fn initiate_unilateral_close_established_channel(
        &mut self,
        mut signed_channel: SignedChannel,
    ) -> Result<(), Error> {
        let contract_id = signed_channel.get_contract_id().ok_or_else(|| {
            Error::InvalidState(
                "Expected to be in a state with an associated contract id but was not.".to_string(),
            )
        })?;

        let confirmed_contract =
            get_contract_in_state!(self, &contract_id, Confirmed, None as Option<PublicKey>)?;

        let (contract_info, adaptor_info, attestations) = self
            .get_closable_contract_info(&confirmed_contract)
            .ok_or_else(|| {
                Error::InvalidState("Could not get closable contract info".to_string())
            })?;

        crate::channel_updater::initiate_unilateral_close_established_channel(
            &self.secp,
            &mut signed_channel,
            &confirmed_contract,
            contract_info,
            &attestations,
            adaptor_info,
            &self.wallet,
        )?;

        let buffer_transaction =
            get_signed_channel_state!(signed_channel, Closing, ref buffer_transaction)?;

        self.blockchain.send_transaction(buffer_transaction)?;

        self.chain_monitor.remove_tx(&buffer_transaction.txid());

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(())
    }

    /// Unilaterally close a channel that has been settled.
    fn close_settled_channel(&mut self, mut signed_channel: SignedChannel) -> Result<(), Error> {
        let settle_tx = crate::channel_updater::close_settled_channel(
            &self.secp,
            &mut signed_channel,
            &self.wallet,
        )?;

        self.blockchain.send_transaction(&settle_tx)?;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use dlc_messages::Message;
    use mocks::{
        dlc_manager::{manager::Manager, Oracle},
        memory_storage_provider::MemoryStorage,
        mock_blockchain::MockBlockchain,
        mock_oracle_provider::MockOracle,
        mock_time::MockTime,
        mock_wallet::MockWallet,
    };
    use secp256k1_zkp::PublicKey;
    use std::{collections::HashMap, rc::Rc};

    type TestManager = Manager<
        Rc<MockWallet>,
        Rc<MockBlockchain>,
        Rc<MemoryStorage>,
        Rc<MockOracle>,
        Rc<MockTime>,
        Rc<MockBlockchain>,
    >;

    fn get_manager() -> TestManager {
        let blockchain = Rc::new(MockBlockchain::new());
        let store = Rc::new(MemoryStorage::new());
        let wallet = Rc::new(MockWallet::new(
            &blockchain,
            &(0..100).map(|x| x as u64 * 1000000).collect::<Vec<_>>(),
        ));

        let oracle_list = (0..5).map(|_| MockOracle::new()).collect::<Vec<_>>();
        let oracles: HashMap<bitcoin::XOnlyPublicKey, _> = oracle_list
            .into_iter()
            .map(|x| (x.get_public_key(), Rc::new(x)))
            .collect();
        let time = Rc::new(MockTime {});

        mocks::mock_time::set_time(0);

        Manager::new(wallet, blockchain.clone(), store, oracles, time, blockchain).unwrap()
    }

    fn pubkey() -> PublicKey {
        "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
            .parse()
            .unwrap()
    }

    #[test]
    fn reject_offer_with_existing_contract_id() {
        let offer_message = Message::Offer(
            serde_json::from_str(include_str!("../test_inputs/offer_contract.json")).unwrap(),
        );

        let mut manager = get_manager();

        manager
            .on_dlc_message(&offer_message, pubkey())
            .expect("To accept the first offer message");

        manager
            .on_dlc_message(&offer_message, pubkey())
            .expect_err("To reject the second offer message");
    }

    #[test]
    fn reject_channel_offer_with_existing_channel_id() {
        let offer_message = Message::OfferChannel(
            serde_json::from_str(include_str!("../test_inputs/offer_channel.json")).unwrap(),
        );

        let mut manager = get_manager();

        manager
            .on_dlc_message(&offer_message, pubkey())
            .expect("To accept the first offer message");

        manager
            .on_dlc_message(&offer_message, pubkey())
            .expect_err("To reject the second offer message");
    }
}
