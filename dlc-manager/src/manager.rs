//! #Manager a component to create and update DLCs.

use super::{
    Blockchain, CachedContractSignerProvider, ContractSigner, Oracle, Storage, Time, Wallet,
};
use crate::chain_monitor::{ChainMonitor, ChannelInfo, RevokedTxType, TxType};
use crate::channel::offered_channel::OfferedChannel;
use crate::channel::signed_channel::{SignedChannel, SignedChannelState, SignedChannelStateType};
use crate::channel::{Channel, ClosedChannel, ClosedPunishedChannel};
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
use crate::utils::get_object_in_state;
use crate::{ChannelId, ContractId, ContractSignerProvider};
use bitcoin::absolute::Height;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::consensus::Decodable;
use bitcoin::Address;
use bitcoin::{OutPoint, Transaction};
use dlc_macros::*;
use dlc_messages::channel::{
    AcceptChannel, CollaborativeCloseOffer, OfferChannel, Reject, RenewAccept, RenewConfirm,
    RenewFinalize, RenewOffer, RenewRevoke, SettleAccept, SettleConfirm, SettleFinalize,
    SettleOffer, SignChannel,
};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::{AcceptDlc, Message as DlcMessage, OfferDlc, SignDlc};
use hex::DisplayHex;
use lightning::chain::chaininterface::FeeEstimator;
use lightning::ln::chan_utils::{
    build_commitment_secret, derive_private_key, derive_private_revocation_key,
};
use log::{error, warn};
use secp256k1_zkp::XOnlyPublicKey;
use secp256k1_zkp::{
    ecdsa::Signature, All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey,
};
use std::collections::HashMap;
use std::ops::Deref;
use std::string::ToString;
use std::sync::{Arc, Mutex};

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
pub struct Manager<
    W: Deref,
    SP: Deref,
    B: Deref,
    S: Deref,
    O: Deref,
    T: Deref,
    F: Deref,
    X: ContractSigner,
> where
    W::Target: Wallet,
    SP::Target: ContractSignerProvider<Signer = X>,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
    F::Target: FeeEstimator,
{
    oracles: HashMap<XOnlyPublicKey, O>,
    wallet: W,
    signer_provider: SP,
    blockchain: B,
    store: S,
    secp: Secp256k1<All>,
    chain_monitor: Mutex<ChainMonitor>,
    time: T,
    fee_estimator: F,
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
                    match $manager.force_close_channel_internal(channel, true) {
                        Err(e) => error!("Error force closing channel {}", e),
                        _ => {}
                    }
                }
            }
        }
    };
}

impl<W: Deref, SP: Deref, B: Deref, S: Deref, O: Deref, T: Deref, F: Deref, X: ContractSigner>
    Manager<W, Arc<CachedContractSignerProvider<SP, X>>, B, S, O, T, F, X>
where
    W::Target: Wallet,
    SP::Target: ContractSignerProvider<Signer = X>,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
    F::Target: FeeEstimator,
{
    /// Create a new Manager struct.
    pub fn new(
        wallet: W,
        signer_provider: SP,
        blockchain: B,
        store: S,
        oracles: HashMap<XOnlyPublicKey, O>,
        time: T,
        fee_estimator: F,
    ) -> Result<Self, Error> {
        let init_height = blockchain.get_blockchain_height()?;
        let chain_monitor = Mutex::new(
            store
                .get_chain_monitor()?
                .unwrap_or(ChainMonitor::new(init_height)),
        );

        let signer_provider = Arc::new(CachedContractSignerProvider::new(signer_provider));

        Ok(Manager {
            secp: secp256k1_zkp::Secp256k1::new(),
            wallet,
            signer_provider,
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

    /// Function called to pass a DlcMessage to the Manager.
    pub fn on_dlc_message(
        &self,
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
                let revoke = self.on_renew_finalize(r, &counter_party)?;
                Ok(Some(DlcMessage::RenewRevoke(revoke)))
            }
            DlcMessage::RenewRevoke(r) => {
                self.on_renew_revoke(r, &counter_party)?;
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
    ///
    /// This function will fetch the oracle announcements from the oracle.
    #[maybe_async]
    pub fn send_offer(
        &self,
        contract_input: &ContractInput,
        counter_party: PublicKey,
    ) -> Result<OfferDlc, Error> {
        let oracle_announcements =
            maybe_await!(self.get_oracle_announcements_from_infos(contract_input))?;

        self.send_offer_with_announcements(contract_input, counter_party, oracle_announcements)
    }

    /// Function called to create a new DLC. The offered contract will be stored
    /// and an OfferDlc message returned.
    ///
    /// This function allows to pass the oracle announcements directly instead of
    /// fetching them from the oracle.
    pub fn send_offer_with_announcements(
        &self,
        contract_input: &ContractInput,
        counter_party: PublicKey,
        oracle_announcements: Vec<Vec<OracleAnnouncement>>,
    ) -> Result<OfferDlc, Error> {
        let (offered_contract, offer_msg) = crate::contract_updater::offer_contract(
            &self.secp,
            contract_input,
            oracle_announcements,
            REFUND_DELAY,
            &counter_party,
            &self.wallet,
            &self.blockchain,
            &self.time,
            &self.signer_provider,
        )?;

        offered_contract.validate()?;

        self.store.create_contract(&offered_contract)?;

        Ok(offer_msg)
    }

    /// Function to call to accept a DLC for which an offer was received.
    pub fn accept_contract_offer(
        &self,
        contract_id: &ContractId,
    ) -> Result<(ContractId, PublicKey, AcceptDlc), Error> {
        let offered_contract =
            get_contract_in_state!(self, contract_id, Offered, None as Option<PublicKey>)?;

        let counter_party = offered_contract.counter_party;

        let (accepted_contract, accept_msg) = accept_contract(
            &self.secp,
            &offered_contract,
            &self.wallet,
            &self.signer_provider,
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

    /// Function to update the state of the [`ChainMonitor`] with new
    /// blocks.
    ///
    /// Consumers **MUST** call this periodically in order to
    /// determine when pending transactions reach confirmation.
    pub fn periodic_chain_monitor(&self) -> Result<(), Error> {
        let cur_height = self.blockchain.get_blockchain_height()?;
        let last_height = self.chain_monitor.lock().unwrap().last_height;

        // TODO(luckysori): We could end up reprocessing a block at
        // the same height if there is a reorg.
        if cur_height < last_height {
            return Err(Error::InvalidState(
                "Current height is lower than last height.".to_string(),
            ));
        }

        for height in last_height + 1..=cur_height {
            let block = self.blockchain.get_block_at_height(height)?;

            self.chain_monitor
                .lock()
                .unwrap()
                .process_block(&block, height);
        }

        Ok(())
    }

    /// Function to call to check the state of the currently executing DLCs and
    /// update them if possible.
    #[maybe_async]
    pub fn periodic_check(&self, check_channels: bool) -> Result<(), Error> {
        self.check_signed_contracts()?;
        maybe_await!(self.check_confirmed_contracts())?;
        self.check_preclosed_contracts()?;

        if check_channels {
            maybe_await!(self.channel_checks())?;
        }

        Ok(())
    }

    fn on_offer_message(
        &self,
        offered_message: &OfferDlc,
        counter_party: PublicKey,
    ) -> Result<(), Error> {
        offered_message.validate(&self.secp, REFUND_DELAY, REFUND_DELAY * 2)?;
        let keys_id = self
            .signer_provider
            .derive_signer_key_id(false, offered_message.temporary_contract_id);
        let contract: OfferedContract =
            OfferedContract::try_from_offer_dlc(offered_message, counter_party, keys_id)?;
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
        &self,
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
            &self.signer_provider,
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

    fn on_sign_message(&self, sign_message: &SignDlc, peer_id: &PublicKey) -> Result<(), Error> {
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

    #[maybe_async]
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
            let announcement = maybe_await!(oracle.get_announcement(&oracle_inputs.event_id))?;
            announcements.push(announcement);
        }

        Ok(announcements)
    }

    fn sign_fail_on_error<R>(
        &self,
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
        &self,
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

    fn check_signed_contract(&self, contract: &SignedContract) -> Result<(), Error> {
        let confirmations = self.blockchain.get_transaction_confirmations(
            &contract
                .accepted_contract
                .dlc_transactions
                .fund
                .compute_txid(),
        )?;
        if confirmations >= NB_CONFIRMATIONS {
            self.store
                .update_contract(&Contract::Confirmed(contract.clone()))?;
        }
        Ok(())
    }

    fn check_signed_contracts(&self) -> Result<(), Error> {
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

    #[maybe_async]
    fn check_confirmed_contracts(&self) -> Result<(), Error> {
        for c in self.store.get_confirmed_contracts()? {
            // Confirmed contracts from channel are processed in channel specific methods.
            if c.channel_id.is_some() {
                continue;
            }
            if let Err(e) = maybe_await!(self.check_confirmed_contract(&c)) {
                error!(
                    "Error checking confirmed contract {}: {}",
                    c.accepted_contract.get_contract_id_string(),
                    e
                )
            }
        }

        Ok(())
    }

    #[maybe_async]
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
                let mut attestations = Vec::new();
                for (i, announcement) in matured {
                    let oracle = match self.oracles.get(&announcement.oracle_public_key) {
                        Some(o) => o,
                        None => {
                            log::warn!(
                                "No oracle found with pubkey. pubkey={}",
                                announcement.oracle_public_key
                            );
                            continue;
                        }
                    };
                    let Ok(attestation) =
                        maybe_await!(oracle.get_attestation(&announcement.oracle_event.event_id))
                    else {
                        log::warn!(
                            "Failed to get attestation. oracle={} event_id={}",
                            announcement.oracle_public_key,
                            announcement.oracle_event.event_id
                        );
                        continue;
                    };

                    if let Err(error) = attestation.validate(&self.secp, announcement) {
                        log::warn!(
                            "Oracle attestation is invalid. error={} pubkey={} event_id={}",
                            error,
                            announcement.oracle_public_key,
                            announcement.oracle_event.event_id
                        );
                        continue;
                    }

                    attestations.push((i, attestation));
                }
                if attestations.len() >= contract_info.threshold {
                    return Some((contract_info, adaptor_info, attestations));
                }
            }
        }
        None
    }

    #[maybe_async]
    fn check_confirmed_contract(&self, contract: &SignedContract) -> Result<(), Error> {
        let closable_contract_info = maybe_await!(self.get_closable_contract_info(contract));
        if let Some((contract_info, adaptor_info, attestations)) = closable_contract_info {
            let offer = &contract.accepted_contract.offered_contract;
            let signer = self.signer_provider.derive_contract_signer(offer.keys_id)?;
            let cet = crate::contract_updater::get_signed_cet(
                &self.secp,
                contract,
                contract_info,
                adaptor_info,
                &attestations,
                &signer,
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

    /// Manually close a contract with the oracle attestations.
    pub fn close_confirmed_contract(
        &self,
        contract_id: &ContractId,
        attestations: Vec<(usize, OracleAttestation)>,
    ) -> Result<Contract, Error> {
        let contract = get_contract_in_state!(self, contract_id, Confirmed, None::<PublicKey>)?;
        let contract_infos = &contract.accepted_contract.offered_contract.contract_info;
        let adaptor_infos = &contract.accepted_contract.adaptor_infos;

        // find the contract info that matches the attestations
        if let Some((contract_info, adaptor_info)) =
            contract_infos.iter().zip(adaptor_infos).find(|(c, _)| {
                let matches = attestations
                    .iter()
                    .filter(|(i, a)| {
                        c.oracle_announcements[*i].oracle_event.oracle_nonces == a.nonces()
                    })
                    .count();

                matches >= c.threshold
            })
        {
            let offer = &contract.accepted_contract.offered_contract;
            let signer = self.signer_provider.derive_contract_signer(offer.keys_id)?;
            let cet = crate::contract_updater::get_signed_cet(
                &self.secp,
                &contract,
                contract_info,
                adaptor_info,
                &attestations,
                &signer,
            )?;

            // Check that the lock time has passed
            let time = bitcoin::absolute::Time::from_consensus(self.time.unix_time_now() as u32)
                .expect("Time is not in valid range. This should never happen.");
            let height = Height::from_consensus(self.blockchain.get_blockchain_height()? as u32)
                .expect("Height is not in valid range. This should never happen.");
            let locktime = cet.lock_time;

            if !locktime.is_satisfied_by(height, time) {
                return Err(Error::InvalidState(
                    "CET lock time has not passed yet".to_string(),
                ));
            }

            match self.close_contract(
                &contract,
                cet,
                attestations.into_iter().map(|x| x.1).collect(),
            ) {
                Ok(closed_contract) => {
                    self.store.update_contract(&closed_contract)?;
                    Ok(closed_contract)
                }
                Err(e) => {
                    warn!(
                        "Failed to close contract {}: {e}",
                        contract.accepted_contract.get_contract_id_string()
                    );
                    Err(e)
                }
            }
        } else {
            Err(Error::InvalidState(
                "Attestations did not match contract infos".to_string(),
            ))
        }
    }

    fn check_preclosed_contracts(&self) -> Result<(), Error> {
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

    fn check_preclosed_contract(&self, contract: &PreClosedContract) -> Result<(), Error> {
        let broadcasted_txid = contract.signed_cet.compute_txid();
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
        &self,
        contract: &SignedContract,
        signed_cet: Transaction,
        attestations: Vec<OracleAttestation>,
    ) -> Result<Contract, Error> {
        let confirmations = self
            .blockchain
            .get_transaction_confirmations(&signed_cet.compute_txid())?;

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

    fn check_refund(&self, contract: &SignedContract) -> Result<(), Error> {
        // TODO(tibo): should check for confirmation of refund before updating state
        if contract
            .accepted_contract
            .dlc_transactions
            .refund
            .lock_time
            .to_consensus_u32() as u64
            <= self.time.unix_time_now()
        {
            let accepted_contract = &contract.accepted_contract;
            let refund = accepted_contract.dlc_transactions.refund.clone();
            let confirmations = self
                .blockchain
                .get_transaction_confirmations(&refund.compute_txid())?;
            if confirmations == 0 {
                let offer = &contract.accepted_contract.offered_contract;
                let signer = self.signer_provider.derive_contract_signer(offer.keys_id)?;
                let refund =
                    crate::contract_updater::get_signed_refund(&self.secp, contract, &signer)?;
                self.blockchain.send_transaction(&refund)?;
            }

            self.store
                .update_contract(&Contract::Refunded(contract.clone()))?;
        }

        Ok(())
    }

    /// Function to call when we detect that a contract was closed by our counter party.
    /// This will update the state of the contract and return the [`Contract`] object.
    pub fn on_counterparty_close(
        &mut self,
        contract: &SignedContract,
        closing_tx: Transaction,
        confirmations: u32,
    ) -> Result<Contract, Error> {
        // check if the closing tx actually spends the funding output
        if !closing_tx.input.iter().any(|i| {
            i.previous_output
                == contract
                    .accepted_contract
                    .dlc_transactions
                    .get_fund_outpoint()
        }) {
            return Err(Error::InvalidParameters(
                "Closing tx does not spend the funding tx".to_string(),
            ));
        }

        // check if it is the refund tx (easy case)
        if contract
            .accepted_contract
            .dlc_transactions
            .refund
            .compute_txid()
            == closing_tx.compute_txid()
        {
            let refunded = Contract::Refunded(contract.clone());
            self.store.update_contract(&refunded)?;
            return Ok(refunded);
        }

        let contract = if confirmations < NB_CONFIRMATIONS {
            Contract::PreClosed(PreClosedContract {
                signed_contract: contract.clone(),
                attestations: None, // todo in some cases we can get the attestations from the closing tx
                signed_cet: closing_tx,
            })
        } else {
            Contract::Closed(ClosedContract {
                attestations: None, // todo in some cases we can get the attestations from the closing tx
                pnl: contract.accepted_contract.compute_pnl(&closing_tx),
                signed_cet: Some(closing_tx),
                contract_id: contract.accepted_contract.get_contract_id(),
                temporary_contract_id: contract.accepted_contract.offered_contract.id,
                counter_party_id: contract.accepted_contract.offered_contract.counter_party,
            })
        };

        self.store.update_contract(&contract)?;

        Ok(contract)
    }

    #[maybe_async]
    fn get_oracle_announcements_from_infos(
        &self,
        contract_input: &ContractInput,
    ) -> Result<Vec<Vec<OracleAnnouncement>>, Error> {
        let mut oracle_announcements = vec![];
        for contract_info in contract_input.contract_infos.clone() {
            let announcement = maybe_await!(self.get_oracle_announcements(&contract_info.oracles))?;
            oracle_announcements.push(announcement);
        }

        Ok(oracle_announcements)
    }
}

impl<W: Deref, SP: Deref, B: Deref, S: Deref, O: Deref, T: Deref, F: Deref, X: ContractSigner>
    Manager<W, Arc<CachedContractSignerProvider<SP, X>>, B, S, O, T, F, X>
where
    W::Target: Wallet,
    SP::Target: ContractSignerProvider<Signer = X>,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
    F::Target: FeeEstimator,
{
    /// Create a new channel offer and return the [`dlc_messages::channel::OfferChannel`]
    /// message to be sent to the `counter_party`.
    #[maybe_async]
    pub fn offer_channel(
        &self,
        contract_input: &ContractInput,
        counter_party: PublicKey,
    ) -> Result<OfferChannel, Error> {
        let oracle_announcements =
            maybe_await!(self.get_oracle_announcements_from_infos(contract_input))?;

        let (offered_channel, offered_contract) = crate::channel_updater::offer_channel(
            &self.secp,
            contract_input,
            &counter_party,
            &oracle_announcements,
            CET_NSEQUENCE,
            REFUND_DELAY,
            &self.wallet,
            &self.signer_provider,
            &self.blockchain,
            &self.time,
            crate::utils::get_new_temporary_id(),
        )?;

        let msg = offered_channel.get_offer_channel_msg(&offered_contract);

        self.store.upsert_channel(
            Channel::Offered(offered_channel),
            Some(Contract::Offered(offered_contract)),
        )?;

        Ok(msg)
    }

    /// Reject a channel that was offered. Returns the [`dlc_messages::channel::Reject`]
    /// message to be sent as well as the public key of the offering node.
    pub fn reject_channel(&self, channel_id: &ChannelId) -> Result<(Reject, PublicKey), Error> {
        let offered_channel =
            get_channel_in_state!(self, channel_id, Offered, None as Option<PublicKey>)?;

        if offered_channel.is_offer_party {
            return Err(Error::InvalidState(
                "Cannot reject channel initiated by us.".to_string(),
            ));
        }

        let offered_contract = get_contract_in_state!(
            self,
            &offered_channel.offered_contract_id,
            Offered,
            None as Option<PublicKey>
        )?;

        let counterparty = offered_channel.counter_party;
        self.store.upsert_channel(
            Channel::Cancelled(offered_channel),
            Some(Contract::Rejected(offered_contract)),
        )?;

        let msg = Reject {
            channel_id: *channel_id,
        };
        Ok((msg, counterparty))
    }

    /// Accept a channel that was offered. Returns the [`dlc_messages::channel::AcceptChannel`]
    /// message to be sent, the updated [`crate::ChannelId`] and [`crate::ContractId`],
    /// as well as the public key of the offering node.
    pub fn accept_channel(
        &self,
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
                &self.signer_provider,
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
    pub fn force_close_channel(&self, channel_id: &ChannelId) -> Result<(), Error> {
        let channel = get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        self.force_close_channel_internal(channel, true)
    }

    /// Offer to settle the balance of a channel so that the counter party gets
    /// `counter_payout`. Returns the [`dlc_messages::channel::SettleChannelOffer`]
    /// message to be sent and the public key of the counter party node.
    pub fn settle_offer(
        &self,
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
            &self.signer_provider,
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
        &self,
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
            &self.signer_provider,
            &self.time,
            &self.chain_monitor,
        )?;

        let counter_party = signed_channel.counter_party;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok((msg, counter_party))
    }

    /// Returns a [`RenewOffer`] message as well as the [`PublicKey`] of the
    /// counter party's node to offer the establishment of a new contract in the
    /// channel.
    #[maybe_async]
    pub fn renew_offer(
        &self,
        channel_id: &ChannelId,
        counter_payout: u64,
        contract_input: &ContractInput,
    ) -> Result<(RenewOffer, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let oracle_announcements =
            maybe_await!(self.get_oracle_announcements_from_infos(contract_input))?;

        let (msg, offered_contract) = crate::channel_updater::renew_offer(
            &self.secp,
            &mut signed_channel,
            contract_input,
            oracle_announcements,
            counter_payout,
            REFUND_DELAY,
            PEER_TIMEOUT,
            CET_NSEQUENCE,
            &self.signer_provider,
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
        &self,
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
            &self.signer_provider,
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
    pub fn reject_renew_offer(&self, channel_id: &ChannelId) -> Result<(Reject, PublicKey), Error> {
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
        &self,
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
        &self,
        channel_id: &ChannelId,
        counter_payout: u64,
    ) -> Result<CollaborativeCloseOffer, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let (msg, close_tx) = crate::channel_updater::offer_collaborative_close(
            &self.secp,
            &mut signed_channel,
            counter_payout,
            &self.signer_provider,
            &self.time,
        )?;

        self.chain_monitor.lock().unwrap().add_tx(
            close_tx.compute_txid(),
            ChannelInfo {
                channel_id: *channel_id,
                tx_type: TxType::CollaborativeClose,
            },
        );

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;
        self.store
            .persist_chain_monitor(&self.chain_monitor.lock().unwrap())?;

        Ok(msg)
    }

    /// Accept an offer to collaboratively close the channel. The close transaction
    /// will be broadcast and the state of the channel updated.
    pub fn accept_collaborative_close(&self, channel_id: &ChannelId) -> Result<(), Error> {
        let signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let closed_contract = if let Some(SignedChannelState::Established {
            signed_contract_id,
            ..
        }) = &signed_channel.roll_back_state
        {
            let counter_payout = get_signed_channel_state!(
                signed_channel,
                CollaborativeCloseOffered,
                counter_payout
            )?;
            Some(self.get_collaboratively_closed_contract(
                signed_contract_id,
                *counter_payout,
                true,
            )?)
        } else {
            None
        };

        let (close_tx, closed_channel) = crate::channel_updater::accept_collaborative_close_offer(
            &self.secp,
            &signed_channel,
            &self.signer_provider,
        )?;

        self.blockchain.send_transaction(&close_tx)?;

        self.store.upsert_channel(closed_channel, None)?;

        if let Some(closed_contract) = closed_contract {
            self.store
                .update_contract(&Contract::Closed(closed_contract))?;
        }

        Ok(())
    }

    #[maybe_async]
    fn try_finalize_closing_established_channel(
        &self,
        signed_channel: SignedChannel,
    ) -> Result<(), Error> {
        let (buffer_tx, contract_id, &is_initiator) = get_signed_channel_state!(
            signed_channel,
            Closing,
            buffer_transaction,
            contract_id,
            is_initiator
        )?;

        if self
            .blockchain
            .get_transaction_confirmations(&buffer_tx.compute_txid())?
            >= CET_NSEQUENCE
        {
            log::info!(
                "Buffer transaction for contract {} has enough confirmations to spend from it",
                serialize_hex(&contract_id)
            );

            let confirmed_contract =
                get_contract_in_state!(self, &contract_id, Confirmed, None as Option<PublicKey>)?;

            let (contract_info, adaptor_info, attestations) = maybe_await!(
                self.get_closable_contract_info(&confirmed_contract)
            )
            .ok_or_else(|| {
                Error::InvalidState("Could not get information to close contract".to_string())
            })?;

            let (signed_cet, closed_channel) =
                crate::channel_updater::finalize_unilateral_close_settled_channel(
                    &self.secp,
                    &signed_channel,
                    &confirmed_contract,
                    contract_info,
                    &attestations,
                    adaptor_info,
                    &self.signer_provider,
                    is_initiator,
                )?;

            let closed_contract = self.close_contract(
                &confirmed_contract,
                signed_cet,
                attestations.iter().map(|x| &x.1).cloned().collect(),
            )?;

            self.chain_monitor
                .lock()
                .unwrap()
                .cleanup_channel(signed_channel.channel_id);

            self.store
                .upsert_channel(closed_channel, Some(closed_contract))?;
        }

        Ok(())
    }

    fn on_offer_channel(
        &self,
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

        let keys_id = self
            .signer_provider
            .derive_signer_key_id(false, offer_channel.temporary_contract_id);
        let (channel, contract) =
            OfferedChannel::from_offer_channel(offer_channel, counter_party, keys_id)?;

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
        &self,
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
                &self.signer_provider,
                &self.chain_monitor,
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
            self.chain_monitor.lock().unwrap().add_tx(
                buffer_transaction.compute_txid(),
                ChannelInfo {
                    channel_id: signed_channel.channel_id,
                    tx_type: TxType::BufferTx,
                },
            );
        } else {
            unreachable!();
        }

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Signed(signed_contract)),
        )?;

        self.store
            .persist_chain_monitor(&self.chain_monitor.lock().unwrap())?;

        Ok(sign_channel)
    }

    fn on_sign_channel(
        &self,
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

        let (signed_channel, signed_contract, signed_fund_tx) = {
            let res = verify_signed_channel(
                &self.secp,
                &accepted_channel,
                &accepted_contract,
                sign_channel,
                &self.wallet,
                &self.chain_monitor,
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
            self.chain_monitor.lock().unwrap().add_tx(
                buffer_transaction.compute_txid(),
                ChannelInfo {
                    channel_id: signed_channel.channel_id,
                    tx_type: TxType::BufferTx,
                },
            );
        } else {
            unreachable!();
        }

        self.blockchain.send_transaction(&signed_fund_tx)?;

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Signed(signed_contract)),
        )?;
        self.store
            .persist_chain_monitor(&self.chain_monitor.lock().unwrap())?;

        Ok(())
    }

    fn on_settle_offer(
        &self,
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
        &self,
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
            &self.signer_provider,
            &self.time,
            &self.chain_monitor,
        )?;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(msg)
    }

    fn on_settle_confirm(
        &self,
        settle_confirm: &SettleConfirm,
        peer_id: &PublicKey,
    ) -> Result<SettleFinalize, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &settle_confirm.channel_id, Signed, Some(*peer_id))?;
        let &own_payout = get_signed_channel_state!(signed_channel, SettledAccepted, own_payout)?;
        let (prev_buffer_tx, own_buffer_adaptor_signature, is_offer, signed_contract_id) = get_signed_channel_rollback_state!(
            signed_channel,
            Established,
            buffer_transaction,
            own_buffer_adaptor_signature,
            is_offer,
            signed_contract_id
        )?;

        let prev_buffer_txid = prev_buffer_tx.compute_txid();
        let own_buffer_adaptor_signature = *own_buffer_adaptor_signature;
        let is_offer = *is_offer;
        let signed_contract_id = *signed_contract_id;

        let msg = crate::channel_updater::settle_channel_finalize(
            &self.secp,
            &mut signed_channel,
            settle_confirm,
            &self.signer_provider,
        )?;

        self.chain_monitor.lock().unwrap().add_tx(
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

        let closed_contract = Contract::Closed(self.get_collaboratively_closed_contract(
            &signed_contract_id,
            own_payout,
            true,
        )?);

        self.store
            .upsert_channel(Channel::Signed(signed_channel), Some(closed_contract))?;
        self.store
            .persist_chain_monitor(&self.chain_monitor.lock().unwrap())?;

        Ok(msg)
    }

    fn on_settle_finalize(
        &self,
        settle_finalize: &SettleFinalize,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &settle_finalize.channel_id, Signed, Some(*peer_id))?;
        let &own_payout = get_signed_channel_state!(signed_channel, SettledConfirmed, own_payout)?;
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
        let buffer_txid = buffer_tx.compute_txid();
        let signed_contract_id = *signed_contract_id;

        crate::channel_updater::settle_channel_on_finalize(
            &self.secp,
            &mut signed_channel,
            settle_finalize,
        )?;

        self.chain_monitor.lock().unwrap().add_tx(
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

        let closed_contract = Contract::Closed(self.get_collaboratively_closed_contract(
            &signed_contract_id,
            own_payout,
            true,
        )?);
        self.store
            .upsert_channel(Channel::Signed(signed_channel), Some(closed_contract))?;
        self.store
            .persist_chain_monitor(&self.chain_monitor.lock().unwrap())?;

        Ok(())
    }

    fn on_renew_offer(
        &self,
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

        let offered_contract = crate::channel_updater::on_renew_offer(
            &mut signed_channel,
            renew_offer,
            PEER_TIMEOUT,
            &self.time,
        )?;

        self.store.create_contract(&offered_contract)?;
        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(None)
    }

    fn on_renew_accept(
        &self,
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
            &self.signer_provider,
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
        &self,
        renew_confirm: &RenewConfirm,
        peer_id: &PublicKey,
    ) -> Result<RenewFinalize, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_confirm.channel_id, Signed, Some(*peer_id))?;
        let own_payout = get_signed_channel_state!(signed_channel, RenewAccepted, own_payout)?;
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
                let closed_contract = Contract::Closed(self.get_collaboratively_closed_contract(
                    signed_contract_id,
                    *own_payout,
                    true,
                )?);
                (
                    TxType::Revoked {
                        update_idx: signed_channel.update_idx,
                        own_adaptor_signature: *own_buffer_adaptor_signature,
                        is_offer: false,
                        revoked_tx_type: RevokedTxType::Buffer,
                    },
                    buffer_transaction.compute_txid(),
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
                settle_tx.compute_txid(),
                None,
            ),
            s => {
                return Err(Error::InvalidState(format!(
                    "Expected rollback state Established or Revoked but found {s:?}"
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
            PEER_TIMEOUT,
            &self.time,
            &self.wallet,
            &self.signer_provider,
            &self.chain_monitor,
        )?;

        self.chain_monitor.lock().unwrap().add_tx(
            prev_tx_id,
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type,
            },
        );

        // Directly confirmed as we're in a channel the fund tx is already confirmed.
        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Confirmed(signed_contract)),
        )?;

        self.store
            .persist_chain_monitor(&self.chain_monitor.lock().unwrap())?;

        if let Some(closed_contract) = closed_contract {
            self.store.update_contract(&closed_contract)?;
        }

        Ok(msg)
    }

    fn on_renew_finalize(
        &self,
        renew_finalize: &RenewFinalize,
        peer_id: &PublicKey,
    ) -> Result<RenewRevoke, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_finalize.channel_id, Signed, Some(*peer_id))?;
        let own_payout = get_signed_channel_state!(signed_channel, RenewConfirmed, own_payout)?;

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
                let closed_contract = self.get_collaboratively_closed_contract(
                    signed_contract_id,
                    *own_payout,
                    true,
                )?;
                (
                    TxType::Revoked {
                        update_idx: signed_channel.update_idx,
                        own_adaptor_signature: *own_buffer_adaptor_signature,
                        is_offer: false,
                        revoked_tx_type: RevokedTxType::Buffer,
                    },
                    buffer_transaction.compute_txid(),
                    Some(Contract::Closed(closed_contract)),
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
                settle_tx.compute_txid(),
                None,
            ),
            s => {
                return Err(Error::InvalidState(format!(
                    "Expected rollback state of Established or Settled but was {s:?}"
                )))
            }
        };

        let msg = crate::channel_updater::renew_channel_on_finalize(
            &self.secp,
            &mut signed_channel,
            renew_finalize,
            &self.signer_provider,
        )?;

        self.chain_monitor.lock().unwrap().add_tx(
            prev_tx_id,
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type,
            },
        );

        let buffer_tx =
            get_signed_channel_state!(signed_channel, Established, ref buffer_transaction)?;

        self.chain_monitor.lock().unwrap().add_tx(
            buffer_tx.compute_txid(),
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type: TxType::BufferTx,
            },
        );

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;
        self.store
            .persist_chain_monitor(&self.chain_monitor.lock().unwrap())?;

        if let Some(closed_contract) = closed_contract {
            self.store.update_contract(&closed_contract)?;
        }

        Ok(msg)
    }

    fn on_renew_revoke(
        &self,
        renew_revoke: &RenewRevoke,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_revoke.channel_id, Signed, Some(*peer_id))?;

        crate::channel_updater::renew_channel_on_revoke(
            &self.secp,
            &mut signed_channel,
            renew_revoke,
        )?;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)
    }

    fn on_collaborative_close_offer(
        &self,
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

    fn on_reject(&self, reject: &Reject, counter_party: &PublicKey) -> Result<(), Error> {
        let channel = self.store.get_channel(&reject.channel_id)?;

        if let Some(channel) = channel {
            if channel.get_counter_party_id() != *counter_party {
                return Err(Error::InvalidParameters(format!(
                    "Peer {:02x?} is not involved with {} {:02x?}.",
                    counter_party,
                    stringify!(Channel),
                    channel.get_id()
                )));
            }
            match channel {
                Channel::Offered(offered_channel) => {
                    let offered_contract = get_contract_in_state!(
                        self,
                        &offered_channel.offered_contract_id,
                        Offered,
                        None as Option<PublicKey>
                    )?;
                    let utxos = offered_contract
                        .funding_inputs
                        .iter()
                        .map(|funding_input| {
                            let txid = Transaction::consensus_decode(
                                &mut funding_input.prev_tx.as_slice(),
                            )
                            .expect("Transaction Decode Error")
                            .compute_txid();
                            let vout = funding_input.prev_tx_vout;
                            OutPoint { txid, vout }
                        })
                        .collect::<Vec<_>>();

                    self.wallet.unreserve_utxos(&utxos)?;

                    // remove rejected channel, since nothing has been confirmed on chain yet.
                    self.store.upsert_channel(
                        Channel::Cancelled(offered_channel),
                        Some(Contract::Rejected(offered_contract)),
                    )?;
                }
                Channel::Signed(mut signed_channel) => {
                    let contract = match signed_channel.state {
                        SignedChannelState::RenewOffered {
                            offered_contract_id,
                            ..
                        } => {
                            let offered_contract = get_contract_in_state!(
                                self,
                                &offered_contract_id,
                                Offered,
                                None::<PublicKey>
                            )?;
                            Some(Contract::Rejected(offered_contract))
                        }
                        _ => None,
                    };

                    crate::channel_updater::on_reject(&mut signed_channel)?;

                    self.store
                        .upsert_channel(Channel::Signed(signed_channel), contract)?;
                }
                channel => {
                    return Err(Error::InvalidState(format!(
                        "Not in a state adequate to receive a reject message. {:?}",
                        channel
                    )))
                }
            }
        } else {
            warn!(
                "Couldn't find rejected dlc channel with id: {}",
                reject.channel_id.to_lower_hex_string()
            );
        }

        Ok(())
    }

    #[maybe_async]
    fn channel_checks(&self) -> Result<(), Error> {
        let established_closing_channels = self
            .store
            .get_signed_channels(Some(SignedChannelStateType::Closing))?;

        for channel in established_closing_channels {
            if let Err(e) = maybe_await!(self.try_finalize_closing_established_channel(channel)) {
                error!("Error trying to close established channel: {}", e);
            }
        }

        if let Err(e) = self.check_for_timed_out_channels() {
            error!("Error checking timed out channels {}", e);
        }
        self.check_for_watched_tx()
    }

    fn check_for_timed_out_channels(&self) -> Result<(), Error> {
        check_for_timed_out_channels!(self, RenewOffered);
        check_for_timed_out_channels!(self, RenewAccepted);
        check_for_timed_out_channels!(self, RenewConfirmed);
        check_for_timed_out_channels!(self, SettledOffered);
        check_for_timed_out_channels!(self, SettledAccepted);
        check_for_timed_out_channels!(self, SettledConfirmed);

        Ok(())
    }

    pub(crate) fn process_watched_txs(
        &self,
        watched_txs: Vec<(Transaction, ChannelInfo)>,
    ) -> Result<(), Error> {
        for (tx, channel_info) in watched_txs {
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

            let persist = match channel_info.tx_type {
                TxType::BufferTx => {
                    // TODO(tibo): should only considered closed after some confirmations.
                    // Ideally should save previous state, and maybe restore in
                    // case of reorg, though if the counter party has sent the
                    // tx to close the channel it is unlikely that the tx will
                    // not be part of a future block.

                    let contract_id = signed_channel
                        .get_contract_id()
                        .expect("to have a contract id");
                    let mut state = SignedChannelState::Closing {
                        buffer_transaction: tx.clone(),
                        is_initiator: false,
                        contract_id,
                        keys_id: signed_channel.keys_id().ok_or_else(|| {
                            Error::InvalidState("Expected to have keys_id.".to_string())
                        })?,
                    };
                    std::mem::swap(&mut signed_channel.state, &mut state);

                    signed_channel.roll_back_state = Some(state);

                    self.store
                        .upsert_channel(Channel::Signed(signed_channel), None)?;

                    false
                }
                TxType::Revoked {
                    update_idx,
                    own_adaptor_signature,
                    is_offer,
                    revoked_tx_type,
                } => {
                    let secret = signed_channel
                        .counter_party_commitment_secrets
                        .get_secret(update_idx)
                        .expect("to be able to retrieve the per update secret");
                    let counter_per_update_secret = SecretKey::from_slice(&secret)
                        .expect("to be able to parse the counter per update secret.");

                    let per_update_seed_pk = signed_channel.own_per_update_seed;

                    let per_update_seed_sk = self
                        .signer_provider
                        .get_secret_key_for_pubkey(&per_update_seed_pk)?;

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
                        .signer_provider
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

                    let own_revocation_base_secret =
                        &self.signer_provider.get_secret_key_for_pubkey(
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
                        lightning::chain::chaininterface::ConfirmationTarget::UrgentOnChainSweep,
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

                    let closed_channel = Channel::ClosedPunished(ClosedPunishedChannel {
                        counter_party: signed_channel.counter_party,
                        temporary_channel_id: signed_channel.temporary_channel_id,
                        channel_id: signed_channel.channel_id,
                        punish_txid: signed_tx.compute_txid(),
                    });

                    //TODO(tibo): should probably make sure the tx is confirmed somewhere before
                    //stop watching the cheating tx.
                    self.chain_monitor
                        .lock()
                        .unwrap()
                        .cleanup_channel(signed_channel.channel_id);
                    self.store.upsert_channel(closed_channel, None)?;
                    true
                }
                TxType::CollaborativeClose => {
                    if let Some(SignedChannelState::Established {
                        signed_contract_id, ..
                    }) = signed_channel.roll_back_state
                    {
                        let counter_payout = get_signed_channel_state!(
                            signed_channel,
                            CollaborativeCloseOffered,
                            counter_payout
                        )?;
                        let closed_contract = self.get_collaboratively_closed_contract(
                            &signed_contract_id,
                            *counter_payout,
                            false,
                        )?;
                        self.store
                            .update_contract(&Contract::Closed(closed_contract))?;
                    }
                    let closed_channel = Channel::CollaborativelyClosed(ClosedChannel {
                        counter_party: signed_channel.counter_party,
                        temporary_channel_id: signed_channel.temporary_channel_id,
                        channel_id: signed_channel.channel_id,
                    });
                    self.chain_monitor
                        .lock()
                        .unwrap()
                        .cleanup_channel(signed_channel.channel_id);
                    self.store.upsert_channel(closed_channel, None)?;
                    true
                }
                TxType::SettleTx => {
                    let closed_channel = Channel::CounterClosed(ClosedChannel {
                        counter_party: signed_channel.counter_party,
                        temporary_channel_id: signed_channel.temporary_channel_id,
                        channel_id: signed_channel.channel_id,
                    });
                    self.chain_monitor
                        .lock()
                        .unwrap()
                        .cleanup_channel(signed_channel.channel_id);
                    self.store.upsert_channel(closed_channel, None)?;
                    true
                }
                TxType::Cet => {
                    let contract_id = signed_channel.get_contract_id();
                    let closed_channel = {
                        match &signed_channel.state {
                            SignedChannelState::Closing { is_initiator, .. } => {
                                if *is_initiator {
                                    Channel::Closed(ClosedChannel {
                                        counter_party: signed_channel.counter_party,
                                        temporary_channel_id: signed_channel.temporary_channel_id,
                                        channel_id: signed_channel.channel_id,
                                    })
                                } else {
                                    Channel::CounterClosed(ClosedChannel {
                                        counter_party: signed_channel.counter_party,
                                        temporary_channel_id: signed_channel.temporary_channel_id,
                                        channel_id: signed_channel.channel_id,
                                    })
                                }
                            }
                            _ => {
                                error!("Saw spending of buffer transaction without being in closing state");
                                Channel::Closed(ClosedChannel {
                                    counter_party: signed_channel.counter_party,
                                    temporary_channel_id: signed_channel.temporary_channel_id,
                                    channel_id: signed_channel.channel_id,
                                })
                            }
                        }
                    };

                    self.chain_monitor
                        .lock()
                        .unwrap()
                        .cleanup_channel(signed_channel.channel_id);

                    let pre_closed_contract = contract_id
                        .map(|contract_id| {
                            self.store.get_contract(&contract_id).map(|contract| {
                                contract.map(|contract| match contract {
                                    Contract::Confirmed(signed_contract) => {
                                        Some(Contract::PreClosed(PreClosedContract {
                                            signed_contract,
                                            attestations: None,
                                            signed_cet: tx.clone(),
                                        }))
                                    }
                                    _ => None,
                                })
                            })
                        })
                        .transpose()?
                        .flatten()
                        .flatten();

                    self.store
                        .upsert_channel(closed_channel, pre_closed_contract)?;

                    true
                }
            };

            if persist {
                self.store
                    .persist_chain_monitor(&self.chain_monitor.lock().unwrap())?;
            }
        }
        Ok(())
    }

    fn check_for_watched_tx(&self) -> Result<(), Error> {
        let confirmed_txs = self.chain_monitor.lock().unwrap().confirmed_txs();

        self.process_watched_txs(confirmed_txs)?;

        self.get_store()
            .persist_chain_monitor(&self.chain_monitor.lock().unwrap())?;

        Ok(())
    }

    fn force_close_channel_internal(
        &self,
        mut channel: SignedChannel,
        is_initiator: bool,
    ) -> Result<(), Error> {
        match &channel.state {
            SignedChannelState::Established {
                counter_buffer_adaptor_signature,
                buffer_transaction,
                ..
            } => {
                let counter_buffer_adaptor_signature = *counter_buffer_adaptor_signature;
                let buffer_transaction = buffer_transaction.clone();
                self.initiate_unilateral_close_established_channel(
                    channel,
                    is_initiator,
                    counter_buffer_adaptor_signature,
                    buffer_transaction,
                )
            }
            SignedChannelState::RenewFinalized {
                buffer_transaction,
                offer_buffer_adaptor_signature,
                ..
            } => {
                let offer_buffer_adaptor_signature = *offer_buffer_adaptor_signature;
                let buffer_transaction = buffer_transaction.clone();
                self.initiate_unilateral_close_established_channel(
                    channel,
                    is_initiator,
                    offer_buffer_adaptor_signature,
                    buffer_transaction,
                )
            }
            SignedChannelState::Settled { .. } => self.close_settled_channel(channel, is_initiator),
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
                self.force_close_channel_internal(channel, is_initiator)
            }
            SignedChannelState::Closing { .. } => Err(Error::InvalidState(
                "Channel is already closing.".to_string(),
            )),
        }
    }

    /// Initiate the unilateral closing of a channel that has been established.
    fn initiate_unilateral_close_established_channel(
        &self,
        mut signed_channel: SignedChannel,
        is_initiator: bool,
        buffer_adaptor_signature: EcdsaAdaptorSignature,
        buffer_transaction: Transaction,
    ) -> Result<(), Error> {
        let keys_id = signed_channel.keys_id().ok_or_else(|| {
            Error::InvalidState("Expected to be in a state with an associated keys id.".to_string())
        })?;

        crate::channel_updater::initiate_unilateral_close_established_channel(
            &self.secp,
            &mut signed_channel,
            buffer_adaptor_signature,
            keys_id,
            buffer_transaction,
            &self.signer_provider,
            is_initiator,
        )?;

        let buffer_transaction =
            get_signed_channel_state!(signed_channel, Closing, ref buffer_transaction)?;

        self.blockchain.send_transaction(buffer_transaction)?;

        self.chain_monitor
            .lock()
            .unwrap()
            .remove_tx(&buffer_transaction.compute_txid());

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        self.store
            .persist_chain_monitor(&self.chain_monitor.lock().unwrap())?;

        Ok(())
    }

    /// Unilaterally close a channel that has been settled.
    fn close_settled_channel(
        &self,
        signed_channel: SignedChannel,
        is_initiator: bool,
    ) -> Result<(), Error> {
        let (settle_tx, closed_channel) = crate::channel_updater::close_settled_channel(
            &self.secp,
            &signed_channel,
            &self.signer_provider,
            is_initiator,
        )?;

        if self
            .blockchain
            .get_transaction_confirmations(&settle_tx.compute_txid())
            .unwrap_or(0)
            == 0
        {
            self.blockchain.send_transaction(&settle_tx)?;
        }

        self.chain_monitor
            .lock()
            .unwrap()
            .cleanup_channel(signed_channel.channel_id);

        self.store.upsert_channel(closed_channel, None)?;

        Ok(())
    }

    fn get_collaboratively_closed_contract(
        &self,
        contract_id: &ContractId,
        payout: u64,
        is_own_payout: bool,
    ) -> Result<ClosedContract, Error> {
        let contract = get_contract_in_state!(self, contract_id, Confirmed, None::<PublicKey>)?;
        let own_collateral = if contract.accepted_contract.offered_contract.is_offer_party {
            contract
                .accepted_contract
                .offered_contract
                .offer_params
                .collateral
        } else {
            contract.accepted_contract.accept_params.collateral
        };
        let own_payout = if is_own_payout {
            payout
        } else {
            contract.accepted_contract.offered_contract.total_collateral - payout
        };
        let pnl = own_payout as i64 - own_collateral as i64;
        Ok(ClosedContract {
            attestations: None,
            signed_cet: None,
            contract_id: *contract_id,
            temporary_contract_id: contract.accepted_contract.offered_contract.id,
            counter_party_id: contract.accepted_contract.offered_contract.counter_party,
            pnl,
        })
    }
}

#[cfg(test)]
mod test {
    use dlc_messages::Message;
    use mocks::{
        dlc_manager::{manager::Manager, CachedContractSignerProvider, Oracle, SimpleSigner},
        memory_storage_provider::MemoryStorage,
        mock_blockchain::MockBlockchain,
        mock_oracle_provider::MockOracle,
        mock_time::MockTime,
        mock_wallet::MockWallet,
    };
    use secp256k1_zkp::{PublicKey, XOnlyPublicKey};
    use std::{collections::HashMap, rc::Rc, sync::Arc};

    type TestManager = Manager<
        Rc<MockWallet>,
        Arc<CachedContractSignerProvider<Rc<MockWallet>, SimpleSigner>>,
        Rc<MockBlockchain>,
        Rc<MemoryStorage>,
        Rc<MockOracle>,
        Rc<MockTime>,
        Rc<MockBlockchain>,
        SimpleSigner,
    >;

    fn get_manager() -> TestManager {
        let blockchain = Rc::new(MockBlockchain::new());
        let store = Rc::new(MemoryStorage::new());
        let wallet = Rc::new(MockWallet::new(
            &blockchain,
            &(0..100).map(|x| x as u64 * 1000000).collect::<Vec<_>>(),
        ));

        let oracle_list = (0..5).map(|_| MockOracle::new()).collect::<Vec<_>>();
        let oracles: HashMap<XOnlyPublicKey, _> = oracle_list
            .into_iter()
            .map(|x| (x.get_public_key(), Rc::new(x)))
            .collect();
        let time = Rc::new(MockTime {});

        mocks::mock_time::set_time(0);

        Manager::new(
            wallet.clone(),
            wallet,
            blockchain.clone(),
            store,
            oracles,
            time,
            blockchain,
        )
        .unwrap()
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

        let manager = get_manager();

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

        let manager = get_manager();

        manager
            .on_dlc_message(&offer_message, pubkey())
            .expect("To accept the first offer message");

        manager
            .on_dlc_message(&offer_message, pubkey())
            .expect_err("To reject the second offer message");
    }
}
