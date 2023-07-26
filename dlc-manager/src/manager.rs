//! #Manager a component to create and update DLCs.

use super::{Blockchain, Oracle, Storage, Time, Wallet};
use crate::contract::{
    accepted_contract::AcceptedContract, contract_info::ContractInfo,
    contract_input::ContractInput, contract_input::OracleInput, offered_contract::OfferedContract,
    signed_contract::SignedContract, AdaptorInfo, ClosedContract, Contract, FailedAcceptContract,
    FailedSignContract, PreClosedContract,
};
use crate::contract_updater::{accept_contract, verify_accepted_and_sign_contract};
use crate::error::Error;
use crate::{ChannelId, ContractId};
use bitcoin::Address;
use bitcoin::Transaction;
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::{AcceptDlc, Message as DlcMessage, OfferDlc, SignDlc};
use lightning::chain::chaininterface::FeeEstimator;
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

macro_rules! get_signed_channel_rollback_state {
    ($signed_channel: ident, $state: ident, $($field: ident),*) => {{
       match $signed_channel.roll_back_state.as_ref() {
           Some(SignedChannelState::$state{$($field,)* ..}) => Ok(($($field,)*)),
           _ => Err(Error::InvalidState(format!("Expected rollback state {} got {:?}", stringify!($state), $signed_channel.state))),
        }
    }};
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
        Ok(Manager {
            secp: secp256k1_zkp::Secp256k1::new(),
            wallet,
            blockchain,
            store,
            oracles,
            time,
            fee_estimator,
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
        let blockchain = Rc::new(MockBlockchain {});
        let store = Rc::new(MemoryStorage::new());
        let wallet = Rc::new(MockWallet::new(&blockchain, 100));

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
