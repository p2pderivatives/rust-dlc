//! #Manager a component to create and update DLCs.

use super::{
    Blockchain, CachedContractSignerProvider, ContractSigner, Oracle, Storage, Time, Wallet,
};
use crate::contract::{
    accepted_contract::AcceptedContract, contract_info::ContractInfo,
    contract_input::ContractInput, contract_input::OracleInput, offered_contract::OfferedContract,
    signed_contract::SignedContract, AdaptorInfo, ClosedContract, Contract, FailedAcceptContract,
    FailedSignContract, PreClosedContract,
};
use crate::contract_updater::{accept_contract, verify_accepted_and_sign_contract};
use crate::error::Error;
use crate::utils::get_object_in_state;
use crate::{ContractId, ContractSignerProvider};
use bitcoin::Transaction;
use bitcoin::{Address, OutPoint};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::{AcceptDlc, Message as DlcMessage, OfferDlc, SignDlc};
use log::{error, warn};
use secp256k1_zkp::XOnlyPublicKey;
use secp256k1_zkp::{All, PublicKey, Secp256k1};
use std::collections::HashMap;
use std::ops::Deref;
use std::string::ToString;
use std::sync::Arc;

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
pub struct Manager<W: Deref, SP: Deref, B: Deref, S: Deref, O: Deref, T: Deref, X: ContractSigner>
where
    W::Target: Wallet,
    SP::Target: ContractSignerProvider<Signer = X>,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
{
    oracles: HashMap<XOnlyPublicKey, O>,
    /// Wallet used by the manager
    pub wallet: W,
    signer_provider: SP,
    blockchain: B,
    store: S,
    secp: Secp256k1<All>,
    time: T,
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

impl<W: Deref, SP: Deref, B: Deref, S: Deref, O: Deref, T: Deref, X: ContractSigner>
    Manager<W, Arc<CachedContractSignerProvider<SP, X>>, B, S, O, T, X>
where
    W::Target: Wallet,
    SP::Target: ContractSignerProvider<Signer = X>,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
{
    /// Create a new Manager struct.
    pub fn new(
        wallet: W,
        signer_provider: SP,
        blockchain: B,
        store: S,
        oracles: HashMap<XOnlyPublicKey, O>,
        time: T,
    ) -> Result<Self, Error> {
        let signer_provider = Arc::new(CachedContractSignerProvider::new(signer_provider));

        Ok(Manager {
            secp: secp256k1_zkp::Secp256k1::new(),
            wallet,
            signer_provider,
            blockchain,
            store,
            oracles,
            time,
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
            _ => unimplemented!(),
        }
    }

    /// Function called to create a new DLC. The offered contract will be stored
    /// and an OfferDlc message returned.
    ///
    /// This function will fetch the oracle announcements from the oracle.
    pub fn send_offer(
        &self,
        contract_input: &ContractInput,
        counter_party: PublicKey,
    ) -> Result<OfferDlc, Error> {
        let oracle_announcements = contract_input
            .contract_infos
            .iter()
            .map(|x| self.get_oracle_announcements(&x.oracles))
            .collect::<Result<Vec<_>, Error>>()?;

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
            &accepted_contract.fund_transaction.output[0].script_pubkey,
            self.blockchain.get_network()?,
        ))?;

        let contract_id = accepted_contract.get_contract_id();

        self.store
            .update_contract(&Contract::Accepted(accepted_contract))?;

        Ok((contract_id, counter_party, accept_msg))
    }

    /// Get the `AcceptDlc` message for an `AcceptedContract`
    pub fn get_accept_offer_msg(
        &self,
        contract_id: &ContractId,
    ) -> Result<(PublicKey, AcceptDlc), Error> {
        let accepted_contract =
            get_contract_in_state!(self, contract_id, Accepted, None as Option<PublicKey>)?;
        Ok((
            accepted_contract.offered_contract.counter_party,
            accepted_contract.get_accept_contract_msg(),
        ))
    }

    /// Get the `SignDlc` message for a `SignedContract`
    pub fn get_sign_msg(&self, contract_id: &ContractId) -> Result<(PublicKey, SignDlc), Error> {
        let accepted_contract =
            get_contract_in_state!(self, contract_id, Signed, None as Option<PublicKey>)?;
        Ok((
            accepted_contract
                .accepted_contract
                .offered_contract
                .counter_party,
            accepted_contract.get_sign_dlc(),
        ))
    }

    /// Function to call to check the state of the currently executing DLCs and
    /// update them if possible.
    pub fn periodic_check(&self) -> Result<(), Error> {
        self.check_signed_contracts()?;
        self.check_confirmed_contracts()?;
        self.check_preclosed_contracts()?;

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
        ) {
            Ok(contract) => contract,
            Err(e) => return self.accept_fail_on_error(offered_contract, accept_msg.clone(), e),
        };

        self.wallet.import_address(&Address::p2wsh(
            &signed_contract.accepted_contract.fund_transaction.output[0].script_pubkey,
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

    /// Resend the funding transaction
    pub fn resend_fund_tx(&self, contract_id: &ContractId) -> Result<(), Error> {
        let signed_contract = get_contract_in_state!(self, contract_id, Signed, None::<PublicKey>)?;

        let (_, fund_tx) = crate::contract_updater::verify_signed_contract(
            &signed_contract.accepted_contract,
            &signed_contract.get_sign_dlc(),
            &self.wallet,
        )?;

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
            &contract.accepted_contract.fund_transaction.compute_txid(),
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

    fn check_confirmed_contracts(&self) -> Result<(), Error> {
        for c in self.store.get_confirmed_contracts()? {
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
                        let attestation = oracle
                            .get_attestation(&announcement.oracle_event.event_id)
                            .ok()?;
                        attestation
                            .validate(&self.secp, announcement)
                            .map_err(|_| {
                                log::error!(
                                    "Oracle attestation is not valid. pubkey={} event_id={}",
                                    announcement.oracle_public_key,
                                    announcement.oracle_event.event_id
                                )
                            })
                            .ok()?;
                        Some((*i, attestation))
                    })
                    .collect();
                if attestations.len() >= contract_info.threshold {
                    return Some((contract_info, adaptor_info, attestations));
                }
            }
        }
        None
    }

    fn check_confirmed_contract(&self, contract: &SignedContract) -> Result<(), Error> {
        let closable_contract_info = self.get_closable_contract_info(contract);
        if let Some((contract_info, adaptor_info, attestations)) = closable_contract_info {
            let cet = crate::contract_updater::get_signed_cet(
                &self.secp,
                contract,
                contract_info,
                adaptor_info,
                &attestations,
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
            let cet = crate::contract_updater::get_signed_cet(
                &self.secp,
                &contract,
                contract_info,
                adaptor_info,
                &attestations,
            )?;

            // // Check that the lock time has passed
            // let time = bitcoin::absolute::Time::from_consensus(self.time.unix_time_now() as u32)
            //     .expect("Time is not in valid range. This should never happen.");
            // let height = Height::from_consensus(self.blockchain.get_blockchain_height()? as u32)
            //     .expect("Height is not in valid range. This should never happen.");
            // let locktime = cet.lock_time;
            //
            // if !locktime.is_satisfied_by(height, time) {
            //     return Err(Error::InvalidState(
            //         "CET lock time has not passed yet".to_string(),
            //     ));
            // }

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
                    .compute_pnl(&contract.signed_cet)?,
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
            pnl: contract.accepted_contract.compute_pnl(&signed_cet)?,
            signed_cet: Some(signed_cet),
            contract_id: contract.accepted_contract.get_contract_id(),
            temporary_contract_id: contract.accepted_contract.offered_contract.id,
            counter_party_id: contract.accepted_contract.offered_contract.counter_party,
        };

        Ok(Contract::Closed(closed_contract))
    }

    /// Function to call when we detect that a contract was closed by our counter party.
    /// This will update the state of the contract and return the [`Contract`] object.
    pub fn on_counterparty_close(
        &mut self,
        contract: &SignedContract,
        closing_tx: Transaction,
        confirmations: u32,
    ) -> Result<Contract, Error> {
        let fund_transaction = &contract.accepted_contract.fund_transaction;

        // check if the closing tx actually spends the funding output
        if !closing_tx.input.iter().any(|i| {
            i.previous_output
                == OutPoint {
                    txid: fund_transaction.compute_txid(),
                    vout: 0,
                }
        }) {
            return Err(Error::InvalidParameters(
                "Closing tx does not spend the funding tx".to_string(),
            ));
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
                pnl: contract.accepted_contract.compute_pnl(&closing_tx)?,
                signed_cet: Some(closing_tx),
                contract_id: contract.accepted_contract.get_contract_id(),
                temporary_contract_id: contract.accepted_contract.offered_contract.id,
                counter_party_id: contract.accepted_contract.offered_contract.counter_party,
            })
        };

        self.store.update_contract(&contract)?;

        Ok(contract)
    }
}

#[cfg(test)]
mod test {
    use bitcoin::Amount;
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
        SimpleSigner,
    >;

    fn get_manager() -> TestManager {
        let blockchain = Rc::new(MockBlockchain::new());
        let store = Rc::new(MemoryStorage::new());
        let wallet = Rc::new(MockWallet::new(
            &blockchain,
            &(0..100)
                .map(|x| Amount::from_sat(x as u64 * 1000000))
                .collect::<Vec<_>>(),
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
}
