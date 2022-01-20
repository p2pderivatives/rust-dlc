//! #Manager a component to create and update DLCs.

use super::{Blockchain, Oracle, Storage, Time, Wallet};
use crate::chain_monitor::{ChainMonitor, ChannelInfo, RevokedTxType, TxType};
use crate::channel::offered_channel::OfferedChannel;
use crate::channel::party_points::PartyBasePoints;
use crate::channel::signed_channel::{SignedChannel, SignedChannelState, SignedChannelStateType};
use crate::channel::Channel;
use crate::channel_updater::verify_signed_channel;
use crate::contract::{
    accepted_contract::AcceptedContract, contract_info::ContractInfo,
    contract_input::ContractInput, contract_input::OracleInput, offered_contract::OfferedContract,
    signed_contract::SignedContract, AdaptorInfo, ClosedContract, Contract, FailedAcceptContract,
    FailedSignContract, FundingInputInfo,
};
use crate::contract_updater::{
    accept_contract, verify_accepted_and_sign_contract, verify_signed_contract,
};
use crate::conversion_utils::get_tx_input_infos;
use crate::error::Error;
use crate::utils::get_new_serial_id;
use crate::Signer;
use crate::{ChannelId, ContractId};
use bitcoin::{consensus::Encodable, Address};
use bitcoin::{OutPoint, Transaction};
use dlc::{PartyParams, TxInputInfo};
use dlc_messages::channel::{
    AcceptChannel, CollaborativeCloseOffer, OfferChannel, RenewChannelAccept, RenewChannelConfirm,
    RenewChannelFinalize, RenewChannelOffer, SettleChannelAccept, SettleChannelConfirm,
    SettleChannelFinalize, SettleChannelOffer, SignChannel,
};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::{
    AcceptDlc, CetAdaptorSignature, CetAdaptorSignatures, FundingInput, Message as DlcMessage,
    OfferDlc, SignDlc,
};
use dlc_trie::RangeInfo;
use lightning::ln::chan_utils::{
    build_commitment_secret, derive_private_key, derive_private_revocation_key,
};
use log::{error, warn};
use secp256k1_zkp::schnorrsig::{PublicKey as SchnorrPublicKey, Signature as SchnorrSignature};
use secp256k1_zkp::{All, PublicKey, Secp256k1, SecretKey, Signature};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::string::ToString;

/// The number of confirmations required before moving the the confirmed state.
pub const NB_CONFIRMATIONS: u32 = 6;
/// The delay to set the refund value to.
pub const REFUND_DELAY: u32 = 86400 * 7;
///
pub const CET_NSEQUENCE: u32 = 288;

type ClosableContractInfo<'a> = Option<(
    &'a ContractInfo,
    &'a AdaptorInfo,
    Vec<(usize, OracleAttestation)>,
)>;

/// Used to create and update DLCs.
pub struct Manager<W: Deref, B: Deref, S: DerefMut, O: Deref, T: Deref>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
{
    oracles: HashMap<SchnorrPublicKey, O>,
    wallet: W,
    blockchain: B,
    store: S,
    secp: Secp256k1<All>,
    chain_monitor: ChainMonitor,
    time: T,
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
            None => Err(Error::InvalidParameters(
                "Unknown $object_type_lc id.".to_string(),
            )),
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

macro_rules! get_signed_channel_state {
    ($signed_channel: ident, $state: ident, $($field: ident),* $(|$($ref_field: ident),*)?) => {{
       match $signed_channel.state {
           SignedChannelState::$state{$($field,)* $($(ref $ref_field,)*)? ..} => Ok(($($field,)* $($($ref_field,)*)?)),
           _ => Err(Error::InvalidState(format!("Expected state {} got {:?}", stringify!($state), $signed_channel.state))),
        }
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

impl<W: Deref, B: Deref, S: DerefMut, O: Deref, T: Deref> Manager<W, B, S, O, T>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
{
    /// Create a new Manager struct.
    pub fn new(
        wallet: W,
        blockchain: B,
        store: S,
        oracles: HashMap<SchnorrPublicKey, O>,
        time: T,
    ) -> Result<Self, Error> {
        let init_height = blockchain.get_blockchain_height()?;
        Ok(Manager {
            secp: secp256k1_zkp::Secp256k1::new(),
            wallet,
            blockchain,
            store,
            oracles,
            time,
            chain_monitor: ChainMonitor::new(init_height),
        })
    }

    /// Get the store from the Manager to access contracts.
    pub fn get_store(&self) -> &S {
        &self.store
    }

    ///
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
            DlcMessage::SettleOffer(s) => {
                self.on_settle_offer(s, &counter_party)?;
                Ok(None)
            }
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
            DlcMessage::RenewChannelOffer(r) => {
                self.on_renew_offer(r, &counter_party)?;
                Ok(None)
            }
            DlcMessage::RenewChannelAccept(r) => Ok(Some(DlcMessage::RenewChannelConfirm(
                self.on_renew_accept(r, &counter_party)?,
            ))),
            DlcMessage::RenewChannelConfirm(r) => Ok(Some(DlcMessage::RenewChannelFinalize(
                self.on_renew_confirm(r, &counter_party)?,
            ))),
            DlcMessage::RenewChannelFinalize(r) => {
                self.on_renew_finalize(r, &counter_party)?;
                Ok(None)
            }
            DlcMessage::CollaborativeCloseOffer(c) => {
                self.on_collaborative_close_offer(c, &counter_party)?;
                Ok(None)
            }
        }
    }

    /// Function called to create a new DLC. The offered contract will be stored
    /// and an OfferDlc message returned.
    pub fn send_offer(
        &mut self,
        contract: &ContractInput,
        counter_party: PublicKey,
    ) -> Result<OfferDlc, Error> {
        let oracle_announcements = contract
            .contract_infos
            .iter()
            .map(|x| self.get_oracle_announcements(&x.oracles))
            .collect::<Result<Vec<_>, Error>>()?;

        let (party_params, _, funding_inputs_info) =
            self.get_party_params(contract.offer_collateral, contract.fee_rate)?;

        let mut offered_contract = OfferedContract::new(
            contract,
            oracle_announcements,
            &party_params,
            &funding_inputs_info,
            contract.maturity_time + REFUND_DELAY,
            &counter_party,
        );

        let offer_msg: OfferDlc = (&offered_contract).into();

        offered_contract.id = offer_msg.get_hash()?;

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

        let (accept_params, fund_secret_key, funding_inputs) = self.get_party_params(
            offered_contract.offer_params.collateral,
            offered_contract.fee_rate_per_vb,
        )?;

        let (accepted_contract, adaptor_sigs) = accept_contract(
            &self.secp,
            &offered_contract,
            &accept_params,
            &funding_inputs,
            &fund_secret_key,
        )?;

        self.wallet.import_address(&Address::p2wsh(
            &accepted_contract.dlc_transactions.funding_script_pubkey,
            self.blockchain.get_network()?,
        ))?;

        let accept_msg: AcceptDlc = accepted_contract.get_accept_contract_msg(adaptor_sigs);

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

        let (tx_input_infos, input_amount) = get_tx_input_infos(&accept_msg.funding_inputs)?;

        let accept_params = PartyParams {
            fund_pubkey: accept_msg.funding_pubkey,
            change_script_pubkey: accept_msg.change_spk.clone(),
            change_serial_id: accept_msg.change_serial_id,
            payout_script_pubkey: accept_msg.payout_spk.clone(),
            payout_serial_id: accept_msg.payout_serial_id,
            inputs: tx_input_infos,
            input_amount,
            collateral: accept_msg.accept_collateral,
        };

        let cet_adaptor_signatures = accept_msg
            .cet_adaptor_signatures
            .ecdsa_adaptor_signatures
            .iter()
            .map(|x| x.signature)
            .collect::<Vec<_>>();

        let (signed_contract, cet_adaptor_signatures) = match verify_accepted_and_sign_contract(
            &self.secp,
            &offered_contract,
            &accept_params,
            &accept_msg
                .funding_inputs
                .iter()
                .map(|x| x.into())
                .collect::<Vec<_>>(),
            &accept_msg.refund_signature,
            &cet_adaptor_signatures,
            &self,
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

        let signed_msg: SignDlc = signed_contract.get_sign_dlc(cet_adaptor_signatures);

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

        let cet_adaptor_signatures = sign_message
            .cet_adaptor_signatures
            .ecdsa_adaptor_signatures
            .iter()
            .map(|x| x.signature)
            .collect::<Vec<_>>();

        let (signed_contract, fund_tx) = match verify_signed_contract(
            &self.secp,
            &accepted_contract,
            &sign_message.refund_signature,
            &cet_adaptor_signatures,
            &sign_message.funding_signatures,
            accepted_contract.dlc_transactions.get_fund_output().value,
            None,
            None,
            &self,
            None,
        ) {
            Ok(contract) => contract,
            Err(e) => return self.sign_fail_on_error(accepted_contract, sign_message.clone(), e),
        };

        self.store
            .update_contract(&Contract::Signed(signed_contract))?;

        self.blockchain.send_transaction(&fund_tx)?;

        Ok(())
    }

    fn get_party_params(
        &self,
        own_collateral: u64,
        fee_rate: u64,
    ) -> Result<(PartyParams, SecretKey, Vec<FundingInputInfo>), Error> {
        let funding_privkey = self.wallet.get_new_secret_key()?;
        let funding_pubkey = PublicKey::from_secret_key(&self.secp, &funding_privkey);

        let payout_addr = self.wallet.get_new_address()?;
        let payout_spk = payout_addr.script_pubkey();
        let payout_serial_id = get_new_serial_id();
        let change_addr = self.wallet.get_new_address()?;
        let change_spk = change_addr.script_pubkey();
        let change_serial_id = get_new_serial_id();

        let appr_required_amount = own_collateral + crate::utils::get_half_common_fee(fee_rate);
        let utxos = self
            .wallet
            .get_utxos_for_amount(appr_required_amount, Some(fee_rate), true)?;

        let mut funding_inputs_info: Vec<FundingInputInfo> = Vec::new();
        let mut funding_tx_info: Vec<TxInputInfo> = Vec::new();
        let mut total_input = 0;
        for utxo in utxos {
            let prev_tx = self.wallet.get_transaction(&utxo.outpoint.txid)?;
            let mut writer = Vec::new();
            prev_tx.consensus_encode(&mut writer)?;
            let prev_tx_vout = utxo.outpoint.vout;
            let sequence = 0xffffffff;
            // TODO(tibo): this assumes P2WPKH with low R
            let max_witness_len = 107;
            let funding_input = FundingInput {
                input_serial_id: get_new_serial_id(),
                prev_tx: writer,
                prev_tx_vout,
                sequence,
                max_witness_len,
                redeem_script: utxo.redeem_script,
            };
            total_input += prev_tx.output[prev_tx_vout as usize].value;
            funding_tx_info.push((&funding_input).into());
            let funding_input_info = FundingInputInfo {
                funding_input,
                address: Some(utxo.address.clone()),
            };
            funding_inputs_info.push(funding_input_info);
        }

        let party_params = PartyParams {
            fund_pubkey: funding_pubkey,
            change_script_pubkey: change_spk,
            change_serial_id,
            payout_script_pubkey: payout_spk,
            payout_serial_id,
            inputs: funding_tx_info,
            collateral: own_collateral,
            input_amount: total_input,
        };

        Ok((party_params, funding_privkey, funding_inputs_info))
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
        let confirmations = self.wallet.get_transaction_confirmations(
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
            let (range_info, sigs) =
                self.get_range_info_and_oracle_sigs(contract_info, adaptor_info, &attestations)?;
            let mut cet =
                contract.accepted_contract.dlc_transactions.cets[range_info.cet_index].clone();
            let offered_contract = &contract.accepted_contract.offered_contract;

            let (adaptor_sigs, fund_pubkey, other_pubkey) = if offered_contract.is_offer_party {
                (
                    contract
                        .accepted_contract
                        .adaptor_signatures
                        .as_ref()
                        .unwrap(),
                    &offered_contract.offer_params.fund_pubkey,
                    &contract.accepted_contract.accept_params.fund_pubkey,
                )
            } else {
                (
                    contract.adaptor_signatures.as_ref().unwrap(),
                    &contract.accepted_contract.accept_params.fund_pubkey,
                    &offered_contract.offer_params.fund_pubkey,
                )
            };

            let funding_sk = self.wallet.get_secret_key_for_pubkey(fund_pubkey)?;

            dlc::sign_cet(
                &self.secp,
                &mut cet,
                &adaptor_sigs[range_info.adaptor_index],
                &sigs,
                &funding_sk,
                other_pubkey,
                &contract
                    .accepted_contract
                    .dlc_transactions
                    .funding_script_pubkey,
                contract
                    .accepted_contract
                    .dlc_transactions
                    .get_fund_output()
                    .value,
            )?;
            match self.close_contract(
                contract,
                cet,
                attestations.iter().map(|x| x.1.clone()).collect(),
            ) {
                Ok(closed_contract) => {
                    self.store
                        .update_contract(&Contract::Closed(closed_contract))?;
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

    fn get_range_info_and_oracle_sigs(
        &self,
        contract_info: &ContractInfo,
        adaptor_info: &AdaptorInfo,
        attestations: &[(usize, OracleAttestation)],
    ) -> Result<(RangeInfo, Vec<Vec<SchnorrSignature>>), Error> {
        let outcomes = attestations
            .iter()
            .map(|(i, x)| (*i, &x.outcomes))
            .collect::<Vec<(usize, &Vec<String>)>>();
        let info_opt = contract_info.get_range_info_for_outcome(adaptor_info, &outcomes, 0);
        if let Some((sig_infos, range_info)) = info_opt {
            let sigs: Vec<Vec<_>> = attestations
                .iter()
                .filter_map(|(i, a)| {
                    let sig_info = sig_infos.iter().find(|x| x.0 == *i)?;
                    Some(a.signatures.iter().take(sig_info.1).cloned().collect())
                })
                .collect();
            return Ok((range_info, sigs));
        }

        Err(Error::InvalidState(
            "Could not find closing info for given outcomes".to_string(),
        ))
    }

    fn close_contract(
        &self,
        contract: &SignedContract,
        signed_cet: Transaction,
        attestations: Vec<OracleAttestation>,
    ) -> Result<ClosedContract, Error> {
        let confirmations = self
            .wallet
            .get_transaction_confirmations(&signed_cet.txid())?;

        if confirmations < 1 {
            // TODO(tibo): if this fails because another tx is already in
            // mempool or blockchain, we might have been cheated. There is
            // not much to be done apart from possibly extracting a fraud
            // proof but ideally it should be handled.
            self.blockchain.send_transaction(&signed_cet)?;
        }

        let closed_contract = ClosedContract {
            signed_contract: contract.clone(),
            attestations: attestations.to_vec(),
            signed_cet,
        };

        Ok(closed_contract)
    }

    fn check_refund(&mut self, contract: &SignedContract) -> Result<(), Error> {
        // TODO(tibo): should check for confirmation of refund before updating state
        if contract.accepted_contract.dlc_transactions.refund.lock_time as u64
            <= self.time.unix_time_now()
        {
            let offered_contract = &contract.accepted_contract.offered_contract;
            let accepted_contract = &contract.accepted_contract;
            let mut refund = accepted_contract.dlc_transactions.refund.clone();
            let confirmations = self.wallet.get_transaction_confirmations(&refund.txid())?;
            if confirmations == 0 {
                let funding_script_pubkey =
                    &accepted_contract.dlc_transactions.funding_script_pubkey;
                let fund_output_value = accepted_contract.dlc_transactions.get_fund_output().value;
                let (fund_pubkey, other_fund_pubkey, other_sig) = if offered_contract.is_offer_party
                {
                    (
                        &offered_contract.offer_params.fund_pubkey,
                        &accepted_contract.accept_params.fund_pubkey,
                        &accepted_contract.accept_refund_signature,
                    )
                } else {
                    (
                        &accepted_contract.accept_params.fund_pubkey,
                        &offered_contract.offer_params.fund_pubkey,
                        &contract.offer_refund_signature,
                    )
                };

                let fund_priv_key = self.wallet.get_secret_key_for_pubkey(fund_pubkey)?;
                dlc::util::sign_multi_sig_input(
                    &self.secp,
                    &mut refund,
                    other_sig,
                    other_fund_pubkey,
                    &fund_priv_key,
                    funding_script_pubkey,
                    fund_output_value,
                    0,
                );

                self.blockchain.send_transaction(&refund)?;
            }

            self.store
                .update_contract(&Contract::Refunded(contract.clone()))?;
        }

        Ok(())
    }
}

impl<W: Deref, B: Deref, S: DerefMut, O: Deref, T: Deref> Manager<W, B, S, O, T>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
{
    /// Create a new channel offer and return the [`dlc_messages::channel::OfferChannel`]
    /// message to be sent to the `counter_party`.
    pub fn send_offer_channel(
        &mut self,
        contract_input: &ContractInput,
        counter_party: PublicKey,
    ) -> Result<OfferChannel, Error> {
        let oracle_announcements = contract_input
            .contract_infos
            .iter()
            .map(|x| self.get_oracle_announcements(&x.oracles))
            .collect::<Result<Vec<_>, Error>>()?;
        let (offer_params, _, funding_inputs_info) =
            self.get_party_params(contract_input.offer_collateral, contract_input.fee_rate)?;
        let party_points = self.get_party_base_points()?;
        let (offered_channel, offered_contract) = crate::channel_updater::offer_channel(
            &self.secp,
            contract_input,
            &counter_party,
            &offer_params,
            &party_points,
            &self.wallet.get_new_secret_key()?,
            &funding_inputs_info,
            &oracle_announcements,
            contract_input.maturity_time + REFUND_DELAY,
        );

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

        let offered_contract = get_contract_in_state!(
            self,
            &offered_channel.offered_contract_id,
            Offered,
            None as Option<PublicKey>
        )?;

        let (accept_params, _, funding_inputs) = self.get_party_params(
            offered_contract.offer_params.collateral,
            offered_contract.fee_rate_per_vb,
        )?;

        let per_update_seed = self.wallet.get_new_secret_key()?;

        let accept_points = self.get_party_base_points()?;

        let own_base_secret_key = self
            .wallet
            .get_secret_key_for_pubkey(&accept_points.own_basepoint)?;

        let fund_sk = self
            .wallet
            .get_secret_key_for_pubkey(&accept_params.fund_pubkey)?;

        let (accepted_channel, accepted_contract, buffer_adaptor_signature, cet_adaptor_sigs) =
            crate::channel_updater::accept_channel_offer(
                &self.secp,
                &offered_channel,
                &offered_contract,
                &accept_params,
                &funding_inputs,
                &fund_sk,
                &own_base_secret_key,
                &per_update_seed,
                &accept_points,
                //TODO(tibo): this should be parameterizable.
                CET_NSEQUENCE,
            )?;

        self.wallet.import_address(&Address::p2wsh(
            &accepted_contract.dlc_transactions.funding_script_pubkey,
            self.blockchain.get_network()?,
        ))?;

        let msg = accepted_channel.get_accept_channel_msg(
            &accepted_contract,
            &buffer_adaptor_signature,
            &cet_adaptor_sigs,
        );

        let channel_id = accepted_channel.channel_id;
        let contract_id = accepted_contract.get_contract_id();
        let counter_party = accepted_contract.offered_contract.counter_party;

        self.store.upsert_channel(
            Channel::Accepted(accepted_channel),
            Some(Contract::Accepted(accepted_contract)),
        )?;

        Ok((msg, channel_id, contract_id, counter_party))
    }

    /// Initiate the unilateral closing of a channel that has been established.
    pub fn initiate_unilateral_close_established_channel(
        &mut self,
        channel_id: &ChannelId,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;
        let (mut buffer_transaction, buffer_adaptor_signature, signed_contract_id) = get_signed_channel_state!(
            signed_channel,
            Established,
            buffer_transaction,
            counter_buffer_adaptor_signature,
            signed_contract_id
        )?;

        let confirmed_contract = get_contract_in_state!(
            self,
            &signed_contract_id,
            Confirmed,
            None as Option<PublicKey>
        )?;

        let (contract_info, adaptor_info, attestations) = self
            .get_closable_contract_info(&confirmed_contract)
            .ok_or_else(|| {
                Error::InvalidState("Could not get closable contract info".to_string())
            })?;

        let publish_base_secret = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_points.publish_basepoint)?;

        let publish_sk = derive_private_key(
            &self.secp,
            &signed_channel.own_per_update_point,
            &publish_base_secret,
        )
        .expect("to be able to derive the publish secret");

        let counter_buffer_signature = buffer_adaptor_signature.decrypt(&publish_sk)?;

        let fund_sk = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

        dlc::util::sign_multi_sig_input(
            &self.secp,
            &mut buffer_transaction,
            &counter_buffer_signature,
            &signed_channel.counter_params.fund_pubkey,
            &fund_sk,
            &signed_channel.fund_script_pubkey,
            signed_channel.fund_tx.output[signed_channel.fund_output_index].value,
            0,
        );

        self.blockchain.send_transaction(&buffer_transaction)?;

        let (range_info, oracle_sigs) =
            self.get_range_info_and_oracle_sigs(contract_info, adaptor_info, &attestations)?;

        self.chain_monitor.remove_tx(&buffer_transaction.txid());

        let mut cet = confirmed_contract.accepted_contract.dlc_transactions.cets
            [range_info.cet_index]
            .clone();

        let is_offer = confirmed_contract
            .accepted_contract
            .offered_contract
            .is_offer_party;

        let (offer_points, accept_points, offer_per_update_point, accept_per_update_point) =
            if is_offer {
                (
                    &signed_channel.own_points,
                    &signed_channel.counter_points,
                    &signed_channel.own_per_update_point,
                    &signed_channel.counter_per_update_point,
                )
            } else {
                (
                    &signed_channel.counter_points,
                    &signed_channel.own_points,
                    &signed_channel.counter_per_update_point,
                    &signed_channel.own_per_update_point,
                )
            };

        let offer_revoke_params = offer_points.get_revokable_params(
            &self.secp,
            &accept_points.revocation_basepoint,
            offer_per_update_point,
        )?;

        let accept_revoke_params = accept_points.get_revokable_params(
            &self.secp,
            &offer_points.revocation_basepoint,
            accept_per_update_point,
        )?;

        let (own_per_update_point, own_basepoint, counter_pk, adaptor_sigs) = if is_offer {
            (
                &offer_per_update_point,
                &offer_points.own_basepoint,
                &accept_revoke_params.own_pk,
                confirmed_contract
                    .accepted_contract
                    .adaptor_signatures
                    .expect("to have adaptor signatures"),
            )
        } else {
            (
                &accept_per_update_point,
                &accept_points.own_basepoint,
                &offer_revoke_params.own_pk,
                confirmed_contract
                    .adaptor_signatures
                    .expect("to have adaptor signatures"),
            )
        };

        let base_secret = self.wallet.get_secret_key_for_pubkey(own_basepoint)?;
        let own_sk = derive_private_key(&self.secp, own_per_update_point, &base_secret)?;

        dlc::channel::sign_cet(
            &self.secp,
            &mut cet,
            buffer_transaction.output[0].value,
            &offer_revoke_params,
            &accept_revoke_params,
            &own_sk,
            counter_pk,
            &adaptor_sigs[range_info.adaptor_index],
            &oracle_sigs,
        )?;

        signed_channel.state = SignedChannelState::Closing {
            buffer_tx: buffer_transaction.clone(),
            signed_cet: cet,
            contract_id: signed_contract_id,
            attestations: attestations.into_iter().map(|x| x.1).collect(),
        };

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(())
    }

    /// Initiate the unilateral close of a channel that has been settled.
    pub fn initiate_unilateral_close_settled_channel(
        &mut self,
        channel_id: &ChannelId,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;
        let (mut settle_tx, counter_settle_adaptor_signature) = get_signed_channel_state!(
            signed_channel,
            Settled,
            settle_tx,
            counter_settle_adaptor_signature
        )?;

        let publish_base_secret = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_points.publish_basepoint)?;

        let publish_sk = derive_private_key(
            &self.secp,
            &signed_channel.own_per_update_point,
            &publish_base_secret,
        )
        .expect("to be able to derive the publish secret");

        let counter_settle_signature = counter_settle_adaptor_signature.decrypt(&publish_sk)?;

        let fund_sk = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

        dlc::util::sign_multi_sig_input(
            &self.secp,
            &mut settle_tx,
            &counter_settle_signature,
            &signed_channel.counter_params.fund_pubkey,
            &fund_sk,
            &signed_channel.fund_script_pubkey,
            signed_channel.fund_tx.output[signed_channel.fund_output_index].value,
            0,
        );

        self.blockchain.send_transaction(&settle_tx)?;

        signed_channel.state = SignedChannelState::SettleClosing {};

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(())
    }

    /// Offer to settle the balance of a channel so that the counter party gets
    /// `counter_payout`. Returns the [`dlc_messages::channel::SettleChannelOffer`]
    /// message to be sent and the public key of the counter party node.
    pub fn settle_offer(
        &mut self,
        channel_id: &ChannelId,
        counter_payout: u64,
    ) -> Result<(SettleChannelOffer, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let per_update_seed_pk = signed_channel.own_per_update_seed;
        let per_update_seed_sk = self.wallet.get_secret_key_for_pubkey(&per_update_seed_pk)?;

        let msg = crate::channel_updater::settle_channel_offer(
            &self.secp,
            &mut signed_channel,
            counter_payout,
            &per_update_seed_sk,
        )?;

        let counter_party = signed_channel.counter_party;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok((msg, counter_party))
    }

    ///
    pub fn accept_settle_offer(
        &mut self,
        channel_id: &ChannelId,
    ) -> Result<(SettleChannelAccept, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let fund_sk = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

        let per_update_seed_pk = signed_channel.own_per_update_seed;
        let per_update_seed_sk = self.wallet.get_secret_key_for_pubkey(&per_update_seed_pk)?;

        let msg = crate::channel_updater::settle_channel_accept(
            &self.secp,
            &mut signed_channel,
            &fund_sk,
            &per_update_seed_sk,
            CET_NSEQUENCE,
            0,
        )?;

        let counter_party = signed_channel.counter_party;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok((msg, counter_party))
    }

    ///
    pub fn send_renew_channel_offer(
        &mut self,
        channel_id: &ChannelId,
        counter_payout: u64,
        contract_input: &ContractInput,
    ) -> Result<(RenewChannelOffer, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

        let oracle_announcements = contract_input
            .contract_infos
            .iter()
            .map(|x| self.get_oracle_announcements(&x.oracles))
            .collect::<Result<Vec<_>, Error>>()?;

        let mut offered_contract = OfferedContract::new(
            contract_input,
            oracle_announcements,
            &signed_channel.own_params,
            &[],
            contract_input.maturity_time + REFUND_DELAY,
            &signed_channel.counter_party,
        );

        offered_contract.fee_rate_per_vb = signed_channel.fee_rate_per_vb;

        let per_update_seed = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_per_update_seed)?;

        let per_update_secret = SecretKey::from_slice(&build_commitment_secret(
            per_update_seed.as_ref(),
            signed_channel.update_idx - 1,
        ))
        .expect("a valid secret key.");

        let next_per_update_point = PublicKey::from_secret_key(&self.secp, &per_update_secret);

        let mut state = SignedChannelState::RenewOffered {
            offered_contract_id: offered_contract.id,
            offer_next_per_update_point: next_per_update_point,
            is_offer: true,
            counter_payout,
        };

        std::mem::swap(&mut signed_channel.state, &mut state);
        signed_channel.roll_back_state = Some(state);

        let msg = RenewChannelOffer {
            channel_id: *channel_id,
            temporary_contract_id: crate::utils::get_new_temporary_id(),
            counter_payout,
            next_per_update_point,
            contract_info: (&offered_contract).into(),
            contract_maturity_bound: offered_contract.contract_maturity_bound,
            contract_timeout: offered_contract.contract_timeout,
        };

        let counter_party = offered_contract.counter_party;

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Offered(offered_contract)),
        )?;

        Ok((msg, counter_party))
    }

    ///
    pub fn accept_channel_renew(
        &mut self,
        channel_id: &ChannelId,
    ) -> Result<(RenewChannelAccept, PublicKey), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;
        let (offered_contract_id, offer_next_per_update_point) = get_signed_channel_state!(
            signed_channel,
            RenewOffered,
            offered_contract_id,
            offer_next_per_update_point
        )?;

        let offered_contract = get_contract_in_state!(
            self,
            &offered_contract_id,
            Offered,
            None as Option<PublicKey>
        )?;

        let own_fund_sk = &self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;
        let own_base_secret_key = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_points.own_basepoint)?;
        let per_update_seed = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_per_update_seed)?;

        let (
            accepted_contract,
            buffer_adaptor_signature,
            cet_adaptor_signatures,
            accept_per_update_point,
        ) = crate::channel_updater::accept_channel_renewal(
            &self.secp,
            &mut signed_channel,
            &offered_contract,
            &offer_next_per_update_point,
            own_fund_sk,
            &own_base_secret_key,
            &per_update_seed,
            CET_NSEQUENCE,
        )?;

        let msg = RenewChannelAccept {
            channel_id: signed_channel.channel_id,
            next_per_update_point: accept_per_update_point,
            buffer_adaptor_signature,
            cet_adaptor_signatures: CetAdaptorSignatures {
                ecdsa_adaptor_signatures: cet_adaptor_signatures
                    .into_iter()
                    .map(|x| CetAdaptorSignature { signature: x })
                    .collect::<Vec<_>>(),
            },
            refund_signature: accepted_contract.accept_refund_signature,
        };

        let counter_party = signed_channel.counter_party;

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Accepted(accepted_contract)),
        )?;

        Ok((msg, counter_party))
    }

    ///
    pub fn offer_collaborative_close(
        &mut self,
        channel_id: &ChannelId,
        counter_payout: u64,
    ) -> Result<CollaborativeCloseOffer, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;
        if counter_payout
            > signed_channel.counter_params.collateral + signed_channel.own_params.collateral
        {
            return Err(Error::InvalidParameters(
                "Counter payout is greater than total collateral".to_string(),
            ));
        }

        let total_collateral =
            signed_channel.own_params.collateral + signed_channel.counter_params.collateral;
        let offer_payout = total_collateral - counter_payout;
        let fund_output_value =
            signed_channel.fund_tx.output[signed_channel.fund_output_index].value;

        let close_tx = dlc::channel::create_collaborative_close_transaction(
            &signed_channel.own_params,
            offer_payout,
            &signed_channel.counter_params,
            counter_payout,
            OutPoint {
                txid: signed_channel.fund_tx.txid(),
                vout: signed_channel.fund_output_index as u32,
            },
            fund_output_value,
        );

        self.chain_monitor.add_tx(
            close_tx.txid(),
            ChannelInfo {
                channel_id: *channel_id,
                tx_type: TxType::CollaborativeClose,
            },
        );

        let own_fund_sk = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

        let close_signature = dlc::util::get_raw_sig_for_tx_input(
            &self.secp,
            &close_tx,
            0,
            &signed_channel.fund_script_pubkey,
            fund_output_value,
            &own_fund_sk,
        );

        let state = SignedChannelState::CollaborativeCloseOffered {
            counter_payout,
            offer_signature: close_signature,
            close_tx,
        };
        signed_channel.state = state;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;
        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(CollaborativeCloseOffer {
            channel_id: *channel_id,
            counter_payout,
            close_signature,
        })
    }

    ///
    pub fn accept_collaborative_close(&mut self, channel_id: &ChannelId) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;
        let (offer_signature, mut close_tx) = get_signed_channel_state!(
            signed_channel,
            CollaborativeCloseOffered,
            offer_signature,
            close_tx
        )?;

        let fund_out_amount = signed_channel.fund_tx.output[signed_channel.fund_output_index].value;

        let own_fund_sk = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

        dlc::util::sign_multi_sig_input(
            &self.secp,
            &mut close_tx,
            &offer_signature,
            &signed_channel.counter_params.fund_pubkey,
            &own_fund_sk,
            &signed_channel.fund_script_pubkey,
            fund_out_amount,
            0,
        );

        self.blockchain.send_transaction(&close_tx)?;

        signed_channel.state = SignedChannelState::CollaborativelyClosed;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(())
    }

    fn try_finalize_closing_established_channel(
        &mut self,
        mut signed_channel: SignedChannel,
    ) -> Result<(), Error> {
        let (buffer_tx, signed_cet, contract_id, attestations) = match signed_channel.state {
            SignedChannelState::Closing {
                buffer_tx,
                signed_cet,
                contract_id,
                attestations,
            } => (buffer_tx, signed_cet, contract_id, attestations),
            s => {
                return Err(Error::InvalidState(format!(
                    "Expected channel to be in Closing state but was {:?}",
                    s
                )))
            }
        };

        if self
            .wallet
            .get_transaction_confirmations(&buffer_tx.txid())?
            > CET_NSEQUENCE
        {
            let confirmed_contract =
                get_contract_in_state!(self, &contract_id, Confirmed, None as Option<PublicKey>)?;

            let closed_contract =
                self.close_contract(&confirmed_contract, signed_cet, attestations)?;

            signed_channel.state = SignedChannelState::Closed;

            self.store.upsert_channel(
                Channel::Signed(signed_channel),
                Some(Contract::Closed(closed_contract)),
            )?;
        }

        Ok(())
    }

    fn on_offer_channel(
        &mut self,
        offer_channel: &OfferChannel,
        counter_party: PublicKey,
    ) -> Result<(), Error> {
        let (channel, contract) = OfferedChannel::from_offer_channel(offer_channel, counter_party)?;

        // TODO(tibo): have a single operation to create both on storage.
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

        let (tx_input_infos, input_amount) = get_tx_input_infos(&accept_channel.funding_inputs)?;

        let accept_params = PartyParams {
            fund_pubkey: accept_channel.funding_pubkey,
            change_script_pubkey: accept_channel.change_spk.clone(),
            change_serial_id: accept_channel.change_serial_id,
            payout_script_pubkey: accept_channel.payout_spk.clone(),
            payout_serial_id: accept_channel.payout_serial_id,
            inputs: tx_input_infos,
            input_amount,
            collateral: accept_channel.accept_collateral,
        };

        let accept_points = PartyBasePoints {
            own_basepoint: accept_channel.own_basepoint,
            revocation_basepoint: accept_channel.revocation_basepoint,
            publish_basepoint: accept_channel.publish_basepoint,
        };

        let offer_own_base_secret = self
            .wallet
            .get_secret_key_for_pubkey(&offered_channel.party_points.own_basepoint)?;

        let offer_own_sk = derive_private_key(
            &self.secp,
            &offered_channel.per_update_point,
            &offer_own_base_secret,
        )
        .expect("to be able to derive the offer own secret");

        let fund_sk = self
            .wallet
            .get_secret_key_for_pubkey(&offered_contract.offer_params.fund_pubkey)?;

        let (signed_channel, signed_contract, cet_adaptor_signatures, buffer_adaptor_signature) = {
            let res = crate::channel_updater::verify_accepted_channel(
                &self.secp,
                &offered_channel,
                &offered_contract,
                &accept_params,
                &accept_points,
                &accept_channel.first_per_update_point,
                &offer_own_sk,
                &fund_sk,
                &accept_channel
                    .funding_inputs
                    .iter()
                    .map(|x| x.into())
                    .collect::<Vec<_>>(),
                &accept_channel.refund_signature,
                &accept_channel
                    .cet_adaptor_signatures
                    .ecdsa_adaptor_signatures
                    .iter()
                    .map(|x| x.signature)
                    .collect::<Vec<_>>(),
                //TODO(tibo): this should be parameterizable.
                CET_NSEQUENCE,
                &accept_channel.buffer_adaptor_signature,
                &self,
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

        let msg = SignChannel {
            channel_id: signed_channel.channel_id,
            cet_adaptor_signatures: CetAdaptorSignatures {
                ecdsa_adaptor_signatures: cet_adaptor_signatures
                    .into_iter()
                    .map(|x| CetAdaptorSignature { signature: x })
                    .collect(),
            },
            buffer_adaptor_signature,
            refund_signature: signed_contract.offer_refund_signature,
            funding_signatures: signed_contract.funding_signatures.clone(),
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

        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Signed(signed_contract)),
        )?;

        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(msg)
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
                &sign_channel.refund_signature,
                &sign_channel
                    .cet_adaptor_signatures
                    .ecdsa_adaptor_signatures
                    .iter()
                    .map(|x| x.signature)
                    .collect::<Vec<_>>(),
                &sign_channel.funding_signatures,
                &sign_channel.buffer_adaptor_signature,
                &self,
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
        settle_offer: &SettleChannelOffer,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &settle_offer.channel_id, Signed, Some(*peer_id))?;

        //TODO(tibo): check that we're in the good signed channel state.
        let mut new_state = SignedChannelState::SettledReceived {
            own_payout: settle_offer.counter_payout,
            counter_next_per_update_point: settle_offer.next_per_update_point,
        };

        std::mem::swap(&mut signed_channel.state, &mut new_state);
        signed_channel.roll_back_state = Some(new_state);

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(())
    }

    fn on_settle_accept(
        &mut self,
        settle_accept: &SettleChannelAccept,
        peer_id: &PublicKey,
    ) -> Result<SettleChannelConfirm, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &settle_accept.channel_id, Signed, Some(*peer_id))?;

        let fund_sk = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

        let per_update_seed_pk = signed_channel.own_per_update_seed;
        let per_update_seed_sk = self.wallet.get_secret_key_for_pubkey(&per_update_seed_pk)?;

        let msg = crate::channel_updater::settle_channel_confirm(
            &self.secp,
            &mut signed_channel,
            settle_accept,
            &fund_sk,
            &per_update_seed_sk,
            CET_NSEQUENCE,
            0,
        )?;

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(msg)
    }

    fn on_settle_confirm(
        &mut self,
        settle_confirm: &SettleChannelConfirm,
        peer_id: &PublicKey,
    ) -> Result<SettleChannelFinalize, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &settle_confirm.channel_id, Signed, Some(*peer_id))?;
        let (prev_buffer_tx, own_buffer_adaptor_signature, is_offer) = get_signed_channel_rollback_state!(
            signed_channel,
            Established,
            buffer_transaction,
            own_buffer_adaptor_signature,
            is_offer
        )?;

        let prev_buffer_txid = prev_buffer_tx.txid();
        let own_buffer_adaptor_signature = *own_buffer_adaptor_signature;
        let is_offer = *is_offer;

        let per_update_seed_pk = signed_channel.own_per_update_seed;
        let per_update_seed_sk = self.wallet.get_secret_key_for_pubkey(&per_update_seed_pk)?;

        let msg = crate::channel_updater::settle_channel_finalize(
            &self.secp,
            &mut signed_channel,
            settle_confirm,
            &per_update_seed_sk,
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

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;
        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(msg)
    }

    fn on_settle_finalize(
        &mut self,
        settle_finalize: &SettleChannelFinalize,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &settle_finalize.channel_id, Signed, Some(*peer_id))?;
        let (buffer_tx, own_buffer_adaptor_signature, is_offer) = get_signed_channel_rollback_state!(
            signed_channel,
            Established,
            buffer_transaction,
            own_buffer_adaptor_signature,
            is_offer
        )?;

        let own_buffer_adaptor_signature = *own_buffer_adaptor_signature;
        let is_offer = *is_offer;
        let buffer_txid = buffer_tx.txid();

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

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;
        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(())
    }

    fn on_renew_offer(
        &mut self,
        renew_offer: &RenewChannelOffer,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_offer.channel_id, Signed, Some(*peer_id))?;

        let offered_contract = OfferedContract {
            id: renew_offer.temporary_contract_id,
            is_offer_party: false,
            contract_info: crate::conversion_utils::get_contract_info_and_announcements(
                &renew_offer.contract_info,
            )?,
            counter_party: signed_channel.counter_party,
            offer_params: signed_channel.counter_params.clone(),
            total_collateral: signed_channel.own_params.collateral
                + signed_channel.counter_params.collateral,
            funding_inputs_info: Vec::new(),
            fund_output_serial_id: 0,
            fee_rate_per_vb: signed_channel.fee_rate_per_vb,
            contract_maturity_bound: renew_offer.contract_maturity_bound,
            contract_timeout: renew_offer.contract_timeout,
        };

        let mut state = SignedChannelState::RenewOffered {
            offered_contract_id: offered_contract.id,
            counter_payout: renew_offer.counter_payout,
            offer_next_per_update_point: renew_offer.next_per_update_point,
            is_offer: false,
        };

        //TODO(tibo) validate previous state

        std::mem::swap(&mut signed_channel.state, &mut state);

        signed_channel.roll_back_state = Some(state);

        self.store.create_contract(&offered_contract)?;
        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(())
    }

    fn on_renew_accept(
        &mut self,
        renew_accept: &RenewChannelAccept,
        peer_id: &PublicKey,
    ) -> Result<RenewChannelConfirm, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_accept.channel_id, Signed, Some(*peer_id))?;
        let (offered_contract_id, offer_per_update_point) = get_signed_channel_state!(
            signed_channel,
            RenewOffered,
            offered_contract_id,
            offer_next_per_update_point
        )?;

        let offered_contract =
            get_contract_in_state!(self, &offered_contract_id, Offered, Some(*peer_id))?;

        let own_fund_sk = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

        let own_base_secret_key = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_points.own_basepoint)?;

        let per_update_seed = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_per_update_seed)?;

        let prev_per_update_secret = SecretKey::from_slice(&build_commitment_secret(
            per_update_seed.as_ref(),
            signed_channel.update_idx,
        ))?;

        println!(
            "Giving prev per update secret: {:?} at index {}",
            prev_per_update_secret, signed_channel.update_idx
        );

        let (signed_contract, cet_adaptor_signatures, buffer_adaptor_signature) =
            crate::channel_updater::verify_renew_accept(
                &self.secp,
                &mut signed_channel,
                &offered_contract,
                &offer_per_update_point,
                &renew_accept.next_per_update_point,
                &own_fund_sk,
                &own_base_secret_key,
                &renew_accept.refund_signature,
                &renew_accept
                    .cet_adaptor_signatures
                    .ecdsa_adaptor_signatures
                    .iter()
                    .map(|x| x.signature)
                    .collect::<Vec<_>>(),
                &renew_accept.buffer_adaptor_signature,
                CET_NSEQUENCE,
                &self,
            )?;

        let msg = RenewChannelConfirm {
            channel_id: signed_channel.channel_id,
            per_update_secret: prev_per_update_secret,
            buffer_adaptor_signature,
            cet_adaptor_signatures: CetAdaptorSignatures {
                ecdsa_adaptor_signatures: cet_adaptor_signatures
                    .into_iter()
                    .map(|x| CetAdaptorSignature { signature: x })
                    .collect::<Vec<_>>(),
            },
            refund_signature: signed_contract.offer_refund_signature,
        };

        // Directly confirmed as we're in a channel the fund tx is already confirmed.
        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Confirmed(signed_contract)),
        )?;

        Ok(msg)
    }

    fn on_renew_confirm(
        &mut self,
        renew_confirm: &RenewChannelConfirm,
        peer_id: &PublicKey,
    ) -> Result<RenewChannelFinalize, Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_confirm.channel_id, Signed, Some(*peer_id))?;
        let (contract_id, offer_per_update_point, accept_per_update_point, buffer_tx) = get_signed_channel_state!(
            signed_channel,
            RenewAccepted,
            contract_id,
            offer_per_update_point,
            accept_per_update_point | buffer_transaction
        )?;

        let buffer_txid = buffer_tx.txid();

        let (tx_type, prev_tx_id) = match signed_channel
            .roll_back_state
            .as_ref()
            .expect("to have a rollback state")
        {
            SignedChannelState::Established {
                own_buffer_adaptor_signature,
                buffer_transaction,
                ..
            } => (
                TxType::Revoked {
                    update_idx: signed_channel.update_idx,
                    own_adaptor_signature: *own_buffer_adaptor_signature,
                    is_offer: false,
                    revoked_tx_type: RevokedTxType::Buffer,
                },
                buffer_transaction.txid(),
            ),
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

        signed_channel.counter_per_update_point = offer_per_update_point.clone();
        signed_channel.own_per_update_point = accept_per_update_point.clone();

        let signed_contract = crate::channel_updater::verify_renew_confirm(
            &self.secp,
            &mut signed_channel,
            &accepted_contract,
            &renew_confirm.refund_signature,
            &renew_confirm
                .cet_adaptor_signatures
                .ecdsa_adaptor_signatures
                .iter()
                .map(|x| x.signature)
                .collect::<Vec<_>>(),
            &renew_confirm.buffer_adaptor_signature,
            &self,
        )?;

        signed_channel
            .counter_party_commitment_secrets
            .provide_secret(
                signed_channel.update_idx + 1,
                *renew_confirm.per_update_secret.as_ref(),
            )
            .map_err(|_| Error::InvalidParameters("Provided secret was invalid".to_string()))?;

        let per_update_seed = self
            .wallet
            .get_secret_key_for_pubkey(&signed_channel.own_per_update_seed)?;

        let prev_per_update_secret = SecretKey::from_slice(&build_commitment_secret(
            per_update_seed.as_ref(),
            signed_channel.update_idx + 1,
        ))?;

        println!(
            "Giving prev per update secret: {:?} at index {}",
            prev_per_update_secret, signed_channel.update_idx
        );

        self.chain_monitor.add_tx(
            prev_tx_id,
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type,
            },
        );

        self.chain_monitor.add_tx(
            buffer_txid,
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type: TxType::Current,
            },
        );

        let msg = RenewChannelFinalize {
            channel_id: signed_channel.channel_id,
            per_update_secret: prev_per_update_secret,
        };

        // Directly confirmed as we're in a channel the fund tx is already confirmed.
        self.store.upsert_channel(
            Channel::Signed(signed_channel),
            Some(Contract::Confirmed(signed_contract)),
        )?;

        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(msg)
    }

    fn on_renew_finalize(
        &mut self,
        renew_finalize: &RenewChannelFinalize,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &renew_finalize.channel_id, Signed, Some(*peer_id))?;
        let (
            contract_id,
            offer_per_update_point,
            accept_per_update_point,
            buffer_transaction,
            offer_buffer_adaptor_signature,
            accept_buffer_adaptor_signature,
        ) = get_signed_channel_state!(
            signed_channel,
            RenewConfirmed,
            contract_id,
            offer_per_update_point,
            accept_per_update_point,
            buffer_transaction,
            offer_buffer_adaptor_signature,
            accept_buffer_adaptor_signature
        )?;

        let (tx_type, prev_tx_id) = match signed_channel
            .roll_back_state
            .as_ref()
            .expect("to have a rollback state")
        {
            SignedChannelState::Established {
                own_buffer_adaptor_signature,
                buffer_transaction,
                ..
            } => (
                TxType::Revoked {
                    update_idx: signed_channel.update_idx,
                    own_adaptor_signature: *own_buffer_adaptor_signature,
                    is_offer: false,
                    revoked_tx_type: RevokedTxType::Buffer,
                },
                buffer_transaction.txid(),
            ),
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
            ),
            s => {
                return Err(Error::InvalidState(format!(
                    "Expected rollback state of Established or Settled but was {:?}",
                    s
                )))
            }
        };

        let buffer_txid = buffer_transaction.txid();

        let state = SignedChannelState::Established {
            signed_contract_id: contract_id,
            counter_buffer_adaptor_signature: accept_buffer_adaptor_signature,
            own_buffer_adaptor_signature: offer_buffer_adaptor_signature,
            buffer_transaction: buffer_transaction.clone(),
            is_offer: true,
        };

        signed_channel
            .counter_party_commitment_secrets
            .provide_secret(
                signed_channel.update_idx,
                *renew_finalize.per_update_secret.as_ref(),
            )
            .map_err(|_| Error::InvalidParameters("Provided secret was invalid".to_string()))?;

        signed_channel.own_per_update_point = offer_per_update_point.clone();
        signed_channel.counter_per_update_point = accept_per_update_point.clone();

        signed_channel.state = state;
        signed_channel.roll_back_state = None;
        signed_channel.update_idx -= 1;

        self.chain_monitor.add_tx(
            prev_tx_id,
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type,
            },
        );

        self.chain_monitor.add_tx(
            buffer_txid,
            ChannelInfo {
                channel_id: signed_channel.channel_id,
                tx_type: TxType::Current,
            },
        );

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;
        self.store.persist_chain_monitor(&self.chain_monitor)?;

        Ok(())
    }

    fn on_collaborative_close_offer(
        &mut self,
        close_offer: &CollaborativeCloseOffer,
        peer_id: &PublicKey,
    ) -> Result<(), Error> {
        let mut signed_channel =
            get_channel_in_state!(self, &close_offer.channel_id, Signed, Some(*peer_id))?;

        let total_collateral =
            signed_channel.own_params.collateral + signed_channel.counter_params.collateral;

        if close_offer.counter_payout > total_collateral {
            const ERR_MSG : &str = "Received collaborative close offer with counter payout greater than total collateral, ignoring.";
            error!("{}", ERR_MSG);
            return Err(Error::InvalidParameters(ERR_MSG.to_string()));
        }

        if signed_channel.roll_back_state.is_some() {
            return Err(Error::InvalidState(
                "Received collaborative close offer in state with rollback, ignoring.".to_string(),
            ));
        }

        let offer_payout = total_collateral - close_offer.counter_payout;
        let fund_output_value =
            signed_channel.fund_tx.output[signed_channel.fund_output_index].value;

        let close_tx = dlc::channel::create_collaborative_close_transaction(
            &signed_channel.own_params,
            offer_payout,
            &signed_channel.counter_params,
            close_offer.counter_payout,
            OutPoint {
                txid: signed_channel.fund_tx.txid(),
                vout: signed_channel.fund_output_index as u32,
            },
            fund_output_value,
        );

        let mut state = SignedChannelState::CollaborativeCloseOffered {
            counter_payout: close_offer.counter_payout,
            offer_signature: close_offer.close_signature,
            close_tx,
        };

        std::mem::swap(&mut state, &mut signed_channel.state);
        signed_channel.roll_back_state = Some(state);

        self.store
            .upsert_channel(Channel::Signed(signed_channel), None)?;

        Ok(())
    }

    fn get_party_base_points(&self) -> Result<PartyBasePoints, Error> {
        Ok(PartyBasePoints {
            own_basepoint: PublicKey::from_secret_key(
                &self.secp,
                &self.wallet.get_new_secret_key()?,
            ),
            publish_basepoint: PublicKey::from_secret_key(
                &self.secp,
                &self.wallet.get_new_secret_key()?,
            ),
            revocation_basepoint: PublicKey::from_secret_key(
                &self.secp,
                &self.wallet.get_new_secret_key()?,
            ),
        })
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

        self.check_for_watched_tx()
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
                    signed_channel.state = SignedChannelState::CounterClosed;
                    self.store
                        .upsert_channel(Channel::Signed(signed_channel), None)?;
                    continue;
                } else if let TxType::Revoked {
                    update_idx,
                    own_adaptor_signature,
                    is_offer,
                    revoked_tx_type: toxic_tx_type,
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
                    )?;

                    let counter_per_update_point =
                        PublicKey::from_secret_key(&self.secp, &counter_per_update_secret);

                    let base_own_sk = self
                        .wallet
                        .get_secret_key_for_pubkey(&signed_channel.own_points.own_basepoint)?;

                    let own_sk = derive_private_key(&self.secp, &per_update_point, &base_own_sk)?;

                    let counter_revocation_params =
                        signed_channel.counter_points.get_revokable_params(
                            &self.secp,
                            &signed_channel.own_points.revocation_basepoint,
                            &counter_per_update_point,
                        )?;

                    let witness = if signed_channel.own_params.fund_pubkey
                        < signed_channel.counter_params.fund_pubkey
                    {
                        &tx.input[0].witness[1]
                    } else {
                        &tx.input[0].witness[2]
                    };

                    let sig_data = witness
                        .iter()
                        .take(witness.len() - 1)
                        .cloned()
                        .collect::<Vec<_>>();
                    let own_sig = Signature::from_der(&sig_data)?;

                    println!(
                        "Trying to recover with counter pubkey: {:?}",
                        counter_revocation_params.publish_pk.key
                    );

                    let counter_sk = own_adaptor_signature.recover(
                        &self.secp,
                        &own_sig,
                        &counter_revocation_params.publish_pk.key,
                    )?;

                    let own_revocation_base_secret = &self.wallet.get_secret_key_for_pubkey(
                        &signed_channel.own_points.revocation_basepoint,
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

                    let signed_tx = match toxic_tx_type {
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
                    signed_channel.state = SignedChannelState::CollaborativelyClosed;
                    self.store
                        .upsert_channel(Channel::Signed(signed_channel), None)?;
                }
            }

            self.chain_monitor.increment_height(&block.block_hash());
        }

        Ok(())
    }
}

impl<W: Deref, B: Deref, S: DerefMut, O: Deref, T: Deref> Signer for &mut Manager<W, B, S, O, T>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    S::Target: Storage,
    O::Target: Oracle,
    T::Target: Time,
{
    fn sign_tx_input(
        &self,
        tx: &mut bitcoin::Transaction,
        input_index: usize,
        tx_out: &bitcoin::TxOut,
        redeem_script: Option<bitcoin::Script>,
    ) -> Result<(), Error> {
        self.wallet
            .sign_tx_input(tx, input_index, tx_out, redeem_script)
    }

    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey, Error> {
        self.wallet.get_secret_key_for_pubkey(pubkey)
    }
}
