//! #Manager a component to create and update DLCs.

use super::{Blockchain, Oracle, Storage, Time, Wallet};
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
use crate::ContractId;
use crate::Signer;
use bitcoin::Transaction;
use bitcoin::{consensus::Encodable, Address};
use dlc::{PartyParams, TxInputInfo};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::{AcceptDlc, FundingInput, Message as DlcMessage, OfferDlc, SignDlc};
use dlc_trie::RangeInfo;
use log::{error, warn};
use secp256k1_zkp::schnorrsig::{PublicKey as SchnorrPublicKey, Signature as SchnorrSignature};
use secp256k1_zkp::{All, PublicKey, Secp256k1, SecretKey};
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
    time: T,
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
    ) -> Self {
        Manager {
            secp: secp256k1_zkp::Secp256k1::new(),
            wallet,
            blockchain,
            store,
            oracles,
            time,
        }
    }

    /// Get the store from the Manager to access contracts.
    pub fn get_store(&self) -> &S {
        &self.store
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
            DlcMessage::Accept(a) => Ok(Some(self.on_accept_message(a)?)),
            DlcMessage::Sign(s) => {
                self.on_sign_message(s)?;
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
        let contract = self.store.get_contract(contract_id)?;

        let offered_contract = match contract {
            Some(Contract::Offered(offered)) => offered,
            None => return Err(Error::InvalidParameters("Unknown contract id.".to_string())),
            _ => return Err(Error::InvalidState),
        };

        let counter_party = offered_contract.counter_party;

        let (accept_params, fund_secret_key, funding_inputs) = self.get_party_params(
            offered_contract.offer_params.collateral,
            offered_contract.fee_rate_per_vb,
        )?;

        let (accepted_contract, adaptor_sigs) = accept_contract(
            &self.secp,
            offered_contract,
            accept_params,
            funding_inputs,
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

        Ok(())
    }

    fn on_offer_message(
        &mut self,
        offered_message: &OfferDlc,
        counter_party: PublicKey,
    ) -> Result<(), Error> {
        let contract: OfferedContract =
            OfferedContract::try_from_offer_dlc(offered_message, counter_party)?;
        self.store.create_contract(&contract)?;

        Ok(())
    }

    fn on_accept_message(&mut self, accept_msg: &AcceptDlc) -> Result<DlcMessage, Error> {
        let contract = self.store.get_contract(&accept_msg.temporary_contract_id)?;

        let offered_contract = match contract {
            Some(Contract::Offered(offered)) => offered,
            None => return Err(Error::InvalidParameters("Unknown contract id.".to_string())),
            _ => return Err(Error::InvalidState),
        };

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
            accept_params,
            accept_msg.funding_inputs.iter().map(|x| x.into()).collect(),
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

    fn on_sign_message(&mut self, sign_message: &SignDlc) -> Result<(), Error> {
        let contract = self.store.get_contract(&sign_message.contract_id)?;
        let accepted_contract = match contract {
            Some(Contract::Accepted(accepted)) => accepted,
            None => return Err(Error::InvalidParameters("Unknown contract id.".to_string())),
            _ => return Err(Error::InvalidState),
        };

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

        Err(Error::InvalidState)
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
