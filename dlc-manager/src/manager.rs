//! #Manager a component to create and update DLCs.

use super::{Blockchain, Oracle, Storage, Time, Wallet};
use crate::contract::{
    accepted_contract::AcceptedContract, contract_info::ContractInfo,
    contract_input::ContractInput, contract_input::ContractInputInfo, contract_input::OracleInput,
    offered_contract::OfferedContract, signed_contract::SignedContract, AdaptorInfo,
    ClosedContract, Contract, FailedAcceptContract, FailedSignContract, FundingInputInfo,
};
use crate::conversion_utils::get_tx_input_infos;
use crate::error::Error;
use crate::ContractId;
use bitcoin::{
    consensus::{Decodable, Encodable},
    Address, Transaction,
};
use dlc::{DlcTransactions, PartyParams, TxInputInfo};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::{
    AcceptDlc, FundingInput, FundingSignature, FundingSignatures, Message as DlcMessage, OfferDlc,
    SignDlc, WitnessElement,
};
use log::{error, warn};
use secp256k1_zkp::rand::{thread_rng, RngCore};
use secp256k1_zkp::schnorrsig::{PublicKey as SchnorrPublicKey, Signature as SchnorrSignature};
use secp256k1_zkp::EcdsaAdaptorSignature;
use secp256k1_zkp::{All, PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::string::ToString;

/// The number of confirmations required before moving the the confirmed state.
pub const NB_CONFIRMATIONS: u32 = 6;
/// The delay to set the refund value to.
pub const REFUND_DELAY: u32 = 86400 * 7;

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

    fn get_party_params(
        &self,
        own_collateral: u64,
        fee_rate: u64,
    ) -> Result<(PartyParams, SecretKey, Vec<FundingInputInfo>), Error> {
        let mut rng = thread_rng();

        let funding_privkey = self.wallet.get_new_secret_key()?;
        let funding_pubkey = PublicKey::from_secret_key(&self.secp, &funding_privkey);

        let payout_addr = self.wallet.get_new_address()?;
        let payout_spk = payout_addr.script_pubkey();
        let payout_serial_id = rng.next_u64();
        let change_addr = self.wallet.get_new_address()?;
        let change_spk = change_addr.script_pubkey();
        let change_serial_id = rng.next_u64();

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
                input_serial_id: rng.next_u64(),
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
            let oracle = self.oracles.get(pubkey).ok_or(Error::InvalidParameters(
                "Unknown oracle public key".to_string(),
            ))?;
            announcements.push(oracle.get_announcement(&oracle_inputs.event_id)?.clone());
        }

        Ok(announcements)
    }

    fn contract_view_info_to_contract_info(
        &self,
        contract_view_info: &ContractInputInfo,
    ) -> Result<ContractInfo, Error> {
        let oracle_announcements = self.get_oracle_announcements(&contract_view_info.oracles)?;
        Ok(ContractInfo {
            contract_descriptor: contract_view_info.contract_descriptor.clone(),
            oracle_announcements,
            threshold: contract_view_info.oracles.threshold as usize,
        })
    }

    /// Function called to create a new DLC. The offered contract will be stored
    /// and an OfferDlc message returned.
    pub fn send_offer(
        &mut self,
        contract: &ContractInput,
        counter_party: PublicKey,
    ) -> Result<OfferDlc, Error> {
        let total_collateral = contract.offer_collateral + contract.accept_collateral;
        let (party_params, _, funding_inputs_info) =
            self.get_party_params(contract.offer_collateral, contract.fee_rate)?;

        let fund_output_serial_id = thread_rng().next_u64();
        let contract_info = contract
            .contract_infos
            .iter()
            .map(|x| self.contract_view_info_to_contract_info(x))
            .collect::<Result<Vec<ContractInfo>, Error>>()?;
        let mut offered_contract = OfferedContract {
            id: [0u8; 32],
            is_offer_party: true,
            contract_info,
            offer_params: party_params,
            total_collateral,
            funding_inputs_info,
            fund_output_serial_id,
            fee_rate_per_vb: contract.fee_rate,
            contract_maturity_bound: contract.maturity_time,
            contract_timeout: contract.maturity_time + REFUND_DELAY,
            counter_party,
        };

        let offer_msg: OfferDlc = (&offered_contract).into();

        offered_contract.id = offer_msg.get_hash()?;

        self.store.create_contract(&offered_contract)?;

        Ok(offer_msg)
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

        let total_collateral = offered_contract.total_collateral;

        let (accept_params, fund_secret_key, funding_inputs) = self.get_party_params(
            offered_contract.offer_params.collateral,
            offered_contract.fee_rate_per_vb,
        )?;

        let dlc_transactions = dlc::create_dlc_transactions(
            &offered_contract.offer_params,
            &accept_params,
            &offered_contract.contract_info[0].get_payouts(total_collateral),
            offered_contract.contract_timeout,
            offered_contract.fee_rate_per_vb,
            0,
            offered_contract.contract_maturity_bound,
            offered_contract.fund_output_serial_id,
        )?;

        self.wallet.import_address(&Address::p2wsh(
            &dlc_transactions.funding_script_pubkey,
            self.blockchain.get_network()?,
        ))?;

        let fund_output_value = dlc_transactions.get_fund_output().value;

        let cet_input = dlc_transactions.cets[0].input[0].clone();
        let (adaptor_info, adaptor_sig) = offered_contract.contract_info[0].get_adaptor_info(
            &self.secp,
            offered_contract.total_collateral,
            &fund_secret_key,
            &dlc_transactions.funding_script_pubkey,
            fund_output_value,
            &dlc_transactions.cets,
            0,
        )?;
        let mut adaptor_infos = vec![adaptor_info];
        let mut adaptor_sigs = adaptor_sig;

        let DlcTransactions {
            fund,
            mut cets,
            refund,
            funding_script_pubkey,
        } = dlc_transactions;

        for contract_info in offered_contract.contract_info.iter().skip(1) {
            let payouts = contract_info.get_payouts(total_collateral);

            let tmp_cets = dlc::create_cets(
                &cet_input,
                &offered_contract.offer_params.payout_script_pubkey,
                offered_contract.offer_params.payout_serial_id,
                &accept_params.payout_script_pubkey,
                accept_params.payout_serial_id,
                &payouts,
                0,
            );

            let (adaptor_info, adaptor_sig) = contract_info.get_adaptor_info(
                &self.secp,
                offered_contract.total_collateral,
                &fund_secret_key,
                &funding_script_pubkey,
                fund_output_value,
                &tmp_cets,
                adaptor_sigs.len(),
            )?;

            cets.extend(tmp_cets);

            adaptor_infos.push(adaptor_info);
            adaptor_sigs.extend(adaptor_sig);
        }

        let refund_signature = dlc::util::get_raw_sig_for_tx_input(
            &self.secp,
            &refund,
            0,
            &funding_script_pubkey,
            fund_output_value,
            &fund_secret_key,
        );

        let dlc_transactions = DlcTransactions {
            fund,
            cets,
            refund,
            funding_script_pubkey,
        };

        let counter_party = offered_contract.counter_party;

        let mut accepted_contract = AcceptedContract {
            offered_contract,
            adaptor_infos,
            adaptor_signatures: Some(adaptor_sigs),
            accept_params,
            funding_inputs,
            dlc_transactions,
            accept_refund_signature: refund_signature,
        };

        let accept_msg: AcceptDlc = (&accepted_contract).into();

        // Drop own adaptor signatures as no point keeping them.
        accepted_contract.adaptor_signatures = None;

        let contract_id = accepted_contract.get_contract_id();

        self.store
            .update_contract(&Contract::Accepted(accepted_contract))?;

        Ok((contract_id, counter_party, accept_msg))
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

        let total_collateral =
            offered_contract.offer_params.collateral + accept_msg.accept_collateral;

        let dlc_transactions = dlc::create_dlc_transactions(
            &offered_contract.offer_params,
            &accept_params,
            &offered_contract.contract_info[0].get_payouts(total_collateral),
            offered_contract.contract_timeout,
            offered_contract.fee_rate_per_vb,
            0,
            offered_contract.contract_maturity_bound,
            offered_contract.fund_output_serial_id,
        )?;

        self.wallet.import_address(&Address::p2wsh(
            &dlc_transactions.funding_script_pubkey,
            self.blockchain.get_network()?,
        ))?;

        let fund_output_value = dlc_transactions.get_fund_output().value;

        let DlcTransactions {
            fund,
            mut cets,
            refund,
            funding_script_pubkey,
        } = dlc_transactions;

        let refund_verify_result = dlc::verify_tx_input_sig(
            &self.secp,
            &accept_msg.refund_signature,
            &refund,
            0,
            &funding_script_pubkey,
            fund_output_value,
            &accept_params.fund_pubkey,
        );

        self.accept_fail_on_error(&offered_contract, accept_msg, refund_verify_result)?;

        let adaptor_signatures: Vec<_> = accept_msg
            .cet_adaptor_signatures
            .ecdsa_adaptor_signatures
            .iter()
            .map(|x| x.signature.clone())
            .collect();

        let adaptor_verify_result = offered_contract.contract_info[0].verify_and_get_adaptor_info(
            &self.secp,
            offered_contract.total_collateral,
            &accept_params.fund_pubkey,
            &funding_script_pubkey,
            fund_output_value,
            &cets,
            &adaptor_signatures,
            0,
        );

        let (adaptor_info, mut adaptor_index) =
            self.accept_fail_on_error(&offered_contract, accept_msg, adaptor_verify_result)?;

        let mut adaptor_infos = vec![adaptor_info];

        let cet_input = cets[0].input[0].clone();

        for contract_info in offered_contract.contract_info.iter().skip(1) {
            let payouts = contract_info.get_payouts(total_collateral);

            let tmp_cets = dlc::create_cets(
                &cet_input,
                &offered_contract.offer_params.payout_script_pubkey,
                offered_contract.offer_params.payout_serial_id,
                &accept_params.payout_script_pubkey,
                accept_params.payout_serial_id,
                &payouts,
                0,
            );

            let (adaptor_info, tmp_adaptor_index) = contract_info.verify_and_get_adaptor_info(
                &self.secp,
                offered_contract.total_collateral,
                &accept_params.fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
                &tmp_cets,
                &adaptor_signatures,
                adaptor_index,
            )?;

            adaptor_index = tmp_adaptor_index;

            cets.extend(tmp_cets);

            adaptor_infos.push(adaptor_info);
        }

        let mut own_signatures: Vec<EcdsaAdaptorSignature> = Vec::new();

        let fund_privkey = self
            .wallet
            .get_secret_key_for_pubkey(&offered_contract.offer_params.fund_pubkey)?;

        for (contract_info, adaptor_info) in offered_contract
            .contract_info
            .iter()
            .zip(adaptor_infos.iter())
        {
            let sigs = contract_info.get_adaptor_signatures(
                &self.secp,
                adaptor_info,
                &fund_privkey,
                &funding_script_pubkey,
                fund_output_value,
                &cets,
            )?;
            own_signatures.extend(sigs);
        }

        let mut input_serial_ids: Vec<_> = offered_contract
            .funding_inputs_info
            .iter()
            .map(|x| &x.funding_input)
            .chain(accept_msg.funding_inputs.iter())
            .map(|x| x.input_serial_id)
            .collect();
        input_serial_ids.sort();

        let funding_signatures: Vec<_> = offered_contract
            .funding_inputs_info
            .iter()
            .map(|x| {
                let address = x.address.as_ref().ok_or(Error::InvalidState)?;
                let sk = self.wallet.get_secret_key_for_address(&address)?;
                let input_index = input_serial_ids
                    .iter()
                    .position(|y| y == &x.funding_input.input_serial_id)
                    .ok_or(Error::InvalidState)?;
                let tx = Transaction::consensus_decode(&*x.funding_input.prev_tx).or(Err(
                    Error::InvalidParameters(
                        "Could not decode funding input previous tx parameter".to_string(),
                    ),
                ))?;
                let vout = x.funding_input.prev_tx_vout;
                let tx_out = tx
                    .output
                    .get(vout as usize)
                    .ok_or(Error::InvalidParameters(format!(
                        "Previous tx output not found at index {}",
                        vout
                    )))?;
                let witness = dlc::util::get_witness_for_p2wpkh_input(
                    &self.secp,
                    &sk,
                    &fund,
                    input_index,
                    bitcoin::SigHashType::All,
                    tx_out.value,
                );
                let witness_elements = witness
                    .into_iter()
                    .map(|z| WitnessElement { witness: z })
                    .collect();
                Ok(FundingSignature { witness_elements })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        input_serial_ids.sort();

        let offer_refund_signature = dlc::util::get_raw_sig_for_tx_input(
            &self.secp,
            &refund,
            0,
            &funding_script_pubkey,
            fund_output_value,
            &fund_privkey,
        );

        let dlc_transactions = DlcTransactions {
            fund,
            cets,
            refund,
            funding_script_pubkey,
        };

        let accepted_contract = AcceptedContract {
            offered_contract,
            accept_params,
            funding_inputs: accept_msg.funding_inputs.iter().map(|x| x.into()).collect(),
            adaptor_infos,
            adaptor_signatures: Some(adaptor_signatures),
            accept_refund_signature: accept_msg.refund_signature.clone(),
            dlc_transactions: dlc_transactions.clone(),
        };

        let mut signed_contract = SignedContract {
            accepted_contract,
            adaptor_signatures: Some(own_signatures),
            offer_refund_signature,
            funding_signatures: FundingSignatures { funding_signatures },
        };

        let signed_msg: SignDlc = (&signed_contract).into();

        // Drop own adaptor signatures as no point keeping them.
        signed_contract.adaptor_signatures = None;

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

        let offered_contract = &accepted_contract.offered_contract;

        let verify_result = dlc::verify_tx_input_sig(
            &self.secp,
            &sign_message.refund_signature,
            &accepted_contract.dlc_transactions.refund,
            0,
            &accepted_contract.dlc_transactions.funding_script_pubkey,
            accepted_contract.dlc_transactions.get_fund_output().value,
            &offered_contract.offer_params.fund_pubkey,
        );

        self.sign_fail_on_error(&accepted_contract, sign_message, verify_result)?;

        let adaptor_signatures: Vec<_> = sign_message
            .cet_adaptor_signatures
            .ecdsa_adaptor_signatures
            .iter()
            .map(|x| x.signature)
            .collect();

        let mut adaptor_sig_start = 0;

        for (adaptor_info, contract_info) in accepted_contract
            .adaptor_infos
            .iter()
            .zip(offered_contract.contract_info.iter())
        {
            let adaptor_verify_result = contract_info.verify_adaptor_info(
                &self.secp,
                &offered_contract.offer_params.fund_pubkey,
                &accepted_contract.dlc_transactions.funding_script_pubkey,
                accepted_contract.dlc_transactions.get_fund_output().value,
                &accepted_contract.dlc_transactions.cets,
                &adaptor_signatures,
                adaptor_sig_start,
                adaptor_info,
            );

            adaptor_sig_start =
                self.sign_fail_on_error(&accepted_contract, sign_message, adaptor_verify_result)?;
        }

        let mut input_serials: Vec<_> = offered_contract
            .funding_inputs_info
            .iter()
            .chain(accepted_contract.funding_inputs.iter())
            .map(|x| x.funding_input.input_serial_id)
            .collect();
        input_serials.sort();

        let mut fund_tx = accepted_contract.dlc_transactions.fund.clone();

        for (funding_input, funding_signatures) in offered_contract
            .funding_inputs_info
            .iter()
            .zip(sign_message.funding_signatures.funding_signatures.iter())
        {
            let input_index = input_serials
                .iter()
                .position(|x| x == &funding_input.funding_input.input_serial_id)
                .ok_or(Error::InvalidState)?;

            fund_tx.input[input_index].witness = funding_signatures
                .witness_elements
                .iter()
                .map(|x| x.witness.clone())
                .collect();
        }

        for funding_input_info in &accepted_contract.funding_inputs {
            let input_index = input_serials
                .iter()
                .position(|x| x == &funding_input_info.funding_input.input_serial_id)
                .ok_or(Error::InvalidState)?;
            let address = funding_input_info
                .address
                .as_ref()
                .ok_or(Error::InvalidState)?;
            let sk = self.wallet.get_secret_key_for_address(&address)?;
            let tx = Transaction::consensus_decode(&*funding_input_info.funding_input.prev_tx).or(
                Err(Error::InvalidParameters(
                    "Could not decode funding input previous tx parameter".to_string(),
                )),
            )?;
            let vout = funding_input_info.funding_input.prev_tx_vout;
            let tx_out = tx
                .output
                .get(vout as usize)
                .ok_or(Error::InvalidParameters(format!(
                    "Previous tx output not found at index {}",
                    vout
                )))?;
            dlc::util::sign_p2wpkh_input(
                &self.secp,
                &sk,
                &mut fund_tx,
                input_index,
                bitcoin::SigHashType::All,
                tx_out.value,
            );
        }

        let signed_contract = SignedContract {
            accepted_contract,
            adaptor_signatures: Some(adaptor_signatures),
            offer_refund_signature: sign_message.refund_signature,
            funding_signatures: sign_message.funding_signatures.clone(),
        };

        self.store
            .update_contract(&Contract::Signed(signed_contract))?;

        self.blockchain.send_transaction(&fund_tx)?;

        Ok(())
    }

    fn sign_fail_on_error<R>(
        &mut self,
        accepted_contract: &AcceptedContract,
        sign_message: &SignDlc,
        result: Result<R, dlc::Error>,
    ) -> Result<R, Error> {
        match result {
            Err(e) => {
                error!("Error in on_sign {}", e);
                self.store
                    .update_contract(&Contract::FailedSign(FailedSignContract {
                        accepted_contract: accepted_contract.clone(),
                        sign_message: sign_message.clone(),
                        error_message: e.to_string(),
                    }))?;
                Err(e.into())
            }
            Ok(val) => Ok(val),
        }
    }

    fn accept_fail_on_error<R>(
        &mut self,
        offered_contract: &OfferedContract,
        accept_message: &AcceptDlc,
        result: Result<R, dlc::Error>,
    ) -> Result<R, Error> {
        match result {
            Err(e) => {
                error!("Error in on_accept {}", e);
                self.store
                    .update_contract(&Contract::FailedAccept(FailedAcceptContract {
                        offered_contract: offered_contract.clone(),
                        accept_message: accept_message.clone(),
                        error_message: e.to_string(),
                    }))?;
                Err(e.into())
            }
            Ok(val) => Ok(val),
        }
    }

    /// Function to call to check the state of the currently executing DLCs and
    /// update them if possible.
    pub fn periodic_check(&mut self) -> Result<(), Error> {
        self.check_signed_contracts()?;
        self.check_confirmed_contracts()?;

        Ok(())
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
            match self.check_signed_contract(&c) {
                Err(e) => error!(
                    "Error checking confirmed contract {}: {}",
                    c.accepted_contract.get_contract_id_string(),
                    e
                ),
                _ => {}
            }
        }

        Ok(())
    }

    fn check_confirmed_contracts(&mut self) -> Result<(), Error> {
        for c in self.store.get_confirmed_contracts()? {
            match self.check_confirmed_contract(&c) {
                Err(e) => error!(
                    "Error checking confirmed contract {}: {}",
                    c.accepted_contract.get_contract_id_string(),
                    e
                ),
                _ => {}
            }
        }

        Ok(())
    }

    fn check_confirmed_contract(&mut self, contract: &SignedContract) -> Result<(), Error> {
        let contract_infos = &contract.accepted_contract.offered_contract.contract_info;
        for (contract_info, adaptor_info) in contract_infos
            .iter()
            .zip(contract.accepted_contract.adaptor_infos.iter())
        {
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
                    match self.try_close_contract(
                        contract,
                        contract_info,
                        adaptor_info,
                        &attestations,
                    ) {
                        Ok(()) => return Ok(()),
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
            }
        }

        self.check_refund(contract)?;

        Ok(())
    }

    fn try_close_contract(
        &mut self,
        contract: &SignedContract,
        contract_info: &ContractInfo,
        adaptor_info: &AdaptorInfo,
        attestations: &[(usize, OracleAttestation)],
    ) -> Result<(), Error> {
        let offered_contract = &contract.accepted_contract.offered_contract;
        let outcomes = attestations
            .iter()
            .map(|(i, x)| (*i, &x.outcomes))
            .collect::<Vec<(usize, &Vec<String>)>>();
        let info_opt = contract_info.get_range_info_for_outcome(adaptor_info, &outcomes, 0)?;
        if let Some((sig_infos, range_info)) = info_opt {
            let sigs: Vec<Vec<SchnorrSignature>> = attestations
                .iter()
                .filter_map(|(i, a)| {
                    let sig_info = sig_infos.iter().find(|x| x.0 == *i)?;
                    Some(a.signatures.iter().take(sig_info.1).cloned().collect())
                })
                .collect();
            let mut cet =
                contract.accepted_contract.dlc_transactions.cets[range_info.cet_index].clone();

            let confirmations = self
                .wallet
                .get_transaction_confirmations(&cet.txid())
                .unwrap();

            if confirmations < 1 {
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

                // TODO(tibo): if this fails because another tx is already in
                // mempool or blockchain, we might have been cheated. There is
                // not much to be done apart from possibly extracting a fraud
                // proof but ideally it should be handled.
                self.blockchain.send_transaction(&cet)?;
            }

            let closed_contract = ClosedContract {
                signed_contract: contract.clone(),
                attestations: attestations.iter().map(|x| x.1.clone()).collect(),
                cet_index: range_info.cet_index,
            };

            self.store
                .update_contract(&Contract::Closed(closed_contract))?;
        }

        Ok(())
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
                    &other_sig,
                    other_fund_pubkey,
                    &fund_priv_key,
                    &funding_script_pubkey,
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
