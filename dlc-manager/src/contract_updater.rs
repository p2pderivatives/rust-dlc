//! # This module contains static functions to update the state of a DLC.

use std::{io::Cursor, ops::Deref};

use bitcoin::{consensus::Decodable, Script, Sequence, Transaction, Witness};
use dlc::{ord::OrdinalUtxo, DlcTransactions, PartyParams};
use dlc_messages::{
    oracle_msgs::{OracleAnnouncement, OracleAttestation},
    AcceptDlc, FundingInput, FundingSignature, FundingSignatures, OfferDlc, SignDlc,
    WitnessElement,
};
use secp256k1_zkp::{
    ecdsa::Signature, All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey, Signing,
};

use crate::{
    contract::{
        accepted_contract::AcceptedContract, contract_info::ContractInfo,
        contract_input::ContractInput, offered_contract::OfferedContract,
        signed_contract::SignedContract, AdaptorInfo, ContractDescriptor, FundingInputInfo,
    },
    conversion_utils::get_tx_input_infos,
    error::Error,
    Blockchain, ChannelId, Signer, Time, Wallet,
};

/// Creates an [`OfferedContract`] and [`OfferDlc`] message from the provided
/// contract and oracle information.
pub fn offer_contract<C: Signing, W: Deref, B: Deref, T: Deref>(
    secp: &Secp256k1<C>,
    contract_input: &ContractInput,
    oracle_announcements: Vec<Vec<OracleAnnouncement>>,
    refund_delay: u32,
    counter_party: &PublicKey,
    wallet: &W,
    blockchain: &B,
    time: &T,
) -> Result<(OfferedContract, OfferDlc), Error>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    T::Target: Time,
{
    contract_input.validate()?;

    let (party_params, _, funding_inputs_info) = crate::utils::get_party_params(
        secp,
        contract_input.offer_collateral,
        contract_input.fee_rate,
        wallet,
        blockchain,
    )?;

    let offered_contract = OfferedContract::new(
        contract_input,
        oracle_announcements,
        &party_params,
        &funding_inputs_info,
        counter_party,
        refund_delay,
        time.unix_time_now() as u32,
    );

    let offer_msg: OfferDlc = (&offered_contract).into();

    Ok((offered_contract, offer_msg))
}

/// Creates an [`AcceptedContract`] and produces
/// the accepting party's cet adaptor signatures.
pub fn accept_contract<W: Deref, B: Deref>(
    secp: &Secp256k1<All>,
    offered_contract: &OfferedContract,
    wallet: &W,
    blockchain: &B,
) -> Result<(AcceptedContract, AcceptDlc), crate::Error>
where
    W::Target: Wallet,
    B::Target: Blockchain,
{
    let total_collateral = offered_contract.total_collateral;

    let (accept_params, fund_secret_key, funding_inputs) = crate::utils::get_party_params(
        secp,
        total_collateral - offered_contract.offer_params.collateral,
        offered_contract.fee_rate_per_vb,
        wallet,
        blockchain,
    )?;

    let dlc_transactions = create_dlc_transactions(offered_contract, &accept_params)?;
    let fund_output_value = dlc_transactions.get_fund_output().value;

    let (accepted_contract, adaptor_sigs) = accept_contract_internal(
        secp,
        offered_contract,
        &accept_params,
        &funding_inputs,
        &fund_secret_key,
        fund_output_value,
        None,
        &dlc_transactions,
    )?;

    let accept_msg: AcceptDlc = accepted_contract.get_accept_contract_msg(&adaptor_sigs);

    Ok((accepted_contract, accept_msg))
}

pub(crate) fn accept_contract_internal(
    secp: &Secp256k1<All>,
    offered_contract: &OfferedContract,
    accept_params: &PartyParams,
    funding_inputs: &[FundingInputInfo],
    adaptor_secret_key: &SecretKey,
    input_value: u64,
    input_script_pubkey: Option<Script>,
    dlc_transactions: &DlcTransactions,
) -> Result<(AcceptedContract, Vec<EcdsaAdaptorSignature>), crate::Error> {
    let total_collateral = offered_contract.total_collateral;

    let input_script_pubkey =
        input_script_pubkey.unwrap_or_else(|| dlc_transactions.funding_script_pubkey.clone());

    let cet_input = dlc_transactions.cets[0].input[0].clone();

    let first_contract = &offered_contract.contract_info[0];

    let is_ord = if let ContractDescriptor::Ord(_) = &first_contract.contract_descriptor {
        true
    } else {
        false
    };

    let (adaptor_info, adaptor_sig) = first_contract.get_adaptor_info(
        secp,
        offered_contract.total_collateral,
        adaptor_secret_key,
        &input_script_pubkey,
        input_value,
        &dlc_transactions.cets,
        0,
    )?;
    let mut adaptor_infos = vec![adaptor_info];
    let mut adaptor_sigs = adaptor_sig;

    let DlcTransactions {
        fund,
        cets,
        refund,
        funding_script_pubkey,
    } = dlc_transactions;

    let mut cets = cets.clone();

    for contract_info in offered_contract.contract_info.iter().skip(1) {
        let tmp_cets = create_cets(
            contract_info,
            &offered_contract.offer_params,
            accept_params,
            &cet_input,
            total_collateral,
            is_ord,
        )?;
        let (adaptor_info, adaptor_sig) = contract_info.get_adaptor_info(
            secp,
            offered_contract.total_collateral,
            adaptor_secret_key,
            &input_script_pubkey,
            input_value,
            &tmp_cets,
            adaptor_sigs.len(),
        )?;

        cets.extend(tmp_cets);

        adaptor_infos.push(adaptor_info);
        adaptor_sigs.extend(adaptor_sig);
    }

    let refund_signature = dlc::util::get_raw_sig_for_tx_input(
        secp,
        refund,
        0,
        &input_script_pubkey,
        input_value,
        adaptor_secret_key,
    )?;

    let dlc_transactions = DlcTransactions {
        fund: fund.clone(),
        cets,
        refund: refund.clone(),
        funding_script_pubkey: funding_script_pubkey.clone(),
    };

    let accepted_contract = AcceptedContract {
        offered_contract: offered_contract.clone(),
        adaptor_infos,
        // Drop own adaptor signatures as no point keeping them.
        adaptor_signatures: None,
        accept_params: accept_params.clone(),
        funding_inputs: funding_inputs.to_vec(),
        dlc_transactions,
        accept_refund_signature: refund_signature,
    };

    Ok((accepted_contract, adaptor_sigs))
}

/// Verifies the information of the accepting party [`Accept` message](dlc_messages::AcceptDlc),
/// creates a [`SignedContract`], and generates the offering party CET adaptor signatures.
pub fn verify_accepted_and_sign_contract<S: Deref>(
    secp: &Secp256k1<All>,
    offered_contract: &OfferedContract,
    accept_msg: &AcceptDlc,
    signer: &S,
) -> Result<(SignedContract, SignDlc), Error>
where
    S::Target: Signer,
{
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

    let dlc_transactions = create_dlc_transactions(offered_contract, &accept_params)?;
    let fund_output_value = dlc_transactions.get_fund_output().value;
    let fund_privkey =
        signer.get_secret_key_for_pubkey(&offered_contract.offer_params.fund_pubkey)?;
    let (signed_contract, adaptor_sigs) = verify_accepted_and_sign_contract_internal(
        secp,
        offered_contract,
        &accept_params,
        &accept_msg
            .funding_inputs
            .iter()
            .map(|x| x.into())
            .collect::<Vec<_>>(),
        &accept_msg.refund_signature,
        &cet_adaptor_signatures,
        fund_output_value,
        &fund_privkey,
        signer,
        None,
        None,
        &dlc_transactions,
        None,
    )?;

    let signed_msg: SignDlc = signed_contract.get_sign_dlc(adaptor_sigs);

    Ok((signed_contract, signed_msg))
}

pub(crate) fn verify_accepted_and_sign_contract_internal<S: Deref>(
    secp: &Secp256k1<All>,
    offered_contract: &OfferedContract,
    accept_params: &PartyParams,
    funding_inputs_info: &[FundingInputInfo],
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    input_value: u64,
    adaptor_secret: &SecretKey,
    signer: &S,
    input_script_pubkey: Option<Script>,
    counter_adaptor_pk: Option<PublicKey>,
    dlc_transactions: &DlcTransactions,
    channel_id: Option<ChannelId>,
) -> Result<(SignedContract, Vec<EcdsaAdaptorSignature>), Error>
where
    S::Target: Signer,
{
    let DlcTransactions {
        fund,
        cets,
        refund,
        funding_script_pubkey,
    } = dlc_transactions;

    let mut fund = fund.clone();
    let mut cets = cets.clone();

    let input_script_pubkey = input_script_pubkey.unwrap_or_else(|| funding_script_pubkey.clone());
    let counter_adaptor_pk = counter_adaptor_pk.unwrap_or(accept_params.fund_pubkey);

    dlc::verify_tx_input_sig(
        secp,
        refund_signature,
        refund,
        0,
        &input_script_pubkey,
        input_value,
        &counter_adaptor_pk,
    )?;

    let (adaptor_info, mut adaptor_index) = offered_contract.contract_info[0]
        .verify_and_get_adaptor_info(
            secp,
            offered_contract.total_collateral,
            &counter_adaptor_pk,
            &input_script_pubkey,
            input_value,
            &cets,
            cet_adaptor_signatures,
            0,
        )?;

    let mut adaptor_infos = vec![adaptor_info];

    let mut own_funding_inputs_info = offered_contract.funding_inputs_info.clone();

    let is_ord = if let ContractDescriptor::Ord(o) =
        &offered_contract.contract_info[0].contract_descriptor
    {
        if o.refund_offer {
            own_funding_inputs_info.insert(
                0,
                FundingInputInfo {
                    funding_input: FundingInput {
                        input_serial_id: 0,
                        prev_tx: bitcoin::consensus::encode::serialize(&o.ordinal_tx),
                        prev_tx_vout: o.ordinal_sat_point.outpoint.vout,
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME.into(),
                        max_witness_len: 107,
                        redeem_script: Script::default(),
                    },
                    address: None,
                },
            );

            true
        } else {
            false
        }
    } else {
        false
    };

    let cet_input = cets[0].input[0].clone();

    let total_collateral = offered_contract.offer_params.collateral + accept_params.collateral;

    for contract_info in offered_contract.contract_info.iter().skip(1) {
        let tmp_cets = create_cets(
            contract_info,
            &offered_contract.offer_params,
            accept_params,
            &cet_input,
            total_collateral,
            is_ord,
        )?;
        let (adaptor_info, tmp_adaptor_index) = contract_info.verify_and_get_adaptor_info(
            secp,
            offered_contract.total_collateral,
            &accept_params.fund_pubkey,
            funding_script_pubkey,
            input_value,
            &tmp_cets,
            cet_adaptor_signatures,
            adaptor_index,
        )?;

        adaptor_index = tmp_adaptor_index;

        cets.extend(tmp_cets);

        adaptor_infos.push(adaptor_info);
    }

    let mut own_signatures: Vec<EcdsaAdaptorSignature> = Vec::new();

    for (contract_info, adaptor_info) in offered_contract
        .contract_info
        .iter()
        .zip(adaptor_infos.iter())
    {
        let sigs = contract_info.get_adaptor_signatures(
            secp,
            adaptor_info,
            adaptor_secret,
            &input_script_pubkey,
            input_value,
            &cets,
        )?;
        own_signatures.extend(sigs);
    }

    // Vec<Witness>
    let witnesses: Vec<Witness> = own_funding_inputs_info
        .iter()
        .map(|x| {
            let tx = Transaction::consensus_decode(&mut x.funding_input.prev_tx.as_slice())
                .map_err(|_| {
                    Error::InvalidParameters(
                        "Could not decode funding input previous tx parameter".to_string(),
                    )
                })?;
            let input_index = fund
                .input
                .iter()
                .position(|y| {
                    y.previous_output.txid == tx.txid()
                        && y.previous_output.vout == x.funding_input.prev_tx_vout
                })
                .ok_or(Error::InvalidParameters(
                    "Could not find matching input in fund transaction".to_string(),
                ))?;
            let vout = x.funding_input.prev_tx_vout;
            let tx_out = tx.output.get(vout as usize).ok_or_else(|| {
                Error::InvalidParameters(format!("Previous tx output not found at index {}", vout))
            })?;

            // pass wallet instead of privkeys
            signer.sign_tx_input(&mut fund, input_index, tx_out, None)?;

            Ok(fund.input[input_index].witness.clone())
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let funding_signatures: Vec<FundingSignature> = witnesses
        .into_iter()
        .map(|witness| {
            let witness_elements = witness
                .iter()
                .map(|z| WitnessElement {
                    witness: z.to_vec(),
                })
                .collect();
            Ok(FundingSignature { witness_elements })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let offer_refund_signature = dlc::util::get_raw_sig_for_tx_input(
        secp,
        refund,
        0,
        &input_script_pubkey,
        input_value,
        adaptor_secret,
    )?;

    let dlc_transactions = DlcTransactions {
        fund,
        cets,
        refund: refund.clone(),
        funding_script_pubkey: funding_script_pubkey.clone(),
    };

    let accepted_contract = AcceptedContract {
        offered_contract: offered_contract.clone(),
        accept_params: accept_params.clone(),
        funding_inputs: funding_inputs_info.to_vec(),
        adaptor_infos,
        adaptor_signatures: Some(cet_adaptor_signatures.to_vec()),
        accept_refund_signature: *refund_signature,
        dlc_transactions,
    };

    let signed_contract = SignedContract {
        accepted_contract,
        adaptor_signatures: None,
        offer_refund_signature,
        funding_signatures: FundingSignatures { funding_signatures },
        channel_id,
    };

    Ok((signed_contract, own_signatures))
}

/// Verifies the information from the offer party [`Sign` message](dlc_messages::SignDlc),
/// creates the accepting party's [`SignedContract`] and returns it along with the
/// signed fund transaction.
pub fn verify_signed_contract<S: Deref>(
    secp: &Secp256k1<All>,
    accepted_contract: &AcceptedContract,
    sign_msg: &SignDlc,
    signer: &S,
) -> Result<(SignedContract, Transaction), Error>
where
    S::Target: Signer,
{
    let cet_adaptor_signatures: Vec<_> = (&sign_msg.cet_adaptor_signatures).into();
    verify_signed_contract_internal(
        secp,
        accepted_contract,
        &sign_msg.refund_signature,
        &cet_adaptor_signatures,
        &sign_msg.funding_signatures,
        accepted_contract.dlc_transactions.get_fund_output().value,
        None,
        None,
        signer,
        None,
    )
}

pub(crate) fn verify_signed_contract_internal<S: Deref>(
    secp: &Secp256k1<All>,
    accepted_contract: &AcceptedContract,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    funding_signatures: &FundingSignatures,
    input_value: u64,
    input_script_pubkey: Option<Script>,
    counter_adaptor_pk: Option<PublicKey>,
    signer: &S,
    channel_id: Option<ChannelId>,
) -> Result<(SignedContract, Transaction), Error>
where
    S::Target: Signer,
{
    let offered_contract = &accepted_contract.offered_contract;
    let input_script_pubkey = input_script_pubkey.unwrap_or_else(|| {
        accepted_contract
            .dlc_transactions
            .funding_script_pubkey
            .clone()
    });
    let counter_adaptor_pk =
        counter_adaptor_pk.unwrap_or(accepted_contract.offered_contract.offer_params.fund_pubkey);

    dlc::verify_tx_input_sig(
        secp,
        refund_signature,
        &accepted_contract.dlc_transactions.refund,
        0,
        &input_script_pubkey,
        input_value,
        &counter_adaptor_pk,
    )?;

    let mut adaptor_sig_start = 0;

    for (adaptor_info, contract_info) in accepted_contract
        .adaptor_infos
        .iter()
        .zip(offered_contract.contract_info.iter())
    {
        adaptor_sig_start = contract_info.verify_adaptor_info(
            secp,
            &counter_adaptor_pk,
            &input_script_pubkey,
            input_value,
            &accepted_contract.dlc_transactions.cets,
            cet_adaptor_signatures,
            adaptor_sig_start,
            adaptor_info,
        )?;
    }

    let mut fund_tx = accepted_contract.dlc_transactions.fund.clone();

    let mut funding_inputs_info = offered_contract.funding_inputs_info.clone();

    let mut own_funding_inputs_info = accepted_contract.funding_inputs.clone();

    if let ContractDescriptor::Ord(o) = &offered_contract.contract_info[0].contract_descriptor {
        if o.refund_offer {
            funding_inputs_info.insert(
                0,
                FundingInputInfo {
                    funding_input: FundingInput {
                        input_serial_id: 0,
                        prev_tx: bitcoin::consensus::encode::serialize(&o.ordinal_tx),
                        prev_tx_vout: o.ordinal_sat_point.outpoint.vout,
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME.into(),
                        max_witness_len: 107,
                        redeem_script: Script::default(),
                    },
                    address: None,
                },
            );
        } else {
            own_funding_inputs_info.insert(
                0,
                FundingInputInfo {
                    funding_input: FundingInput {
                        input_serial_id: 0,
                        prev_tx: bitcoin::consensus::encode::serialize(&o.ordinal_tx),
                        prev_tx_vout: o.ordinal_sat_point.outpoint.vout,
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME.into(),
                        max_witness_len: 107,
                        redeem_script: Script::default(),
                    },
                    address: None,
                },
            );
        }
    }

    for (funding_input, funding_signatures) in funding_inputs_info
        .iter()
        .zip(funding_signatures.funding_signatures.iter())
    {
        let txid =
            Transaction::consensus_decode(&mut Cursor::new(&funding_input.funding_input.prev_tx))
                .map_err(|e| {
                    Error::InvalidParameters(format!("Error decoding transaction: {}", e))
                })?
                .txid();
        let input_index = fund_tx
            .input
            .iter()
            .position(|y| {
                y.previous_output.txid == txid
                    && y.previous_output.vout == funding_input.funding_input.prev_tx_vout
            })
            .ok_or(Error::InvalidParameters(
                "Could not find matching input in fund transaction".to_string(),
            ))?;

        fund_tx.input[input_index].witness = Witness::from_vec(
            funding_signatures
                .witness_elements
                .iter()
                .map(|x| x.witness.clone())
                .collect(),
        );
    }

    for funding_input_info in &own_funding_inputs_info {
        let tx =
            Transaction::consensus_decode(&mut funding_input_info.funding_input.prev_tx.as_slice())
                .map_err(|_| {
                    Error::InvalidParameters(
                        "Could not decode funding input previous tx parameter".to_string(),
                    )
                })?;
        let vout = funding_input_info.funding_input.prev_tx_vout;
        let tx_out = tx.output.get(vout as usize).ok_or_else(|| {
            Error::InvalidParameters(format!("Previous tx output not found at index {}", vout))
        })?;
        let input_index = fund_tx
            .input
            .iter()
            .position(|y| {
                y.previous_output.txid == tx.txid()
                    && y.previous_output.vout == funding_input_info.funding_input.prev_tx_vout
            })
            .ok_or(Error::InvalidParameters(
                "Could not find matching input in fund transaction".to_string(),
            ))?;

        signer.sign_tx_input(&mut fund_tx, input_index, tx_out, None)?;
    }

    let signed_contract = SignedContract {
        accepted_contract: accepted_contract.clone(),
        adaptor_signatures: Some(cet_adaptor_signatures.to_vec()),
        offer_refund_signature: *refund_signature,
        funding_signatures: funding_signatures.clone(),
        channel_id,
    };

    Ok((signed_contract, fund_tx))
}

/// Signs and return the CET that can be used to close the given contract.
pub fn get_signed_cet<C: Signing, S: Deref>(
    secp: &Secp256k1<C>,
    contract: &SignedContract,
    contract_info: &ContractInfo,
    adaptor_info: &AdaptorInfo,
    attestations: &[(usize, OracleAttestation)],
    signer: &S,
) -> Result<Transaction, Error>
where
    S::Target: Signer,
{
    let (range_info, sigs) =
        crate::utils::get_range_info_and_oracle_sigs(contract_info, adaptor_info, attestations)?;
    let mut cet = contract.accepted_contract.dlc_transactions.cets[range_info.cet_index].clone();
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

    let funding_sk = signer.get_secret_key_for_pubkey(fund_pubkey)?;

    dlc::sign_cet(
        secp,
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

    Ok(cet)
}

/// Signs and return the refund transaction to refund the contract.
pub fn get_signed_refund<C: Signing, S: Deref>(
    secp: &Secp256k1<C>,
    contract: &SignedContract,
    signer: &S,
) -> Result<Transaction, Error>
where
    S::Target: Signer,
{
    let accepted_contract = &contract.accepted_contract;
    let offered_contract = &accepted_contract.offered_contract;
    let funding_script_pubkey = &accepted_contract.dlc_transactions.funding_script_pubkey;
    let fund_output_value = accepted_contract.dlc_transactions.get_fund_output().value;
    let (fund_pubkey, other_fund_pubkey, other_sig) = if offered_contract.is_offer_party {
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

    let fund_priv_key = signer.get_secret_key_for_pubkey(fund_pubkey)?;
    let mut refund = accepted_contract.dlc_transactions.refund.clone();
    dlc::util::sign_multi_sig_input(
        secp,
        &mut refund,
        other_sig,
        other_fund_pubkey,
        &fund_priv_key,
        funding_script_pubkey,
        fund_output_value,
        0,
    )?;
    Ok(refund)
}

fn create_dlc_transactions(
    offered_contract: &OfferedContract,
    accept_params: &PartyParams,
) -> Result<DlcTransactions, Error> {
    match &offered_contract.contract_info[0].contract_descriptor {
        crate::contract::ContractDescriptor::Enum(e) => Ok(e.create_dlc_transactions(
            &offered_contract.offer_params,
            accept_params,
            offered_contract.refund_locktime,
            offered_contract.fee_rate_per_vb,
            0,
            offered_contract.cet_locktime,
            offered_contract.fund_output_serial_id,
        )?),
        crate::contract::ContractDescriptor::Numerical(n) => Ok(n.create_dlc_transactions(
            &offered_contract.offer_params,
            accept_params,
            offered_contract.refund_locktime,
            offered_contract.fee_rate_per_vb,
            0,
            offered_contract.cet_locktime,
            offered_contract.fund_output_serial_id,
        )?),
        crate::contract::ContractDescriptor::Ord(o) => {
            let ordinal_utxo = OrdinalUtxo {
                sat_point: o.ordinal_sat_point,
                value: o.ordinal_tx.output[o.ordinal_sat_point.outpoint.vout as usize].value,
            };

            Ok(dlc::ord::create_dlc_transactions(
                &offered_contract.offer_params,
                accept_params,
                &o.get_ord_payouts(offered_contract.total_collateral)?,
                &ordinal_utxo,
                offered_contract.refund_locktime,
                offered_contract.fee_rate_per_vb,
                0,
                offered_contract.cet_locktime,
                o.refund_offer,
                0,
            )?)
        }
    }
}

fn create_cets(
    contract_info: &ContractInfo,
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    cet_input: &bitcoin::TxIn,
    total_collateral: u64,
    is_ord: bool,
) -> Result<Vec<Transaction>, Error> {
    match &contract_info.contract_descriptor {
        ContractDescriptor::Ord(_) if !is_ord => Err(Error::InvalidParameters(
            "OrdDescriptor cannot be combined with other descripto".to_string(),
        )),
        ContractDescriptor::Enum(_) | ContractDescriptor::Numerical(_) if is_ord => {
            Err(Error::InvalidParameters(
                "OrdDescriptor cannot be combined with other descripto".to_string(),
            ))
        }
        ContractDescriptor::Ord(o) => {
            let payouts = o.get_ord_payouts(total_collateral)?;
            Ok(dlc::ord::create_cets(
                &offer_params.payout_script_pubkey,
                &accept_params.payout_script_pubkey,
                &payouts,
                o.get_postage(),
                cet_input,
                0,
            ))
        }
        ContractDescriptor::Numerical(n) => {
            let payouts = n.get_payouts(total_collateral)?;
            Ok(dlc::create_cets(
                cet_input,
                &offer_params.payout_script_pubkey,
                offer_params.payout_serial_id,
                &accept_params.payout_script_pubkey,
                accept_params.payout_serial_id,
                &payouts,
                0,
            ))
        }
        ContractDescriptor::Enum(e) => {
            let payouts = e.get_payouts();
            Ok(dlc::create_cets(
                cet_input,
                &offer_params.payout_script_pubkey,
                offer_params.payout_serial_id,
                &accept_params.payout_script_pubkey,
                accept_params.payout_serial_id,
                &payouts,
                0,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use mocks::dlc_manager::contract::offered_contract::OfferedContract;
    use secp256k1_zkp::PublicKey;

    #[test]
    fn accept_contract_test() {
        let offer_dlc =
            serde_json::from_str(include_str!("../test_inputs/offer_contract.json")).unwrap();
        let dummy_pubkey: PublicKey =
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"
                .parse()
                .unwrap();
        let offered_contract =
            OfferedContract::try_from_offer_dlc(&offer_dlc, dummy_pubkey).unwrap();
        let blockchain = Rc::new(mocks::mock_blockchain::MockBlockchain::new());
        let fee_rate: u64 = offered_contract.fee_rate_per_vb;
        let utxo_value: u64 = offered_contract.total_collateral
            - offered_contract.offer_params.collateral
            + crate::utils::get_half_common_fee(fee_rate).unwrap();
        let wallet = Rc::new(mocks::mock_wallet::MockWallet::new(
            &blockchain,
            &[utxo_value, 10000],
        ));

        mocks::dlc_manager::contract_updater::accept_contract(
            secp256k1_zkp::SECP256K1,
            &offered_contract,
            &wallet,
            &blockchain,
        )
        .expect("Not to fail");
    }
}
