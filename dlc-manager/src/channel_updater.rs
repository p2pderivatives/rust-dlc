//! #

use std::ops::Deref;

use crate::{
    channel::{
        accepted_channel::AcceptedChannel,
        offered_channel::OfferedChannel,
        party_points::PartyBasePoints,
        signed_channel::{SignedChannel, SignedChannelState},
        utils::derive_bitcoin_public_key,
    },
    contract::{
        accepted_contract::AcceptedContract, contract_input::ContractInput,
        offered_contract::OfferedContract, signed_contract::SignedContract, FundingInputInfo,
    },
    contract_updater::{
        accept_contract_internal, verify_accepted_and_sign_contract_internal,
        verify_signed_contract,
    },
    error::Error,
    utils::get_new_temporary_id,
    Signer,
};
use bitcoin::{Script, Transaction, TxIn};
use dlc::{
    channel::{get_tx_adaptor_signature, verify_tx_adaptor_signature, DlcChannelTransactions},
    PartyParams,
};
use dlc_messages::{
    channel::{
        SettleChannelAccept, SettleChannelConfirm, SettleChannelFinalize, SettleChannelOffer,
    },
    oracle_msgs::OracleAnnouncement,
    FundingSignatures,
};
use lightning::ln::chan_utils::{
    build_commitment_secret, derive_private_key, CounterpartyCommitmentSecrets,
};
use secp256k1_zkp::{
    All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey, Signature, Signing,
};

const INITIAL_UPDATE_NUMBER: u64 = (1 << 48) - 1;

///
pub fn offer_channel<C: Signing>(
    secp: &Secp256k1<C>,
    contract: &ContractInput,
    counter_party: &PublicKey,
    offer_params: &PartyParams,
    party_points: &PartyBasePoints,
    per_update_seed: &SecretKey,
    funding_inputs_info: &[FundingInputInfo],
    oracle_announcements: &[Vec<OracleAnnouncement>],
    contract_timeout: u32,
) -> (OfferedChannel, OfferedContract) {
    let offered_contract = OfferedContract::new(
        contract,
        oracle_announcements.to_vec(),
        offer_params,
        funding_inputs_info,
        contract_timeout,
        counter_party,
    );

    let temporary_channel_id = get_new_temporary_id();

    let first_per_update_point = PublicKey::from_secret_key(
        secp,
        &SecretKey::from_slice(&build_commitment_secret(
            per_update_seed.as_ref(),
            INITIAL_UPDATE_NUMBER,
        ))
        .expect("to have generated a valid secret key."),
    );

    let offered_channel = OfferedChannel {
        offered_contract_id: offered_contract.id,
        party_points: party_points.clone(),
        temporary_channel_id,
        per_update_point: first_per_update_point,
        offer_per_update_seed: Some(PublicKey::from_secret_key(secp, per_update_seed)),
        is_offer_party: false,
        counter_party: *counter_party,
    };

    (offered_channel, offered_contract)
}

///
pub fn accept_channel_offer(
    secp: &Secp256k1<All>,
    offered_channel: &OfferedChannel,
    offered_contract: &OfferedContract,
    accept_params: &PartyParams,
    funding_inputs_info: &[FundingInputInfo],
    own_fund_sk: &SecretKey,
    own_base_secret_key: &SecretKey,
    per_update_seed: &SecretKey,
    accept_points: &PartyBasePoints,
    cet_nsequence: u32,
) -> Result<
    (
        AcceptedChannel,
        AcceptedContract,
        EcdsaAdaptorSignature,
        Vec<EcdsaAdaptorSignature>,
    ),
    Error,
> {
    assert_eq!(offered_channel.offered_contract_id, offered_contract.id);
    let offer_revoke_params = offered_channel.party_points.get_revokable_params(
        secp,
        &accept_points.revocation_basepoint,
        &offered_channel.per_update_point,
    )?;

    let first_per_update_point = PublicKey::from_secret_key(
        secp,
        &SecretKey::from_slice(&build_commitment_secret(
            per_update_seed.as_ref(),
            INITIAL_UPDATE_NUMBER,
        ))
        .expect("to have generated a valid secret key."),
    );
    let accept_revoke_params = accept_points.get_revokable_params(
        secp,
        &offered_channel.party_points.revocation_basepoint,
        &first_per_update_point,
    )?;

    let total_collateral = offered_contract.total_collateral;

    let DlcChannelTransactions {
        buffer_transaction,
        buffer_script_pubkey,
        dlc_transactions,
    } = dlc::channel::create_channel_transactions(
        &offered_contract.offer_params,
        accept_params,
        &offer_revoke_params,
        &accept_revoke_params,
        &offered_contract.contract_info[0].get_payouts(total_collateral)?,
        offered_contract.contract_timeout,
        offered_contract.fee_rate_per_vb,
        0,
        offered_contract.contract_maturity_bound,
        offered_contract.fund_output_serial_id,
        cet_nsequence,
    )?;

    let own_secret_key = derive_private_key(secp, &first_per_update_point, own_base_secret_key)
        .expect("to get a valid secret.");

    let channel_id = crate::utils::compute_id(
        dlc_transactions.fund.txid(),
        dlc_transactions.get_fund_output_index() as u16,
        &offered_channel.temporary_channel_id,
    );

    let buffer_adaptor_signature = get_tx_adaptor_signature(
        secp,
        &buffer_transaction,
        dlc_transactions.get_fund_output().value,
        &dlc_transactions.funding_script_pubkey,
        own_fund_sk,
        &offer_revoke_params.publish_pk.key,
    );

    let (accepted_contract, adaptor_sigs) = accept_contract_internal(
        secp,
        offered_contract,
        accept_params,
        funding_inputs_info,
        &own_secret_key,
        buffer_transaction.output[0].value,
        Some(buffer_script_pubkey.clone()),
        &dlc_transactions,
    )?;

    let accepted_channel = AcceptedChannel {
        offer_base_points: offered_channel.party_points.clone(),
        accept_base_points: accept_points.clone(),
        accepted_contract_id: accepted_contract.get_contract_id(),
        buffer_transaction,
        buffer_script_pubkey,
        offer_per_update_point: offered_channel.per_update_point,
        accept_per_update_point: first_per_update_point,
        temporary_channel_id: offered_channel.temporary_channel_id,
        channel_id,
        accept_per_update_seed: PublicKey::from_secret_key(secp, per_update_seed),
        accept_buffer_adaptor_signature: buffer_adaptor_signature,
        counter_party: offered_contract.counter_party,
    };

    Ok((
        accepted_channel,
        accepted_contract,
        buffer_adaptor_signature,
        adaptor_sigs,
    ))
}

///
pub fn verify_accepted_channel<S: Deref>(
    secp: &Secp256k1<All>,
    offered_channel: &OfferedChannel,
    offered_contract: &OfferedContract,
    accept_params: &PartyParams,
    accept_points: &PartyBasePoints,
    accept_per_update_point: &PublicKey,
    offer_own_sk: &SecretKey,
    offer_fund_sk: &SecretKey,
    funding_inputs_info: &[FundingInputInfo],
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    cet_nsequence: u32,
    buffer_adaptor_signature: &EcdsaAdaptorSignature,
    wallet: S,
) -> Result<
    (
        SignedChannel,
        SignedContract,
        Vec<EcdsaAdaptorSignature>,
        EcdsaAdaptorSignature,
    ),
    Error,
>
where
    S::Target: Signer,
{
    let offer_revoke_params = offered_channel.party_points.get_revokable_params(
        secp,
        &accept_points.revocation_basepoint,
        &offered_channel.per_update_point,
    )?;
    let accept_revoke_params = accept_points.get_revokable_params(
        secp,
        &offered_channel.party_points.revocation_basepoint,
        accept_per_update_point,
    )?;

    let total_collateral = offered_contract.total_collateral;

    let DlcChannelTransactions {
        buffer_transaction,
        dlc_transactions,
        buffer_script_pubkey,
    } = dlc::channel::create_channel_transactions(
        &offered_contract.offer_params,
        accept_params,
        &offer_revoke_params,
        &accept_revoke_params,
        &offered_contract.contract_info[0].get_payouts(total_collateral)?,
        offered_contract.contract_timeout,
        offered_contract.fee_rate_per_vb,
        0,
        offered_contract.contract_maturity_bound,
        offered_contract.fund_output_serial_id,
        cet_nsequence,
    )?;

    let channel_id = crate::utils::compute_id(
        dlc_transactions.fund.txid(),
        dlc_transactions.get_fund_output_index() as u16,
        &offered_channel.temporary_channel_id,
    );

    let (signed_contract, cet_adaptor_signatures) = verify_accepted_and_sign_contract_internal(
        secp,
        offered_contract,
        accept_params,
        funding_inputs_info,
        refund_signature,
        cet_adaptor_signatures,
        buffer_transaction.output[0].value,
        offer_own_sk,
        wallet,
        Some(buffer_script_pubkey),
        Some(accept_revoke_params.own_pk.key),
        &dlc_transactions,
        Some(channel_id),
    )?;

    verify_tx_adaptor_signature(
        secp,
        &buffer_transaction,
        dlc_transactions.get_fund_output().value,
        &dlc_transactions.funding_script_pubkey,
        &signed_contract.accepted_contract.accept_params.fund_pubkey,
        &offer_revoke_params.publish_pk.key,
        buffer_adaptor_signature,
    )?;

    let own_buffer_adaptor_signature = get_tx_adaptor_signature(
        secp,
        &buffer_transaction,
        dlc_transactions.get_fund_output().value,
        &dlc_transactions.funding_script_pubkey,
        offer_fund_sk,
        &accept_revoke_params.publish_pk.key,
    );

    let signed_channel = SignedChannel {
        counter_party: signed_contract
            .accepted_contract
            .offered_contract
            .counter_party,
        own_points: offered_channel.party_points.clone(),
        counter_points: accept_points.clone(),
        counter_params: signed_contract.accepted_contract.accept_params.clone(),
        counter_per_update_point: *accept_per_update_point,
        state: SignedChannelState::Established {
            signed_contract_id: signed_contract.accepted_contract.get_contract_id(),
            own_buffer_adaptor_signature,
            counter_buffer_adaptor_signature: *buffer_adaptor_signature,
            buffer_transaction,
            is_offer: true,
        },
        update_idx: INITIAL_UPDATE_NUMBER,
        channel_id,
        temporary_channel_id: offered_channel.temporary_channel_id,
        roll_back_state: None,
        fund_tx: dlc_transactions.fund.clone(),
        fund_script_pubkey: dlc_transactions.funding_script_pubkey.clone(),
        fund_output_index: dlc_transactions.get_fund_output_index(),
        own_params: offered_contract.offer_params.clone(),
        own_per_update_point: offered_channel.per_update_point,
        own_per_update_seed: offered_channel
            .offer_per_update_seed
            .expect("to have the offer update seed"),
        counter_party_commitment_secrets: CounterpartyCommitmentSecrets::new(),
        fee_rate_per_vb: signed_contract
            .accepted_contract
            .offered_contract
            .fee_rate_per_vb,
    };

    Ok((
        signed_channel,
        signed_contract,
        cet_adaptor_signatures,
        own_buffer_adaptor_signature,
    ))
}

///
pub fn verify_signed_channel<S: Deref>(
    secp: &Secp256k1<All>,
    accepted_channel: &AcceptedChannel,
    accepted_contract: &AcceptedContract,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    funding_signatures: &FundingSignatures,
    buffer_adaptor_signature: &EcdsaAdaptorSignature,
    signer: S,
) -> Result<(SignedChannel, SignedContract), Error>
where
    S::Target: Signer,
{
    let own_publish_pk = derive_bitcoin_public_key(
        secp,
        &accepted_channel.accept_per_update_point,
        &accepted_channel.accept_base_points.publish_basepoint,
    )?;

    let counter_own_pk = derive_bitcoin_public_key(
        secp,
        &accepted_channel.offer_per_update_point,
        &accepted_channel.offer_base_points.own_basepoint,
    )?;
    verify_tx_adaptor_signature(
        secp,
        &accepted_channel.buffer_transaction,
        accepted_contract.dlc_transactions.get_fund_output().value,
        &accepted_contract.dlc_transactions.funding_script_pubkey,
        &accepted_contract.offered_contract.offer_params.fund_pubkey,
        &own_publish_pk.key,
        buffer_adaptor_signature,
    )?;
    let (signed_contract, fund_tx) = verify_signed_contract(
        secp,
        accepted_contract,
        refund_signature,
        cet_adaptor_signatures,
        funding_signatures,
        accepted_channel.buffer_transaction.output[0].value,
        Some(accepted_channel.buffer_script_pubkey.clone()),
        Some(counter_own_pk.key),
        signer,
        Some(accepted_channel.channel_id),
    )?;

    let signed_channel = SignedChannel {
        counter_party: signed_contract
            .accepted_contract
            .offered_contract
            .counter_party,
        channel_id: accepted_channel.channel_id,
        temporary_channel_id: accepted_channel.temporary_channel_id,
        own_points: accepted_channel.accept_base_points.clone(),
        counter_points: accepted_channel.offer_base_points.clone(),
        counter_per_update_point: accepted_channel.offer_per_update_point,
        counter_params: accepted_contract.offered_contract.offer_params.clone(),
        fund_output_index: accepted_contract.dlc_transactions.get_fund_output_index(),
        own_params: accepted_contract.accept_params.clone(),
        own_per_update_point: accepted_channel.accept_per_update_point,
        state: SignedChannelState::Established {
            signed_contract_id: signed_contract.accepted_contract.get_contract_id(),
            own_buffer_adaptor_signature: accepted_channel.accept_buffer_adaptor_signature,
            counter_buffer_adaptor_signature: *buffer_adaptor_signature,
            buffer_transaction: accepted_channel.buffer_transaction.clone(),
            is_offer: false,
        },
        update_idx: INITIAL_UPDATE_NUMBER,
        fund_tx,
        fund_script_pubkey: accepted_contract
            .dlc_transactions
            .funding_script_pubkey
            .clone(),
        roll_back_state: None,
        own_per_update_seed: accepted_channel.accept_per_update_seed,
        counter_party_commitment_secrets: CounterpartyCommitmentSecrets::new(),
        fee_rate_per_vb: signed_contract
            .accepted_contract
            .offered_contract
            .fee_rate_per_vb,
    };

    Ok((signed_channel, signed_contract))
}

///
pub fn settle_channel_offer<C: Signing>(
    secp: &Secp256k1<C>,
    channel: &mut SignedChannel,
    counter_payout: u64,
    per_update_seed: &SecretKey,
) -> Result<SettleChannelOffer, Error> {
    if let SignedChannelState::Established { .. } = channel.state {
    } else {
        return Err(Error::InvalidState(
            "Signed channel was not in Established state as expected.".to_string(),
        ));
    }

    let per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        channel.update_idx - 1,
    ))
    .expect("a valid secret key.");

    let next_per_update_point = PublicKey::from_secret_key(secp, &per_update_secret);

    let mut state = SignedChannelState::SettledOffered {
        counter_payout,
        next_per_update_point,
    };

    std::mem::swap(&mut channel.state, &mut state);

    channel.roll_back_state = Some(state);

    let settle_channel_offer = SettleChannelOffer {
        channel_id: channel.channel_id,
        counter_payout,
        next_per_update_point,
    };

    Ok(settle_channel_offer)
}

///
pub fn settle_channel_accept(
    secp: &Secp256k1<All>,
    channel: &mut SignedChannel,
    own_fund_sk: &SecretKey,
    per_update_seed: &SecretKey,
    csv_timelock: u32,
    lock_time: u32,
) -> Result<SettleChannelAccept, Error> {
    let (own_payout, counter_next_per_update_point) = if let SignedChannelState::SettledReceived {
        own_payout,
        counter_next_per_update_point,
    } = channel.state
    {
        (own_payout, counter_next_per_update_point)
    } else {
        return Err(Error::InvalidState(
            "Signed channel was not in SettledReceived state as expected.".to_string(),
        ));
    };
    let per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        channel.update_idx - 1,
    ))
    .expect("a valid secret key.");

    let own_next_per_update_point = PublicKey::from_secret_key(secp, &per_update_secret);

    let total_collateral = channel.counter_params.collateral + channel.own_params.collateral;
    //Todo(tibo): compute fee for settle transaction.
    let fee_remainder = 0; //channel.fund_tx.output[channel.fund_output_index].value - total_collateral;
    let final_offer_payout = total_collateral - own_payout + fee_remainder / 2;
    let final_accept_payout = own_payout + fee_remainder / 2;

    let fund_tx = &channel.fund_tx;
    let fund_vout = channel.fund_output_index;
    let funding_script_pubkey = &channel.fund_script_pubkey;

    let (settle_tx, settle_adaptor_signature) = get_settle_tx_and_adaptor_sig(
        secp,
        &own_next_per_update_point,
        fund_tx,
        fund_vout,
        funding_script_pubkey,
        own_fund_sk,
        &channel.counter_points,
        &channel.own_points,
        &counter_next_per_update_point,
        final_offer_payout,
        final_accept_payout,
        csv_timelock,
        lock_time,
        None,
    )?;

    channel.state = SignedChannelState::SettledAccepted {
        counter_next_per_update_point,
        own_next_per_update_point,
        settle_tx,
        own_settle_adaptor_signature: settle_adaptor_signature,
    };

    let msg = SettleChannelAccept {
        channel_id: channel.channel_id,
        next_per_update_point: own_next_per_update_point,
        settle_adaptor_signature,
    };

    Ok(msg)
}

///
pub fn settle_channel_confirm(
    secp: &Secp256k1<All>,
    channel: &mut SignedChannel,
    settle_channel_accept: &SettleChannelAccept,
    own_fund_sk: &SecretKey,
    per_update_seed: &SecretKey,
    csv_timelock: u32,
    lock_time: u32,
) -> Result<SettleChannelConfirm, Error> {
    let (counter_payout, next_per_update_point) = match channel.state {
        SignedChannelState::SettledOffered {
            counter_payout,
            next_per_update_point,
        } => (counter_payout, next_per_update_point),
        _ => {
            return Err(Error::InvalidState(
                "Signed channel was not in SettledOffered state as expected.".to_string(),
            ))
        }
    };

    let total_collateral = channel.counter_params.collateral + channel.own_params.collateral;
    //Todo(tibo): compute fee for settle transaction.
    let fee_remainder = 0; //channel.fund_tx.output[channel.fund_output_index].value - total_collateral;
    let final_offer_payout = total_collateral - counter_payout + fee_remainder / 2;
    let final_accept_payout = counter_payout + fee_remainder / 2;

    let fund_tx = &channel.fund_tx;
    let fund_vout = channel.fund_output_index;
    let funding_script_pubkey = &channel.fund_script_pubkey;

    let (settle_tx, settle_adaptor_signature) = get_settle_tx_and_adaptor_sig(
        secp,
        &next_per_update_point,
        fund_tx,
        fund_vout,
        funding_script_pubkey,
        own_fund_sk,
        &channel.own_points,
        &channel.counter_points,
        &settle_channel_accept.next_per_update_point,
        final_offer_payout,
        final_accept_payout,
        csv_timelock,
        lock_time,
        Some((
            &settle_channel_accept.settle_adaptor_signature,
            channel.counter_params.fund_pubkey,
        )),
    )?;

    let prev_per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        channel.update_idx,
    ))?;

    println!(
        "Giving prev per update secret 2: {:?}",
        prev_per_update_secret
    );

    let state = SignedChannelState::SettledConfirmed {
        settle_tx,
        counter_settle_adaptor_signature: settle_channel_accept.settle_adaptor_signature,
        own_next_per_update_point: next_per_update_point,
        counter_next_per_update_point: settle_channel_accept.next_per_update_point,
        own_settle_adaptor_signature: settle_adaptor_signature,
    };

    channel.state = state;

    let msg = SettleChannelConfirm {
        channel_id: channel.channel_id,
        prev_per_update_secret,
        settle_adaptor_signature,
    };

    Ok(msg)
}

///
pub fn settle_channel_finalize(
    secp: &Secp256k1<All>,
    channel: &mut SignedChannel,
    settle_channel_confirm: &SettleChannelConfirm,
    per_update_seed: &SecretKey,
) -> Result<SettleChannelFinalize, Error> {
    let (
        own_next_per_update_point,
        counter_next_per_update_point,
        settle_tx,
        own_settle_adaptor_signature,
    ) = match &channel.state {
        SignedChannelState::SettledAccepted {
            counter_next_per_update_point,
            own_next_per_update_point,
            settle_tx,
            own_settle_adaptor_signature,
        } => (
            own_next_per_update_point,
            counter_next_per_update_point,
            settle_tx,
            own_settle_adaptor_signature,
        ),
        _ => {
            return Err(Error::InvalidState(
                "Signed channel was not in SettledAccepted state as expected.".to_string(),
            ))
        }
    };

    let accept_revoke_params = channel.own_points.get_revokable_params(
        secp,
        &channel.counter_points.revocation_basepoint,
        own_next_per_update_point,
    )?;

    verify_tx_adaptor_signature(
        secp,
        settle_tx,
        channel.fund_tx.output[channel.fund_output_index].value,
        &channel.fund_script_pubkey,
        &channel.counter_params.fund_pubkey,
        &accept_revoke_params.publish_pk.key,
        &settle_channel_confirm.settle_adaptor_signature,
    )?;

    if PublicKey::from_secret_key(secp, &settle_channel_confirm.prev_per_update_secret)
        != channel.counter_per_update_point
    {
        return Err(Error::InvalidParameters(
            "Invalid per update secret in channel confirm".to_string(),
        ));
    }

    channel
        .counter_party_commitment_secrets
        .provide_secret(
            channel.update_idx,
            *settle_channel_confirm.prev_per_update_secret.as_ref(),
        )
        .map_err(|_| {
            Error::InvalidParameters("Received per update secret is invalid".to_string())
        })?;

    let prev_per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        channel.update_idx,
    ))?;

    println!(
        "Giving prev per update secret: {:?}",
        prev_per_update_secret
    );

    let state = SignedChannelState::Settled {
        settle_tx: settle_tx.clone(),
        counter_settle_adaptor_signature: settle_channel_confirm.settle_adaptor_signature,
        own_settle_adaptor_signature: *own_settle_adaptor_signature,
    };

    channel.own_per_update_point = *own_next_per_update_point;
    channel.counter_per_update_point = *counter_next_per_update_point;
    channel.state = state;
    channel.roll_back_state = None;
    channel.update_idx -= 1;

    let msg = SettleChannelFinalize {
        channel_id: channel.channel_id,
        prev_per_update_secret,
    };

    Ok(msg)
}

///
pub fn settle_channel_on_finalize<C: Signing>(
    secp: &Secp256k1<C>,
    channel: &mut SignedChannel,
    settle_channel_finalize: &SettleChannelFinalize,
) -> Result<(), Error> {
    let (
        settle_tx,
        counter_settle_adaptor_signature,
        counter_next_per_update_point,
        own_next_per_update_point,
        own_settle_adaptor_signature,
    ) = match &channel.state {
        SignedChannelState::SettledConfirmed {
            settle_tx,
            counter_settle_adaptor_signature,
            counter_next_per_update_point,
            own_next_per_update_point,
            own_settle_adaptor_signature,
        } => (
            settle_tx.clone(),
            *counter_settle_adaptor_signature,
            *counter_next_per_update_point,
            *own_next_per_update_point,
            *own_settle_adaptor_signature,
        ),
        _ => {
            return Err(Error::InvalidState(
                "Signed channel was not in SettledConfirmed state as expected.".to_string(),
            ))
        }
    };

    if PublicKey::from_secret_key(secp, &settle_channel_finalize.prev_per_update_secret)
        != channel.counter_per_update_point
    {
        return Err(Error::InvalidParameters(
            "Invalid per update secret in channel finalize".to_string(),
        ));
    }

    channel
        .counter_party_commitment_secrets
        .provide_secret(
            channel.update_idx,
            *settle_channel_finalize.prev_per_update_secret.as_ref(),
        )
        .map_err(|_| {
            Error::InvalidParameters("Received per update secret is invalid".to_string())
        })?;

    channel.state = SignedChannelState::Settled {
        settle_tx,
        counter_settle_adaptor_signature,
        own_settle_adaptor_signature,
    };

    channel.own_per_update_point = own_next_per_update_point;
    channel.counter_per_update_point = counter_next_per_update_point;
    channel.update_idx -= 1;

    Ok(())
}

fn get_settle_tx_and_adaptor_sig(
    secp: &Secp256k1<All>,
    own_next_per_update_point: &PublicKey,
    fund_tx: &Transaction,
    fund_vout: usize,
    funding_script_pubkey: &Script,
    own_fund_sk: &SecretKey,
    offer_points: &PartyBasePoints,
    accept_points: &PartyBasePoints,
    counter_per_update_point: &PublicKey,
    offer_payout: u64,
    accept_payout: u64,
    csv_timelock: u32,
    lock_time: u32,
    counter_adaptor_signature: Option<(&EcdsaAdaptorSignature, PublicKey)>,
) -> Result<(Transaction, EcdsaAdaptorSignature), Error> {
    let is_offer = counter_adaptor_signature.is_some();
    let (offer_per_update_point, accept_per_update_point) = if is_offer {
        (own_next_per_update_point, counter_per_update_point)
    } else {
        (counter_per_update_point, own_next_per_update_point)
    };

    let fund_tx_in = TxIn {
        previous_output: bitcoin::OutPoint {
            txid: fund_tx.txid(),
            vout: fund_vout as u32,
        },
        script_sig: Script::new(),
        sequence: 0xffffffff,
        witness: vec![],
    };

    let offer_revoke_params = offer_points.get_revokable_params(
        secp,
        &accept_points.revocation_basepoint,
        offer_per_update_point,
    )?;

    let accept_revoke_params = accept_points.get_revokable_params(
        secp,
        &offer_points.revocation_basepoint,
        accept_per_update_point,
    )?;

    let settle_tx = dlc::channel::create_settle_transaction(
        &fund_tx_in,
        &offer_revoke_params,
        &accept_revoke_params,
        offer_payout,
        accept_payout,
        csv_timelock,
        lock_time,
    );

    if let Some((adaptor_sig, fund_pk)) = counter_adaptor_signature {
        verify_tx_adaptor_signature(
            secp,
            &settle_tx,
            fund_tx.output[fund_vout].value,
            funding_script_pubkey,
            &fund_pk,
            &offer_revoke_params.publish_pk.key,
            adaptor_sig,
        )?;
    }

    let counter_pk = if is_offer {
        accept_revoke_params.publish_pk.key
    } else {
        offer_revoke_params.publish_pk.key
    };

    println!("Encrypting with pubkey: {:?}", counter_pk);

    let settle_adaptor_signature = dlc::channel::get_tx_adaptor_signature(
        secp,
        &settle_tx,
        fund_tx.output[fund_vout].value,
        funding_script_pubkey,
        own_fund_sk,
        &counter_pk,
    );

    Ok((settle_tx, settle_adaptor_signature))
}

///
pub fn accept_channel_renewal(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    offered_contract: &OfferedContract,
    offer_per_update_point: &PublicKey,
    own_fund_sk: &SecretKey,
    own_base_secret_key: &SecretKey,
    per_update_seed: &SecretKey,
    cet_nsequence: u32,
) -> Result<
    (
        AcceptedContract,
        EcdsaAdaptorSignature,
        Vec<EcdsaAdaptorSignature>,
        PublicKey,
    ),
    Error,
> {
    // assert_eq!(signed_channel.offered_contract_id, offered_contract.id);

    let total_collateral = offered_contract.total_collateral;

    let offer_revoke_params = signed_channel.counter_points.get_revokable_params(
        secp,
        &signed_channel.own_points.revocation_basepoint,
        offer_per_update_point,
    )?;

    let accept_per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        signed_channel.update_idx - 1,
    ))?;

    let accept_per_update_point = PublicKey::from_secret_key(secp, &accept_per_update_secret);

    let accept_revoke_params = signed_channel.own_points.get_revokable_params(
        secp,
        &signed_channel.counter_points.revocation_basepoint,
        &accept_per_update_point,
    )?;

    let DlcChannelTransactions {
        buffer_transaction,
        buffer_script_pubkey,
        dlc_transactions,
    } = dlc::channel::create_renewal_channel_transactions(
        &offered_contract.offer_params,
        &signed_channel.own_params,
        &offer_revoke_params,
        &accept_revoke_params,
        &signed_channel.fund_tx,
        &signed_channel.fund_script_pubkey,
        &offered_contract.contract_info[0].get_payouts(total_collateral)?,
        offered_contract.contract_timeout,
        offered_contract.fee_rate_per_vb,
        0,
        cet_nsequence,
    )?;

    println!("Encrypting with {:?}", offer_revoke_params.publish_pk.key);

    let buffer_adaptor_signature = get_tx_adaptor_signature(
        secp,
        &buffer_transaction,
        dlc_transactions.get_fund_output().value,
        &dlc_transactions.funding_script_pubkey,
        own_fund_sk,
        &offer_revoke_params.publish_pk.key,
    );

    let own_secret_key = derive_private_key(secp, &accept_per_update_point, own_base_secret_key)
        .expect("to get a valid secret.");

    let (accepted_contract, adaptor_sigs) = accept_contract_internal(
        secp,
        offered_contract,
        &signed_channel.own_params,
        &[],
        &own_secret_key,
        buffer_transaction.output[0].value,
        Some(buffer_script_pubkey.clone()),
        &dlc_transactions,
    )?;

    let state = SignedChannelState::RenewAccepted {
        contract_id: accepted_contract.get_contract_id(),
        offer_per_update_point: *offer_per_update_point,
        accept_per_update_point,
        buffer_transaction,
        buffer_script_pubkey,
        accept_buffer_adaptor_signature: buffer_adaptor_signature,
    };

    signed_channel.state = state;

    Ok((
        accepted_contract,
        buffer_adaptor_signature,
        adaptor_sigs,
        accept_per_update_point,
    ))
}

///
pub fn verify_renew_accept<S: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    offered_contract: &OfferedContract,
    offer_per_update_point: &PublicKey,
    accept_per_update_point: &PublicKey,
    offer_fund_sk: &SecretKey,
    offer_base_secret_key: &SecretKey,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    buffer_adaptor_signature: &EcdsaAdaptorSignature,
    cet_nsequence: u32,
    wallet: S,
) -> Result<
    (
        SignedContract,
        Vec<EcdsaAdaptorSignature>,
        EcdsaAdaptorSignature,
    ),
    Error,
>
where
    S::Target: Signer,
{
    let offer_revoke_params = signed_channel.own_points.get_revokable_params(
        secp,
        &signed_channel.counter_points.revocation_basepoint,
        offer_per_update_point,
    )?;
    let accept_revoke_params = signed_channel.counter_points.get_revokable_params(
        secp,
        &signed_channel.own_points.revocation_basepoint,
        accept_per_update_point,
    )?;

    let total_collateral = offered_contract.total_collateral;

    let DlcChannelTransactions {
        buffer_transaction,
        dlc_transactions,
        buffer_script_pubkey,
    } = dlc::channel::create_renewal_channel_transactions(
        &offered_contract.offer_params,
        &signed_channel.counter_params,
        &offer_revoke_params,
        &accept_revoke_params,
        &signed_channel.fund_tx,
        &signed_channel.fund_script_pubkey,
        &offered_contract.contract_info[0].get_payouts(total_collateral)?,
        offered_contract.contract_timeout,
        offered_contract.fee_rate_per_vb,
        0,
        cet_nsequence,
    )?;

    let offer_own_sk = derive_private_key(secp, offer_per_update_point, offer_base_secret_key)?;

    let (signed_contract, cet_adaptor_signatures) = verify_accepted_and_sign_contract_internal(
        secp,
        offered_contract,
        &signed_channel.counter_params,
        &[],
        refund_signature,
        cet_adaptor_signatures,
        buffer_transaction.output[0].value,
        &offer_own_sk,
        wallet,
        Some(buffer_script_pubkey.clone()),
        Some(accept_revoke_params.own_pk.key),
        &dlc_transactions,
        Some(signed_channel.channel_id),
    )?;

    verify_tx_adaptor_signature(
        secp,
        &buffer_transaction,
        dlc_transactions.get_fund_output().value,
        &dlc_transactions.funding_script_pubkey,
        &signed_contract.accepted_contract.accept_params.fund_pubkey,
        &offer_revoke_params.publish_pk.key,
        buffer_adaptor_signature,
    )?;

    println!("Encrypting with {:?}", accept_revoke_params.publish_pk.key);

    let own_buffer_adaptor_signature = get_tx_adaptor_signature(
        secp,
        &buffer_transaction,
        dlc_transactions.get_fund_output().value,
        &dlc_transactions.funding_script_pubkey,
        offer_fund_sk,
        &accept_revoke_params.publish_pk.key,
    );

    let state = SignedChannelState::RenewConfirmed {
        contract_id: signed_contract.accepted_contract.get_contract_id(),
        offer_per_update_point: *offer_per_update_point,
        accept_per_update_point: *accept_per_update_point,
        buffer_transaction,
        buffer_script_pubkey,
        offer_buffer_adaptor_signature: own_buffer_adaptor_signature,
        accept_buffer_adaptor_signature: *buffer_adaptor_signature,
    };

    signed_channel.state = state;

    Ok((
        signed_contract,
        cet_adaptor_signatures,
        own_buffer_adaptor_signature,
    ))
}

///
pub fn verify_renew_confirm<S: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    accepted_contract: &AcceptedContract,
    refund_signature: &Signature,
    cet_adaptor_signatures: &[EcdsaAdaptorSignature],
    buffer_adaptor_signature: &EcdsaAdaptorSignature,
    signer: S,
) -> Result<SignedContract, Error>
where
    S::Target: Signer,
{
    let (
        offer_per_update_point,
        accept_per_update_point,
        buffer_transaction,
        buffer_script_pubkey,
        accept_buffer_adaptor_signature,
    ) = match &signed_channel.state {
        SignedChannelState::RenewAccepted {
            offer_per_update_point,
            accept_per_update_point,
            buffer_transaction,
            buffer_script_pubkey,
            accept_buffer_adaptor_signature,
            ..
        } => (
            offer_per_update_point,
            accept_per_update_point,
            buffer_transaction,
            buffer_script_pubkey,
            accept_buffer_adaptor_signature,
        ),
        _ => {
            return Err(Error::InvalidState(
                "Signed channel was not in RenewAccepted state as expected.".to_string(),
            ))
        }
    };
    let own_publish_pk = derive_bitcoin_public_key(
        secp,
        accept_per_update_point,
        &signed_channel.own_points.publish_basepoint,
    )?;

    let counter_own_pk = derive_bitcoin_public_key(
        secp,
        offer_per_update_point,
        &signed_channel.counter_points.own_basepoint,
    )?;
    verify_tx_adaptor_signature(
        secp,
        buffer_transaction,
        accepted_contract.dlc_transactions.get_fund_output().value,
        &accepted_contract.dlc_transactions.funding_script_pubkey,
        &accepted_contract.offered_contract.offer_params.fund_pubkey,
        &own_publish_pk.key,
        buffer_adaptor_signature,
    )?;
    let (signed_contract, _) = verify_signed_contract(
        secp,
        accepted_contract,
        refund_signature,
        cet_adaptor_signatures,
        &FundingSignatures {
            funding_signatures: Vec::new(),
        },
        buffer_transaction.output[0].value,
        Some(buffer_script_pubkey.clone()),
        Some(counter_own_pk.key),
        signer,
        Some(signed_channel.channel_id),
    )?;

    signed_channel.state = SignedChannelState::Established {
        signed_contract_id: signed_contract.accepted_contract.get_contract_id(),
        own_buffer_adaptor_signature: *accept_buffer_adaptor_signature,
        counter_buffer_adaptor_signature: *buffer_adaptor_signature,
        buffer_transaction: buffer_transaction.clone(),
        is_offer: false,
    };

    signed_channel.update_idx -= 1;

    Ok(signed_contract)
}
