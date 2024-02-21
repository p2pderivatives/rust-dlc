//! # This module contains static functions to update the state of a DLC channel.

use std::{ops::Deref, sync::Mutex};

use crate::{
    chain_monitor::{ChainMonitor, ChannelInfo, TxType},
    channel::{
        accepted_channel::AcceptedChannel,
        offered_channel::OfferedChannel,
        party_points::PartyBasePoints,
        signed_channel::{SignedChannel, SignedChannelState},
        Channel, ClosedChannel,
    },
    contract::{
        accepted_contract::AcceptedContract, contract_info::ContractInfo,
        contract_input::ContractInput, offered_contract::OfferedContract,
        signed_contract::SignedContract, AdaptorInfo,
    },
    contract_updater::{
        accept_contract_internal, verify_accepted_and_sign_contract_internal,
        verify_signed_contract_internal,
    },
    error::Error,
    subchannel::{ClosingSubChannel, SubChannel},
    Blockchain, ContractId, DlcChannelId, Signer, Time, Wallet,
};
use bitcoin::{OutPoint, Script, Sequence, Transaction};
use dlc::{
    channel::{get_tx_adaptor_signature, verify_tx_adaptor_signature, DlcChannelTransactions},
    PartyParams,
};
use dlc_messages::{
    channel::{
        AcceptChannel, CollaborativeCloseOffer, Reject, RenewAccept, RenewConfirm, RenewFinalize,
        RenewOffer, RenewRevoke, SettleAccept, SettleConfirm, SettleFinalize, SettleOffer,
        SignChannel,
    },
    oracle_msgs::{OracleAnnouncement, OracleAttestation},
    FundingSignatures,
};
use lightning::ln::{
    chan_utils::{build_commitment_secret, derive_private_key, CounterpartyCommitmentSecrets},
    ChannelId,
};
use secp256k1_zkp::{All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey, Signing};

const INITIAL_UPDATE_NUMBER: u64 = (1 << 48) - 1;

macro_rules! get_signed_channel_state {
    ($signed_channel: ident, $state: ident, ref $field: ident) => {{
       match &$signed_channel.state {
           SignedChannelState::$state{ref $field, ..} => Ok($field),
           _ => Err(Error::InvalidState(format!("Expected state {} got {:?}", stringify!($state), $signed_channel.state))),
        }
    }};
    ($signed_channel: ident, $state: ident, $field: ident) => {{
       match &$signed_channel.state {
           SignedChannelState::$state{$field, ..} => Ok($field),
           _ => Err(Error::InvalidState(format!("Expected state {} got {:?}", stringify!($state), $signed_channel.state))),
        }
    }};
    ($signed_channel: ident, $state: ident, $($field: ident),* $(|$($ref_field: ident),*)?) => {{
       match &$signed_channel.state {
           SignedChannelState::$state{$($field,)* $($(ref $ref_field,)*)? ..} => Ok(($($field,)* $($($ref_field,)*)?)),
           _ => Err(Error::InvalidState(format!("Expected state {} got {:?}", stringify!($state), $signed_channel.state))),
        }
    }};
}
pub(crate) use get_signed_channel_state;

/// Information about the funding input of a sub channel.
pub struct FundingInfo {
    /// The funding transaction for the sub channel.
    pub funding_tx: Transaction,
    /// The script pubkey of the funding output.
    pub funding_script_pubkey: Script,
    /// The value of the funding output.
    pub funding_input_value: u64,
}

pub(crate) struct SubChannelSignVerifyInfo {
    pub funding_info: FundingInfo,
    pub own_adaptor_sk: SecretKey,
    pub counter_adaptor_pk: PublicKey,
    pub sub_channel_id: ChannelId,
}

pub(crate) struct SubChannelSignInfo {
    pub funding_info: FundingInfo,
    pub own_adaptor_sk: SecretKey,
}

pub(crate) struct SubChannelVerifyInfo {
    pub funding_info: FundingInfo,
    pub counter_adaptor_pk: PublicKey,
    pub sub_channel_id: ChannelId,
}

/// Creates an [`OfferedChannel`] and an associated [`OfferedContract`] using
/// the given parameter.
pub fn offer_channel<C: Signing, W: Deref, B: Deref, T: Deref>(
    secp: &Secp256k1<C>,
    contract: &ContractInput,
    counter_party: &PublicKey,
    oracle_announcements: &[Vec<OracleAnnouncement>],
    cet_nsequence: u32,
    refund_delay: u32,
    wallet: &W,
    blockchain: &B,
    time: &T,
    temporary_channel_id: DlcChannelId,
    is_sub_channel: bool,
) -> Result<(OfferedChannel, OfferedContract), Error>
where
    W::Target: Wallet,
    B::Target: Blockchain,
    T::Target: Time,
{
    let (offer_params, _, funding_inputs_info) = crate::utils::get_party_params(
        secp,
        contract.offer_collateral,
        contract.fee_rate,
        wallet,
        blockchain,
        !is_sub_channel,
    )?;
    let party_points = crate::utils::get_party_base_points(secp, wallet)?;

    let temporary_contract_id =
        crate::channel::generate_temporary_contract_id(temporary_channel_id, INITIAL_UPDATE_NUMBER);

    let offered_contract = OfferedContract::new(
        contract,
        oracle_announcements.to_vec(),
        &offer_params,
        &funding_inputs_info,
        counter_party,
        refund_delay,
        time.unix_time_now() as u32,
        temporary_contract_id,
    );

    let per_update_seed = wallet.get_new_secret_key()?;

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
        party_points,
        temporary_channel_id,
        per_update_point: first_per_update_point,
        offer_per_update_seed: Some(PublicKey::from_secret_key(secp, &per_update_seed)),
        is_offer_party: true,
        counter_party: *counter_party,
        cet_nsequence,
    };

    Ok((offered_channel, offered_contract))
}

/// Move the given [`OfferedChannel`] and [`OfferedContract`] to an [`AcceptedChannel`]
/// and [`AcceptedContract`], returning them as well as the [`AcceptChannel`]
/// message to be sent to the counter party.
pub fn accept_channel_offer<W: Deref, B: Deref>(
    secp: &Secp256k1<All>,
    offered_channel: &OfferedChannel,
    offered_contract: &OfferedContract,
    wallet: &W,
    blockchain: &B,
) -> Result<(AcceptedChannel, AcceptedContract, AcceptChannel), Error>
where
    W::Target: Wallet,
    B::Target: Blockchain,
{
    accept_channel_offer_internal(
        secp,
        offered_channel,
        offered_contract,
        wallet,
        blockchain,
        None,
        None,
    )
}

pub(crate) fn accept_channel_offer_internal<W: Deref, B: Deref>(
    secp: &Secp256k1<All>,
    offered_channel: &OfferedChannel,
    offered_contract: &OfferedContract,
    wallet: &W,
    blockchain: &B,
    sub_channel_info: Option<SubChannelSignInfo>,
    params: Option<(
        PartyParams,
        Vec<crate::contract::FundingInputInfo>,
        PartyBasePoints,
        PublicKey,
    )>,
) -> Result<(AcceptedChannel, AcceptedContract, AcceptChannel), Error>
where
    W::Target: Wallet,
    B::Target: Blockchain,
{
    assert_eq!(offered_channel.offered_contract_id, offered_contract.id);

    let (accept_params, funding_inputs, accept_points, per_update_seed) =
        if let Some((params, funding_inputs_info, accept_points, per_update_seed_pk)) = params {
            let per_update_seed = wallet.get_secret_key_for_pubkey(&per_update_seed_pk)?;
            (params, funding_inputs_info, accept_points, per_update_seed)
        } else {
            let (params, _, funding_input_infos) = crate::utils::get_party_params(
                secp,
                offered_contract.total_collateral - offered_contract.offer_params.collateral,
                offered_contract.fee_rate_per_vb,
                wallet,
                blockchain,
                sub_channel_info.is_none(),
            )?;
            let accept_points = crate::utils::get_party_base_points(secp, wallet)?;
            let per_update_seed = wallet.get_new_secret_key()?;
            (params, funding_input_infos, accept_points, per_update_seed)
        };

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
    );

    let total_collateral = offered_contract.total_collateral;

    let offer_revoke_params = offered_channel.party_points.get_revokable_params(
        secp,
        &accept_points.revocation_basepoint,
        &offered_channel.per_update_point,
    );

    let (
        DlcChannelTransactions {
            buffer_transaction,
            dlc_transactions,
            buffer_script_pubkey,
        },
        own_buffer_adaptor_sk,
        buffer_input_value,
        buffer_input_spk,
        funding_vout,
    ) = if let Some(sub_channel_info) = sub_channel_info {
        let SubChannelSignInfo {
            funding_info,
            own_adaptor_sk,
        } = sub_channel_info;
        let txs = dlc::channel::create_renewal_channel_transactions(
            &offered_contract.offer_params,
            &accept_params,
            &offer_revoke_params,
            &accept_revoke_params,
            &funding_info.funding_tx,
            &funding_info.funding_script_pubkey,
            &offered_contract.contract_info[0].get_payouts(total_collateral)?,
            offered_contract.refund_locktime,
            offered_contract.fee_rate_per_vb,
            offered_contract.cet_locktime,
            Sequence(crate::manager::CET_NSEQUENCE),
            Some(1),
            Some(Sequence(crate::manager::CET_NSEQUENCE)),
        )?;
        (
            txs,
            own_adaptor_sk,
            funding_info.funding_input_value,
            funding_info.funding_script_pubkey,
            1,
        )
    } else {
        let txs = dlc::channel::create_channel_transactions(
            &offered_contract.offer_params,
            &accept_params,
            &offer_revoke_params,
            &accept_revoke_params,
            &offered_contract.contract_info[0].get_payouts(total_collateral)?,
            offered_contract.refund_locktime,
            offered_contract.fee_rate_per_vb,
            0,
            offered_contract.cet_locktime,
            offered_contract.fund_output_serial_id,
            Sequence(offered_channel.cet_nsequence),
        )?;
        let accept_fund_sk = wallet.get_secret_key_for_pubkey(&accept_params.fund_pubkey)?;
        let funding_output_value = txs.dlc_transactions.get_fund_output().value;
        let funding_vout = txs.dlc_transactions.get_fund_output_index();
        let funding_spk = txs.dlc_transactions.funding_script_pubkey.clone();
        (
            txs,
            accept_fund_sk,
            funding_output_value,
            funding_spk,
            funding_vout,
        )
    };

    let own_base_secret_key = wallet.get_secret_key_for_pubkey(&accept_points.own_basepoint)?;

    let own_secret_key = derive_private_key(secp, &first_per_update_point, &own_base_secret_key);

    let channel_id = crate::utils::compute_id(
        dlc_transactions.fund.txid(),
        funding_vout as u16,
        &offered_channel.temporary_channel_id,
    );

    let buffer_adaptor_signature = get_tx_adaptor_signature(
        secp,
        &buffer_transaction,
        buffer_input_value,
        &buffer_input_spk,
        &own_buffer_adaptor_sk,
        &offer_revoke_params.publish_pk.inner,
    )?;

    let (accepted_contract, adaptor_sigs) = accept_contract_internal(
        secp,
        offered_contract,
        &accept_params,
        &funding_inputs,
        &own_secret_key,
        buffer_transaction.output[0].value,
        Some(buffer_script_pubkey.clone()),
        &dlc_transactions,
    )?;

    let accepted_channel = AcceptedChannel {
        offer_base_points: offered_channel.party_points.clone(),
        accept_base_points: accept_points,
        accepted_contract_id: accepted_contract.get_contract_id(),
        buffer_transaction,
        buffer_script_pubkey,
        offer_per_update_point: offered_channel.per_update_point,
        accept_per_update_point: first_per_update_point,
        temporary_channel_id: offered_channel.temporary_channel_id,
        channel_id,
        accept_per_update_seed: PublicKey::from_secret_key(secp, &per_update_seed),
        counter_party: offered_contract.counter_party,
        accept_buffer_adaptor_signature: buffer_adaptor_signature,
    };

    let accept_channel = accepted_channel.get_accept_channel_msg(
        &accepted_contract,
        &buffer_adaptor_signature,
        &adaptor_sigs,
    );

    Ok((accepted_channel, accepted_contract, accept_channel))
}

/// Verify that the [`AcceptChannel`]  message is valid with respect
/// to the given [`OfferedChannel`] and [`OfferedContract`], transforming them
/// to a [`SignedChannel`] and [`SignedContract`], returning them as well as the
/// [`SignChannel`] to be sent to the counter party.
pub fn verify_and_sign_accepted_channel<S: Deref>(
    secp: &Secp256k1<All>,
    offered_channel: &OfferedChannel,
    offered_contract: &OfferedContract,
    accept_channel: &AcceptChannel,
    cet_nsequence: u32,
    signer: &S,
    chain_monitor: &Mutex<ChainMonitor>,
) -> Result<(SignedChannel, SignedContract, SignChannel), Error>
where
    S::Target: Signer,
{
    verify_and_sign_accepted_channel_internal(
        secp,
        offered_channel,
        offered_contract,
        accept_channel,
        cet_nsequence,
        signer,
        None,
        chain_monitor,
    )
}

pub(crate) fn verify_and_sign_accepted_channel_internal<S: Deref>(
    secp: &Secp256k1<All>,
    offered_channel: &OfferedChannel,
    offered_contract: &OfferedContract,
    accept_channel: &AcceptChannel,
    cet_nsequence: u32,
    signer: &S,
    sub_channel_info: Option<SubChannelSignVerifyInfo>,
    chain_monitor: &Mutex<ChainMonitor>,
) -> Result<(SignedChannel, SignedContract, SignChannel), Error>
where
    S::Target: Signer,
{
    let (tx_input_infos, input_amount) =
        crate::conversion_utils::get_tx_input_infos(&accept_channel.funding_inputs)?;

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

    let offer_own_base_secret =
        signer.get_secret_key_for_pubkey(&offered_channel.party_points.own_basepoint)?;

    let offer_own_sk = derive_private_key(
        secp,
        &offered_channel.per_update_point,
        &offer_own_base_secret,
    );

    let offer_revoke_params = offered_channel.party_points.get_revokable_params(
        secp,
        &accept_points.revocation_basepoint,
        &offered_channel.per_update_point,
    );

    let accept_revoke_params = accept_points.get_revokable_params(
        secp,
        &offered_channel.party_points.revocation_basepoint,
        &accept_channel.first_per_update_point,
    );

    let total_collateral = offered_contract.total_collateral;

    let (
        DlcChannelTransactions {
            buffer_transaction,
            dlc_transactions,
            buffer_script_pubkey,
        },
        own_buffer_adaptor_sk,
        counter_buffer_adaptor_pk,
        buffer_input_value,
        buffer_input_spk,
        is_sub_channel,
        sub_channel_id,
    ) = if let Some(sub_channel_info) = sub_channel_info {
        let SubChannelSignVerifyInfo {
            funding_info,
            own_adaptor_sk,
            counter_adaptor_pk,
            sub_channel_id,
        } = sub_channel_info;
        let txs = dlc::channel::create_renewal_channel_transactions(
            &offered_contract.offer_params,
            &accept_params,
            &offer_revoke_params,
            &accept_revoke_params,
            &funding_info.funding_tx,
            &funding_info.funding_script_pubkey,
            &offered_contract.contract_info[0].get_payouts(total_collateral)?,
            offered_contract.refund_locktime,
            offered_contract.fee_rate_per_vb,
            offered_contract.cet_locktime,
            Sequence(crate::manager::CET_NSEQUENCE),
            Some(1),
            Some(Sequence(crate::manager::CET_NSEQUENCE)),
        )?;
        (
            txs,
            own_adaptor_sk,
            counter_adaptor_pk,
            funding_info.funding_input_value,
            funding_info.funding_script_pubkey,
            true,
            Some(sub_channel_id),
        )
    } else {
        let txs = dlc::channel::create_channel_transactions(
            &offered_contract.offer_params,
            &accept_params,
            &offer_revoke_params,
            &accept_revoke_params,
            &offered_contract.contract_info[0].get_payouts(total_collateral)?,
            offered_contract.refund_locktime,
            offered_contract.fee_rate_per_vb,
            0,
            offered_contract.cet_locktime,
            offered_contract.fund_output_serial_id,
            Sequence(cet_nsequence),
        )?;
        let offer_fund_sk =
            signer.get_secret_key_for_pubkey(&offered_contract.offer_params.fund_pubkey)?;
        let counter_fund_pk = accept_params.fund_pubkey;
        let funding_output_value = txs.dlc_transactions.get_fund_output().value;
        let funding_spk = txs.dlc_transactions.funding_script_pubkey.clone();
        (
            txs,
            offer_fund_sk,
            counter_fund_pk,
            funding_output_value,
            funding_spk,
            false,
            None,
        )
    };

    let fund_output_index = if is_sub_channel {
        1
    } else {
        dlc_transactions.get_fund_output_index()
    };

    let channel_id = crate::utils::compute_id(
        dlc_transactions.fund.txid(),
        fund_output_index as u16,
        &offered_channel.temporary_channel_id,
    );

    let accept_cet_adaptor_signatures: Vec<_> = (&accept_channel.cet_adaptor_signatures).into();

    let (signed_contract, cet_adaptor_signatures) = verify_accepted_and_sign_contract_internal(
        secp,
        offered_contract,
        &accept_params,
        &accept_channel
            .funding_inputs
            .iter()
            .map(|x| x.into())
            .collect::<Vec<_>>(),
        &accept_channel.refund_signature,
        &accept_cet_adaptor_signatures,
        buffer_transaction.output[0].value,
        &offer_own_sk,
        signer,
        Some(buffer_script_pubkey),
        Some(accept_revoke_params.own_pk.inner),
        &dlc_transactions,
        Some(channel_id),
    )?;

    verify_tx_adaptor_signature(
        secp,
        &buffer_transaction,
        buffer_input_value,
        &dlc_transactions.funding_script_pubkey,
        &counter_buffer_adaptor_pk,
        &offer_revoke_params.publish_pk.inner,
        &accept_channel.buffer_adaptor_signature,
    )?;

    let own_buffer_adaptor_signature = get_tx_adaptor_signature(
        secp,
        &buffer_transaction,
        buffer_input_value,
        &buffer_input_spk,
        &own_buffer_adaptor_sk,
        &accept_revoke_params.publish_pk.inner,
    )?;

    chain_monitor.lock().unwrap().add_tx(
        buffer_transaction.txid(),
        ChannelInfo {
            channel_id,
            tx_type: TxType::BufferTx,
        },
    );

    let signed_channel = SignedChannel {
        counter_party: signed_contract
            .accepted_contract
            .offered_contract
            .counter_party,
        own_points: offered_channel.party_points.clone(),
        counter_points: accept_points,
        counter_params: signed_contract.accepted_contract.accept_params.clone(),
        counter_per_update_point: accept_channel.first_per_update_point,
        state: SignedChannelState::Established {
            signed_contract_id: signed_contract.accepted_contract.get_contract_id(),
            own_buffer_adaptor_signature,
            counter_buffer_adaptor_signature: accept_channel.buffer_adaptor_signature,
            buffer_transaction,
            is_offer: true,
            total_collateral,
        },
        update_idx: INITIAL_UPDATE_NUMBER,
        channel_id,
        temporary_channel_id: offered_channel.temporary_channel_id,
        roll_back_state: None,
        fund_tx: dlc_transactions.fund.clone(),
        fund_script_pubkey: dlc_transactions.funding_script_pubkey,
        fund_output_index,
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
        sub_channel_id,
    };

    let sign_channel = SignChannel {
        channel_id,
        cet_adaptor_signatures: (&cet_adaptor_signatures as &[_]).into(),
        buffer_adaptor_signature: own_buffer_adaptor_signature,
        refund_signature: signed_contract.offer_refund_signature,
        funding_signatures: signed_contract.funding_signatures.clone(),
    };

    Ok((signed_channel, signed_contract, sign_channel))
}

/// Verify that the given [`SignChannel`] message is valid with respect to the
/// given [`AcceptedChannel`] and [`AcceptedContract`], transforming them
/// to a [`SignedChannel`] and [`SignedContract`], and returning them.
pub fn verify_signed_channel<S: Deref>(
    secp: &Secp256k1<All>,
    accepted_channel: &AcceptedChannel,
    accepted_contract: &AcceptedContract,
    sign_channel: &SignChannel,
    signer: &S,
    chain_monitor: &Mutex<ChainMonitor>,
) -> Result<(SignedChannel, SignedContract, Transaction), Error>
where
    S::Target: Signer,
{
    verify_signed_channel_internal(
        secp,
        accepted_channel,
        accepted_contract,
        sign_channel,
        signer,
        None,
        chain_monitor,
    )
}

pub(crate) fn verify_signed_channel_internal<S: Deref>(
    secp: &Secp256k1<All>,
    accepted_channel: &AcceptedChannel,
    accepted_contract: &AcceptedContract,
    sign_channel: &SignChannel,
    signer: &S,
    sub_channel_info: Option<SubChannelVerifyInfo>,
    chain_monitor: &Mutex<ChainMonitor>,
) -> Result<(SignedChannel, SignedContract, Transaction), Error>
where
    S::Target: Signer,
{
    let own_publish_pk = accepted_channel
        .accept_base_points
        .get_publish_pk(secp, &accepted_channel.accept_per_update_point);

    let counter_own_pk = accepted_channel
        .offer_base_points
        .get_own_pk(secp, &accepted_channel.offer_per_update_point);

    let (
        buffer_input_spk,
        buffer_input_value,
        counter_buffer_adaptor_key,
        is_sub_channel,
        sub_channel_id,
    ) = if let Some(sub_channel_info) = sub_channel_info {
        (
            sub_channel_info.funding_info.funding_script_pubkey.clone(),
            sub_channel_info.funding_info.funding_input_value,
            sub_channel_info.counter_adaptor_pk,
            true,
            Some(sub_channel_info.sub_channel_id),
        )
    } else {
        (
            accepted_contract
                .dlc_transactions
                .funding_script_pubkey
                .clone(),
            accepted_contract.dlc_transactions.get_fund_output().value,
            accepted_contract.offered_contract.offer_params.fund_pubkey,
            false,
            None,
        )
    };

    verify_tx_adaptor_signature(
        secp,
        &accepted_channel.buffer_transaction,
        buffer_input_value,
        &buffer_input_spk,
        &counter_buffer_adaptor_key,
        &own_publish_pk,
        &sign_channel.buffer_adaptor_signature,
    )?;

    let cet_adaptor_signatures: Vec<_> = (&sign_channel.cet_adaptor_signatures).into();

    let (signed_contract, signed_fund_tx) = verify_signed_contract_internal(
        secp,
        accepted_contract,
        &sign_channel.refund_signature,
        &cet_adaptor_signatures,
        &sign_channel.funding_signatures,
        accepted_channel.buffer_transaction.output[0].value,
        Some(accepted_channel.buffer_script_pubkey.clone()),
        Some(counter_own_pk),
        signer,
        Some(accepted_channel.channel_id),
    )?;

    let fund_output_index = if is_sub_channel {
        1
    } else {
        accepted_contract.dlc_transactions.get_fund_output_index()
    };

    chain_monitor.lock().unwrap().add_tx(
        accepted_channel.buffer_transaction.txid(),
        ChannelInfo {
            channel_id: accepted_channel.channel_id,
            tx_type: TxType::BufferTx,
        },
    );

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
        fund_output_index,
        own_params: accepted_contract.accept_params.clone(),
        own_per_update_point: accepted_channel.accept_per_update_point,
        state: SignedChannelState::Established {
            signed_contract_id: signed_contract.accepted_contract.get_contract_id(),
            own_buffer_adaptor_signature: accepted_channel.accept_buffer_adaptor_signature,
            counter_buffer_adaptor_signature: sign_channel.buffer_adaptor_signature,
            buffer_transaction: accepted_channel.buffer_transaction.clone(),
            is_offer: false,
            total_collateral: accepted_contract.offered_contract.total_collateral,
        },
        update_idx: INITIAL_UPDATE_NUMBER,
        fund_tx: signed_contract
            .accepted_contract
            .dlc_transactions
            .fund
            .clone(),
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
        sub_channel_id,
    };

    Ok((signed_channel, signed_contract, signed_fund_tx))
}

/// Creates a [`SettleOffer`] message from the given [`SignedChannel`] and parameters,
/// updating the state of the channel at the same time.  Expects the
/// channel to be in [`SignedChannelState::Established`] state.
pub fn settle_channel_offer<C: Signing, S: Deref, T: Deref>(
    secp: &Secp256k1<C>,
    channel: &mut SignedChannel,
    counter_payout: u64,
    peer_timeout: u64,
    signer: &S,
    time: &T,
) -> Result<SettleOffer, Error>
where
    S::Target: Signer,
    T::Target: Time,
{
    if let SignedChannelState::Established { .. } = channel.state {
    } else {
        return Err(Error::InvalidState(
            "Signed channel was not in Established state as expected.".to_string(),
        ));
    }

    let per_update_seed_pk = channel.own_per_update_seed;
    let per_update_seed = signer.get_secret_key_for_pubkey(&per_update_seed_pk)?;

    let per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        channel.update_idx - 1,
    ))
    .expect("a valid secret key.");

    let next_per_update_point = PublicKey::from_secret_key(secp, &per_update_secret);

    let mut state = SignedChannelState::SettledOffered {
        counter_payout,
        next_per_update_point,
        timeout: time.unix_time_now() + peer_timeout,
    };

    std::mem::swap(&mut channel.state, &mut state);

    channel.roll_back_state = Some(state);

    let settle_channel_offer = SettleOffer {
        channel_id: channel.channel_id,
        counter_payout,
        next_per_update_point,
        timestamp: get_unix_time_now()
    };

    Ok(settle_channel_offer)
}

/// Updates the state of the given [`SignedChannel`] using the given [`SettleOffer`]
/// message.
pub fn on_settle_offer(
    signed_channel: &mut SignedChannel,
    settle_offer: &SettleOffer,
) -> Result<(), Error> {
    if let SignedChannelState::Established { .. } = signed_channel.state {
    } else {
        return Err(Error::InvalidState(
            "Received settle offer while not in Established state.".to_string(),
        ));
    }

    let total_collateral =
        signed_channel.own_params.collateral + signed_channel.counter_params.collateral;

    if settle_offer.counter_payout > total_collateral {
        return Err(Error::InvalidState(
            "Proposed settle offer payout greater than total collateral".to_string(),
        ));
    }

    let mut new_state = SignedChannelState::SettledReceived {
        own_payout: settle_offer.counter_payout,
        counter_next_per_update_point: settle_offer.next_per_update_point,
        counter_payout: total_collateral - settle_offer.counter_payout,
    };

    std::mem::swap(&mut signed_channel.state, &mut new_state);
    signed_channel.roll_back_state = Some(new_state);

    Ok(())
}

/// Creates a [`SettleAccept`] message from the given [`SignedChannel`] and other
/// parameters, updating the state of the channel at the same time. Expects the
/// channel to be in [`SignedChannelState::SettledReceived`] state.
pub fn settle_channel_accept<S: Deref, T: Deref>(
    secp: &Secp256k1<All>,
    channel: &mut SignedChannel,
    csv_timelock: u32,
    lock_time: u32,
    peer_timeout: u64,
    signer: &S,
    time: &T,
    chain_monitor: &Mutex<ChainMonitor>,
) -> Result<SettleAccept, Error>
where
    S::Target: Signer,
    T::Target: Time,
{
    settle_channel_accept_internal(
        secp,
        channel,
        csv_timelock,
        lock_time,
        peer_timeout,
        signer,
        time,
        None,
        chain_monitor,
    )
}

pub(crate) fn settle_channel_accept_internal<S: Deref, T: Deref>(
    secp: &Secp256k1<All>,
    channel: &mut SignedChannel,
    csv_timelock: u32,
    lock_time: u32,
    peer_timeout: u64,
    signer: &S,
    time: &T,
    own_settle_adaptor_sk: Option<SecretKey>,
    chain_monitor: &Mutex<ChainMonitor>,
) -> Result<SettleAccept, Error>
where
    S::Target: Signer,
    T::Target: Time,
{
    let (own_payout, counter_next_per_update_point, counter_payout) =
        if let SignedChannelState::SettledReceived {
            own_payout,
            counter_next_per_update_point,
            counter_payout,
        } = channel.state
        {
            (own_payout, counter_next_per_update_point, counter_payout)
        } else {
            return Err(Error::InvalidState(
                "Signed channel was not in SettledReceived state as expected.".to_string(),
            ));
        };

    let per_update_seed_pk = channel.own_per_update_seed;
    let per_update_seed = signer.get_secret_key_for_pubkey(&per_update_seed_pk)?;
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

    let fund_vout = channel.fund_output_index;
    let funding_script_pubkey = &channel.fund_script_pubkey;

    let own_adaptor_sk = if let Some(own_settle_adaptor_sk) = own_settle_adaptor_sk {
        own_settle_adaptor_sk
    } else {
        signer.get_secret_key_for_pubkey(&channel.own_params.fund_pubkey)?
    };

    let settle_input_outpoint = OutPoint {
        txid: channel.fund_tx.txid(),
        vout: channel.fund_output_index as u32,
    };

    let (settle_tx, settle_adaptor_signature) = get_settle_tx_and_adaptor_sig(
        secp,
        &own_next_per_update_point,
        &settle_input_outpoint,
        channel.fund_tx.output[fund_vout].value,
        funding_script_pubkey,
        &own_adaptor_sk,
        &channel.counter_points,
        &channel.own_points,
        &counter_next_per_update_point,
        final_offer_payout,
        final_accept_payout,
        csv_timelock,
        lock_time,
        None,
        channel.fee_rate_per_vb,
    )?;

    chain_monitor.lock().unwrap().add_tx(
        settle_tx.txid(),
        ChannelInfo {
            channel_id: channel.channel_id,
            tx_type: TxType::SettleTx,
        },
    );

    channel.state = SignedChannelState::SettledAccepted {
        counter_next_per_update_point,
        own_next_per_update_point,
        settle_tx,
        own_settle_adaptor_signature: settle_adaptor_signature,
        timeout: time.unix_time_now() + peer_timeout,
        own_payout,
        counter_payout,
    };

    let msg = SettleAccept {
        channel_id: channel.channel_id,
        next_per_update_point: own_next_per_update_point,
        settle_adaptor_signature,
    };

    Ok(msg)
}

/// Creates a [`SettleConfirm`] message from the given [`SignedChannel`] and
/// [`SettleAccept`] message, verifying the content of the message and updating
/// the state of the channel at the same time.  Expects the channel to be in
/// [`SignedChannelState::SettledOffered`] state.
pub fn settle_channel_confirm<T: Deref, S: Deref>(
    secp: &Secp256k1<All>,
    channel: &mut SignedChannel,
    settle_channel_accept: &SettleAccept,
    csv_timelock: u32,
    lock_time: u32,
    peer_timeout: u64,
    signer: &S,
    time: &T,
    chain_monitor: &Mutex<ChainMonitor>,
) -> Result<SettleConfirm, Error>
where
    T::Target: Time,
    S::Target: Signer,
{
    settle_channel_confirm_internal(
        secp,
        channel,
        settle_channel_accept,
        csv_timelock,
        lock_time,
        peer_timeout,
        signer,
        time,
        None,
        None,
        chain_monitor,
    )
}

pub(crate) fn settle_channel_confirm_internal<T: Deref, S: Deref>(
    secp: &Secp256k1<All>,
    channel: &mut SignedChannel,
    settle_channel_accept: &SettleAccept,
    csv_timelock: u32,
    lock_time: u32,
    peer_timeout: u64,
    signer: &S,
    time: &T,
    own_settle_adaptor_sk: Option<SecretKey>,
    counter_settle_adaptor_pk: Option<PublicKey>,
    chain_monitor: &Mutex<ChainMonitor>,
) -> Result<SettleConfirm, Error>
where
    T::Target: Time,
    S::Target: Signer,
{
    let (counter_payout, next_per_update_point) = match channel.state {
        SignedChannelState::SettledOffered {
            counter_payout,
            next_per_update_point,
            ..
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

    let settle_input_outpoint = OutPoint {
        txid: channel.fund_tx.txid(),
        vout: channel.fund_output_index as u32,
    };
    let funding_script_pubkey = &channel.fund_script_pubkey;

    let own_settle_adaptor_sk = if let Some(own_settle_adaptor_sk) = own_settle_adaptor_sk {
        own_settle_adaptor_sk
    } else {
        signer.get_secret_key_for_pubkey(&channel.own_params.fund_pubkey)?
    };

    let counter_settle_adaptor_pk =
        counter_settle_adaptor_pk.unwrap_or(channel.counter_params.fund_pubkey);

    let (settle_tx, settle_adaptor_signature) = get_settle_tx_and_adaptor_sig(
        secp,
        &next_per_update_point,
        &settle_input_outpoint,
        channel.fund_tx.output[channel.fund_output_index].value,
        funding_script_pubkey,
        &own_settle_adaptor_sk,
        &channel.own_points,
        &channel.counter_points,
        &settle_channel_accept.next_per_update_point,
        final_offer_payout,
        final_accept_payout,
        csv_timelock,
        lock_time,
        Some((
            &settle_channel_accept.settle_adaptor_signature,
            counter_settle_adaptor_pk,
        )),
        channel.fee_rate_per_vb,
    )?;

    chain_monitor.lock().unwrap().add_tx(
        settle_tx.txid(),
        ChannelInfo {
            channel_id: channel.channel_id,
            tx_type: TxType::SettleTx,
        },
    );

    let per_update_seed_pk = channel.own_per_update_seed;
    let per_update_seed = signer.get_secret_key_for_pubkey(&per_update_seed_pk)?;

    let prev_per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        channel.update_idx,
    ))?;

    let state = SignedChannelState::SettledConfirmed {
        settle_tx,
        counter_settle_adaptor_signature: settle_channel_accept.settle_adaptor_signature,
        own_next_per_update_point: next_per_update_point,
        counter_next_per_update_point: settle_channel_accept.next_per_update_point,
        own_settle_adaptor_signature: settle_adaptor_signature,
        timeout: time.unix_time_now() + peer_timeout,
        own_payout: final_offer_payout,
        counter_payout: final_accept_payout,
    };

    channel.state = state;

    let msg = SettleConfirm {
        channel_id: channel.channel_id,
        prev_per_update_secret,
        settle_adaptor_signature,
    };

    Ok(msg)
}

/// Creates a [`SettleFinalize`] message from the given [`SignedChannel`] and
/// [`SettleConfirm`] message, validating the message and updating the state of
/// the channel at the same time.  Expects the channel to be in
/// [`SignedChannelState::SettledAccepted`] state.
pub fn settle_channel_finalize<S: Deref>(
    secp: &Secp256k1<All>,
    channel: &mut SignedChannel,
    settle_channel_confirm: &SettleConfirm,
    signer: &S,
) -> Result<SettleFinalize, Error>
where
    S::Target: Signer,
{
    settle_channel_finalize_internal(secp, channel, settle_channel_confirm, signer, None)
}

pub(crate) fn settle_channel_finalize_internal<S: Deref>(
    secp: &Secp256k1<All>,
    channel: &mut SignedChannel,
    settle_channel_confirm: &SettleConfirm,
    signer: &S,
    counter_settle_adaptor_pk: Option<PublicKey>,
) -> Result<SettleFinalize, Error>
where
    S::Target: Signer,
{
    let (
        own_next_per_update_point,
        counter_next_per_update_point,
        settle_tx,
        own_settle_adaptor_signature,
        own_payout,
        counter_payout,
    ) = match &channel.state {
        SignedChannelState::SettledAccepted {
            counter_next_per_update_point,
            own_next_per_update_point,
            settle_tx,
            own_settle_adaptor_signature,
            own_payout,
            counter_payout,
            ..
        } => (
            own_next_per_update_point,
            counter_next_per_update_point,
            settle_tx,
            own_settle_adaptor_signature,
            *own_payout,
            *counter_payout,
        ),
        _ => {
            return Err(Error::InvalidState(
                "Signed channel was not in SettledAccepted state as expected.".to_string(),
            ))
        }
    };

    let per_update_seed_pk = channel.own_per_update_seed;
    let per_update_seed = signer.get_secret_key_for_pubkey(&per_update_seed_pk)?;

    let accept_revoke_params = channel.own_points.get_revokable_params(
        secp,
        &channel.counter_points.revocation_basepoint,
        own_next_per_update_point,
    );

    let counter_settle_adaptor_pk =
        counter_settle_adaptor_pk.unwrap_or(channel.counter_params.fund_pubkey);

    verify_tx_adaptor_signature(
        secp,
        settle_tx,
        channel.fund_tx.output[channel.fund_output_index].value,
        &channel.fund_script_pubkey,
        &counter_settle_adaptor_pk,
        &accept_revoke_params.publish_pk.inner,
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

    let state = SignedChannelState::Settled {
        settle_tx: settle_tx.clone(),
        counter_settle_adaptor_signature: settle_channel_confirm.settle_adaptor_signature,
        own_settle_adaptor_signature: *own_settle_adaptor_signature,
        own_payout,
        counter_payout,
    };

    channel.own_per_update_point = *own_next_per_update_point;
    channel.counter_per_update_point = *counter_next_per_update_point;
    channel.state = state;
    channel.roll_back_state = None;
    channel.update_idx -= 1;

    let msg = SettleFinalize {
        channel_id: channel.channel_id,
        prev_per_update_secret,
    };

    Ok(msg)
}

/// Checks that the [`SettleFinalize`] message is valid with respect to the given
/// channel and updates the state of the channel.
/// Expects the channel to be in [`SignedChannelState::SettledConfirmed`]
/// state.
pub fn settle_channel_on_finalize<C: Signing>(
    secp: &Secp256k1<C>,
    channel: &mut SignedChannel,
    settle_channel_finalize: &SettleFinalize,
) -> Result<(), Error> {
    let (
        settle_tx,
        counter_settle_adaptor_signature,
        counter_next_per_update_point,
        own_next_per_update_point,
        own_settle_adaptor_signature,
        own_payout,
        counter_payout,
    ) = match &channel.state {
        SignedChannelState::SettledConfirmed {
            settle_tx,
            counter_settle_adaptor_signature,
            counter_next_per_update_point,
            own_next_per_update_point,
            own_settle_adaptor_signature,
            own_payout,
            counter_payout,
            ..
        } => (
            settle_tx.clone(),
            *counter_settle_adaptor_signature,
            *counter_next_per_update_point,
            *own_next_per_update_point,
            *own_settle_adaptor_signature,
            *own_payout,
            *counter_payout,
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
        own_payout,
        counter_payout,
    };
    channel.roll_back_state = None;

    channel.own_per_update_point = own_next_per_update_point;
    channel.counter_per_update_point = counter_next_per_update_point;
    channel.update_idx -= 1;

    Ok(())
}

/// Creates a [`Reject`] message and rolls back the state of the channel. Expects
/// the channel to be in [`SignedChannelState::SettledOffered`] state.
pub fn reject_settle_offer(signed_channel: &mut SignedChannel) -> Result<Reject, Error> {
    get_signed_channel_state!(signed_channel, SettledReceived,)?;

    signed_channel.state = signed_channel
        .roll_back_state
        .take()
        .expect("to have a rollback state");

    Ok(Reject {
        channel_id: signed_channel.channel_id,
        timestamp: get_unix_time_now()
    })
}

/// Creates a [`RenewOffer`] message and [`OfferedContract`] for the given channel
/// using the provided parameters.
pub fn renew_offer<C: Signing, S: Deref, T: Deref>(
    secp: &Secp256k1<C>,
    signed_channel: &mut SignedChannel,
    contract_input: &ContractInput,
    oracle_announcements: Vec<Vec<OracleAnnouncement>>,
    counter_payout: u64,
    refund_delay: u32,
    peer_timeout: u64,
    cet_nsequence: u32,
    signer: &S,
    time: &T,
) -> Result<(RenewOffer, OfferedContract), Error>
where
    S::Target: Signer,
    T::Target: Time,
{
    // Validity checks.
    match &signed_channel.state {
        SignedChannelState::Established {
            total_collateral, ..
        } => {
            if *total_collateral
                != contract_input.accept_collateral + contract_input.offer_collateral
            {
                return Err(Error::InvalidParameters(
                    "Sum of collaterals in contract must equal total collateral in channel."
                        .to_string(),
                ));
            }
        }
        SignedChannelState::Settled {
            own_payout,
            counter_payout,
            ..
        } => {
            if contract_input.offer_collateral != *own_payout
                || contract_input.accept_collateral != *counter_payout
            {
                return Err(Error::InvalidParameters(
                    "Contract collateral not equal to each party's balance in the channel"
                        .to_string(),
                ));
            }
        }
        s => {
            return Err(Error::InvalidState(format!(
                "Can only renewed established or closed channels, not {s}."
            )));
        }
    };

    let temporary_contract_id: ContractId = crate::channel::generate_temporary_contract_id(
        signed_channel.channel_id,
        signed_channel.update_idx,
    );

    let mut offered_contract = OfferedContract::new(
        contract_input,
        oracle_announcements,
        &signed_channel.own_params,
        &[],
        &signed_channel.counter_party,
        refund_delay,
        time.unix_time_now() as u32,
        temporary_contract_id,
    );

    offered_contract.fund_output_serial_id = 0;

    offered_contract.fee_rate_per_vb = signed_channel.fee_rate_per_vb;

    let per_update_seed = signer.get_secret_key_for_pubkey(&signed_channel.own_per_update_seed)?;

    let per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        signed_channel.update_idx - 1,
    ))
    .expect("a valid secret key.");

    let next_per_update_point = PublicKey::from_secret_key(secp, &per_update_secret);

    let mut state = SignedChannelState::RenewOffered {
        offered_contract_id: offered_contract.id,
        offer_next_per_update_point: next_per_update_point,
        is_offer: true,
        counter_payout,
        timeout: time.unix_time_now() + peer_timeout,
    };

    std::mem::swap(&mut signed_channel.state, &mut state);
    signed_channel.roll_back_state = Some(state);

    let msg = RenewOffer {
        channel_id: signed_channel.channel_id,
        counter_payout,
        next_per_update_point,
        contract_info: (&offered_contract).into(),
        cet_locktime: offered_contract.cet_locktime,
        refund_locktime: offered_contract.refund_locktime,
        cet_nsequence,
    };

    Ok((msg, offered_contract))
}

/// Update the state of the given [`SignedChannel`] from the given [`RenewOffer`].
/// Expects the channel to be in one of [`SignedChannelState::Settled`] or
/// [`SignedChannelState::Established`] state.
pub fn on_renew_offer<T: Deref>(
    signed_channel: &mut SignedChannel,
    renew_offer: &RenewOffer,
    peer_timeout: u64,
    time: &T,
) -> Result<OfferedContract, Error> where
    T::Target: Time,
{
    if let SignedChannelState::Settled { .. } | SignedChannelState::Established { .. } =
        signed_channel.state
    {
    } else {
        return Err(Error::InvalidState(
            "Received renew offer while not in Settled or Established states.".to_string(),
        ));
    }

    let temporary_contract_id = crate::channel::generate_temporary_contract_id(
        signed_channel.channel_id,
        signed_channel.update_idx,
    );

    let offered_contract = OfferedContract {
        id: temporary_contract_id,
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
        cet_locktime: renew_offer.cet_locktime,
        refund_locktime: renew_offer.refund_locktime,
    };

    let mut state = SignedChannelState::RenewOffered {
        offered_contract_id: offered_contract.id,
        counter_payout: renew_offer.counter_payout,
        offer_next_per_update_point: renew_offer.next_per_update_point,
        is_offer: false,
        timeout: time.unix_time_now() + peer_timeout,
    };

    std::mem::swap(&mut signed_channel.state, &mut state);

    signed_channel.roll_back_state = Some(state);

    Ok(offered_contract)
}

/// Creates a [`RenewAccept`] message from the given [`SignedChannel`] and other
/// parameters, updating the state of the channel and the associated contract the
/// same time.  Expects the channel to be in [`SignedChannelState::RenewOffered`]
/// state.
pub fn accept_channel_renewal<S: Deref, T: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    offered_contract: &OfferedContract,
    cet_nsequence: u32,
    peer_timeout: u64,
    signer: &S,
    time: &T,
) -> Result<(AcceptedContract, RenewAccept), Error>
where
    S::Target: Signer,
    T::Target: Time,
{
    accept_channel_renewal_internal(
        secp,
        signed_channel,
        offered_contract,
        cet_nsequence,
        peer_timeout,
        signer,
        time,
    )
}

pub(crate) fn accept_channel_renewal_internal<S: Deref, T: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    offered_contract: &OfferedContract,
    cet_nsequence: u32,
    peer_timeout: u64,
    signer: &S,
    time: &T,
) -> Result<(AcceptedContract, RenewAccept), Error>
where
    S::Target: Signer,
    T::Target: Time,
{
    let (offer_next_per_update_point, own_payout) = match signed_channel.state {
        SignedChannelState::RenewOffered {
            offer_next_per_update_point,
            counter_payout,
            ..
        } => (offer_next_per_update_point, counter_payout),
        _ => {
            return Err(Error::InvalidState(
                "Signed channel was not in SettledOffered state as expected.".to_string(),
            ))
        }
    };

    let own_base_secret_key =
        signer.get_secret_key_for_pubkey(&signed_channel.own_points.own_basepoint)?;
    let per_update_seed = signer.get_secret_key_for_pubkey(&signed_channel.own_per_update_seed)?;

    let total_collateral = offered_contract.total_collateral;

    let offer_revoke_params = signed_channel.counter_points.get_revokable_params(
        secp,
        &signed_channel.own_points.revocation_basepoint,
        &offer_next_per_update_point,
    );

    let accept_per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        signed_channel.update_idx - 1,
    ))?;

    let accept_per_update_point = PublicKey::from_secret_key(secp, &accept_per_update_secret);

    let accept_revoke_params = signed_channel.own_points.get_revokable_params(
        secp,
        &signed_channel.counter_points.revocation_basepoint,
        &accept_per_update_point,
    );

    let (fund_vout, buffer_nsequence) = if signed_channel.is_sub_channel() {
        (Some(1), Some(Sequence(crate::manager::CET_NSEQUENCE)))
    } else {
        (None, None)
    };

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
        offered_contract.refund_locktime,
        offered_contract.fee_rate_per_vb,
        0,
        Sequence(cet_nsequence),
        fund_vout,
        buffer_nsequence,
    )?;

    let own_secret_key = derive_private_key(secp, &accept_per_update_point, &own_base_secret_key);

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
        offer_per_update_point: offer_next_per_update_point,
        accept_per_update_point,
        buffer_transaction,
        buffer_script_pubkey,
        timeout: time.unix_time_now() + peer_timeout,
        own_payout,
    };

    signed_channel.state = state;

    let renew_accept = RenewAccept {
        channel_id: signed_channel.channel_id,
        next_per_update_point: accept_per_update_point,
        cet_adaptor_signatures: (&adaptor_sigs as &[_]).into(),
        refund_signature: accepted_contract.accept_refund_signature,
    };

    Ok((accepted_contract, renew_accept))
}

/// Creates a [`RenewConfirm`] message from the given [`SignedChannel`] and
/// [`RenewAccept`] message, verifying the message and updating the state of the
/// channel and associated contract the same time. Expects the channel to be in
/// [`SignedChannelState::RenewOffered`] state.
pub fn verify_renew_accept_and_confirm<S: Deref, T: Deref>(
    secp: &Secp256k1<All>,
    renew_accept: &RenewAccept,
    signed_channel: &mut SignedChannel,
    offered_contract: &OfferedContract,
    cet_nsequence: u32,
    peer_timeout: u64,
    signer: &S,
    time: &T,
) -> Result<(SignedContract, RenewConfirm), Error>
where
    S::Target: Signer,
    T::Target: Time,
{
    verify_renew_accept_and_confirm_internal(
        secp,
        renew_accept,
        signed_channel,
        offered_contract,
        cet_nsequence,
        peer_timeout,
        signer,
        time,
        None,
    )
}

pub(crate) fn verify_renew_accept_and_confirm_internal<S: Deref, T: Deref>(
    secp: &Secp256k1<All>,
    renew_accept: &RenewAccept,
    signed_channel: &mut SignedChannel,
    offered_contract: &OfferedContract,
    cet_nsequence: u32,
    peer_timeout: u64,
    signer: &S,
    time: &T,
    own_buffer_adaptor_sk: Option<SecretKey>,
) -> Result<(SignedContract, RenewConfirm), Error>
where
    S::Target: Signer,
    T::Target: Time,
{
    let own_fund_sk = signer.get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

    let own_base_secret_key =
        signer.get_secret_key_for_pubkey(&signed_channel.own_points.own_basepoint)?;

    let offer_per_update_point =
        get_signed_channel_state!(signed_channel, RenewOffered, offer_next_per_update_point)?;

    let offer_revoke_params = signed_channel.own_points.get_revokable_params(
        secp,
        &signed_channel.counter_points.revocation_basepoint,
        offer_per_update_point,
    );
    let accept_revoke_params = signed_channel.counter_points.get_revokable_params(
        secp,
        &signed_channel.own_points.revocation_basepoint,
        &renew_accept.next_per_update_point,
    );

    let total_collateral = offered_contract.total_collateral;

    let own_payout =
        total_collateral - get_signed_channel_state!(signed_channel, RenewOffered, counter_payout)?;
    let (fund_vout, buffer_nsequence) = if signed_channel.is_sub_channel() {
        (Some(1), Some(Sequence(crate::manager::CET_NSEQUENCE)))
    } else {
        (None, None)
    };

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
        offered_contract.refund_locktime,
        offered_contract.fee_rate_per_vb,
        0,
        Sequence(cet_nsequence),
        fund_vout,
        buffer_nsequence,
    )?;

    let offer_own_sk = derive_private_key(secp, offer_per_update_point, &own_base_secret_key);
    let cet_adaptor_signatures: Vec<_> = (&renew_accept.cet_adaptor_signatures).into();

    let (signed_contract, cet_adaptor_signatures) = verify_accepted_and_sign_contract_internal(
        secp,
        offered_contract,
        &signed_channel.counter_params,
        &[],
        &renew_accept.refund_signature,
        &cet_adaptor_signatures,
        buffer_transaction.output[0].value,
        &offer_own_sk,
        signer,
        Some(buffer_script_pubkey.clone()),
        Some(accept_revoke_params.own_pk.inner),
        &dlc_transactions,
        Some(signed_channel.channel_id),
    )?;

    let buffer_input_value = if signed_channel.is_sub_channel() {
        signed_channel.fund_tx.output[1].value
    } else {
        signed_channel.fund_tx.output[signed_channel.fund_output_index].value
    };
    let own_buffer_adaptor_sk = own_buffer_adaptor_sk.as_ref().unwrap_or(&own_fund_sk);

    let own_buffer_adaptor_signature = get_tx_adaptor_signature(
        secp,
        &buffer_transaction,
        buffer_input_value,
        &dlc_transactions.funding_script_pubkey,
        own_buffer_adaptor_sk,
        &accept_revoke_params.publish_pk.inner,
    )?;

    let state = SignedChannelState::RenewConfirmed {
        contract_id: signed_contract.accepted_contract.get_contract_id(),
        offer_per_update_point: *offer_per_update_point,
        accept_per_update_point: renew_accept.next_per_update_point,
        buffer_transaction,
        buffer_script_pubkey,
        offer_buffer_adaptor_signature: own_buffer_adaptor_signature,
        timeout: time.unix_time_now() + peer_timeout,
        own_payout,
        total_collateral: offered_contract.total_collateral,
    };

    signed_channel.state = state;

    let renew_confirm = RenewConfirm {
        channel_id: signed_channel.channel_id,
        buffer_adaptor_signature: own_buffer_adaptor_signature,
        cet_adaptor_signatures: (&cet_adaptor_signatures as &[_]).into(),
        refund_signature: signed_contract.offer_refund_signature,
    };

    Ok((signed_contract, renew_confirm))
}

/// Creates a [`RenewFinalize`] message from the given [`SignedChannel`] and
/// [`RenewAccept`] message, verifying the message and updating the state of the
/// channel and associated contract the same time. Expects the channel to be in
/// [`SignedChannelState::RenewAccepted`] state.
pub fn verify_renew_confirm_and_finalize<T: Deref, S: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    accepted_contract: &AcceptedContract,
    renew_confirm: &RenewConfirm,
    peer_timeout: u64,
    time: &T,
    signer: &S,
    chain_monitor: &Mutex<ChainMonitor>,
) -> Result<(SignedContract, RenewFinalize), Error>
where
    T::Target: Time,
    S::Target: Signer,
{
    verify_renew_confirm_and_finalize_internal(
        secp,
        signed_channel,
        accepted_contract,
        renew_confirm,
        peer_timeout,
        time,
        signer,
        None,
        None,
        chain_monitor,
    )
}

pub(crate) fn verify_renew_confirm_and_finalize_internal<S: Deref, T: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    accepted_contract: &AcceptedContract,
    renew_confirm: &RenewConfirm,
    peer_timeout: u64,
    time: &T,
    signer: &S,
    counter_buffer_own_pk: Option<PublicKey>,
    own_buffer_adaptor_sk: Option<SecretKey>,
    chain_monitor: &Mutex<ChainMonitor>,
) -> Result<(SignedContract, RenewFinalize), Error>
where
    T::Target: Time,
    S::Target: Signer,
{
    let (
        &offer_per_update_point,
        &accept_per_update_point,
        own_payout,
        buffer_transaction,
        buffer_script_pubkey,
    ) = get_signed_channel_state!(
        signed_channel,
        RenewAccepted,
        offer_per_update_point,
        accept_per_update_point,
        own_payout | buffer_transaction,
        buffer_script_pubkey
    )?;

    let own_publish_pk = signed_channel
        .own_points
        .get_publish_pk(secp, &accept_per_update_point);

    let counter_own_pk = signed_channel
        .counter_points
        .get_own_pk(secp, &offer_per_update_point);
    let counter_buffer_own_pk = counter_buffer_own_pk
        .as_ref()
        .unwrap_or(&accepted_contract.offered_contract.offer_params.fund_pubkey);

    verify_tx_adaptor_signature(
        secp,
        buffer_transaction,
        signed_channel.fund_tx.output[signed_channel.fund_output_index].value,
        &signed_channel.fund_script_pubkey,
        counter_buffer_own_pk,
        &own_publish_pk,
        &renew_confirm.buffer_adaptor_signature,
    )?;

    let cet_adaptor_signatures: Vec<_> = (&renew_confirm.cet_adaptor_signatures).into();
    let (signed_contract, _) = verify_signed_contract_internal(
        secp,
        accepted_contract,
        &renew_confirm.refund_signature,
        &cet_adaptor_signatures,
        &FundingSignatures {
            funding_signatures: Vec::new(),
        },
        buffer_transaction.output[0].value,
        Some(buffer_script_pubkey.clone()),
        Some(counter_own_pk),
        signer,
        Some(signed_channel.channel_id),
    )?;

    let prev_offer_per_update_point = signed_channel.counter_per_update_point;
    signed_channel.counter_per_update_point = offer_per_update_point;
    signed_channel.own_per_update_point = accept_per_update_point;

    let per_update_seed = signer.get_secret_key_for_pubkey(&signed_channel.own_per_update_seed)?;

    let prev_per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        signed_channel.update_idx,
    ))?;

    let offer_revoke_params = signed_channel.counter_points.get_revokable_params(
        secp,
        &signed_channel.own_points.revocation_basepoint,
        &signed_channel.counter_per_update_point,
    );

    let own_fund_sk = signer.get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;
    let own_buffer_adaptor_sk = own_buffer_adaptor_sk.as_ref().unwrap_or(&own_fund_sk);

    let buffer_input_value = if signed_channel.is_sub_channel() {
        signed_channel.fund_tx.output[1].value
    } else {
        signed_channel.fund_tx.output[signed_channel.fund_output_index].value
    };

    let buffer_adaptor_signature = get_tx_adaptor_signature(
        secp,
        buffer_transaction,
        buffer_input_value,
        &signed_channel.fund_script_pubkey,
        own_buffer_adaptor_sk,
        &offer_revoke_params.publish_pk.inner,
    )?;
    let total_collateral =
        signed_channel.own_params.collateral + signed_channel.counter_params.collateral;

    chain_monitor.lock().unwrap().add_tx(
        buffer_transaction.txid(),
        ChannelInfo {
            channel_id: signed_channel.channel_id,
            tx_type: TxType::BufferTx,
        },
    );

    signed_channel.state = SignedChannelState::RenewFinalized {
        contract_id: signed_contract.accepted_contract.get_contract_id(),
        prev_offer_per_update_point,
        buffer_transaction: buffer_transaction.clone(),
        buffer_script_pubkey: buffer_script_pubkey.clone(),
        offer_buffer_adaptor_signature: renew_confirm.buffer_adaptor_signature,
        accept_buffer_adaptor_signature: buffer_adaptor_signature,
        timeout: time.unix_time_now() + peer_timeout,
        own_payout: *own_payout,
        total_collateral,
    };

    let renew_finalize = RenewFinalize {
        channel_id: signed_channel.channel_id,
        per_update_secret: prev_per_update_secret,
        buffer_adaptor_signature,
    };

    Ok((signed_contract, renew_finalize))
}

/// Verify the given [`RenewFinalize`] and update the state of the channel.
pub fn renew_channel_on_finalize<S: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    renew_finalize: &RenewFinalize,
    counter_buffer_own_pk: Option<PublicKey>,
    signer: &S,
) -> Result<RenewRevoke, Error>
where
    S::Target: Signer,
{
    let (
        contract_id,
        total_collateral,
        offer_per_update_point,
        accept_per_update_point,
        offer_buffer_adaptor_signature,
        buffer_transaction,
    ) = get_signed_channel_state!(
        signed_channel,
        RenewConfirmed,
        contract_id,
        total_collateral,
        offer_per_update_point,
        accept_per_update_point,
        offer_buffer_adaptor_signature | buffer_transaction
    )?;

    let offer_revoke_params = signed_channel.own_points.get_revokable_params(
        secp,
        &signed_channel.counter_points.revocation_basepoint,
        offer_per_update_point,
    );

    let buffer_input_value = if signed_channel.is_sub_channel() {
        signed_channel.fund_tx.output[1].value
    } else {
        signed_channel.fund_tx.output[signed_channel.fund_output_index].value
    };
    let counter_buffer_own_pk = counter_buffer_own_pk
        .as_ref()
        .unwrap_or(&signed_channel.counter_params.fund_pubkey);

    verify_tx_adaptor_signature(
        secp,
        buffer_transaction,
        buffer_input_value,
        &signed_channel.fund_script_pubkey,
        counter_buffer_own_pk,
        &offer_revoke_params.publish_pk.inner,
        &renew_finalize.buffer_adaptor_signature,
    )?;

    let state = SignedChannelState::Established {
        signed_contract_id: *contract_id,
        counter_buffer_adaptor_signature: renew_finalize.buffer_adaptor_signature,
        own_buffer_adaptor_signature: *offer_buffer_adaptor_signature,
        buffer_transaction: buffer_transaction.clone(),
        is_offer: true,
        total_collateral: *total_collateral,
    };

    if PublicKey::from_secret_key(secp, &renew_finalize.per_update_secret)
        != signed_channel.counter_per_update_point
    {
        return Err(Error::InvalidParameters(
            "Invalid per update secret in channel renew finalize".to_string(),
        ));
    }

    signed_channel
        .counter_party_commitment_secrets
        .provide_secret(
            signed_channel.update_idx,
            *renew_finalize.per_update_secret.as_ref(),
        )
        .map_err(|_| Error::InvalidParameters("Provided secret was invalid".to_string()))?;

    let per_update_seed = signer.get_secret_key_for_pubkey(&signed_channel.own_per_update_seed)?;

    let prev_per_update_secret = SecretKey::from_slice(&build_commitment_secret(
        per_update_seed.as_ref(),
        signed_channel.update_idx,
    ))?;

    signed_channel.own_per_update_point = *offer_per_update_point;
    signed_channel.counter_per_update_point = *accept_per_update_point;

    signed_channel.state = state;
    signed_channel.roll_back_state = None;
    signed_channel.update_idx -= 1;

    let msg = RenewRevoke {
        channel_id: signed_channel.channel_id,
        per_update_secret: prev_per_update_secret,
    };

    Ok(msg)
}

/// Verify the given [`RenewRevoke`] and update the state of the channel.
pub fn renew_channel_on_revoke(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    renew_revoke: &RenewRevoke,
) -> Result<(), Error> {
    let (
        contract_id,
        total_collateral,
        prev_offer_per_update_point,
        offer_buffer_adaptor_signature,
        accept_buffer_adaptor_signature,
        buffer_transaction,
    ) = get_signed_channel_state!(
        signed_channel,
        RenewFinalized,
        contract_id,
        total_collateral,
        prev_offer_per_update_point,
        offer_buffer_adaptor_signature,
        accept_buffer_adaptor_signature | buffer_transaction
    )?;

    if PublicKey::from_secret_key(secp, &renew_revoke.per_update_secret)
        != *prev_offer_per_update_point
    {
        return Err(Error::InvalidParameters(
            "Invalid per update secret in channel renew revoke".to_string(),
        ));
    }

    signed_channel
        .counter_party_commitment_secrets
        .provide_secret(
            signed_channel.update_idx,
            *renew_revoke.per_update_secret.as_ref(),
        )
        .map_err(|_| Error::InvalidParameters("Provided secret was invalid".to_string()))?;

    signed_channel.update_idx -= 1;

    signed_channel.state = SignedChannelState::Established {
        signed_contract_id: *contract_id,
        counter_buffer_adaptor_signature: *offer_buffer_adaptor_signature,
        own_buffer_adaptor_signature: *accept_buffer_adaptor_signature,
        buffer_transaction: buffer_transaction.clone(),
        is_offer: true,
        total_collateral: *total_collateral,
    };

    Ok(())
}

/// Creates a [`Reject`] message and rolls back the state of the channel. Expects
/// the channel to be in [`SignedChannelState::RenewOffered`] state and the local
/// party not to be the offer party.
pub fn reject_renew_offer(signed_channel: &mut SignedChannel) -> Result<Reject, Error> {
    let is_offer = get_signed_channel_state!(signed_channel, RenewOffered, is_offer)?;

    if *is_offer {
        return Err(Error::InvalidState(
            "Cannot reject own renew offer.".to_string(),
        ));
    }

    signed_channel.state = signed_channel
        .roll_back_state
        .take()
        .expect("to have a rollback state");

    Ok(Reject {
        channel_id: signed_channel.channel_id,
        timestamp: get_unix_time_now()
    })
}

/// Creates a [`CollaborativeCloseOffer`] message and update the state of the
/// given [`SignedChannel`].
pub fn offer_collaborative_close<C: Signing, S: Deref, T: Deref>(
    secp: &Secp256k1<C>,
    signed_channel: &mut SignedChannel,
    counter_payout: u64,
    signer: &S,
    time: &T,
) -> Result<(CollaborativeCloseOffer, Transaction), Error>
where
    S::Target: Signer,
    T::Target: Time,
{
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
    let fund_output_value = signed_channel.fund_tx.output[signed_channel.fund_output_index].value;

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

    let own_fund_sk = signer.get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

    let close_signature = dlc::util::get_raw_sig_for_tx_input(
        secp,
        &close_tx,
        0,
        &signed_channel.fund_script_pubkey,
        fund_output_value,
        &own_fund_sk,
    )?;

    let mut state = SignedChannelState::CollaborativeCloseOffered {
        counter_payout,
        offer_signature: close_signature,
        close_tx: close_tx.clone(),
        timeout: time.unix_time_now() + super::manager::PEER_TIMEOUT,
        is_offer: true,
    };
    std::mem::swap(&mut state, &mut signed_channel.state);
    signed_channel.roll_back_state = Some(state);

    Ok((
        CollaborativeCloseOffer {
            channel_id: signed_channel.channel_id,
            counter_payout,
            close_signature,
        },
        close_tx,
    ))
}

/// Validates the given [`CollaborativeCloseOffer`] and updates the state of the
/// channel.
pub fn on_collaborative_close_offer<T: Deref>(
    signed_channel: &mut SignedChannel,
    close_offer: &CollaborativeCloseOffer,
    peer_timeout: u64,
    time: &T,
) -> Result<(), Error>
where
    T::Target: Time,
{
    let total_collateral =
        signed_channel.own_params.collateral + signed_channel.counter_params.collateral;

    if close_offer.counter_payout > total_collateral {
        return Err(Error::InvalidParameters("Received collaborative close offer with counter payout greater than total collateral, ignoring.".to_string()));
    }

    if signed_channel.roll_back_state.is_some() {
        return Err(Error::InvalidState(
            "Received collaborative close offer in state with rollback, ignoring.".to_string(),
        ));
    }

    let offer_payout = total_collateral - close_offer.counter_payout;
    let fund_output_value = signed_channel.fund_tx.output[signed_channel.fund_output_index].value;

    let close_tx = dlc::channel::create_collaborative_close_transaction(
        &signed_channel.counter_params,
        offer_payout,
        &signed_channel.own_params,
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
        timeout: time.unix_time_now() + peer_timeout,
        is_offer: false
    };

    std::mem::swap(&mut state, &mut signed_channel.state);
    signed_channel.roll_back_state = Some(state);

    Ok(())
}

/// Accept an offer to collaboratively close the channel, signing the
/// closing transaction and returning it.
pub fn accept_collaborative_close_offer<C: Signing, S: Deref>(
    secp: &Secp256k1<C>,
    signed_channel: &SignedChannel,
    signer: &S,
) -> Result<(Transaction, Channel), Error>
where
    S::Target: Signer,
{
    let (offer_signature, close_tx, is_offer) = get_signed_channel_state!(
        signed_channel,
        CollaborativeCloseOffered,
        offer_signature | close_tx, is_offer
    )?;

    if *is_offer {
        return Err(Error::InvalidState(
            "Cannot accept own collaborative close offer".to_string(),
        ));
    }

    let fund_out_amount = signed_channel.fund_tx.output[signed_channel.fund_output_index].value;

    let own_fund_sk = signer.get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

    let mut close_tx = close_tx.clone();

    dlc::util::sign_multi_sig_input(
        secp,
        &mut close_tx,
        offer_signature,
        &signed_channel.counter_params.fund_pubkey,
        &own_fund_sk,
        &signed_channel.fund_script_pubkey,
        fund_out_amount,
        0,
    )?;

    // TODO(tibo): should only transition to close after confirmation.
    let channel = Channel::CollaborativelyClosed(ClosedChannel {
        counter_party: signed_channel.counter_party,
        temporary_channel_id: signed_channel.temporary_channel_id,
        channel_id: signed_channel.channel_id,
    });
    Ok((close_tx, channel))
}

fn get_settle_tx_and_adaptor_sig(
    secp: &Secp256k1<All>,
    own_next_per_update_point: &PublicKey,
    settle_input_outpoint: &OutPoint,
    settle_input_value: u64,
    settle_input_spk: &Script,
    own_adaptor_sk: &SecretKey,
    offer_points: &PartyBasePoints,
    accept_points: &PartyBasePoints,
    counter_per_update_point: &PublicKey,
    offer_payout: u64,
    accept_payout: u64,
    csv_timelock: u32,
    lock_time: u32,
    counter_adaptor_signature: Option<(&EcdsaAdaptorSignature, PublicKey)>,
    fee_rate_per_vb: u64,
) -> Result<(Transaction, EcdsaAdaptorSignature), Error> {
    let is_offer = counter_adaptor_signature.is_some();
    let (offer_per_update_point, accept_per_update_point) = if is_offer {
        (own_next_per_update_point, counter_per_update_point)
    } else {
        (counter_per_update_point, own_next_per_update_point)
    };

    let offer_revoke_params = offer_points.get_revokable_params(
        secp,
        &accept_points.revocation_basepoint,
        offer_per_update_point,
    );

    let accept_revoke_params = accept_points.get_revokable_params(
        secp,
        &offer_points.revocation_basepoint,
        accept_per_update_point,
    );

    let settle_tx = dlc::channel::create_settle_transaction(
        settle_input_outpoint,
        &offer_revoke_params,
        &accept_revoke_params,
        offer_payout,
        accept_payout,
        csv_timelock,
        lock_time,
        settle_input_value,
        fee_rate_per_vb,
    )?;

    if let Some((adaptor_sig, fund_pk)) = counter_adaptor_signature {
        verify_tx_adaptor_signature(
            secp,
            &settle_tx,
            settle_input_value,
            settle_input_spk,
            &fund_pk,
            &offer_revoke_params.publish_pk.inner,
            adaptor_sig,
        )?;
    }

    let counter_pk = if is_offer {
        accept_revoke_params.publish_pk.inner
    } else {
        offer_revoke_params.publish_pk.inner
    };

    let settle_adaptor_signature = dlc::channel::get_tx_adaptor_signature(
        secp,
        &settle_tx,
        settle_input_value,
        settle_input_spk,
        own_adaptor_sk,
        &counter_pk,
    )?;

    Ok((settle_tx, settle_adaptor_signature))
}

/// Update the state of the channel if currently in a state that can be rejected.
pub fn on_reject(signed_channel: &mut SignedChannel) -> Result<(), Error> {
    if let SignedChannelState::Established { .. } | SignedChannelState::Settled { .. } =
        signed_channel.state
    {
        return Ok(());
    }

    let mut rollback = false;

    if let SignedChannelState::RenewOffered { is_offer, .. } = signed_channel.state {
        rollback = is_offer;
    }

    if let SignedChannelState::SettledOffered { .. } = signed_channel.state {
        rollback = true;
    }

    if rollback {
        signed_channel.state = signed_channel
            .roll_back_state
            .take()
            .expect("to have a rollback state.");
        Ok(())
    } else {
        Err(Error::InvalidState(
            "Not in a state adequate to receive a reject message".to_string(),
        ))
    }
}

/// Sign the buffer transaction and closing CET and update the state of the channel.
pub fn initiate_unilateral_close_established_channel<S: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    buffer_adaptor_signature: EcdsaAdaptorSignature,
    mut buffer_transaction: Transaction,
    signer: &S,
    sub_channel: Option<(SubChannel, &ClosingSubChannel)>,
    is_initiator: bool,
) -> Result<(), Error>
where
    S::Target: Signer,
{
    let publish_base_secret =
        signer.get_secret_key_for_pubkey(&signed_channel.own_points.publish_basepoint)?;

    let publish_sk = derive_private_key(
        secp,
        &signed_channel.own_per_update_point,
        &publish_base_secret,
    );

    let counter_buffer_signature = buffer_adaptor_signature.decrypt(&publish_sk)?;

    if let Some((sub_channel, closing)) = sub_channel {
        let signed_sub_channel = &closing.signed_sub_channel;
        let own_base_secret_key =
            signer.get_secret_key_for_pubkey(&sub_channel.own_base_points.own_basepoint)?;
        let own_secret_key = derive_private_key(
            secp,
            &signed_sub_channel.own_per_split_point,
            &own_base_secret_key,
        );
        let sig = dlc::util::get_raw_sig_for_tx_input(
            secp,
            &buffer_transaction,
            0,
            &signed_sub_channel.split_tx.output_script,
            signed_sub_channel.split_tx.transaction.output[1].value,
            &own_secret_key,
        )?;

        let (own_pk, counter_pk, offer_params, accept_params) = {
            let own_revoke_params = sub_channel.own_base_points.get_revokable_params(
                secp,
                &sub_channel
                    .counter_base_points
                    .as_ref()
                    .expect("to have counter base points")
                    .revocation_basepoint,
                &signed_sub_channel.own_per_split_point,
            );
            let counter_revoke_params = sub_channel
                .counter_base_points
                .as_ref()
                .expect("to have counter base points")
                .get_revokable_params(
                    secp,
                    &sub_channel.own_base_points.revocation_basepoint,
                    &signed_sub_channel.counter_per_split_point,
                );
            if sub_channel.is_offer {
                (
                    own_revoke_params.own_pk,
                    counter_revoke_params.own_pk,
                    own_revoke_params,
                    counter_revoke_params,
                )
            } else {
                (
                    own_revoke_params.own_pk,
                    counter_revoke_params.own_pk,
                    counter_revoke_params,
                    own_revoke_params,
                )
            }
        };

        dlc::channel::satisfy_buffer_descriptor(
            &mut buffer_transaction,
            &offer_params,
            &accept_params,
            &own_pk.inner,
            &sig,
            &counter_pk,
            &counter_buffer_signature,
        )?;
    } else {
        let buffer_input_sk =
            signer.get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;
        dlc::util::sign_multi_sig_input(
            secp,
            &mut buffer_transaction,
            &counter_buffer_signature,
            &signed_channel.counter_params.fund_pubkey,
            &buffer_input_sk,
            &signed_channel.fund_script_pubkey,
            signed_channel.fund_tx.output[signed_channel.fund_output_index].value,
            0,
        )?;
    }

    let contract_id = signed_channel.get_contract_id().ok_or_else(|| {
        Error::InvalidState(
            "Expected to be in a state with an associated contract id but was not.".to_string(),
        )
    })?;

    signed_channel.state = SignedChannelState::Closing {
        buffer_transaction,
        contract_id,
        is_initiator,
    };

    Ok(())
}

/// Extract the CET and computes the signature for it, and marks the channel as closed.
pub fn finalize_unilateral_close_settled_channel<S: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &SignedChannel,
    confirmed_contract: &SignedContract,
    contract_info: &ContractInfo,
    attestations: &[(usize, OracleAttestation)],
    adaptor_info: &AdaptorInfo,
    signer: &S,
    is_initiator: bool,
) -> Result<(Transaction, Channel), Error>
where
    S::Target: Signer,
{
    let buffer_transaction =
        get_signed_channel_state!(signed_channel, Closing, buffer_transaction)?;

    let (range_info, oracle_sigs) =
        crate::utils::get_range_info_and_oracle_sigs(contract_info, adaptor_info, attestations)?;

    let mut cet =
        confirmed_contract.accepted_contract.dlc_transactions.cets[range_info.cet_index].clone();

    let is_offer = confirmed_contract
        .accepted_contract
        .offered_contract
        .is_offer_party;

    let (offer_points, accept_points, offer_per_update_point, accept_per_update_point) = if is_offer
    {
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
        secp,
        &accept_points.revocation_basepoint,
        offer_per_update_point,
    );

    let accept_revoke_params = accept_points.get_revokable_params(
        secp,
        &offer_points.revocation_basepoint,
        accept_per_update_point,
    );

    let (own_per_update_point, own_basepoint, counter_pk, adaptor_sigs) = if is_offer {
        (
            &offer_per_update_point,
            &offer_points.own_basepoint,
            &accept_revoke_params.own_pk,
            confirmed_contract
                .accepted_contract
                .adaptor_signatures
                .as_ref()
                .expect("to have adaptor signatures"),
        )
    } else {
        (
            &accept_per_update_point,
            &accept_points.own_basepoint,
            &offer_revoke_params.own_pk,
            confirmed_contract
                .adaptor_signatures
                .as_ref()
                .expect("to have adaptor signatures"),
        )
    };

    let base_secret = signer.get_secret_key_for_pubkey(own_basepoint)?;
    let own_sk = derive_private_key(secp, own_per_update_point, &base_secret);

    dlc::channel::sign_cet(
        secp,
        &mut cet,
        buffer_transaction.output[0].value,
        &offer_revoke_params,
        &accept_revoke_params,
        &own_sk,
        counter_pk,
        &adaptor_sigs[range_info.adaptor_index],
        &oracle_sigs,
    )?;
    let closed_channel = ClosedChannel {
        counter_party: signed_channel.counter_party,
        temporary_channel_id: signed_channel.temporary_channel_id,
        channel_id: signed_channel.channel_id,
    };
    let channel = if is_initiator {
        Channel::Closed(closed_channel)
    } else {
        Channel::CounterClosed(closed_channel)
    };

    Ok((cet, channel))
}

/// Sign the settlement transaction and update the state of the channel.
pub fn close_settled_channel<S: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &mut SignedChannel,
    signer: &S,
    is_initiator: bool,
) -> Result<(Transaction, Channel), Error>
where
    S::Target: Signer,
{
    close_settled_channel_internal(secp, signed_channel, signer, None, is_initiator)
}

pub(crate) fn close_settled_channel_internal<S: Deref>(
    secp: &Secp256k1<All>,
    signed_channel: &SignedChannel,
    signer: &S,
    sub_channel: Option<(SubChannel, &ClosingSubChannel)>,
    is_initiator: bool,
) -> Result<(Transaction, Channel), Error>
where
    S::Target: Signer,
{
    let (counter_settle_adaptor_signature, settle_tx) = get_signed_channel_state!(
        signed_channel,
        Settled,
        counter_settle_adaptor_signature | settle_tx
    )?;

    let mut settle_tx = settle_tx.clone();

    let publish_base_secret =
        signer.get_secret_key_for_pubkey(&signed_channel.own_points.publish_basepoint)?;

    let publish_sk = derive_private_key(
        secp,
        &signed_channel.own_per_update_point,
        &publish_base_secret,
    );

    let counter_settle_signature = counter_settle_adaptor_signature.decrypt(&publish_sk)?;

    if let Some((sub_channel, closing)) = sub_channel {
        let signed_sub_channel = &closing.signed_sub_channel;
        let own_base_secret_key =
            signer.get_secret_key_for_pubkey(&sub_channel.own_base_points.own_basepoint)?;
        let own_secret_key = derive_private_key(
            secp,
            &signed_sub_channel.own_per_split_point,
            &own_base_secret_key,
        );
        let sig = dlc::util::get_raw_sig_for_tx_input(
            secp,
            &settle_tx,
            0,
            &signed_sub_channel.split_tx.output_script,
            signed_sub_channel.split_tx.transaction.output[1].value,
            &own_secret_key,
        )?;

        let (own_pk, counter_pk, offer_params, accept_params) = {
            let own_revoke_params = sub_channel.own_base_points.get_revokable_params(
                secp,
                &sub_channel
                    .counter_base_points
                    .as_ref()
                    .expect("to have counter base points")
                    .revocation_basepoint,
                &signed_sub_channel.own_per_split_point,
            );
            let counter_revoke_params = sub_channel
                .counter_base_points
                .as_ref()
                .expect("to have counter base points")
                .get_revokable_params(
                    secp,
                    &sub_channel.own_base_points.revocation_basepoint,
                    &signed_sub_channel.counter_per_split_point,
                );
            if sub_channel.is_offer {
                (
                    own_revoke_params.own_pk,
                    counter_revoke_params.own_pk,
                    own_revoke_params,
                    counter_revoke_params,
                )
            } else {
                (
                    own_revoke_params.own_pk,
                    counter_revoke_params.own_pk,
                    counter_revoke_params,
                    own_revoke_params,
                )
            }
        };

        dlc::channel::satisfy_buffer_descriptor(
            &mut settle_tx,
            &offer_params,
            &accept_params,
            &own_pk.inner,
            &sig,
            &counter_pk,
            &counter_settle_signature,
        )?;
    } else {
        let fund_sk = signer.get_secret_key_for_pubkey(&signed_channel.own_params.fund_pubkey)?;

        dlc::util::sign_multi_sig_input(
            secp,
            &mut settle_tx,
            &counter_settle_signature,
            &signed_channel.counter_params.fund_pubkey,
            &fund_sk,
            &signed_channel.fund_script_pubkey,
            signed_channel.fund_tx.output[signed_channel.fund_output_index].value,
            0,
        )?;
    }

    let channel = if is_initiator {
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
    };
    Ok((settle_tx, channel))
}

/// Returns the current time as unix time (in seconds)
pub fn get_unix_time_now() -> u64 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .expect("Unexpected time error")
        .as_secs()
}
