//! # Serialization implementation for DLC channel related structures.
use super::accepted_channel::AcceptedChannel;
use super::offered_channel::OfferedChannel;
use super::party_points::PartyBasePoints;
use super::signed_channel::{SignedChannel, SignedChannelState};
use super::{ClosedChannel, ClosedPunishedChannel, ClosingChannel, FailedAccept, FailedSign, SettledClosingChannel};

use dlc_messages::ser_impls::{
    read_ecdsa_adaptor_signature, read_string, write_ecdsa_adaptor_signature, write_string,
};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};

impl_dlc_writeable!(PartyBasePoints, { (own_basepoint, writeable), (publish_basepoint, writeable), (revocation_basepoint, writeable) });
impl_dlc_writeable!(OfferedChannel, { (offered_contract_id, writeable), (temporary_channel_id, writeable), (party_points, writeable), (per_update_point, writeable), (offer_per_update_seed, writeable), (is_offer_party, writeable), (counter_party, writeable), (cet_nsequence, writeable), (reference_id, option) });
impl_dlc_writeable!(AcceptedChannel, {
    (accepted_contract_id, writeable),
    (offer_base_points, writeable),
    (accept_base_points, writeable),
    (offer_per_update_point, writeable),
    (accept_per_update_point, writeable),
    (buffer_transaction, writeable),
    (buffer_script_pubkey, writeable),
    (temporary_channel_id, writeable),
    (channel_id, writeable),
    (accept_per_update_seed, writeable),
    (accept_buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (counter_party, writeable),
    (reference_id, option)
});
impl_dlc_writeable!(SignedChannel, {
    (channel_id, writeable),
    (counter_party, writeable),
    (temporary_channel_id, writeable),
    (fund_output_index, usize),
    (own_points, writeable),
    (own_params, { cb_writeable, dlc_messages::ser_impls::party_params::write, dlc_messages::ser_impls::party_params::read }),
    (own_per_update_point, writeable),
    (counter_points, writeable),
    (counter_per_update_point, writeable),
    (counter_params, { cb_writeable, dlc_messages::ser_impls::party_params::write, dlc_messages::ser_impls::party_params::read }),
    (state, writeable),
    (update_idx, writeable),
    (fund_tx, writeable),
    (fund_script_pubkey, writeable),
    (roll_back_state, option),
    (own_per_update_seed, writeable),
    (counter_party_commitment_secrets, writeable),
    (fee_rate_per_vb, writeable),
    (sub_channel_id, option),
    (reference_id, option)
});

impl_dlc_writeable_enum!(
    SignedChannelState,;
    (0, Established, {(signed_contract_id, writeable), (own_buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}), (counter_buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}), (buffer_transaction, writeable), (is_offer, writeable), (total_collateral, writeable)}),
    (1, SettledOffered, {(counter_payout, writeable), (next_per_update_point, writeable), (timeout, writeable)}),
    (2, SettledReceived, {(own_payout, writeable), (counter_next_per_update_point, writeable), (counter_payout, writeable)}),
    (3, SettledAccepted, {(counter_next_per_update_point, writeable), (own_next_per_update_point, writeable), (settle_tx, writeable), (own_settle_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}), (timeout, writeable), (own_payout, writeable), (counter_payout, writeable)}),
    (4, SettledConfirmed, {(settle_tx, writeable), (counter_settle_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}), (own_settle_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}), (counter_next_per_update_point, writeable), (own_next_per_update_point, writeable), (timeout, writeable), (own_payout, writeable), (counter_payout, writeable) }),
    (5, Settled, {(settle_tx, writeable), (counter_settle_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}), (own_settle_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}), (own_payout, writeable), (counter_payout, writeable)}),
    (6, RenewOffered, {(offered_contract_id, writeable), (counter_payout, writeable), (is_offer, writeable), (offer_next_per_update_point, writeable), (timeout, writeable)}),
    (7, RenewAccepted, {(contract_id, writeable), (offer_per_update_point, writeable), (accept_per_update_point, writeable), (buffer_transaction, writeable), (buffer_script_pubkey, writeable), (timeout, writeable), (own_payout, writeable)}),
    (8, RenewConfirmed, {(contract_id, writeable), (offer_per_update_point, writeable), (accept_per_update_point, writeable), (buffer_transaction, writeable), (buffer_script_pubkey, writeable), (offer_buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}), (timeout, writeable), (own_payout, writeable), (total_collateral, writeable)}),
    (10, RenewFinalized, {(contract_id, writeable), (prev_offer_per_update_point, writeable), (buffer_transaction, writeable), (buffer_script_pubkey, writeable), (offer_buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}), (accept_buffer_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}), (timeout, writeable), (own_payout, writeable), (total_collateral, writeable)}),
    (9, Closing, {(buffer_transaction, writeable), (contract_id, writeable), (is_initiator, writeable)}),
    (11, CollaborativeCloseOffered, { (counter_payout, writeable), (offer_signature, writeable), (close_tx, writeable), (timeout, writeable), (is_offer, writeable) }),
    (12, SettledClosing, {(settle_transaction, writeable), (is_offer, writeable), (is_initiator, writeable)})
    ;;
);

impl_dlc_writeable!(FailedAccept, {(temporary_channel_id, writeable), (error_message, {cb_writeable, write_string, read_string}), (accept_message, writeable), (counter_party, writeable), (reference_id, option)});
impl_dlc_writeable!(FailedSign, {(channel_id, writeable), (error_message, {cb_writeable, write_string, read_string}), (sign_message, writeable), (counter_party, writeable), (reference_id, option)});

impl_dlc_writeable!(ClosingChannel, {
    (channel_id, writeable),
    (counter_party, writeable),
    (temporary_channel_id, writeable),
    (rollback_state, option),
    (buffer_transaction, writeable),
    (contract_id, writeable),
    (is_closer, writeable),
    (reference_id, option)
});
impl_dlc_writeable!(SettledClosingChannel, {
    (channel_id, writeable),
    (counter_party, writeable),
    (temporary_channel_id, writeable),
    (rollback_state, option),
    (settle_transaction, writeable),
    (claim_transaction, writeable),
    (is_closer, writeable),
    (reference_id, option)
});
impl_dlc_writeable!(ClosedChannel, {(channel_id, writeable), (counter_party, writeable), (temporary_channel_id, writeable), (reference_id, option), (closing_txid, writeable)});
impl_dlc_writeable!(ClosedPunishedChannel, {(channel_id, writeable), (counter_party, writeable), (temporary_channel_id, writeable), (punish_txid, writeable), (reference_id, option)});
