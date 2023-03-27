//! Serialization of DLC on Lightning related data structures.
use dlc::channel::sub_channel::SplitTx;
use dlc_messages::ser_impls::{read_ecdsa_adaptor_signature, write_ecdsa_adaptor_signature};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};

use super::{
    AcceptedSubChannel, CloseAcceptedSubChannel, CloseConfirmedSubChannel, CloseOfferedSubChannel,
    ClosingSubChannel, OfferedSubChannel, SignedSubChannel, SubChannel, SubChannelState,
};

impl_dlc_writeable!(SubChannel, {
    (channel_id, writeable),
    (counter_party, writeable),
    (update_idx, writeable),
    (state, writeable),
    (per_split_seed, option),
    (fee_rate_per_vb, writeable),
    (own_base_points, writeable),
    (counter_base_points, option),
    (fund_value_satoshis, writeable),
    (original_funding_redeemscript, writeable),
    (is_offer, writeable),
    (own_fund_pk, writeable),
    (counter_fund_pk, writeable),
    (counter_party_secrets, writeable)
});

impl_dlc_writeable_enum!(SubChannelState,
    (0, Offered),
    (1, Accepted),
    (2, Confirmed),
    (3, Signed),
    (4, Closing),
    (5, CloseOffered),
    (6, CloseAccepted),
    (7, CloseConfirmed),
    (8, ClosedPunished)
    ;;;
    (9, OnChainClosed),
    (10, CounterOnChainClosed),
    (11, OffChainClosed),
    (12, Rejected)
);

impl_dlc_writeable!(OfferedSubChannel, { (per_split_point, writeable) });

impl_dlc_writeable_external!(SplitTx, split_tx, {(transaction, writeable), (output_script, writeable)});

impl_dlc_writeable!(AcceptedSubChannel, {
    (offer_per_split_point, writeable),
    (accept_per_split_point, writeable),
    (accept_split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (split_tx, {cb_writeable, split_tx::write, split_tx::read}),
    (ln_glue_transaction, writeable)
});

impl_dlc_writeable!(SignedSubChannel, {
    (own_per_split_point, writeable),
    (counter_per_split_point, writeable),
    (own_split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (counter_split_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
    (split_tx, {cb_writeable, split_tx::write, split_tx::read}),
    (ln_glue_transaction, writeable),
    (counter_glue_signature, writeable)
});

impl_dlc_writeable!(CloseOfferedSubChannel, {
    (signed_subchannel, writeable),
    (offer_balance, writeable),
    (accept_balance, writeable)
});

impl_dlc_writeable!(CloseAcceptedSubChannel, { (signed_subchannel, writeable), (own_balance, writeable) });

impl_dlc_writeable!(CloseConfirmedSubChannel, { (signed_subchannel, writeable), (own_balance, writeable) });

impl_dlc_writeable!(ClosingSubChannel, { (signed_sub_channel, writeable) });
