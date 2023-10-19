use std::ops::Deref;

use dlc_messages::{oracle_msgs::OracleAnnouncement, sub_channel::SubChannelRenewOffer};
use lightning::{
    chain::chaininterface::FeeEstimator, ln::chan_utils::build_commitment_secret,
    sign::ChannelSigner,
};
use secp256k1_zkp::{PublicKey, SecretKey};

use crate::{
    channel::signed_channel::SignedChannel,
    contract::contract_input::ContractInput,
    error::Error,
    manager::{get_channel_in_state, Manager},
    sub_channel_manager::{get_sub_channel_in_state, SubChannelManager},
    subchannel::{
        self, LNChainMonitor, LNChannelManager, LnDlcChannelSigner, LnDlcSignerProvider,
        SubChannelState,
    },
    Blockchain, ChannelId, Oracle, Signer, Storage, Time, Wallet,
};

impl<
        W: Deref,
        M: Deref,
        C: Deref,
        S: Deref,
        B: Deref,
        O: Deref,
        T: Deref,
        F: Deref,
        D: Deref<Target = Manager<W, B, S, O, T, F>>,
        CS: ChannelSigner,
        SP: Deref,
        LCS: LnDlcChannelSigner,
    > SubChannelManager<W, M, C, S, B, O, T, F, D, CS, SP, LCS>
where
    W::Target: Wallet,
    M::Target: LNChannelManager<CS>,
    C::Target: LNChainMonitor,
    S::Target: Storage,
    B::Target: Blockchain,
    O::Target: Oracle,
    T::Target: Time,
    F::Target: FeeEstimator,
    SP::Target: LnDlcSignerProvider<LCS>,
{
    pub fn offer_subchannel_renew(
        &self,
        channel_id: &ChannelId,
        contract_input: &ContractInput,
    ) -> Result<(SubChannelRenewOffer, PublicKey)> {
        let (mut subchannel, prev_state) = get_sub_channel_in_state!(
            self.dlc_channel_manager,
            *channel_id,
            Signed,
            None::<PublicKey>
        )?;

        let per_split_seed_sk = {
            let per_split_seed_pk = subchannel
                .per_split_seed
                .expect("Should have a per split seed.");
            self.dlc_channel_manager
                .get_wallet()
                .get_secret_key_for_pubkey(&per_split_seed_pk)?
        };

        let next_per_split_secret = SecretKey::from_slice(&build_commitment_secret(
            per_split_seed_sk.as_ref(),
            subchannel.update_idx,
        ))
        .expect("A valid secret key.");

        let next_per_split_point =
            PublicKey::from_secret_key(self.dlc_channel_manager.get_secp(), &next_per_split_secret);

        let new_state = subchannel::RenewOffered {
            signed_subchannel: prev_state,
            offer_per_split_point: next_per_split_point,
        };

        // DLC channel renewal starts here
        {
            // TODO(lucas): Remove `counter_payout`, see
            // https://github.com/p2pderivatives/rust-dlc/issues/149.
            let counter_payout = 0;

            // We load the pre-existing DLC channel so that we can modify certain values
            // (basepoints) whilst keeping others!
            let mut signed_channel =
                get_channel_in_state!(self, channel_id, Signed, None as Option<PublicKey>)?;

            // Load oracle announcements based on the `ContractInput` like in `renew_offer`, unlike
            // in `offer_sub_channel`.
            //
            // TODO(lucas): Update `offer_sub_channel` API so that consumers don't have to pass in
            // their own oracle announcements, since they should match the `ContractInput` passed in
            // anyway.
            let oracle_announcements = contract_input
                .contract_infos
                .iter()
                .map(|x| {
                    self.dlc_channel_manager
                        .get_oracle_announcements(&x.oracles)
                })
                .collect::<Result<Vec<_>, Error>>()?;

            let SignedChannel {
                // Unchanged.
                channel_id,
                // Unchanged.
                counter_party,
                // Unchanged.
                temporary_channel_id,
                // Unchanged.
                own_points,
                // Unchanged.
                counter_points,
                // Unchanged.
                sub_channel_id,

                // Unchanged?
                own_per_update_seed,

                // May change. Let's not mess with this yet, because it's not designed to change
                // currently.
                fee_rate_per_vb,

                // EASY TO UPDATE FIELDS

                // Must change.
                state,
                // Must change.
                roll_back_state,

                // Must change.
                own_per_update_point,
                // Must change.
                counter_per_update_point,
                // Must change.
                update_idx,

                // Must change (towards the end of the protocol).
                counter_party_commitment_secrets,

                // HARD TO UPDATE FIELDS. This is because they are not designed to be updated.

                // Must change: `inputs`, `input_amounts` and `collateral`.
                own_params,
                // Must change: `inputs`, `input_amounts` and `collateral`.
                counter_params,

                // Must change.
                fund_tx,
                // Must change.
                fund_script_pubkey,
                // Must change (although probably still 0).
                fund_output_index,
            } = signed_channel;
        }

        let msg = SubChannelRenewOffer {
            channel_id: *channel_id,
            next_per_split_point,
            next_per_channel_point: renew_offer.next_per_update_point,
            contract_info: renew_offer.contract_info,
            offer_collateral,
            cet_locktime: todo!(),
            refund_locktime: todo!(),
            cet_nsequence: todo!(),
            fee_rate_per_vbyte: todo!(),
        };

        self.dlc_channel_manager
            .get_store()
            .upsert_sub_channel(&new_state);

        Ok((msg, subchannel.counter_party))
    }
}
