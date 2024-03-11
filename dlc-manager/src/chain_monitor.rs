//! This module includes the [`ChainMonitor`] struct that helps watching the blockchain for
//! transactions of interest in the context of DLC.

use std::collections::HashMap;
use std::ops::Deref;

use bitcoin::{OutPoint, Transaction, Txid};
use dlc_messages::ser_impls::{
    read_ecdsa_adaptor_signature, read_hash_map, write_ecdsa_adaptor_signature, write_hash_map,
};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::EcdsaAdaptorSignature;

use crate::Blockchain;

/// A `ChainMonitor` keeps a list of transaction ids to watch for in the blockchain,
/// and some associated information used to apply an action when the id is seen.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainMonitor {
    pub(crate) watched_tx: HashMap<Txid, WatchState>,
    pub(crate) watched_txo: HashMap<OutPoint, WatchState>,
    pub(crate) last_height: u64,
}

impl_dlc_writeable!(ChainMonitor, { (watched_tx, { cb_writeable, write_hash_map, read_hash_map}), (watched_txo, { cb_writeable, write_hash_map, read_hash_map}), (last_height, writeable) });

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChannelInfo {
    /// The identifier for _either_ a Lightning channel or a DLC channel.
    pub channel_id: [u8; 32],
    pub tx_type: TxType,
}

impl_dlc_writeable!(ChannelInfo, { (channel_id, writeable), (tx_type, writeable) });

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxType {
    Revoked {
        update_idx: u64,
        own_adaptor_signature: EcdsaAdaptorSignature,
        is_offer: bool,
        revoked_tx_type: RevokedTxType,
    },
    BufferTx,
    CollaborativeClose,
    SplitTx,
    SettleTx,
    Cet,
}

impl_dlc_writeable_enum!(TxType,;
    (0, Revoked, {
        (update_idx, writeable),
        (own_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
        (is_offer, writeable),
        (revoked_tx_type, writeable)
    });;
    (1, BufferTx), (2, CollaborativeClose), (3, SplitTx), (4, SettleTx), (5, Cet)
);

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub(crate) enum RevokedTxType {
    Buffer,
    Settle,
    Split,
}

impl_dlc_writeable_enum!(RevokedTxType,;;;(0, Buffer), (1, Settle), (2, Split));

impl ChainMonitor {
    /// Returns a new [`ChainMonitor`] with fields properly initialized.
    pub fn new(init_height: u64) -> Self {
        ChainMonitor {
            watched_tx: HashMap::new(),
            watched_txo: HashMap::new(),
            last_height: init_height,
        }
    }

    /// Returns true if the monitor doesn't contain any transaction to be watched.
    pub fn is_empty(&self) -> bool {
        self.watched_tx.is_empty()
    }

    pub(crate) fn add_tx(&mut self, txid: Txid, channel_info: ChannelInfo) {
        log::debug!("Watching transaction {txid}: {channel_info:?}");
        self.watched_tx.insert(txid, WatchState::new(channel_info));

        // When we watch a buffer transaction we also want to watch
        // the buffer transaction _output_ so that we can detect when
        // a CET spends it without having to watch every possible CET
        if channel_info.tx_type == TxType::BufferTx {
            let outpoint = OutPoint {
                txid,
                // We can safely assume that the buffer transaction
                // only has one output
                vout: 0,
            };
            self.add_txo(
                outpoint,
                ChannelInfo {
                    channel_id: channel_info.channel_id,
                    tx_type: TxType::Cet,
                },
            );
        }
    }

    fn add_txo(&mut self, outpoint: OutPoint, channel_info: ChannelInfo) {
        log::debug!("Watching transaction output {outpoint}: {channel_info:?}");
        self.watched_txo
            .insert(outpoint, WatchState::new(channel_info));
    }

    pub(crate) fn cleanup_channel(&mut self, channel_id: [u8; 32]) {
        log::debug!("Cleaning up data related to channel {channel_id:?}");

        self.watched_tx
            .retain(|_, state| state.channel_id() != channel_id);

        self.watched_txo
            .retain(|_, state| state.channel_id() != channel_id);
    }

    pub(crate) fn remove_tx(&mut self, txid: &Txid) {
        log::debug!("Stopped watching transaction {txid}");
        self.watched_tx.remove(txid);
    }

    /// Check if any watched transactions have been confirmed.
    pub(crate) fn check_transactions<B>(&mut self, blockchain: &B)
    where
        B: Deref,
        B::Target: Blockchain,
    {
        for (txid, state) in self.watched_tx.iter_mut() {
            let confirmations = match blockchain.get_transaction_confirmations(txid) {
                Ok(confirmations) => confirmations,
                Err(e) => {
                    log::error!("Failed to get transaction confirmations for {txid}: {e}");
                    continue;
                }
            };

            if confirmations > 0 {
                let tx = match blockchain.get_transaction(txid) {
                    Ok(tx) => tx,
                    Err(e) => {
                        log::error!("Failed to get transaction for {txid}: {e}");
                        continue;
                    }
                };

                state.confirm(tx.clone());
            }
        }

        for (txo, state) in self.watched_txo.iter_mut() {
            let (confirmations, txid) = match blockchain.get_txo_confirmations(txo) {
                Ok(Some((confirmations, txid))) => (confirmations, txid),
                Ok(None) => continue,
                Err(e) => {
                    log::error!("Failed to get transaction confirmations for {txo}: {e}");
                    continue;
                }
            };

            if confirmations > 0 {
                let tx = match blockchain.get_transaction(&txid) {
                    Ok(tx) => tx,
                    Err(e) => {
                        log::error!("Failed to get transaction for {txid}: {e}");
                        continue;
                    }
                };

                state.confirm(tx.clone());
            }
        }
    }

    /// All the currently watched transactions which have been confirmed.
    pub(crate) fn confirmed_txs(&self) -> Vec<(Transaction, ChannelInfo)> {
        (self.watched_tx.values())
            .chain(self.watched_txo.values())
            .filter_map(|state| match state {
                WatchState::Registered { .. } => None,
                WatchState::Confirmed {
                    channel_info,
                    transaction,
                } => Some((transaction.clone(), *channel_info)),
            })
            .collect()
    }
}

/// The state of a watched transaction or transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WatchState {
    /// It has been registered but we are not aware of any
    /// confirmations.
    Registered { channel_info: ChannelInfo },
    /// It has received at least one confirmation.
    Confirmed {
        channel_info: ChannelInfo,
        transaction: Transaction,
    },
}

impl_dlc_writeable_enum!(
    WatchState,;
    (0, Registered, {(channel_info, writeable)}),
    (1, Confirmed, {(channel_info, writeable), (transaction, writeable)});;
);

impl WatchState {
    fn new(channel_info: ChannelInfo) -> Self {
        Self::Registered { channel_info }
    }

    fn confirm(&mut self, transaction: Transaction) {
        match self {
            WatchState::Registered { ref channel_info } => {
                log::info!(
                    "Transaction {} confirmed: {channel_info:?}",
                    transaction.txid()
                );

                *self = WatchState::Confirmed {
                    channel_info: *channel_info,
                    transaction,
                }
            }
            WatchState::Confirmed {
                channel_info,
                transaction,
            } => {
                log::error!(
                    "Transaction {} already confirmed: {channel_info:?}",
                    transaction.txid()
                );
            }
        }
    }

    fn channel_info(&self) -> ChannelInfo {
        match self {
            WatchState::Registered { channel_info }
            | WatchState::Confirmed { channel_info, .. } => *channel_info,
        }
    }

    fn channel_id(&self) -> [u8; 32] {
        self.channel_info().channel_id
    }
}
