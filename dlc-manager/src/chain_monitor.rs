//! This module includes the [`ChainMonitor`] struct that helps watching the blockchain for
//! transactions of interest in the context of DLC.

use std::collections::HashMap;

use bitcoin::{Block, Transaction, Txid};
use dlc_messages::ser_impls::{
    read_ecdsa_adaptor_signature, read_hash_map, write_ecdsa_adaptor_signature, write_hash_map,
};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::EcdsaAdaptorSignature;

use crate::ChannelId;

/// A `ChainMonitor` keeps a list of transaction ids to watch for in the blockchain,
/// and some associated information used to apply an action when the id is seen.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainMonitor {
    pub(crate) watched_tx: HashMap<Txid, ChannelInfo>,
    pub(crate) last_height: u64,
}

impl_dlc_writeable!(ChainMonitor, { (watched_tx, { cb_writeable, write_hash_map, read_hash_map}), (last_height, writeable) });

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChannelInfo {
    pub channel_id: ChannelId,
    pub tx_type: TxType,
}

impl_dlc_writeable!(ChannelInfo, { (channel_id, writeable), (tx_type, writeable) });

#[derive(Clone, Debug, PartialEq, Eq)]
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
}

impl_dlc_writeable_enum!(TxType,;
    (0, Revoked, {
        (update_idx, writeable),
        (own_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
        (is_offer, writeable),
        (revoked_tx_type, writeable)
    });;
    (1, BufferTx), (2, CollaborativeClose), (3, SplitTx), (4, SettleTx)
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
            last_height: init_height,
        }
    }

    /// Returns true if the monitor doesn't contain any transaction to be watched.
    pub fn is_empty(&self) -> bool {
        self.watched_tx.is_empty()
    }

    pub(crate) fn add_tx(&mut self, txid: Txid, channel_info: ChannelInfo) {
        self.watched_tx.insert(txid, channel_info);
    }

    pub(crate) fn remove_tx(&mut self, txid: &Txid) {
        self.watched_tx.remove(txid);
    }

    pub(crate) fn cleanup_channel(&mut self, channel_id: ChannelId) {
        let to_remove = self
            .watched_tx
            .iter()
            .filter_map(|x| {
                if x.1.channel_id == channel_id {
                    Some(*x.0)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for txid in to_remove {
            self.watched_tx.remove(&txid);
        }
    }

    pub(crate) fn process_block(
        &self,
        block: &Block,
        height: u64,
    ) -> Vec<(Transaction, ChannelInfo)> {
        let mut res = Vec::new();

        assert_eq!(self.last_height + 1, height);

        for tx in &block.txdata {
            let channel_info = self.watched_tx.get(&tx.txid()).or_else(|| {
                for txid in tx.input.iter().map(|x| &x.previous_output.txid) {
                    let info = self.watched_tx.get(txid);
                    if info.is_some() {
                        return info;
                    }
                }
                None
            });
            if let Some(channel_info) = channel_info {
                res.push((tx.clone(), channel_info.clone()));
            }
        }

        res
    }

    /// To be safe this is a separate function from process block to make sure updates are
    /// saved before we update the state. It is better to re-process a block than not
    /// process it at all.
    pub(crate) fn increment_height(&mut self) {
        self.last_height += 1;
    }
}
