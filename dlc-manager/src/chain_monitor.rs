//!

use std::collections::HashMap;

use bitcoin::{Block, BlockHash, Transaction, Txid};
use dlc_messages::ser_impls::{
    read_ecdsa_adaptor_signature, read_vec, write_ecdsa_adaptor_signature, write_vec,
};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::EcdsaAdaptorSignature;

use crate::ChannelId;

const NB_SAVED_BLOCK_HASHES: usize = 6;

/// A `ChainMonitor` keeps a list of transaction ids to watch for in the blockchain,
/// and some associated information used to apply an action when the id is seen.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainMonitor {
    watched_tx: HashMap<Txid, ChannelInfo>,
    pub(crate) last_height: u64,
    pub(crate) last_block_hashes: Vec<BlockHash>,
}

impl_dlc_writeable!(ChainMonitor, { (watched_tx, writeable), (last_height, writeable), (last_block_hashes, { cb_writeable, write_vec, read_vec}) });

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
    Current,
    CollaborativeClose,
}

impl_dlc_writeable_enum!(TxType,;
    (0, Revoked, {
        (update_idx, writeable),
        (own_adaptor_signature, {cb_writeable, write_ecdsa_adaptor_signature, read_ecdsa_adaptor_signature}),
        (is_offer, writeable),
        (revoked_tx_type, writeable)
    });;
    (1, Current), (2, CollaborativeClose)
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RevokedTxType {
    Buffer,
    Settle,
}

impl_dlc_writeable_enum!(RevokedTxType,;;;(0, Buffer), (1, Settle));

impl ChainMonitor {
    /// Returns a new [`ChainMonitor`] with fields properly initialized.
    pub fn new(init_height: u64) -> Self {
        ChainMonitor {
            watched_tx: HashMap::new(),
            last_height: init_height,
            last_block_hashes: Vec::with_capacity(NB_SAVED_BLOCK_HASHES),
        }
    }

    pub(crate) fn add_tx(&mut self, txid: Txid, channel_info: ChannelInfo) {
        self.watched_tx.insert(txid, channel_info);
    }

    pub(crate) fn remove_tx(&mut self, txid: &Txid) {
        self.watched_tx.remove(txid);
    }

    pub(crate) fn process_block(
        &self,
        block: &Block,
        height: u64,
    ) -> Vec<(Transaction, ChannelInfo)> {
        let mut res = Vec::new();

        assert_eq!(self.last_height + 1, height);

        for tx in &block.txdata {
            let txid = tx.txid();
            if self.watched_tx.contains_key(&txid) {
                let channel_info = self
                    .watched_tx
                    .get(&txid)
                    .expect("to be able to retrieve the channel info");
                res.push((tx.clone(), channel_info.clone()));
            }
        }

        res
    }

    /// To be safe this is a separate function from process block to make sure updates are
    /// saved before we update the state. It is better to re-process a block than not
    /// process it at all.
    pub(crate) fn increment_height(&mut self, last_block_hash: &BlockHash) {
        self.last_height += 1;
        self.last_block_hashes.push(*last_block_hash);
        if self.last_block_hashes.len() > NB_SAVED_BLOCK_HASHES {
            self.last_block_hashes.remove(0);
        }
    }
}
