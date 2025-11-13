//! # Dlc-trie
//! Package for storing and retrieving DLC data using tries.

#![crate_name = "dlc_trie"]
// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

extern crate bitcoin;
extern crate dlc;
#[cfg(feature = "parallel")]
extern crate rayon;
extern crate secp256k1_zkp;
#[cfg(feature = "use-serde")]
extern crate serde;

use bitcoin::{Script, ScriptBuf};
use dlc::{Error, RangePayout};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use secp256k1_zkp::PublicKey;
#[cfg(feature = "use-serde")]
use serde::{Deserialize, Serialize};

pub mod combination_iterator;
pub mod digit_decomposition;
pub mod digit_trie;
pub mod multi_oracle;
pub mod multi_oracle_trie;
pub mod multi_oracle_trie_with_diff;
pub mod multi_trie;
#[cfg(test)]
mod test_utils;
mod utils;

pub(crate) type IndexedPath = (usize, Vec<usize>);

/// Structure containing a reference to a looked-up value and the
/// path at which it was found.
#[derive(Debug, Clone)]
pub struct LookupResult<'a, TValue, TPath> {
    /// The path at which the `value` was found.
    pub path: Vec<TPath>,
    /// The value that was returned.
    pub value: &'a TValue,
}

/// Enum representing the different type of nodes in a tree
#[derive(Debug, Clone)]
pub enum Node<TLeaf, TNode> {
    /// None is only used as a placeholder when taking mutable ownership of a
    /// node during insertion.
    None,
    /// A leaf is a node in the tree that does not have any children.
    Leaf(TLeaf),
    /// A node is parent to at least one other node in a tree.
    Node(TNode),
}

#[derive(Eq, PartialEq, Debug, Clone)]
/// Structure that stores the indexes at which the script
/// related to a given outcome is located in the script array
pub struct RangeInfo {
    /// the script index
    pub script_index: usize,
    /// the payout index
    pub payout_index: usize,
}

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "use-serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase")
)]
/// Information about the base and number of digits used by the oracle.
pub struct OracleNumericInfo {
    /// The base in which the oracle will represent the outcome value.
    pub base: usize,
    /// The number of digits that each oracle will use to represent the outcome value.
    pub nb_digits: Vec<usize>,
}

impl OracleNumericInfo {
    /// Return the minimum number of digits supported by an oracle in the group.
    pub fn get_min_nb_digits(&self) -> usize {
        *self.nb_digits.iter().min().unwrap()
    }

    /// Returns whether oracles have varying number of digits.
    pub fn has_diff_nb_digits(&self) -> bool {
        self.nb_digits
            .iter()
            .skip(1)
            .any(|x| *x != self.nb_digits[0])
    }
}

/// A common trait for trie data structures that store DLC adaptor signature
/// information.
pub trait DlcTrie<'a, TrieIterator: Iterator<Item = TrieIterInfo>> {
    /// Generate the trie using the provided outcomes and oracle information,
    /// calling the provided callback with the CET index and adaptor point for
    /// each adaptor signature.
    fn generate(
        &'a mut self,
        index_start: usize,
        outcomes: &[RangePayout],
    ) -> Result<Vec<TrieIterInfo>, Error>;

    /// Returns an iterator to this trie.
    fn iter(&'a self) -> TrieIterator;

    /// Generate the trie and generate the scripts
    fn generate_scripts(
        &'a mut self,
        offer_spk: &Script,
        accept_spk: &Script,
        outcomes: &[RangePayout],
        precomputed_points: &[Vec<Vec<PublicKey>>],
        index_start: usize,
    ) -> Result<Vec<ScriptBuf>, Error> {
        let trie_info = self.generate(index_start, outcomes)?;
        script_helper(
            offer_spk,
            accept_spk,
            outcomes,
            precomputed_points,
            trie_info.into_iter(),
        )
    }
}

#[derive(Debug)]
/// Holds information provided when iterating a DlcTrie.
pub struct TrieIterInfo {
    indexes: Vec<usize>,
    paths: Vec<Vec<usize>>,
    value: RangeInfo,
}

#[cfg(not(feature = "parallel"))]
fn script_helper<T: Iterator<Item = TrieIterInfo>>(
    offer_spk: &Script,
    accept_spk: &Script,
    payouts: &[RangePayout],
    precomputed_points: &[Vec<Vec<PublicKey>>],
    trie_info: T,
) -> Result<Vec<ScriptBuf>, Error> {
    let mut unsorted = trie_info
        .map(|x| {
            use bitcoin::XOnlyPublicKey;

            use dlc::opcat_utils::vault_dlc_withdrawal;

            let adaptor_point = utils::get_adaptor_point_for_indexed_paths(
                &x.indexes,
                &x.paths,
                precomputed_points,
            )?;
            let payout = &payouts[x.value.payout_index];
            let outputs = dlc::get_payout_outputs(&payout.payout, offer_spk, accept_spk);
            let pubkey: XOnlyPublicKey = adaptor_point.into();
            let script = vault_dlc_withdrawal(&outputs, pubkey);
            Ok((x.value.script_index, script))
        })
        .collect::<Result<Vec<(usize, ScriptBuf)>, Error>>()?;
    unsorted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    Ok(unsorted.into_iter().map(|(_, y)| y).collect())
}

#[cfg(feature = "parallel")]
fn script_helper<T: Iterator<Item = TrieIterInfo>>(
    offer_spk: &Script,
    accept_spk: &Script,
    payouts: &[RangePayout],
    precomputed_points: &[Vec<Vec<PublicKey>>],
    trie_info: T,
) -> Result<Vec<ScriptBuf>, Error> {
    let trie_info: Vec<TrieIterInfo> = trie_info.collect();
    let mut unsorted = trie_info
        .par_iter()
        .map(|x| {
            use bitcoin::XOnlyPublicKey;

            use dlc::opcat_utils::vault_dlc_withdrawal;

            let adaptor_point = utils::get_adaptor_point_for_indexed_paths(
                &x.indexes,
                &x.paths,
                precomputed_points,
            )?;
            let payout = &payouts[x.value.payout_index];
            let outputs = dlc::get_payout_outputs(&payout.payout, offer_spk, accept_spk);
            let pubkey: XOnlyPublicKey = adaptor_point.into();
            let script = vault_dlc_withdrawal(&outputs, pubkey);
            Ok((x.value.script_index, script))
        })
        .collect::<Result<Vec<(usize, ScriptBuf)>, Error>>()?;
    unsorted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    Ok(unsorted.into_iter().map(|(_, y)| y).collect())
}
