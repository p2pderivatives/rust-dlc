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

use bitcoin::{Script, Transaction};
use dlc::{Error, RangePayout};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use secp256k1_zkp::{All, EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey};
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

#[derive(PartialEq, Debug, Clone)]
/// Structure that stores the indexes at which the CET and adaptor signature
/// related to a given outcome are located in CET and adaptor signatures arrays
/// respectively.
pub struct RangeInfo {
    /// a cet index
    pub cet_index: usize,
    /// an adaptor signature index
    pub adaptor_index: usize,
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
        adaptor_index_start: usize,
        outcomes: &[RangePayout],
    ) -> Result<Vec<TrieIterInfo>, Error>;

    /// Returns an iterator to this trie.
    fn iter(&'a self) -> TrieIterator;

    /// Generate the trie while verifying the provided adaptor signatures.
    fn generate_verify(
        &'a mut self,
        secp: &Secp256k1<secp256k1_zkp::All>,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        outcomes: &[RangePayout],
        cets: &[Transaction],
        precomputed_points: &[Vec<Vec<PublicKey>>],
        adaptor_sigs: &[EcdsaAdaptorSignature],
        adaptor_index_start: usize,
    ) -> Result<usize, Error> {
        let trie_info = self.generate(adaptor_index_start, outcomes)?;
        verify_helper(
            secp,
            cets,
            adaptor_sigs,
            fund_pubkey,
            funding_script_pubkey,
            fund_output_value,
            precomputed_points,
            trie_info.into_iter(),
        )
    }

    /// Generate the trie while creating the set of adaptor signatures.
    fn generate_sign(
        &'a mut self,
        secp: &Secp256k1<All>,
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        outcomes: &[RangePayout],
        cets: &[Transaction],
        precomputed_points: &[Vec<Vec<PublicKey>>],
        adaptor_index_start: usize,
    ) -> Result<Vec<EcdsaAdaptorSignature>, Error> {
        let trie_info = self.generate(adaptor_index_start, outcomes)?;
        sign_helper(
            secp,
            cets,
            fund_privkey,
            funding_script_pubkey,
            fund_output_value,
            precomputed_points,
            trie_info.into_iter(),
        )
    }

    /// Verify that the provided signatures are valid with respect to the
    /// information stored in the trie.
    fn verify(
        &'a self,
        secp: &Secp256k1<All>,
        fund_pubkey: &PublicKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        adaptor_sigs: &[EcdsaAdaptorSignature],
        cets: &[Transaction],
        precomputed_points: &[Vec<Vec<PublicKey>>],
    ) -> Result<usize, Error> {
        verify_helper(
            secp,
            cets,
            adaptor_sigs,
            fund_pubkey,
            funding_script_pubkey,
            fund_output_value,
            precomputed_points,
            self.iter(),
        )
    }

    /// Produce the set of adaptor signatures for the trie.
    fn sign(
        &'a self,
        secp: &Secp256k1<All>,
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        precomputed_points: &[Vec<Vec<PublicKey>>],
    ) -> Result<Vec<EcdsaAdaptorSignature>, Error> {
        let trie_info = self.iter();
        sign_helper(
            secp,
            cets,
            fund_privkey,
            funding_script_pubkey,
            fund_output_value,
            precomputed_points,
            trie_info,
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
fn sign_helper<T: Iterator<Item = TrieIterInfo>>(
    secp: &Secp256k1<All>,
    cets: &[Transaction],
    fund_privkey: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    precomputed_points: &[Vec<Vec<PublicKey>>],
    trie_info: T,
) -> Result<Vec<EcdsaAdaptorSignature>, Error> {
    let mut unsorted = trie_info
        .map(|x| {
            let adaptor_point = utils::get_adaptor_point_for_indexed_paths(
                &x.indexes,
                &x.paths,
                precomputed_points,
            )?;
            let adaptor_sig = dlc::create_cet_adaptor_sig_from_point(
                secp,
                &cets[x.value.cet_index],
                &adaptor_point,
                fund_privkey,
                funding_script_pubkey,
                fund_output_value,
            )?;
            Ok((x.value.adaptor_index, adaptor_sig))
        })
        .collect::<Result<Vec<(usize, EcdsaAdaptorSignature)>, Error>>()?;
    unsorted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    Ok(unsorted.into_iter().map(|(_, y)| y).collect())
}

#[cfg(feature = "parallel")]
fn sign_helper<T: Iterator<Item = TrieIterInfo>>(
    secp: &Secp256k1<All>,
    cets: &[Transaction],
    fund_privkey: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    precomputed_points: &[Vec<Vec<PublicKey>>],
    trie_info: T,
) -> Result<Vec<EcdsaAdaptorSignature>, Error> {
    let trie_info: Vec<TrieIterInfo> = trie_info.collect();
    let mut unsorted = trie_info
        .par_iter()
        .map(|x| {
            let adaptor_point = utils::get_adaptor_point_for_indexed_paths(
                &x.indexes,
                &x.paths,
                precomputed_points,
            )?;
            let adaptor_sig = dlc::create_cet_adaptor_sig_from_point(
                secp,
                &cets[x.value.cet_index],
                &adaptor_point,
                fund_privkey,
                funding_script_pubkey,
                fund_output_value,
            )?;
            Ok((x.value.adaptor_index, adaptor_sig))
        })
        .collect::<Result<Vec<(usize, EcdsaAdaptorSignature)>, Error>>()?;
    unsorted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    Ok(unsorted.into_iter().map(|(_, y)| y).collect())
}

#[cfg(not(feature = "parallel"))]
fn verify_helper<T: Iterator<Item = TrieIterInfo>>(
    secp: &Secp256k1<All>,
    cets: &[Transaction],
    adaptor_sigs: &[EcdsaAdaptorSignature],
    fund_pubkey: &PublicKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    precomputed_points: &[Vec<Vec<PublicKey>>],
    trie_info: T,
) -> Result<usize, Error> {
    let mut max_adaptor_index = 0;
    for x in trie_info {
        let adaptor_point =
            utils::get_adaptor_point_for_indexed_paths(&x.indexes, &x.paths, precomputed_points)?;
        let adaptor_sig = adaptor_sigs[x.value.adaptor_index];
        let cet = &cets[x.value.cet_index];
        if x.value.adaptor_index > max_adaptor_index {
            max_adaptor_index = x.value.adaptor_index;
        }
        dlc::verify_cet_adaptor_sig_from_point(
            secp,
            &adaptor_sig,
            cet,
            &adaptor_point,
            fund_pubkey,
            funding_script_pubkey,
            fund_output_value,
        )?;
    }
    Ok(max_adaptor_index + 1)
}

#[cfg(feature = "parallel")]
fn verify_helper<T: Iterator<Item = TrieIterInfo>>(
    secp: &Secp256k1<All>,
    cets: &[Transaction],
    adaptor_sigs: &[EcdsaAdaptorSignature],
    fund_pubkey: &PublicKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    precomputed_points: &[Vec<Vec<PublicKey>>],
    trie_info: T,
) -> Result<usize, Error> {
    let trie_info: Vec<TrieIterInfo> = trie_info.collect();
    let max_adaptor_index = trie_info
        .iter()
        .max_by(|x, y| x.value.adaptor_index.cmp(&y.value.adaptor_index))
        .unwrap();
    trie_info.par_iter().try_for_each(|x| {
        let adaptor_point =
            utils::get_adaptor_point_for_indexed_paths(&x.indexes, &x.paths, precomputed_points)?;
        let adaptor_sig = adaptor_sigs[x.value.adaptor_index];
        let cet = &cets[x.value.cet_index];
        dlc::verify_cet_adaptor_sig_from_point(
            secp,
            &adaptor_sig,
            cet,
            &adaptor_point,
            fund_pubkey,
            funding_script_pubkey,
            fund_output_value,
        )
    })?;

    Ok(max_adaptor_index.value.adaptor_index + 1)
}
