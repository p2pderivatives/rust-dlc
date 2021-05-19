//!
//!
//!

use crate::digit_decomposition::group_by_ignoring_digits;
use crate::dlc_trie::DlcTrie;
use crate::dlc_trie_utils::get_adaptor_point_for_indexed_paths;
use crate::multi_trie::{MultiTrie, MultiTrieIterator};
use crate::{Error, OracleInfo, RangeInfo, RangePayout};
use bitcoin::{Script, Transaction};
use secp256k1::{
    ecdsa_adaptor::{AdaptorProof, AdaptorSignature},
    All, PublicKey, Secp256k1, SecretKey, Signing,
};

///
#[derive(Clone)]
pub struct MultiOracleTrieWithDiff {
    ///
    pub multi_trie: MultiTrie<RangeInfo>,
    base: usize,
    nb_digits: usize,
}

impl MultiOracleTrieWithDiff {
    ///
    pub fn new(
        base: usize,
        nb_oracles: usize,
        threshold: usize,
        nb_digits: usize,
        min_support_exp: usize,
        max_error_exp: usize,
    ) -> Self {
        let multi_trie = MultiTrie::new(
            nb_oracles,
            threshold,
            base,
            min_support_exp,
            max_error_exp,
            nb_digits,
            true,
        );
        MultiOracleTrieWithDiff {
            multi_trie,
            base,
            nb_digits,
        }
    }
}

impl DlcTrie for MultiOracleTrieWithDiff {
    fn generate<C: Signing, F>(
        &mut self,
        secp: &Secp256k1<C>,
        outcomes: &[RangePayout],
        oracle_infos: &[OracleInfo],
        callback: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(usize, &PublicKey) -> Result<usize, Error>,
    {
        let mut cet_index = 0;

        for outcome in outcomes {
            let groups = group_by_ignoring_digits(
                outcome.start,
                outcome.start + outcome.count - 1,
                self.base,
                self.nb_digits,
            )
            .unwrap();
            for group in groups {
                let mut get_value = |paths: &Vec<Vec<usize>>,
                                     oracle_indexes: &Vec<usize>|
                 -> Result<RangeInfo, Error> {
                    let adaptor_point = get_adaptor_point_for_indexed_paths(
                        &secp,
                        &oracle_infos,
                        oracle_indexes,
                        paths,
                    )?;
                    let adaptor_index = callback(cet_index, &adaptor_point)?;
                    let range_info = RangeInfo {
                        cet_index,
                        adaptor_index,
                    };
                    Ok(range_info)
                };
                self.multi_trie.insert(&group, &mut get_value)?;
            }
            cet_index += 1;
        }
        Ok(())
    }

    ///
    fn iter<F>(
        &self,
        secp: &Secp256k1<All>,
        oracle_infos: &[OracleInfo],
        callback: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(&PublicKey, &RangeInfo) -> Result<(), Error>,
    {
        let m_trie_iter = MultiTrieIterator::new(&self.multi_trie);

        for res in m_trie_iter {
            let (oracle_indexes, paths) =
                res.path
                    .iter()
                    .fold((Vec::new(), Vec::new()), |(mut indexes, mut paths), x| {
                        indexes.push(x.0);
                        paths.push(x.1.clone());
                        (indexes, paths)
                    });
            let adaptor_point =
                get_adaptor_point_for_indexed_paths(secp, oracle_infos, &oracle_indexes, &paths)?;
            callback(&adaptor_point, &res.value)?;
        }
        Ok(())
    }

    fn sign(
        &self,
        secp: &Secp256k1<All>,
        fund_privkey: &SecretKey,
        funding_script_pubkey: &Script,
        fund_output_value: u64,
        cets: &[Transaction],
        oracle_infos: &[OracleInfo],
    ) -> Result<Vec<(AdaptorSignature, AdaptorProof)>, Error> {
        let mut adaptor_pairs = Vec::<(usize, (AdaptorSignature, AdaptorProof))>::new();
        let mut callback =
            |adaptor_point: &PublicKey, range_info: &RangeInfo| -> Result<(), Error> {
                let adaptor_pair = crate::create_cet_adaptor_sig_from_point(
                    &secp,
                    &cets[range_info.cet_index],
                    &adaptor_point,
                    fund_privkey,
                    &funding_script_pubkey,
                    fund_output_value,
                )?;

                adaptor_pairs.push((range_info.adaptor_index, adaptor_pair));

                Ok(())
            };
        self.iter(secp, oracle_infos, &mut callback)?;
        adaptor_pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        Ok(adaptor_pairs.into_iter().map(|x| x.1).collect())
    }
}
