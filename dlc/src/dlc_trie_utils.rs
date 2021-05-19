//! Utility functions when working with DLC trie

use super::{Error, OracleInfo, RangeInfo, RangePayout};
use bitcoin::hashes::*;
use bitcoin::{Script, Transaction};
use combination_iterator::CombinationIterator;
use digit_decomposition::group_by_ignoring_digits;
use digit_trie::{DigitTrie, DigitTrieIter};
use multi_trie::{MultiTrie, MultiTrieIterator};
use secp256k1::ecdsa_adaptor::{AdaptorProof, AdaptorSignature};
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Signing};

///
pub type MultiOracleTrie = DigitTrie<Vec<RangeInfo>>;

///
pub type MultiOracleTrieWithDiff = MultiTrie<RangeInfo>;

///
pub fn generate_trie_no_diff_sign<C: Signing>(
    secp: &Secp256k1<C>,
    fund_privkey: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    nb_oracles: usize,
    nb_required: usize,
    base: usize,
    nb_digits: usize,
    outcomes: &[RangePayout],
    cets: &[Transaction],
    oracle_infos: &[OracleInfo],
    adaptor_index_start: usize,
) -> Result<
    (
        DigitTrie<Vec<RangeInfo>>,
        Vec<(AdaptorSignature, AdaptorProof)>,
    ),
    Error,
> {
    let mut adaptor_index = adaptor_index_start;
    let mut adaptor_pairs = Vec::new();
    let mut sign_callback =
        |cet_index: usize, adaptor_point: &PublicKey| -> Result<usize, crate::Error> {
            let adaptor_pair = crate::create_cet_adaptor_sig_from_point(
                &secp,
                &cets[cet_index],
                &adaptor_point,
                fund_privkey,
                &funding_script_pubkey,
                fund_output_value,
            )?;
            adaptor_pairs.push(adaptor_pair);
            adaptor_index += 1;
            Ok(adaptor_index - 1)
        };

    let trie = generate_trie_no_diff(
        secp,
        nb_oracles,
        nb_required,
        base,
        nb_digits,
        outcomes,
        oracle_infos,
        &mut sign_callback,
    )?;

    Ok((trie, adaptor_pairs))
}

///
pub fn generate_trie_no_diff_verify(
    secp: &Secp256k1<secp256k1::All>,
    fund_pubkey: &PublicKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    nb_oracles: usize,
    nb_required: usize,
    base: usize,
    nb_digits: usize,
    outcomes: &Vec<RangePayout>,
    cets: &[Transaction],
    oracle_infos: &[OracleInfo],
    adaptor_pairs: &[(AdaptorSignature, AdaptorProof)],
    adaptor_index_start: usize,
) -> Result<(DigitTrie<Vec<RangeInfo>>, usize), Error> {
    let mut adaptor_sig_index = adaptor_index_start;
    let mut verify_callback =
        |cet_index: usize, adaptor_point: &PublicKey| -> Result<usize, crate::Error> {
            let adaptor_pair = adaptor_pairs[adaptor_sig_index];
            let cet = &cets[cet_index];
            adaptor_sig_index += 1;
            super::verify_cet_adaptor_sig_from_point(
                secp,
                &adaptor_pair.0,
                &adaptor_pair.1,
                cet,
                &adaptor_point,
                &fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
            )?;
            Ok(adaptor_sig_index)
        };

    Ok((
        generate_trie_no_diff(
            secp,
            nb_oracles,
            nb_required,
            base,
            nb_digits,
            outcomes,
            oracle_infos,
            &mut verify_callback,
        )?,
        adaptor_sig_index,
    ))
}

///
fn generate_trie_no_diff<F, C: Signing>(
    secp: &Secp256k1<C>,
    nb_oracles: usize,
    nb_required: usize,
    base: usize,
    nb_digits: usize,
    outcomes: &[RangePayout],
    oracle_infos: &[OracleInfo],
    callback: &mut F,
) -> Result<DigitTrie<Vec<RangeInfo>>, Error>
where
    F: FnMut(usize, &PublicKey) -> Result<usize, Error>,
{
    let mut oracle_trie = DigitTrie::new(base);
    let mut cet_index = 0;

    for outcome in outcomes {
        let groups = group_by_ignoring_digits(
            outcome.start,
            outcome.start + outcome.count - 1,
            base,
            nb_digits,
        )
        .unwrap();
        for group in groups {
            let mut get_value = |_: Option<Vec<RangeInfo>>| -> Result<Vec<RangeInfo>, Error> {
                let combination_iterator = CombinationIterator::new(nb_oracles, nb_required);
                let mut range_infos: Vec<RangeInfo> = Vec::new();
                for selector in combination_iterator {
                    let adaptor_point = get_adaptor_point_for_indexed_paths(
                        &secp,
                        &oracle_infos,
                        &selector,
                        &std::iter::repeat(group.clone()).take(nb_required).collect(),
                    )?;
                    let adaptor_index = callback(cet_index, &adaptor_point)?;
                    range_infos.push(RangeInfo {
                        cet_index,
                        adaptor_index,
                    });
                }
                Ok(range_infos)
            };
            oracle_trie.insert(&group, &mut get_value)?;
        }
        cet_index += 1;
    }

    Ok(oracle_trie)
}

///
pub fn generate_trie_sign<C: Signing>(
    secp: &Secp256k1<C>,
    fund_privkey: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    nb_oracles: usize,
    nb_required: usize,
    base: usize,
    nb_digits: usize,
    min_support_exp: usize,
    max_error_exp: usize,
    outcomes: &Vec<RangePayout>,
    cets: &[Transaction],
    oracle_infos: &[OracleInfo],
    adaptor_index_start: usize,
) -> Result<(MultiTrie<RangeInfo>, Vec<(AdaptorSignature, AdaptorProof)>), Error> {
    let mut adaptor_pairs = Vec::new();
    let mut adaptor_index = adaptor_index_start;
    let mut sign_callback =
        |cet_index: usize, adaptor_point: &PublicKey| -> Result<usize, crate::Error> {
            let adaptor_pair = crate::create_cet_adaptor_sig_from_point(
                &secp,
                &cets[cet_index],
                &adaptor_point,
                fund_privkey,
                &funding_script_pubkey,
                fund_output_value,
            )?;
            adaptor_pairs.push(adaptor_pair);
            adaptor_index += 1;
            Ok(adaptor_index - 1)
        };

    let trie = generate_trie(
        secp,
        nb_oracles,
        nb_required,
        base,
        min_support_exp,
        max_error_exp,
        nb_digits,
        outcomes,
        oracle_infos,
        &mut sign_callback,
    )?;

    Ok((trie, adaptor_pairs))
}

///
pub fn generate_trie_verify(
    secp: &Secp256k1<secp256k1::All>,
    fund_pubkey: &PublicKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    nb_oracles: usize,
    nb_required: usize,
    base: usize,
    nb_digits: usize,
    min_support_exp: usize,
    max_error_exp: usize,
    outcomes: &Vec<RangePayout>,
    cets: &[Transaction],
    oracle_infos: &[OracleInfo],
    adaptor_pairs: &[(AdaptorSignature, AdaptorProof)],
    adaptor_pair_index_start: usize,
) -> Result<(MultiTrie<RangeInfo>, usize), Error> {
    let mut adaptor_sig_index = adaptor_pair_index_start;
    let mut verify_callback =
        |cet_index: usize, adaptor_point: &PublicKey| -> Result<usize, crate::Error> {
            let adaptor_pair = adaptor_pairs[adaptor_sig_index];
            let cet = &cets[cet_index];
            adaptor_sig_index += 1;
            super::verify_cet_adaptor_sig_from_point(
                secp,
                &adaptor_pair.0,
                &adaptor_pair.1,
                cet,
                &adaptor_point,
                &fund_pubkey,
                &funding_script_pubkey,
                fund_output_value,
            )?;
            Ok(adaptor_sig_index - 1)
        };

    Ok((
        generate_trie(
            secp,
            nb_oracles,
            nb_required,
            base,
            min_support_exp,
            max_error_exp,
            nb_digits,
            outcomes,
            oracle_infos,
            &mut verify_callback,
        )?,
        adaptor_sig_index,
    ))
}

///
pub fn generate_trie<C: Signing, F>(
    secp: &Secp256k1<C>,
    nb_oracles: usize,
    nb_required: usize,
    base: usize,
    min_support_exp: usize,
    max_error_exp: usize,
    nb_digits: usize,
    outcomes: &[RangePayout],
    oracle_infos: &[OracleInfo],
    callback: &mut F,
) -> Result<MultiTrie<RangeInfo>, Error>
where
    F: FnMut(usize, &PublicKey) -> Result<usize, Error>,
{
    let mut multi_oracle_trie = MultiTrie::new(
        nb_oracles,
        nb_required,
        base,
        min_support_exp,
        max_error_exp,
        nb_digits,
        true,
    );
    let mut cet_index = 0;

    for outcome in outcomes {
        let groups = group_by_ignoring_digits(
            outcome.start,
            outcome.start + outcome.count - 1,
            base,
            nb_digits,
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
            multi_oracle_trie.insert(&group, &mut get_value)?;
        }
        cet_index += 1;
    }

    Ok(multi_oracle_trie)
}

///
pub fn verify_trie_no_diff(
    secp: &Secp256k1<All>,
    oracle_trie: &DigitTrie<Vec<RangeInfo>>,
    fund_pubkey: &PublicKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    adaptor_pairs: &[(AdaptorSignature, AdaptorProof)],
    cets: &[Transaction],
    oracle_infos: &[OracleInfo],
    nb_required: usize,
) -> Result<usize, Error> {
    let mut max_adaptor_index = 0;
    let mut callback = |adaptor_point: &PublicKey, range_info: &RangeInfo| -> Result<(), Error> {
        let adaptor_pair = adaptor_pairs[range_info.adaptor_index];
        let cet = &cets[range_info.cet_index];
        if range_info.adaptor_index > max_adaptor_index {
            max_adaptor_index = range_info.adaptor_index;
        }
        super::verify_cet_adaptor_sig_from_point(
            secp,
            &adaptor_pair.0,
            &adaptor_pair.1,
            cet,
            &adaptor_point,
            &fund_pubkey,
            &funding_script_pubkey,
            fund_output_value,
        )
    };

    iter_trie_no_diff(secp, oracle_trie, oracle_infos, nb_required, &mut callback)?;
    Ok(max_adaptor_index + 1)
}

///
pub fn adaptor_sign_trie_no_diff(
    secp: &Secp256k1<All>,
    oracle_trie: &DigitTrie<Vec<RangeInfo>>,
    fund_privkey: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    cets: &[Transaction],
    oracle_infos: &[OracleInfo],
    nb_required: usize,
) -> Result<Vec<(AdaptorSignature, AdaptorProof)>, Error> {
    let mut adaptor_pairs = Vec::new();
    let mut callback = |adaptor_point: &PublicKey, range_info: &RangeInfo| -> Result<(), Error> {
        let adaptor_pair = crate::create_cet_adaptor_sig_from_point(
            &secp,
            &cets[range_info.cet_index],
            &adaptor_point,
            fund_privkey,
            &funding_script_pubkey,
            fund_output_value,
        )?;
        adaptor_pairs.push(adaptor_pair);
        Ok(())
    };

    iter_trie_no_diff(secp, oracle_trie, oracle_infos, nb_required, &mut callback)?;
    Ok(adaptor_pairs)
}

///
pub fn adaptor_sign_trie(
    secp: &Secp256k1<All>,
    multi_oracle_trie: &MultiTrie<RangeInfo>,
    fund_privkey: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    cets: &[Transaction],
    oracle_infos: &[OracleInfo],
    nb_required: usize,
) -> Result<Vec<(AdaptorSignature, AdaptorProof)>, Error> {
    let mut adaptor_pairs = Vec::<(usize, (AdaptorSignature, AdaptorProof))>::new();
    let mut callback = |adaptor_point: &PublicKey, range_info: &RangeInfo| -> Result<(), Error> {
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

    iter_trie(
        secp,
        multi_oracle_trie,
        oracle_infos,
        nb_required,
        &mut callback,
    )?;

    adaptor_pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

    Ok(adaptor_pairs.into_iter().map(|x| x.1).collect())
}

///
pub fn verify_trie(
    secp: &Secp256k1<All>,
    multi_oracle_trie: &MultiTrie<RangeInfo>,
    fund_pubkey: &PublicKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    adaptor_pairs: &[(AdaptorSignature, AdaptorProof)],
    cets: &[Transaction],
    oracle_infos: &[OracleInfo],
    nb_required: usize,
) -> Result<usize, Error> {
    let mut max_adaptor_index = 0;
    let mut callback = |adaptor_point: &PublicKey, range_info: &RangeInfo| -> Result<(), Error> {
        let adaptor_pair = adaptor_pairs[range_info.adaptor_index];
        let cet = &cets[range_info.cet_index];
        if range_info.adaptor_index > max_adaptor_index {
            max_adaptor_index = range_info.adaptor_index;
        }
        super::verify_cet_adaptor_sig_from_point(
            secp,
            &adaptor_pair.0,
            &adaptor_pair.1,
            cet,
            &adaptor_point,
            &fund_pubkey,
            &funding_script_pubkey,
            fund_output_value,
        )
    };

    iter_trie(
        secp,
        multi_oracle_trie,
        oracle_infos,
        nb_required,
        &mut callback,
    )?;

    Ok(max_adaptor_index + 1)
}

///
fn iter_trie<F>(
    secp: &Secp256k1<All>,
    multi_oracle_trie: &MultiTrie<RangeInfo>,
    oracle_infos: &[OracleInfo],
    nb_required: usize,
    callback: &mut F,
) -> Result<(), Error>
where
    F: FnMut(&PublicKey, &RangeInfo) -> Result<(), Error>,
{
    let m_trie_iter = MultiTrieIterator::new(multi_oracle_trie);

    for res in m_trie_iter {
        let mut cur_oracle_infos: Vec<OracleInfo> = Vec::with_capacity(nb_required);
        let mut paths = Vec::new();

        for (oracle_index, path) in res.path {
            cur_oracle_infos.push(oracle_infos[oracle_index].clone());
            paths.push(path);
        }

        let adaptor_point = get_adaptor_point_from_paths(secp, &cur_oracle_infos, &paths)?;
        callback(&adaptor_point, &res.value)?;
    }

    Ok(())
}

///
fn iter_trie_no_diff<F>(
    secp: &Secp256k1<All>,
    oracle_trie: &DigitTrie<Vec<RangeInfo>>,
    oracle_infos: &[OracleInfo],
    nb_required: usize,
    callback: &mut F,
) -> Result<(), Error>
where
    F: FnMut(&PublicKey, &RangeInfo) -> Result<(), Error>,
{
    let trie_iter = DigitTrieIter::new(oracle_trie);
    let combinations: Vec<Vec<usize>> =
        CombinationIterator::new(oracle_infos.len(), nb_required).collect();

    for res in trie_iter {
        let path = res.path;

        for (i, selector) in combinations.iter().enumerate() {
            let adaptor_point = get_adaptor_point_for_indexed_paths(
                secp,
                &oracle_infos,
                &selector,
                &std::iter::repeat(path.clone()).take(nb_required).collect(),
            )?;

            callback(&adaptor_point, &res.value[i])?;
        }
    }

    Ok(())
}

///
pub fn get_adaptor_point_from_paths<C: Signing>(
    secp: &Secp256k1<C>,
    oracle_infos: &[OracleInfo],
    paths: &Vec<Vec<usize>>,
) -> Result<PublicKey, super::Error> {
    let paths_msg: Vec<Vec<Message>> = paths
        .iter()
        .map(|x| {
            x.iter()
                .map(|y| Message::from_hashed_data::<sha256::Hash>(y.to_string().as_bytes()))
                .collect()
        })
        .collect();
    super::get_adaptor_point_from_oracle_info(&secp, oracle_infos, &paths_msg)
}

///
pub fn get_adaptor_point_for_indexed_paths<C: Signing>(
    secp: &Secp256k1<C>,
    oracle_infos: &[OracleInfo],
    indexes: &Vec<usize>,
    paths: &Vec<Vec<usize>>,
) -> Result<PublicKey, super::Error> {
    let filtered_oracle_infos: Vec<OracleInfo> = oracle_infos
        .iter()
        .enumerate()
        .filter_map(|(i, x)| {
            if indexes.contains(&i) {
                Some(x.clone())
            } else {
                None
            }
        })
        .collect();

    get_adaptor_point_from_paths(&secp, &filtered_oracle_infos, paths)
}
