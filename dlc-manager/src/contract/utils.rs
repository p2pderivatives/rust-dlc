use std::collections::HashMap;
use std::hash::Hash;

use bitcoin::{Script, Transaction};
use dlc::OracleInfo;
use dlc_trie::{combination_iterator::CombinationIterator, RangeInfo};
use secp256k1_zkp::{
    All, EcdsaAdaptorSignature, Message, PublicKey, Secp256k1, SecretKey, Verification,
};

use crate::error::Error;

use super::contract_info::OracleIndexAndPrefixLength;

pub(crate) fn get_majority_combination(
    outcomes: &[(usize, &Vec<String>)],
) -> Option<(Vec<String>, Vec<usize>)> {
    let mut hash_set: HashMap<&Vec<String>, Vec<usize>> = HashMap::new();

    for outcome in outcomes {
        let index = outcome.0;
        let outcome_value = outcome.1;

        let index_set = hash_set.entry(outcome_value).or_default();
        index_set.push(index);
    }

    if hash_set.is_empty() {
        return None;
    }

    let mut values: Vec<_> = hash_set.into_iter().collect();
    values.sort_by(|x, y| x.1.len().partial_cmp(&y.1.len()).unwrap());
    let (last_outcomes, last_indexes) = values.pop().expect("to have at least one element.");
    Some((last_outcomes.to_vec(), last_indexes))
}

pub(super) fn unordered_equal<T: Eq + Hash>(a: &[T], b: &[T]) -> bool {
    fn count<T>(items: &[T]) -> HashMap<&T, usize>
    where
        T: Eq + Hash,
    {
        let mut cnt = HashMap::new();
        for i in items {
            *cnt.entry(i).or_insert(0) += 1
        }
        cnt
    }

    count(a) == count(b)
}

/// Returns the `RangeInfo` that matches the given set of outcomes if any.
pub(crate) fn get_range_info_for_enum_outcome(
    nb_oracles: usize,
    threshold: usize,
    outcomes: &[(usize, &Vec<String>)],
    payout_outcomes: &[String],
    adaptor_sig_start: usize,
) -> Option<(OracleIndexAndPrefixLength, RangeInfo)> {
    if outcomes.len() < threshold {
        return None;
    }

    let filtered_outcomes: Vec<(usize, &Vec<String>)> = outcomes
        .iter()
        .filter(|x| x.1.len() == 1)
        .cloned()
        .collect();
    let (mut outcome, mut actual_combination) = get_majority_combination(&filtered_outcomes)?;
    let outcome = outcome.remove(0);

    if actual_combination.len() < threshold {
        return None;
    }

    actual_combination.truncate(threshold);

    let pos = payout_outcomes.iter().position(|x| x == &outcome)?;

    let combinator = CombinationIterator::new(nb_oracles, threshold);
    let mut comb_pos = 0;
    let mut comb_count = 0;

    for (i, combination) in combinator.enumerate() {
        if combination == actual_combination {
            comb_pos = i;
        }
        comb_count += 1;
    }

    let range_info = RangeInfo {
        cet_index: pos,
        adaptor_index: comb_count * pos + comb_pos + adaptor_sig_start,
    };

    Some((
        actual_combination.iter().map(|x| (*x, 1)).collect(),
        range_info,
    ))
}

/// Verify the given set adaptor signatures.
pub fn verify_adaptor_info(
    secp: &Secp256k1<All>,
    messages: &[Vec<Vec<Message>>],
    oracle_infos: &[OracleInfo],
    threshold: usize,
    fund_pubkey: &PublicKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
    cets: &[Transaction],
    adaptor_sigs: &[EcdsaAdaptorSignature],
    adaptor_sig_start: usize,
) -> Result<usize, dlc::Error> {
    let mut adaptor_sig_index = adaptor_sig_start;
    let mut callback = |adaptor_point: &PublicKey, cet_index: usize| -> Result<(), dlc::Error> {
        let sig = adaptor_sigs[adaptor_sig_index];
        adaptor_sig_index += 1;
        dlc::verify_cet_adaptor_sig_from_point(
            secp,
            &sig,
            &cets[cet_index],
            adaptor_point,
            fund_pubkey,
            funding_script_pubkey,
            fund_output_value,
        )?;
        Ok(())
    };

    iter_outcomes(secp, messages, oracle_infos, threshold, &mut callback)?;

    Ok(adaptor_sig_index)
}

/// Generate the set of adaptor signatures.
pub fn get_enum_adaptor_signatures(
    secp: &Secp256k1<All>,
    messages: &[Vec<Vec<Message>>],
    oracle_infos: &[OracleInfo],
    threshold: usize,
    cets: &[Transaction],
    fund_privkey: &SecretKey,
    funding_script_pubkey: &Script,
    fund_output_value: u64,
) -> Result<Vec<EcdsaAdaptorSignature>, Error> {
    let mut adaptor_sigs = Vec::new();
    let mut callback = |adaptor_point: &PublicKey, cet_index: usize| -> Result<(), dlc::Error> {
        let sig = dlc::create_cet_adaptor_sig_from_point(
            secp,
            &cets[cet_index],
            adaptor_point,
            fund_privkey,
            funding_script_pubkey,
            fund_output_value,
        )?;
        adaptor_sigs.push(sig);
        Ok(())
    };

    iter_outcomes(secp, messages, oracle_infos, threshold, &mut callback)?;

    Ok(adaptor_sigs)
}

pub(crate) fn iter_outcomes<C: Verification, F>(
    secp: &Secp256k1<C>,
    messages: &[Vec<Vec<Message>>],
    oracle_infos: &[OracleInfo],
    threshold: usize,
    callback: &mut F,
) -> Result<(), dlc::Error>
where
    F: FnMut(&PublicKey, usize) -> Result<(), dlc::Error>,
{
    let combination_iter = CombinationIterator::new(oracle_infos.len(), threshold);
    let combinations: Vec<Vec<usize>> = combination_iter.collect();

    for (i, outcome_messages) in messages.iter().enumerate() {
        for selector in &combinations {
            let cur_oracle_infos: Vec<_> = oracle_infos
                .iter()
                .enumerate()
                .filter_map(|(i, x)| {
                    if selector.contains(&i) {
                        Some(x.clone())
                    } else {
                        None
                    }
                })
                .collect();
            let adaptor_point =
                dlc::get_adaptor_point_from_oracle_info(secp, &cur_oracle_infos, outcome_messages)?;
            callback(&adaptor_point, i)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_majority_combination_test() {
        let outcomes_a = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let outcomes_b = vec!["d".to_string(), "e".to_string(), "f".to_string()];

        let input = vec![
            (0_usize, &outcomes_a),
            (1, &outcomes_a),
            (2, &outcomes_b),
            (3, &outcomes_a),
            (5, &outcomes_a),
            (10, &outcomes_b),
            (14, &outcomes_b),
            (17, &outcomes_a),
        ];

        let actual_combination = get_majority_combination(&input);

        let expected_majority = Some((outcomes_a, vec![0, 1, 3, 5, 17]));

        assert_eq!(expected_majority, actual_combination);
    }

    #[test]
    fn unordered_equal_test() {
        let a = vec![4, 7, 2, 9, 12];
        let b = vec![7, 12, 9, 2, 4];
        let c = vec![12, 2, 9, 4, 7];
        let d = vec![4, 7, 3, 9, 12];

        assert!(unordered_equal(&a, &b));
        assert!(unordered_equal(&a, &c));
        assert!(unordered_equal(&b, &c));
        assert!(!unordered_equal(&a, &d));
    }
}
