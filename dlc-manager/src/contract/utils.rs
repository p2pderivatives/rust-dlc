use std::collections::HashMap;
use std::hash::Hash;

pub(crate) fn get_majority_combination(
    outcomes: &[(usize, &Vec<String>)],
) -> Option<(Vec<String>, Vec<usize>)> {
    let mut hash_set: HashMap<&Vec<String>, Vec<usize>> = HashMap::new();

    for outcome in outcomes {
        let index = outcome.0;
        let outcome_value = outcome.1;

        let index_set = hash_set.entry(outcome_value).or_insert(Vec::new());
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
