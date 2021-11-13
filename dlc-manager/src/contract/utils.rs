pub(crate) fn get_majority_combination(
    outcomes: &[(usize, &Vec<String>)],
) -> Option<(Vec<String>, Vec<usize>)> {
    let mut hash_set: std::collections::HashMap<Vec<String>, Vec<usize>> =
        std::collections::HashMap::new();

    for outcome in outcomes {
        let index = outcome.0;
        let outcome_value = outcome.1;

        if let Some(index_set) = hash_set.get_mut(outcome_value) {
            index_set.push(index);
        } else {
            let index_set = vec![index];
            hash_set.insert(outcome_value.to_vec(), index_set);
        }
    }

    if hash_set.is_empty() {
        return None;
    }

    let mut values: Vec<_> = hash_set.into_iter().collect();
    values.sort_by(|x, y| x.1.len().partial_cmp(&y.1.len()).unwrap());
    Some(values.remove(values.len() - 1))
}
