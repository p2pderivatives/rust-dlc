pub(crate) fn get_majority_combination(
    outcomes: &[(usize, &Vec<String>)],
) -> Result<(Vec<String>, Vec<usize>), crate::error::Error> {
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

    if hash_set.len() == 0 {
        return Err(crate::error::Error::InvalidParameters(
            "No majority found.".to_string(),
        ));
    }

    let mut values: Vec<_> = hash_set.into_iter().collect();
    values.sort_by(|x, y| x.1.len().partial_cmp(&y.1.len()).unwrap());
    Ok(values.remove(values.len() - 1))
}
