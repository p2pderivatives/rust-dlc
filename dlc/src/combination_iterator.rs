//! # Combination Iterator
//! Utility struct and functions too support iterating though all possible
//! t combinations of n elements (where t >= n).

/// Structure to use to support iteration through all possible t combinations
/// of n elements.
pub struct CombinationIterator {
    selector: Vec<usize>,
    nb_selected: usize,
    nb_elements: usize,
    is_init: bool,
}

impl CombinationIterator {
    /// Creates a new combination iterator for a collection of `nb_elements`
    /// where each combination includes `nb_selected` elements. Panics if
    /// `nb_elements < nb_selected`.
    pub fn new(nb_elements: usize, nb_selected: usize) -> CombinationIterator {
        assert!(nb_elements >= nb_selected);

        let selector = (0..nb_selected).collect();
        CombinationIterator {
            selector,
            nb_elements,
            nb_selected,
            is_init: false,
        }
    }

    /// Returns the index of the provided combination if part of the set of
    /// combinations produced by the iterator, None otherwise.
    pub fn get_index_for_combination(self, combination: &[usize]) -> Option<usize> {
        for (i, cur) in self.enumerate() {
            if combination == cur {
                return Some(i);
            }
        }

        None
    }
}

impl Iterator for CombinationIterator {
    type Item = Vec<usize>;
    fn next(&mut self) -> Option<Self::Item> {
        if !self.is_init {
            self.is_init = true;
            return Some(self.selector.clone());
        }

        let last_index = self.nb_selected - 1;
        let mut cur_index = last_index;
        while cur_index > 0
            && self.selector[cur_index] == self.nb_elements - 1 - (last_index - cur_index)
        {
            cur_index -= 1;
        }

        self.selector[cur_index] += 1;
        cur_index += 1;

        while cur_index <= last_index {
            self.selector[cur_index] = self.selector[cur_index - 1] + 1;
            cur_index += 1;
        }

        if self.selector[0] == self.nb_elements - self.nb_selected + 1 {
            return None;
        }

        Some(self.selector.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_combinations_test() {
        let combination_iterator = CombinationIterator::new(4, 3);
        let expected = vec![vec![0, 1, 2], vec![0, 1, 3], vec![0, 2, 3], vec![1, 2, 3]];

        for (i, cur) in combination_iterator.enumerate() {
            assert_eq!(cur, expected[i]);
        }
    }

    #[test]
    fn get_combination_index_test() {
        let combination_iterator = CombinationIterator::new(4, 3);

        assert_eq!(
            2,
            combination_iterator
                .get_index_for_combination(&[0, 2, 3])
                .expect("Could not find combination")
        );
    }
}
