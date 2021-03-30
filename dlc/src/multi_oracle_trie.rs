//! Data structures and functions to use multiple oracles in a single DLC.

use digit_trie::{DigitTrie, DigitTrieIter};
use multi_oracle::compute_outcome_combinations;
use trie::{LookupError, LookupResult, Node};

struct OracleTrieNodeInfo {
    oracle_index: usize,
    store_index: usize,
}

type MultiOracleTrieNode<T> = Node<DigitTrie<T>, DigitTrie<Vec<OracleTrieNodeInfo>>>;

impl<T> MultiOracleTrieNode<T> {
    fn new_node(base: usize) -> MultiOracleTrieNode<T> {
        let m_trie = DigitTrie::<Vec<OracleTrieNodeInfo>>::new(base);
        MultiOracleTrieNode::Node(m_trie)
    }
    fn new_leaf(base: usize) -> MultiOracleTrieNode<T> {
        let d_trie = DigitTrie::<T>::new(base);
        MultiOracleTrieNode::Leaf(d_trie)
    }
}

/// Struct for iterating over the values of a MultiOracleTrie.
pub struct MultiOracleTrieIterator<'a, T> {
    trie: &'a MultiOracleTrie<T>,
    node_stack: Vec<(
        (usize, Vec<usize>),
        std::iter::Enumerate<DigitTrieIter<'a, Vec<OracleTrieNodeInfo>>>,
    )>,
    oracle_info_iter: Option<(
        Vec<usize>,
        std::iter::Enumerate<std::slice::Iter<'a, OracleTrieNodeInfo>>,
    )>,
    leaf_iter: Vec<(usize, DigitTrieIter<'a, T>)>,
    cur_path: Vec<(usize, Vec<usize>)>,
    parent_index: usize,
}

fn create_node_iterator<'a, T>(
    node: &'a MultiOracleTrieNode<T>,
) -> std::iter::Enumerate<DigitTrieIter<'a, Vec<OracleTrieNodeInfo>>> {
    match node {
        Node::Node(d_trie) => DigitTrieIter::new(d_trie).enumerate(),
        _ => unreachable!(),
    }
}

fn create_leaf_iterator<'a, T>(node: &'a MultiOracleTrieNode<T>) -> DigitTrieIter<'a, T> {
    match node {
        Node::Leaf(d_trie) => DigitTrieIter::new(d_trie),
        _ => unreachable!(),
    }
}

impl<'a, T> MultiOracleTrieIterator<'a, T> {
    /// Create a new MultiOracleTrie iterator.
    pub fn new(trie: &'a MultiOracleTrie<T>) -> MultiOracleTrieIterator<'a, T> {
        let mut node_stack = Vec::with_capacity(trie.nb_required);
        let nb_roots = trie.nb_oracles - trie.nb_required + 1;
        let mut leaf_iter = Vec::new();
        for i in (0..nb_roots).rev() {
            if trie.nb_required > 1 {
                node_stack.push((
                    (i, Vec::<usize>::new()),
                    create_node_iterator(&trie.store[i]),
                ));
            } else {
                leaf_iter.push((i, create_leaf_iterator(&trie.store[i])));
            }
        }
        MultiOracleTrieIterator {
            trie,
            node_stack,
            oracle_info_iter: None,
            leaf_iter,
            cur_path: Vec::new(),
            parent_index: 0,
        }
    }
}

/// Implements the Iterator trait for MultiOracleTrieIterator.
impl<'a, T> Iterator for MultiOracleTrieIterator<'a, T> {
    type Item = LookupResult<'a, T, (usize, Vec<usize>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut leaf_iter = self.leaf_iter.last_mut();
        match &mut leaf_iter {
            Some(ref mut iter) => match iter.1.next() {
                Some(res) => {
                    let mut path = self.cur_path.clone();
                    path.push((iter.0, res.path));
                    return Some(LookupResult {
                        value: res.value,
                        path,
                    });
                }
                None => {
                    self.leaf_iter.pop();
                    return self.next();
                }
            },
            _ => {}
        };

        match &mut self.oracle_info_iter {
            Some(ref mut iter) => match iter.1.next() {
                None => {
                    self.oracle_info_iter = None;
                    self.cur_path.pop();
                }
                Some((i, info)) => match &self.trie.store[info.store_index] {
                    Node::None => unreachable!(),
                    Node::Node(d_trie) => {
                        self.node_stack.push((
                            (info.oracle_index, iter.0.clone()),
                            DigitTrieIter::new(d_trie).enumerate(),
                        ));
                        return self.next();
                    }
                    Node::Leaf(d_trie) => {
                        if i == 0 {
                            self.cur_path.push((self.parent_index, iter.0.clone()));
                        }
                        self.leaf_iter
                            .push((info.oracle_index, DigitTrieIter::new(d_trie)));
                        return self.next();
                    }
                },
            },
            _ => {}
        }

        let res = self.node_stack.pop();

        let ((cur_oracle_index, parent_path), mut cur_iter) = match res {
            None => return None,
            Some(cur) => cur,
        };

        match cur_iter.next() {
            None => {
                self.cur_path.pop();
                self.next()
            }
            Some((i, res)) => {
                if i == 0 && !parent_path.is_empty() {
                    self.cur_path.push((self.parent_index, parent_path.clone()));
                }
                self.parent_index = cur_oracle_index;
                self.node_stack
                    .push(((cur_oracle_index, parent_path), cur_iter));

                self.oracle_info_iter = Some((res.path, res.value.iter().enumerate()));
                self.next()
            }
        }
    }
}

/// Struct used to store DLC outcome information for multi oracle cases.  
pub struct MultiOracleTrie<T> {
    store: Vec<Node<DigitTrie<T>, DigitTrie<Vec<OracleTrieNodeInfo>>>>,
    base: usize,
    nb_oracles: usize,
    nb_required: usize,
    min_support_exp: usize,
    max_error_exp: usize,
    nb_digits: usize,
    maximize_coverage: bool,
}

struct CombinationIterator {
    selector: Vec<usize>,
    nb_selected: usize,
    nb_elements: usize,
    is_init: bool,
}

impl CombinationIterator {
    fn new(nb_elements: usize, nb_selected: usize) -> CombinationIterator {
        assert!(nb_elements >= nb_selected);

        let selector = (0..nb_selected).collect();
        CombinationIterator {
            selector,
            nb_elements,
            nb_selected,
            is_init: false,
        }
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

impl<T> MultiOracleTrie<T> {
    /// Create a new MultiOracleTrie. Panics if `nb_required` is less or equal to
    /// zero, or if `nb_oracles` is less than `nb_required`.
    pub fn new(
        nb_oracles: usize,
        nb_required: usize,
        base: usize,
        min_support_exp: usize,
        max_error_exp: usize,
        nb_digits: usize,
        maximize_coverage: bool,
    ) -> MultiOracleTrie<T> {
        assert!(nb_required > 0 && nb_oracles >= nb_required);
        let nb_roots = nb_oracles - nb_required + 1;
        let mut store = Vec::new();

        if nb_required > 1 {
            store.resize_with(nb_roots, || MultiOracleTrieNode::new_node(base));
        } else {
            store.resize_with(nb_roots, || MultiOracleTrieNode::new_leaf(base));
        }

        MultiOracleTrie {
            store,
            base,
            nb_oracles,
            nb_required,
            min_support_exp,
            max_error_exp,
            nb_digits,
            maximize_coverage,
        }
    }

    fn swap_remove(&mut self, index: usize) -> MultiOracleTrieNode<T> {
        self.store.push(MultiOracleTrieNode::None);
        self.store.swap_remove(index)
    }

    /// Insert the value returned by `get_value` at the position specified by `path`.
    pub fn insert<F>(&mut self, path: &[usize], get_value: &mut F)
    where
        F: FnMut(&Vec<Vec<usize>>, &Vec<usize>) -> T,
    {
        let combinations = if self.nb_required > 1 {
            compute_outcome_combinations(
                self.nb_digits,
                &path,
                self.max_error_exp,
                self.min_support_exp,
                self.maximize_coverage,
                self.nb_required,
            )
        } else {
            vec![vec![path.to_vec()]]
        };

        for combination in combinations {
            let combination_iter = CombinationIterator::new(self.nb_oracles, self.nb_required);

            for selector in combination_iter {
                self.insert_internal(selector[0], &combination, 0, &selector, get_value);
            }
        }
    }

    fn insert_new(&mut self, is_leaf: bool) {
        let m_trie = if is_leaf {
            let d_trie = DigitTrie::<T>::new(self.base);
            MultiOracleTrieNode::Leaf(d_trie)
        } else {
            let d_trie = DigitTrie::<Vec<OracleTrieNodeInfo>>::new(self.base);
            MultiOracleTrieNode::Node(d_trie)
        };
        self.store.push(m_trie);
    }

    fn insert_internal<F>(
        &mut self,
        cur_node_index: usize,
        paths: &Vec<Vec<usize>>,
        path_index: usize,
        oracle_indexes: &Vec<usize>,
        get_value: &mut F,
    ) where
        F: FnMut(&Vec<Vec<usize>>, &Vec<usize>) -> T,
    {
        assert!(path_index < paths.len());
        let cur_node = self.swap_remove(cur_node_index);
        match cur_node {
            MultiOracleTrieNode::None => unreachable!(),
            MultiOracleTrieNode::Leaf(mut digit_trie) => {
                assert_eq!(path_index, paths.len() - 1);
                let mut get_data = |_| get_value(paths, oracle_indexes);
                digit_trie.insert(&paths[path_index], &mut get_data);
                self.store[cur_node_index] = MultiOracleTrieNode::Leaf(digit_trie);
            }
            MultiOracleTrieNode::Node(mut node) => {
                assert!(path_index < paths.len() - 1);
                let mut store_index = 0;
                let mut callback =
                    |cur_data_res: Option<Vec<OracleTrieNodeInfo>>| -> Vec<OracleTrieNodeInfo> {
                        let mut cur_data = match cur_data_res {
                            Some(cur_data) => {
                                if let Ok(cur_store_index) =
                                    find_store_index(&cur_data, oracle_indexes[path_index + 1])
                                {
                                    store_index = cur_store_index;
                                    return cur_data;
                                }
                                cur_data
                            }
                            _ => vec![],
                        };
                        self.insert_new(paths.len() - 1 == path_index + 1);
                        store_index = self.store.len() - 1;
                        let oracle_index = oracle_indexes[path_index + 1];
                        let oracle_node_info = OracleTrieNodeInfo {
                            oracle_index,
                            store_index,
                        };
                        cur_data.push(oracle_node_info);
                        cur_data
                    };
                node.insert(&paths[path_index], &mut callback);
                self.store[cur_node_index] = MultiOracleTrieNode::Node(node);
                self.insert_internal(
                    store_index,
                    paths,
                    path_index + 1,
                    oracle_indexes,
                    get_value,
                );
            }
        }
    }

    /// Lookup in the trie for a value that matches with `paths`.
    pub fn look_up<'a>(
        &'a self,
        paths: &Vec<(usize, Vec<usize>)>,
    ) -> Result<LookupResult<'a, T, (usize, Vec<usize>)>, LookupError> {
        if paths.len() < self.nb_required {
            return Err(LookupError::NotFound);
        }

        let store = &self.store;

        let combination_iter = CombinationIterator::new(paths.len(), self.nb_required);

        let nb_roots = self.nb_oracles - self.nb_required + 1;

        for selector in combination_iter {
            let first_index = paths[selector[0]].0;
            if first_index >= nb_roots {
                continue;
            }

            let res = self.look_up_internal(
                &store[first_index],
                &paths
                    .iter()
                    .enumerate()
                    .filter_map(|(i, x)| {
                        if selector.contains(&i) {
                            return Some(x);
                        }
                        None
                    })
                    .collect(),
                0,
            );
            match res {
                Ok(mut l_res) => {
                    l_res.path.reverse();
                    return Ok(l_res);
                }
                _ => {}
            }
        }

        Err(LookupError::NotFound)
    }

    fn look_up_internal<'a>(
        &'a self,
        cur_node: &'a MultiOracleTrieNode<T>,
        paths: &Vec<&(usize, Vec<usize>)>,
        path_index: usize,
    ) -> Result<LookupResult<'a, T, (usize, Vec<usize>)>, LookupError> {
        assert!(path_index < paths.len());
        let oracle_index = paths[path_index].0;

        match cur_node {
            MultiOracleTrieNode::None => unreachable!(),
            MultiOracleTrieNode::Leaf(d_trie) => {
                let res = d_trie.look_up(&paths[path_index].1)?;
                Ok(LookupResult {
                    value: res[0].value,
                    path: vec![(oracle_index, res[0].path.clone())],
                })
            }
            MultiOracleTrieNode::Node(d_trie) => {
                assert!(path_index < paths.len() - 1);
                let results = d_trie.look_up(&paths[path_index].1)?;

                for l_res in results {
                    if let Ok(index) = find_store_index(l_res.value, paths[path_index + 1].0) {
                        let next_node = &self.store[index];
                        if let Ok(mut child_l_res) =
                            self.look_up_internal(next_node, paths, path_index + 1)
                        {
                            child_l_res.path.push((oracle_index, l_res.path.clone()));
                            return Ok(child_l_res);
                        }
                    }
                }

                Err(LookupError::NotFound)
            }
        }
    }
}

fn find_store_index(
    children: &Vec<OracleTrieNodeInfo>,
    oracle_index: usize,
) -> Result<usize, LookupError> {
    for info in children {
        if oracle_index == info.oracle_index {
            return Ok(info.store_index);
        }
    }

    Err(LookupError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tests_common(
        mut m_trie: MultiOracleTrie<usize>,
        path: Vec<usize>,
        good_paths: Vec<Vec<(usize, Vec<usize>)>>,
        bad_paths: Vec<Vec<(usize, Vec<usize>)>>,
        expected_iter: Option<Vec<Vec<(usize, Vec<usize>)>>>,
    ) {
        let mut get_value = |_: &Vec<Vec<usize>>, _: &Vec<usize>| -> usize { 2 };

        m_trie.insert(&path, &mut get_value);

        for good_path in good_paths {
            assert!(m_trie.look_up(&good_path).is_ok());
        }

        for bad_path in bad_paths {
            assert!(m_trie.look_up(&bad_path).is_err());
        }

        if let Some(expected) = expected_iter {
            let iter = MultiOracleTrieIterator::new(&m_trie);
            let mut actual = Vec::new();
            for res in iter {
                actual.push(res.path);
            }

            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn multi_oracle_trie_1_of_1_test() {
        let m_trie = MultiOracleTrie::<usize>::new(1, 1, 2, 2, 3, 5, true);

        let path = vec![0, 1, 1, 1];

        let good_paths = vec![
            vec![(0, vec![0, 1, 1, 1, 1])],
            vec![(0, vec![0, 1, 1, 1, 0])],
        ];

        let bad_paths = vec![
            vec![(0, vec![1, 1, 1, 1, 1])],
            vec![(0, vec![0, 1, 1, 0, 1])],
            vec![(0, vec![0, 1, 0, 1, 0])],
        ];

        let expected_iter: Vec<Vec<(usize, Vec<usize>)>> = vec![vec![(0, vec![0, 1, 1, 1])]];

        tests_common(m_trie, path, good_paths, bad_paths, Some(expected_iter));
    }

    #[test]
    fn multi_oracle_trie_1_of_2_test() {
        let m_trie = MultiOracleTrie::<usize>::new(2, 1, 2, 2, 3, 5, true);

        let path = vec![0, 1, 1, 1];

        let good_paths = vec![
            vec![(0, vec![0, 1, 1, 1, 1])],
            vec![(1, vec![0, 1, 1, 1, 1])],
            vec![(0, vec![0, 1, 1, 1, 0])],
            vec![(1, vec![0, 1, 1, 1, 0])],
        ];

        let bad_paths = vec![
            vec![(0, vec![1, 1, 1, 1, 1])],
            vec![(1, vec![0, 1, 1, 0, 1])],
            vec![(0, vec![0, 1, 0, 1, 0])],
        ];

        let expected_iter: Vec<Vec<(usize, Vec<usize>)>> =
            vec![vec![(0, vec![0, 1, 1, 1])], vec![(1, vec![0, 1, 1, 1])]];

        tests_common(m_trie, path, good_paths, bad_paths, Some(expected_iter));
    }

    #[test]
    fn multi_oracle_trie_2_of_2_test() {
        let m_trie = MultiOracleTrie::<usize>::new(2, 2, 2, 2, 3, 5, true);

        let path = vec![0, 1, 1, 1];

        let good_paths = vec![
            vec![(0, vec![0, 1, 1, 1, 1]), (1, vec![0, 1, 1, 1, 1])],
            vec![(0, vec![0, 1, 1, 1, 1]), (1, vec![1, 0, 0, 1, 1])],
            vec![(0, vec![0, 1, 1, 1, 1]), (1, vec![0, 1, 1, 0, 0])],
        ];

        let bad_paths = vec![
            vec![(0, vec![1, 1, 1, 1, 1]), (1, vec![0, 1, 1, 1, 1])],
            vec![(0, vec![0, 1, 1, 1, 1]), (1, vec![1, 1, 0, 1, 1])],
            vec![(0, vec![0, 1, 0, 1, 1]), (1, vec![0, 1, 1, 0, 0])],
        ];

        let expected_iter: Vec<Vec<(usize, Vec<usize>)>> = vec![
            vec![(0, vec![0, 1, 1, 1]), (1, vec![0, 1])],
            vec![(0, vec![0, 1, 1, 1]), (1, vec![1, 0, 0])],
        ];

        tests_common(m_trie, path, good_paths, bad_paths, Some(expected_iter));
    }

    #[test]
    fn multi_oracle_trie_2_of_3_test() {
        let m_trie = MultiOracleTrie::<usize>::new(3, 2, 2, 2, 3, 5, true);

        let path = vec![0, 1, 1, 1];

        let good_paths = vec![
            vec![(0, vec![0, 1, 1, 1, 1]), (1, vec![0, 1, 1, 1, 1])],
            vec![(1, vec![0, 1, 1, 1, 1]), (2, vec![0, 1, 1, 1, 1])],
            vec![(0, vec![0, 1, 1, 1, 1]), (2, vec![0, 1, 1, 1, 1])],
            vec![(0, vec![0, 1, 1, 1, 1]), (2, vec![1, 0, 0, 1, 1])],
            vec![(1, vec![0, 1, 1, 1, 1]), (2, vec![1, 0, 0, 1, 1])],
        ];

        let bad_paths = vec![
            vec![(0, vec![1, 1, 1, 1, 1]), (1, vec![0, 1, 1, 1, 1])],
            vec![(2, vec![0, 1, 1, 1, 1]), (1, vec![0, 1, 1, 1, 1])],
            vec![(0, vec![0, 1, 1, 1, 1]), (2, vec![1, 1, 1, 1, 1])],
            vec![(1, vec![0, 1, 1, 1, 1]), (2, vec![1, 1, 1, 1, 1])],
        ];

        tests_common(m_trie, path, good_paths, bad_paths, None);
    }
}
