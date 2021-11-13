//! Data structure and functions to create, insert, lookup and iterate a trie
//! of trie.

use crate::{
    utils::{get_max_covering_paths, pre_pad_vec},
    LookupResult, Node, OracleNumericInfo,
};
use combination_iterator::CombinationIterator;
use digit_trie::{DigitTrie, DigitTrieDump, DigitTrieIter};
use dlc::Error;
use multi_oracle::compute_outcome_combinations;

#[derive(Clone, Debug)]
/// Information stored in a node.
pub struct TrieNodeInfo {
    /// The index of the sub-trie.
    pub trie_index: usize,
    /// The index of the node in the trie store.
    pub store_index: usize,
}

type MultiTrieNode<T> = Node<DigitTrie<T>, DigitTrie<Vec<TrieNodeInfo>>>;
type NodeStackElement<'a> = Vec<(IndexedPath, DigitTrieIter<'a, Vec<TrieNodeInfo>>)>;
type IndexedPath = (usize, Vec<usize>);

impl<T> MultiTrieNode<T> {
    fn new_node(base: usize) -> MultiTrieNode<T> {
        let m_trie = DigitTrie::<Vec<TrieNodeInfo>>::new(base);
        MultiTrieNode::Node(m_trie)
    }
    fn new_leaf(base: usize) -> MultiTrieNode<T> {
        let d_trie = DigitTrie::<T>::new(base);
        MultiTrieNode::Leaf(d_trie)
    }
}

/// Struct for iterating over the values of a MultiTrie.
pub(crate) struct MultiTrieIterator<'a, T> {
    trie: &'a MultiTrie<T>,
    node_stack: NodeStackElement<'a>,
    trie_info_iter: Vec<(
        Vec<usize>,
        std::iter::Enumerate<std::slice::Iter<'a, TrieNodeInfo>>,
    )>,
    leaf_iter: Vec<(usize, DigitTrieIter<'a, T>)>,
    cur_path: Vec<(usize, Vec<usize>)>,
}

fn create_node_iterator<T>(node: &MultiTrieNode<T>) -> DigitTrieIter<Vec<TrieNodeInfo>> {
    match node {
        Node::Node(d_trie) => DigitTrieIter::new(d_trie),
        _ => unreachable!(),
    }
}

fn create_leaf_iterator<T>(node: &MultiTrieNode<T>) -> DigitTrieIter<T> {
    match node {
        Node::Leaf(d_trie) => DigitTrieIter::new(d_trie),
        _ => unreachable!(),
    }
}

impl<'a, T> MultiTrieIterator<'a, T> {
    /// Create a new MultiTrie iterator.
    pub fn new(trie: &'a MultiTrie<T>) -> MultiTrieIterator<'a, T> {
        let mut node_stack = Vec::with_capacity(trie.nb_required);
        let nb_roots = trie.nb_tries - trie.nb_required + 1;
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
        MultiTrieIterator {
            trie,
            node_stack,
            trie_info_iter: Vec::new(),
            leaf_iter,
            cur_path: Vec::new(),
        }
    }
}

/// Implements the Iterator trait for MultiTrieIterator.
impl<'a, T> Iterator for MultiTrieIterator<'a, T> {
    type Item = LookupResult<'a, T, (usize, Vec<usize>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut leaf_iter = self.leaf_iter.last_mut();
        if let Some(ref mut iter) = &mut leaf_iter {
            match iter.1.next() {
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
            }
        };

        let mut trie_info_iter = self.trie_info_iter.last_mut();

        if let Some(ref mut iter) = &mut trie_info_iter {
            match iter.1.next() {
                None => {
                    self.trie_info_iter.pop();
                    self.cur_path.pop();
                }
                Some((i, info)) => {
                    if i == 0 {
                        self.cur_path
                            .push((self.node_stack.last().unwrap().0 .0, iter.0.clone()));
                    }
                    match &self.trie.store[info.store_index] {
                        Node::None => unreachable!(),
                        Node::Node(d_trie) => {
                            self.node_stack.push((
                                (info.trie_index, iter.0.clone()),
                                DigitTrieIter::new(d_trie),
                            ));
                        }
                        Node::Leaf(d_trie) => {
                            self.leaf_iter
                                .push((info.trie_index, DigitTrieIter::new(d_trie)));
                            return self.next();
                        }
                    }
                }
            }
        }

        let res = self.node_stack.pop();

        let ((cur_trie_index, parent_path), mut cur_iter) = match res {
            None => return None,
            Some(cur) => cur,
        };

        match cur_iter.next() {
            None => self.next(),
            Some(res) => {
                // Put back the node on the stack
                self.node_stack
                    .push(((cur_trie_index, parent_path), cur_iter));

                // Push an iterator to the child on the trie info stack
                self.trie_info_iter
                    .push((res.path, res.value.iter().enumerate()));

                self.next()
            }
        }
    }
}

/// Struct used to store DLC outcome information for multi oracle cases.  
#[derive(Clone)]
pub struct MultiTrie<T> {
    store: Vec<MultiTrieNode<T>>,
    nb_tries: usize,
    nb_required: usize,
    min_support_exp: usize,
    max_error_exp: usize,
    maximize_coverage: bool,
    oracle_numeric_infos: OracleNumericInfo,
}

impl<T> MultiTrie<T> {
    /// Create a new MultiTrie. Panics if `nb_required` is less or equal to
    /// zero, or if `nb_tries` is less than `nb_required`.
    pub fn new(
        oracle_numeric_infos: &OracleNumericInfo,
        nb_required: usize,
        min_support_exp: usize,
        max_error_exp: usize,
        maximize_coverage: bool,
    ) -> MultiTrie<T> {
        let nb_tries = oracle_numeric_infos.nb_digits.len();
        assert!(
            nb_required > 0
                && nb_tries >= nb_required
                && !oracle_numeric_infos.nb_digits.is_empty()
        );
        let nb_roots = nb_tries - nb_required + 1;

        let store: Vec<_> = if nb_required > 1 {
            (0..nb_tries)
                .take(nb_roots)
                .map(|_| MultiTrieNode::new_node(oracle_numeric_infos.base))
                .collect()
        } else {
            (0..nb_tries)
                .take(nb_roots)
                .map(|_| MultiTrieNode::new_leaf(oracle_numeric_infos.base))
                .collect()
        };

        MultiTrie {
            store,
            nb_tries,
            nb_required,
            min_support_exp,
            max_error_exp,
            maximize_coverage,
            oracle_numeric_infos: oracle_numeric_infos.clone(),
        }
    }

    fn swap_remove(&mut self, index: usize) -> MultiTrieNode<T> {
        self.store.push(MultiTrieNode::None);
        self.store.swap_remove(index)
    }

    /// Insert the paths to cover outcomes outside of the range of the oracle with
    /// minimum number of digits. Should only be called when oracles have varying
    /// number of digits.
    pub fn insert_max_paths<F>(&mut self, get_value: &mut F) -> Result<(), Error>
    where
        F: FnMut(&[Vec<usize>], &[usize]) -> Result<T, Error>,
    {
        let indexed_paths = get_max_covering_paths(&self.oracle_numeric_infos, self.nb_required);
        for indexed_path in indexed_paths {
            let (indexes, paths): (Vec<usize>, Vec<Vec<usize>>) = indexed_path.into_iter().unzip();
            self.insert_internal(indexes[0], &paths, 0, &indexes, get_value)?;
        }
        Ok(())
    }

    /// Insert the value returned by `get_value` at the position specified by `path`.
    pub fn insert<F>(&mut self, path: &[usize], get_value: &mut F) -> Result<(), Error>
    where
        F: FnMut(&[Vec<usize>], &[usize]) -> Result<T, Error>,
    {
        let combination_iter = CombinationIterator::new(self.nb_tries, self.nb_required);
        let min_nb_digits = self.oracle_numeric_infos.get_min_nb_digits();

        for selector in combination_iter {
            let combinations = if self.nb_required > 1 {
                let mut digit_infos = self
                    .oracle_numeric_infos
                    .nb_digits
                    .iter()
                    .enumerate()
                    .filter_map(|(i, x)| {
                        if selector.contains(&i) {
                            Some(*x)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let min_index = reorder_to_min_first(&mut digit_infos);
                let to_pad = digit_infos[0] - min_nb_digits;
                let padded_path = pre_pad_vec(path.to_vec(), path.len() + to_pad);
                let mut combinations = compute_outcome_combinations(
                    &digit_infos,
                    &padded_path,
                    self.max_error_exp,
                    self.min_support_exp,
                    self.maximize_coverage,
                );
                if min_index != 0 {
                    for combination in &mut combinations {
                        let to_reorder = combination.remove(0);
                        combination.insert(min_index, to_reorder);
                    }
                }
                combinations
            } else {
                vec![vec![path.to_vec()]]
            };

            for combination in combinations {
                self.insert_internal(selector[0], &combination, 0, &selector, get_value)?;
            }
        }

        Ok(())
    }

    fn insert_new(&mut self, is_leaf: bool) {
        let m_trie = if is_leaf {
            let d_trie = DigitTrie::<T>::new(self.oracle_numeric_infos.base);
            MultiTrieNode::Leaf(d_trie)
        } else {
            let d_trie = DigitTrie::<Vec<TrieNodeInfo>>::new(self.oracle_numeric_infos.base);
            MultiTrieNode::Node(d_trie)
        };
        self.store.push(m_trie);
    }

    fn insert_internal<F>(
        &mut self,
        cur_node_index: usize,
        paths: &[Vec<usize>],
        path_index: usize,
        trie_indexes: &[usize],
        get_value: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(&[Vec<usize>], &[usize]) -> Result<T, Error>,
    {
        assert!(path_index < paths.len());
        let cur_node = self.swap_remove(cur_node_index);
        match cur_node {
            MultiTrieNode::None => unreachable!(),
            MultiTrieNode::Leaf(mut digit_trie) => {
                assert_eq!(path_index, paths.len() - 1);
                let mut get_data = |_| get_value(paths, trie_indexes);
                digit_trie.insert(&paths[path_index], &mut get_data)?;
                self.store[cur_node_index] = MultiTrieNode::Leaf(digit_trie);
            }
            MultiTrieNode::Node(mut node) => {
                assert!(path_index < paths.len() - 1);
                let mut store_index = 0;
                let mut callback =
                    |cur_data_res: Option<Vec<TrieNodeInfo>>| -> Result<Vec<TrieNodeInfo>, Error> {
                        let mut cur_data = match cur_data_res {
                            Some(cur_data) => {
                                if let Some(cur_store_index) =
                                    find_store_index(&cur_data, trie_indexes[path_index + 1])
                                {
                                    store_index = cur_store_index;
                                    return Ok(cur_data);
                                }
                                cur_data
                            }
                            _ => vec![],
                        };
                        self.insert_new(paths.len() - 1 == path_index + 1);
                        store_index = self.store.len() - 1;
                        let trie_index = trie_indexes[path_index + 1];
                        let trie_node_info = TrieNodeInfo {
                            trie_index,
                            store_index,
                        };
                        cur_data.push(trie_node_info);
                        Ok(cur_data)
                    };
                node.insert(&paths[path_index], &mut callback)?;
                self.store[cur_node_index] = MultiTrieNode::Node(node);
                self.insert_internal(store_index, paths, path_index + 1, trie_indexes, get_value)?;
            }
        }
        Ok(())
    }

    /// Lookup in the trie for a value that matches with `paths`.
    pub fn look_up<'a>(
        &'a self,
        paths: &[(usize, Vec<usize>)],
    ) -> Option<(&'a T, Vec<IndexedPath>)> {
        if paths.len() < self.nb_required {
            return None;
        }

        let store = &self.store;

        let combination_iter = CombinationIterator::new(paths.len(), self.nb_required);

        let nb_roots = self.nb_tries - self.nb_required + 1;

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
                    .collect::<Vec<_>>(),
                0,
            );
            if let Some(mut l_res) = res {
                l_res.path.reverse();
                return Some((l_res.value, l_res.path.clone()));
            }
        }

        None
    }

    fn look_up_internal<'a>(
        &'a self,
        cur_node: &'a MultiTrieNode<T>,
        paths: &[&(usize, Vec<usize>)],
        path_index: usize,
    ) -> Option<LookupResult<'a, T, (usize, Vec<usize>)>> {
        assert!(path_index < paths.len());
        let trie_index = paths[path_index].0;

        match cur_node {
            MultiTrieNode::None => unreachable!(),
            MultiTrieNode::Leaf(d_trie) => {
                let res = d_trie.look_up(&paths[path_index].1)?;
                Some(LookupResult {
                    value: res[0].value,
                    path: vec![(trie_index, res[0].path.clone())],
                })
            }
            MultiTrieNode::Node(d_trie) => {
                assert!(path_index < paths.len() - 1);
                let results = d_trie.look_up(&paths[path_index].1)?;

                for l_res in results {
                    if let Some(index) = find_store_index(l_res.value, paths[path_index + 1].0) {
                        let next_node = &self.store[index];
                        if let Some(mut child_l_res) =
                            self.look_up_internal(next_node, paths, path_index + 1)
                        {
                            child_l_res.path.push((trie_index, l_res.path));
                            return Some(child_l_res);
                        }
                    }
                }

                None
            }
        }
    }
}

fn find_store_index(children: &[TrieNodeInfo], trie_index: usize) -> Option<usize> {
    for info in children {
        if trie_index == info.trie_index {
            return Some(info.store_index);
        }
    }

    None
}

fn reorder_to_min_first(oracle_digit_infos: &mut Vec<usize>) -> usize {
    let min_index = oracle_digit_infos
        .iter()
        .enumerate()
        .min_by_key(|(_, x)| *x)
        .unwrap()
        .0;
    if min_index != 0 {
        let min_val = oracle_digit_infos.remove(min_index);
        oracle_digit_infos.insert(0, min_val);
    }
    min_index
}

/// Container for a dump of a MultiTrie used for serialization purpose.
pub struct MultiTrieDump<T>
where
    T: Clone,
{
    /// The node data.
    pub node_data: Vec<MultiTrieNodeData<T>>,
    /// The total number of tries.
    pub nb_tries: usize,
    /// The number of trie per path.
    pub nb_required: usize,
    /// The guaranteed support as a power of 2.
    pub min_support_exp: usize,
    /// The maximum support as a power of 2.
    pub max_error_exp: usize,
    /// Whether this trie maximizes outcome coverage.
    pub maximize_coverage: bool,
    /// Information about the numerical representation of oracles
    pub oracle_numeric_infos: OracleNumericInfo,
}

impl<T> MultiTrie<T>
where
    T: Clone,
{
    /// Dump the content of the trie for the purpose of serialization.
    pub fn dump(&self) -> MultiTrieDump<T> {
        let node_data = self.store.iter().map(|x| x.get_data()).collect();
        MultiTrieDump {
            node_data,
            nb_tries: self.nb_tries,
            nb_required: self.nb_required,
            min_support_exp: self.min_support_exp,
            max_error_exp: self.max_error_exp,
            maximize_coverage: self.maximize_coverage,
            oracle_numeric_infos: self.oracle_numeric_infos.clone(),
        }
    }

    /// Restore a trie from a dump.
    pub fn from_dump(dump: MultiTrieDump<T>) -> MultiTrie<T> {
        let MultiTrieDump {
            node_data,
            nb_tries,
            nb_required,
            min_support_exp,
            max_error_exp,
            maximize_coverage,
            oracle_numeric_infos,
        } = dump;

        let store = node_data
            .into_iter()
            .map(|x| MultiTrieNode::from_data(x))
            .collect();

        MultiTrie {
            store,
            nb_tries,
            nb_required,
            min_support_exp,
            max_error_exp,
            maximize_coverage,
            oracle_numeric_infos,
        }
    }
}

/// Holds the data of a multi trie node. Used for serialization purpose.
pub enum MultiTrieNodeData<T>
where
    T: Clone,
{
    /// A leaf in the trie.
    Leaf(DigitTrieDump<T>),
    /// A node in the trie.
    Node(DigitTrieDump<Vec<TrieNodeInfo>>),
}

impl<T> MultiTrieNode<T>
where
    T: Clone,
{
    fn get_data(&self) -> MultiTrieNodeData<T> {
        match self {
            Node::Leaf(l) => MultiTrieNodeData::Leaf(l.dump()),
            Node::Node(n) => MultiTrieNodeData::Node(n.dump()),
            Node::None => unreachable!(),
        }
    }

    fn from_data(data: MultiTrieNodeData<T>) -> MultiTrieNode<T> {
        match data {
            MultiTrieNodeData::Leaf(l) => Node::Leaf(DigitTrie::from_dump(l)),
            MultiTrieNodeData::Node(n) => Node::Node(DigitTrie::from_dump(n)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        get_variable_oracle_numeric_infos, same_num_digits_oracle_numeric_infos,
    };

    fn tests_common(
        m_trie: &mut MultiTrie<usize>,
        path: Vec<usize>,
        good_paths: Vec<Vec<(usize, Vec<usize>)>>,
        bad_paths: Vec<Vec<(usize, Vec<usize>)>>,
        expected_iter: Option<Vec<Vec<(usize, Vec<usize>)>>>,
    ) {
        let mut get_value = |_: &[Vec<usize>], _: &[usize]| -> Result<usize, Error> { Ok(2) };

        m_trie.insert(&path, &mut get_value).unwrap();

        for good_path in good_paths {
            assert!(
                m_trie.look_up(&good_path).is_some(),
                "Path {:?} not found",
                good_path
            );
        }

        for bad_path in bad_paths {
            assert!(
                m_trie.look_up(&bad_path).is_none(),
                "Path {:?} was found",
                bad_path
            );
        }

        if let Some(expected) = expected_iter {
            let iter = MultiTrieIterator::new(&m_trie);

            for (i, res) in iter.enumerate() {
                assert_eq!(expected[i], res.path);
            }
        }
    }

    #[test]
    fn multi_trie_1_of_1_test() {
        let mut m_trie = MultiTrie::<usize>::new(
            &same_num_digits_oracle_numeric_infos(1, 5, 2),
            1,
            2,
            3,
            true,
        );

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

        tests_common(
            &mut m_trie,
            path,
            good_paths,
            bad_paths,
            Some(expected_iter),
        );
    }

    #[test]
    fn multi_trie_1_of_2_test() {
        let mut m_trie = MultiTrie::<usize>::new(
            &same_num_digits_oracle_numeric_infos(2, 5, 2),
            1,
            2,
            3,
            true,
        );

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

        tests_common(
            &mut m_trie,
            path,
            good_paths,
            bad_paths,
            Some(expected_iter),
        );
    }

    #[test]
    fn multi_trie_2_of_2_test() {
        let mut m_trie = MultiTrie::<usize>::new(
            &same_num_digits_oracle_numeric_infos(2, 5, 2),
            2,
            2,
            3,
            true,
        );

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

        tests_common(
            &mut m_trie,
            path,
            good_paths,
            bad_paths,
            Some(expected_iter),
        );
    }

    #[test]
    fn multi_trie_2_of_3_test() {
        let mut m_trie = MultiTrie::<usize>::new(
            &same_num_digits_oracle_numeric_infos(3, 5, 2),
            2,
            2,
            3,
            true,
        );

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

        tests_common(&mut m_trie, path, good_paths, bad_paths, None);
    }

    #[test]
    fn multi_trie_5_of_5_test() {
        let mut m_trie = MultiTrie::<usize>::new(
            &same_num_digits_oracle_numeric_infos(5, 3, 2),
            5,
            1,
            2,
            true,
        );

        let path = vec![0, 0, 0];

        let good_paths = vec![vec![
            (0, vec![0, 0, 0]),
            (1, vec![0]),
            (2, vec![0]),
            (3, vec![0]),
            (4, vec![0]),
        ]];

        tests_common(
            &mut m_trie,
            path,
            good_paths.clone(),
            vec![],
            Some(good_paths),
        );
    }

    #[test]
    fn multi_3_of_3_test_lexicographic_order() {
        let mut m_trie = MultiTrie::<usize>::new(
            &same_num_digits_oracle_numeric_infos(3, 3, 2),
            3,
            1,
            2,
            true,
        );

        let inputs = vec![
            vec![0, 0],
            vec![0, 0, 1],
            vec![0, 1, 0],
            vec![0, 1, 1],
            vec![1, 0, 0],
            vec![1, 0, 1],
        ];

        let mut counter = 0;

        let mut get_value = |_: &[std::vec::Vec<usize>], _: &[usize]| -> Result<usize, Error> {
            counter += 1;
            Ok(counter - 1)
        };

        for input in inputs {
            m_trie
                .insert(&input, &mut get_value)
                .expect("Error inserting in trie");
        }

        let iter = MultiTrieIterator::new(&m_trie);

        for (i, res) in iter.enumerate() {
            assert_eq!(i, *res.value);
        }
    }

    fn multi_enumerate_equal_lookup_common(mut m_trie: MultiTrie<usize>) {
        let inputs = vec![
            // vec![0, 0],
            vec![0, 1, 0],
            // vec![0, 1, 1],
            // vec![1, 0, 0],
            // vec![1, 0, 1],
        ];

        let mut counter = 0;

        let mut get_value = |_: &[Vec<usize>], _: &[usize]| -> Result<usize, Error> {
            counter += 1;
            Ok(counter - 1)
        };

        for input in inputs {
            m_trie
                .insert(&input, &mut get_value)
                .expect("Error inserting in trie");
        }

        let iter = MultiTrieIterator::new(&m_trie);

        for res in iter {
            assert_eq!(
                m_trie.look_up(&res.path).expect("Path not found").0,
                res.value
            );
        }
    }

    #[test]
    fn multi_3_of_5_test_enumerate_equal_lookup() {
        let m_trie = MultiTrie::<usize>::new(
            &same_num_digits_oracle_numeric_infos(5, 3, 2),
            3,
            1,
            2,
            true,
        );
        multi_enumerate_equal_lookup_common(m_trie);
    }

    #[test]
    fn multi_5_of_5_test_enumerate_equal_lookup() {
        let m_trie = MultiTrie::<usize>::new(
            &same_num_digits_oracle_numeric_infos(5, 3, 2),
            5,
            1,
            2,
            true,
        );
        multi_enumerate_equal_lookup_common(m_trie);
    }

    #[test]
    fn multi_2_of_3_diff_nb_digits_enumerate_equal_lookup() {
        let m_trie = MultiTrie::<usize>::new(
            &get_variable_oracle_numeric_infos(&[3, 4, 5], 2),
            2,
            1,
            2,
            true,
        );
        multi_enumerate_equal_lookup_common(m_trie);
    }

    struct TestCase {
        path: Vec<usize>,
        good_paths: Vec<Vec<(usize, Vec<usize>)>>,
        bad_paths: Vec<Vec<(usize, Vec<usize>)>>,
    }

    #[test]
    fn multi_trie_2_of_3_diff_nb_digits_test() {
        let mut m_trie = MultiTrie::<usize>::new(
            &get_variable_oracle_numeric_infos(&[5, 6, 7], 2),
            2,
            2,
            3,
            true,
        );

        let test_cases = vec![
            TestCase {
                path: vec![0, 1, 1, 1],
                good_paths: vec![
                    vec![(0, vec![0, 1, 1, 1, 1]), (1, vec![0, 0, 1, 1, 1, 1])],
                    vec![(1, vec![0, 0, 1, 1, 1, 1]), (2, vec![0, 0, 0, 1, 1, 1, 1])],
                    vec![(0, vec![0, 1, 1, 1, 1]), (2, vec![0, 0, 0, 1, 1, 1, 1])],
                    vec![(0, vec![0, 1, 1, 1, 1]), (2, vec![0, 0, 1, 0, 0, 1, 1])],
                    vec![(1, vec![0, 0, 1, 1, 1, 1]), (2, vec![0, 0, 1, 0, 0, 1, 1])],
                    vec![(1, vec![0, 0, 1, 1, 1, 1]), (2, vec![0, 0, 1, 0, 0, 1, 1])],
                ],
                bad_paths: vec![
                    vec![(0, vec![1, 1, 1, 1, 1]), (1, vec![0, 1, 1, 1, 1])],
                    vec![(2, vec![0, 1, 1, 1, 1]), (1, vec![0, 1, 1, 1, 1])],
                    vec![(0, vec![0, 1, 1, 1, 1]), (2, vec![1, 1, 1, 1, 1])],
                    vec![(1, vec![0, 1, 1, 1, 1]), (2, vec![1, 1, 1, 1, 1])],
                ],
            },
            TestCase {
                path: vec![1, 1, 1],
                good_paths: vec![
                    vec![(0, vec![1, 1, 1, 1, 1]), (1, vec![1, 0, 0, 0, 0])],
                    vec![(0, vec![1, 1, 1, 1, 1]), (2, vec![0, 1, 0, 0, 0, 0, 0])],
                    vec![(0, vec![1, 1, 1, 1, 1]), (2, vec![0, 1, 0, 0, 0, 0, 1])],
                    vec![(1, vec![0, 1, 1, 1, 1, 1]), (2, vec![0, 1, 0, 0, 0, 0, 0])],
                ],
                bad_paths: vec![
                    vec![(0, vec![1, 1, 1, 1, 1]), (1, vec![1, 0, 0, 1, 1, 1])],
                    vec![(1, vec![0, 1, 1, 1, 1, 1]), (2, vec![0, 1, 0, 1, 1, 1])],
                    vec![(0, vec![1, 1, 1, 0, 0]), (2, vec![0, 1, 0, 0, 1, 0, 1])],
                    vec![(0, vec![1, 1, 1, 1, 1]), (2, vec![0, 1, 0, 1, 0, 0, 0])],
                ],
            },
        ];

        for case in test_cases {
            tests_common(
                &mut m_trie,
                case.path,
                case.good_paths,
                case.bad_paths,
                None,
            );
        }
    }

    #[test]
    fn multi_trie_2_of_3_diff_nb_digits_unordered_test() {
        let mut m_trie = MultiTrie::<usize>::new(
            &get_variable_oracle_numeric_infos(&[6, 5, 7], 2),
            2,
            2,
            3,
            true,
        );

        let test_cases = vec![
            TestCase {
                path: vec![0, 1, 1, 1],
                good_paths: vec![
                    vec![(0, vec![0, 0, 1, 1, 1, 1]), (1, vec![0, 1, 1, 1, 1])],
                    vec![(0, vec![0, 0, 1, 1, 1, 1]), (2, vec![0, 0, 0, 1, 1, 1, 1])],
                    vec![(1, vec![0, 1, 1, 1, 1]), (2, vec![0, 0, 0, 1, 1, 1, 1])],
                    vec![(1, vec![0, 1, 1, 1, 1]), (2, vec![0, 0, 1, 0, 0, 1, 1])],
                    vec![(0, vec![0, 0, 1, 1, 1, 1]), (2, vec![0, 0, 1, 0, 0, 1, 1])],
                    vec![(0, vec![0, 0, 1, 1, 1, 1]), (2, vec![0, 0, 1, 0, 0, 1, 1])],
                ],
                bad_paths: vec![
                    vec![(1, vec![1, 1, 1, 1, 1]), (0, vec![0, 1, 1, 1, 1])],
                    vec![(2, vec![0, 1, 1, 1, 1]), (0, vec![0, 1, 1, 1, 1])],
                    vec![(1, vec![0, 1, 1, 1, 1]), (2, vec![1, 1, 1, 1, 1])],
                    vec![(0, vec![0, 1, 1, 1, 1]), (2, vec![1, 1, 1, 1, 1])],
                ],
            },
            TestCase {
                path: vec![1, 1, 1],
                good_paths: vec![
                    vec![(0, vec![1, 0, 0, 0, 0]), (1, vec![1, 1, 1, 1, 1])],
                    vec![(1, vec![1, 1, 1, 1, 1]), (2, vec![0, 1, 0, 0, 0, 0, 0])],
                    vec![(1, vec![1, 1, 1, 1, 1]), (2, vec![0, 1, 0, 0, 0, 0, 1])],
                    vec![(0, vec![0, 1, 1, 1, 1, 1]), (2, vec![0, 1, 0, 0, 0, 0, 0])],
                ],
                bad_paths: vec![
                    vec![(1, vec![1, 1, 1, 1, 1]), (0, vec![1, 0, 0, 1, 1, 1])],
                    vec![(0, vec![0, 1, 1, 1, 1, 1]), (2, vec![0, 1, 0, 1, 1, 1])],
                    vec![(1, vec![1, 1, 1, 0, 0]), (2, vec![0, 1, 0, 0, 1, 0, 1])],
                    vec![(1, vec![1, 1, 1, 1, 1]), (2, vec![0, 1, 0, 1, 0, 0, 0])],
                ],
            },
        ];

        for case in test_cases {
            tests_common(
                &mut m_trie,
                case.path,
                case.good_paths,
                case.bad_paths,
                None,
            );
        }
    }

    #[test]
    fn ttt() {
        let inputs = vec![
            vec![0, 0, 0],
            vec![0, 0, 1],
            vec![0, 1, 0],
            vec![0, 1, 1],
            vec![1],
        ];
        let mut m_trie = MultiTrie::<usize>::new(
            &get_variable_oracle_numeric_infos(&[4, 3], 2),
            2,
            1,
            2,
            true,
        );

        let mut counter = 0;
        let mut get_value = |_: &[Vec<usize>], _: &[usize]| -> Result<usize, Error> {
            let res = counter;
            counter += 1;
            Ok(res)
        };
        for input in inputs {
            m_trie.insert(&input, &mut get_value).unwrap();
        }

        let iterator = MultiTrieIterator::new(&m_trie);
        let mut unordered = iterator.map(|x| *x.value).collect::<Vec<_>>();

        unordered.sort();

        let mut prev_index = 0;
        for i in unordered.iter().skip(1) {
            assert_eq!(*i, prev_index + 1);
            prev_index += 1;
        }
    }
}
