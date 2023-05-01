//! # DigitTrie
//! Data structure to store and lookup digit decomposition data.

use crate::{LookupResult, Node};
use dlc::Error;

/// Structure to store data inserted and looked-up based on digit paths.
#[derive(Clone)]
pub struct DigitTrie<T> {
    /// Use the arena allocated approach which makes it easier to
    /// satisfy the borrow checker.  
    store: Vec<Node<DigitLeaf<T>, DigitNode<T>>>,
    root: Option<usize>,
    pub(crate) base: usize,
}

/// Container for a dump of a DigitTrie used for serialization purpose.
pub struct DigitTrieDump<T>
where
    T: Clone,
{
    /// The data of the trie node.
    pub node_data: Vec<DigitNodeData<T>>,
    /// The root of the trie.
    pub root: Option<usize>,
    /// The base for which this trie was built for.
    pub base: usize,
}

impl<T> DigitTrie<T>
where
    T: Clone,
{
    /// Dump the content of the trie for the purpose of serialization.
    pub fn dump(&self) -> DigitTrieDump<T> {
        let node_data = self.store.iter().map(|x| x.get_data()).collect();
        DigitTrieDump {
            root: self.root,
            base: self.base,
            node_data,
        }
    }

    /// Restore a trie from a dump.
    pub fn from_dump(dump: DigitTrieDump<T>) -> DigitTrie<T> {
        let DigitTrieDump {
            root,
            base,
            node_data,
        } = dump;
        let store = node_data.into_iter().map(|x| Node::from_data(x)).collect();
        DigitTrie { store, root, base }
    }
}

/// External representation of a node used for serialization purpose.
pub struct DigitNodeData<T> {
    /// The data contained in the node.
    pub data: Option<T>,
    /// The prefix path of the node.
    pub prefix: Vec<usize>,
    /// The descendants of the node.
    pub children: Option<Vec<Option<usize>>>,
}

impl<T> Node<DigitLeaf<T>, DigitNode<T>>
where
    T: Clone,
{
    fn get_data(&self) -> DigitNodeData<T> {
        match self {
            Node::Leaf(l) => DigitNodeData {
                data: Some(l.data.clone()),
                prefix: l.prefix.clone(),
                children: None,
            },
            Node::Node(n) => DigitNodeData {
                data: n.data.clone(),
                prefix: n.prefix.clone(),
                children: Some(n.children.clone()),
            },
            Node::None => unreachable!(),
        }
    }

    fn from_data(data: DigitNodeData<T>) -> Node<DigitLeaf<T>, DigitNode<T>> {
        match data.children {
            Some(c) => Node::Node(DigitNode {
                children: c,
                prefix: data.prefix,
                data: data.data,
            }),
            None => Node::Leaf(DigitLeaf {
                prefix: data.prefix,
                data: data.data.unwrap(),
            }),
        }
    }
}

/// Structure used to iterated through a `DigitTrie` values. The iterator performs
/// a pre-order traversal of the trie.
pub struct DigitTrieIter<'a, T> {
    trie: &'a DigitTrie<T>,
    /// Stack storing the node index of parents of the node currently being
    /// visited (first item in the tuple), as well as the index of the child that
    /// was last visited. An `isize` is used as the value -1 is used to indicate
    /// that the node value has not yet been yield.
    index_stack: Vec<(Option<usize>, isize)>,
    cur_prefix: Vec<Vec<usize>>,
}

impl<'a, T> DigitTrieIter<'a, T> {
    /// Create a new `DigitTrieIter` struct.
    pub fn new(trie: &'a DigitTrie<T>) -> DigitTrieIter<'a, T> {
        DigitTrieIter {
            index_stack: vec![(trie.root, -1)],
            trie,
            cur_prefix: Vec::new(),
        }
    }

    fn cur_prefix_append(&mut self, to_append: &[usize]) {
        self.cur_prefix.push(to_append.to_vec());
    }
    fn cur_prefix_drop(&mut self) {
        self.cur_prefix.pop();
    }
}

#[derive(Clone)]
struct DigitLeaf<T> {
    data: T,
    prefix: Vec<usize>,
}

#[derive(Clone)]
struct DigitNode<T> {
    children: Vec<Option<usize>>,
    prefix: Vec<usize>,
    data: Option<T>,
}

trait NodePrefix {
    fn get_node_prefix(&self) -> Vec<usize>;
    fn set_node_prefix(&mut self, prefix: Vec<usize>);
}

impl<T> NodePrefix for Node<DigitLeaf<T>, DigitNode<T>> {
    fn get_node_prefix(&self) -> Vec<usize> {
        match self {
            Node::None => unreachable!(),
            Node::Leaf(digit_leaf) => digit_leaf.prefix.clone(),
            Node::Node(digit_node) => digit_node.prefix.clone(),
        }
    }

    fn set_node_prefix(&mut self, prefix: Vec<usize>) {
        let pref = match self {
            Node::None => unreachable!(),
            Node::Leaf(digit_leaf) => &mut digit_leaf.prefix,
            Node::Node(digit_node) => &mut digit_node.prefix,
        };

        *pref = prefix;
    }
}

fn get_common_prefix(a: &[usize], b: &[usize]) -> Vec<usize> {
    a.iter()
        .zip(b.iter())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x)
        .cloned()
        .collect()
}

fn insert_new_leaf<T>(trie: &mut DigitTrie<T>, path: &[usize], data: T) -> usize {
    trie.store.push(Node::Leaf(DigitLeaf {
        prefix: path.to_vec(),
        data,
    }));
    trie.store.len() - 1
}

fn is_prefix_of(prefix: &[usize], value: &[usize]) -> bool {
    if prefix.len() > value.len() {
        return false;
    }
    for i in 0..prefix.len() {
        if prefix[i] != value[i] {
            return false;
        }
    }

    true
}

/// Implementation of the `Iterator` trait for `DigitTrieIter`
impl<'a, T> Iterator for DigitTrieIter<'a, T> {
    type Item = LookupResult<'a, T, usize>;
    fn next(&mut self) -> Option<Self::Item> {
        let popped = self.index_stack.pop();
        let (cur_index, mut cur_child) = match popped {
            None => return None,
            Some((cur_index, cur_child)) => match cur_index {
                None => {
                    return self.next();
                }
                Some(cur_index) => (cur_index, cur_child),
            },
        };

        match &self.trie.store[cur_index] {
            Node::None => unreachable!(),
            Node::Leaf(digit_leaf) => Some(LookupResult {
                value: &digit_leaf.data,
                path: self
                    .cur_prefix
                    .iter()
                    .filter(|x| !x.is_empty())
                    .flatten()
                    .chain(digit_leaf.prefix.iter())
                    .cloned()
                    .collect(),
            }),
            Node::Node(digit_node) => {
                let node_prefix = digit_node.prefix.clone();

                if cur_child >= (self.trie.base as isize) {
                    self.cur_prefix_drop();
                    self.next()
                } else {
                    let cur_children = digit_node.children.clone();
                    if cur_child == -1 {
                        match &digit_node.data {
                            Some(data) => {
                                self.index_stack.push((Some(cur_index), cur_child + 1));
                                return Some(LookupResult {
                                    value: data,
                                    path: self
                                        .cur_prefix
                                        .iter()
                                        .filter(|x| !x.is_empty())
                                        .flatten()
                                        .chain(digit_node.prefix.iter())
                                        .cloned()
                                        .collect(),
                                });
                            }
                            _ => {
                                cur_child += 1;
                            }
                        }
                    }
                    if cur_child == 0 {
                        self.cur_prefix_append(&node_prefix);
                    }
                    while cur_child < (self.trie.base as isize) {
                        self.index_stack.push((Some(cur_index), cur_child + 1));
                        self.index_stack
                            .push((cur_children[cur_child as usize], -1));
                        match self.next() {
                            None => {
                                self.index_stack.pop();
                                cur_child += 1;
                            }
                            Some(res) => {
                                return Some(res);
                            }
                        };
                    }
                    self.cur_prefix_drop();
                    self.index_stack.pop();
                    None
                }
            }
        }
    }
}

impl<T> DigitTrie<T> {
    /// Create a new `DigitTrie`.
    pub fn new(base: usize) -> DigitTrie<T> {
        DigitTrie {
            store: Vec::new(),
            root: None,
            base,
        }
    }

    /// Insert or update data at `path`.
    pub fn insert<F>(&mut self, path: &[usize], get_data: &mut F) -> Result<(), Error>
    where
        F: FnMut(Option<T>) -> Result<T, Error>,
    {
        if path.is_empty() || path.iter().any(|x| x > &self.base) {
            panic!("Invalid path");
        }

        self.root = Some(self.insert_internal(self.root, path, get_data)?);
        Ok(())
    }

    fn insert_internal<F>(
        &mut self,
        cur_index: Option<usize>,
        path: &[usize],
        get_data: &mut F,
    ) -> Result<usize, Error>
    where
        F: FnMut(Option<T>) -> Result<T, Error>,
    {
        match cur_index {
            None => Ok(insert_new_leaf(self, path, get_data(None)?)),
            Some(cur_index) => {
                self.store.push(Node::None);
                let mut cur_node = self.store.swap_remove(cur_index);
                let prefix = cur_node.get_node_prefix();
                if prefix == path {
                    match cur_node {
                        Node::Leaf(digit_leaf) => {
                            self.store[cur_index] = Node::Leaf(DigitLeaf {
                                data: get_data(Some(digit_leaf.data))?,
                                prefix: digit_leaf.prefix.to_vec(),
                            });
                            Ok(cur_index)
                        }
                        Node::Node(mut node) => {
                            node.data = Some(get_data(node.data)?);
                            self.store[cur_index] = Node::Node(node);
                            Ok(cur_index)
                        }
                        Node::None => unreachable!(),
                    }
                } else {
                    let common_prefix = get_common_prefix(&prefix, path);
                    let suffix: Vec<_> = path.iter().skip(common_prefix.len()).cloned().collect();
                    if prefix == common_prefix {
                        match cur_node {
                            Node::Node(mut digit_node) => {
                                digit_node.children[suffix[0]] = Some(self.insert_internal(
                                    digit_node.children[suffix[0]],
                                    &suffix,
                                    get_data,
                                )?);
                                self.store[cur_index] = Node::Node(DigitNode {
                                    children: digit_node.children,
                                    prefix: digit_node.prefix,
                                    data: digit_node.data,
                                });
                                return Ok(cur_index);
                            }
                            Node::None => unreachable!(),
                            Node::Leaf(digit_leaf) => {
                                let mut new_children = Vec::new();
                                new_children.resize_with(self.base, || None);
                                new_children[suffix[0]] =
                                    Some(insert_new_leaf(self, &suffix, get_data(None)?));
                                self.store[cur_index] = Node::Node(DigitNode {
                                    prefix: digit_leaf.prefix,
                                    children: new_children,
                                    data: Some(digit_leaf.data),
                                });
                                return Ok(cur_index);
                            }
                        }
                    }

                    let mut new_children = Vec::new();
                    new_children.resize_with(self.base, || None);

                    let data = if path == common_prefix {
                        Some(get_data(None)?)
                    } else {
                        new_children[path[common_prefix.len()]] =
                            Some(insert_new_leaf(self, &suffix, get_data(None)?));
                        None
                    };

                    new_children[prefix[common_prefix.len()]] = Some(cur_index);
                    cur_node.set_node_prefix(
                        prefix.iter().skip(common_prefix.len()).cloned().collect(),
                    );
                    self.store.push(Node::Node(DigitNode {
                        children: new_children,
                        prefix: common_prefix,
                        data,
                    }));
                    self.store[cur_index] = cur_node;
                    Ok(self.store.len() - 1)
                }
            }
        }
    }

    /// Lookup for nodes whose path is either equal or a prefix of `path`.
    pub fn look_up(&self, path: &[usize]) -> Option<Vec<LookupResult<T, usize>>> {
        self.look_up_internal(self.root, path)
    }

    fn look_up_internal(
        &self,
        cur_index: Option<usize>,
        path: &[usize],
    ) -> Option<Vec<LookupResult<T, usize>>> {
        match cur_index {
            None => None,
            Some(cur_index) => match &self.store[cur_index] {
                Node::None => unreachable!(),
                Node::Leaf(digit_leaf) => {
                    let common_prefix = get_common_prefix(&digit_leaf.prefix, path);
                    if digit_leaf.prefix == common_prefix {
                        Some(vec![LookupResult {
                            path: digit_leaf.prefix.to_vec(),
                            value: &digit_leaf.data,
                        }])
                    } else {
                        None
                    }
                }
                Node::Node(digit_node) => {
                    if digit_node.prefix.len() > path.len()
                        || !is_prefix_of(&digit_node.prefix, path)
                    {
                        return None;
                    }

                    if digit_node.prefix.len() == path.len() {
                        return digit_node.data.as_ref().map(|data| {
                            vec![LookupResult {
                                value: data,
                                path: digit_node.prefix.clone(),
                            }]
                        });
                    }

                    let prefix = path[digit_node.prefix.len()];
                    let suffix: Vec<_> =
                        path.iter().skip(digit_node.prefix.len()).cloned().collect();
                    let res = self.look_up_internal(digit_node.children[prefix], &suffix);
                    match res {
                        None => digit_node.data.as_ref().map(|data| {
                            vec![LookupResult {
                                value: data,
                                path: digit_node.prefix.clone(),
                            }]
                        }),
                        Some(l_res) => match &digit_node.data {
                            None => Some(extend_lookup_res_paths(l_res, &digit_node.prefix)),
                            Some(data) => {
                                let mut up_res = extend_lookup_res_paths(l_res, &digit_node.prefix);
                                let mut final_res = vec![LookupResult {
                                    value: data,
                                    path: digit_node.prefix.clone(),
                                }];
                                final_res.append(&mut up_res);
                                Some(final_res)
                            }
                        },
                    }
                }
            },
        }
    }
}

fn extend_lookup_res_paths<'a, T>(
    l_res: Vec<LookupResult<'a, T, usize>>,
    path: &[usize],
) -> Vec<LookupResult<'a, T, usize>> {
    l_res
        .into_iter()
        .map(|x| LookupResult {
            value: x.value,
            path: path.iter().chain(x.path.iter()).cloned().collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digit_trie_test_cases() -> Vec<Vec<Vec<usize>>> {
        vec![
            vec![
                vec![10, 11],
                vec![10, 12],
                vec![10, 13],
                vec![10, 14],
                vec![10, 15],
                vec![11],
                vec![12],
                vec![13, 0],
                vec![13, 1],
                vec![13, 2],
            ],
            vec![
                vec![0, 1, 2, 0, 10, 11],
                vec![0, 1, 2, 0, 10, 12],
                vec![0, 1, 2, 0, 10, 13],
                vec![0, 1, 2, 0, 10, 14],
                vec![0, 1, 2, 0, 10, 15],
                vec![0, 1, 2, 0, 11],
                vec![0, 1, 2, 0, 12],
                vec![0, 1, 2, 0, 13, 0],
                vec![0, 1, 2, 0, 13, 1],
                vec![0, 1, 2, 0, 13, 2],
            ],
        ]
    }

    #[test]
    fn digit_trie_returns_inserted_elements() {
        for test_case in digit_trie_test_cases() {
            let mut digit_trie = DigitTrie::<usize>::new(16);
            for (i, path) in test_case.iter().enumerate() {
                digit_trie.insert(path, &mut |_| Ok(i)).unwrap();
            }

            for (i, path) in test_case.iter().enumerate() {
                let actual = digit_trie.look_up(path);
                match actual {
                    None => panic!(),
                    Some(l_res) => {
                        assert_eq!(1, l_res.len());
                        assert_eq!(path, &l_res[0].path);
                        assert_eq!(i, *l_res[0].value);
                    }
                }
            }
        }
    }

    #[test]
    fn digit_trie_return_value_with_longer_path_query() {
        let mut digit_trie = DigitTrie::new(5);
        let expected_path = &[0, 1];
        let expected_value = 1;
        digit_trie
            .insert(expected_path, &mut |_| Ok(expected_value))
            .unwrap();
        let actual = digit_trie.look_up(&[0, 1, 2]);
        match actual {
            None => panic!(),
            Some(l_res) => {
                assert_eq!(1, l_res.len());
                assert_eq!(l_res[0].path, &[0, 1]);
                assert_eq!(*l_res[0].value, expected_value);
            }
        }
    }

    #[test]
    fn digit_trie_insert_on_common_prefix_query_longest_returns_both() {
        let mut digit_trie = DigitTrie::new(5);
        digit_trie.insert(&[0, 1, 2, 3], &mut |_| Ok(1)).unwrap();
        digit_trie.insert(&[0, 1, 2], &mut |_| Ok(2)).unwrap();
        let res = digit_trie.look_up(&[0, 1, 2, 3]).unwrap();

        assert_eq!(res.len(), 2);
        assert_eq!(vec![0, 1, 2], res[0].path);
        assert_eq!(vec![0, 1, 2, 3], res[1].path);
    }

    #[test]
    fn digit_trie_insert_on_common_prefix_query_shortest_returns_single() {
        let mut digit_trie = DigitTrie::new(5);
        digit_trie.insert(&[0, 1, 2, 3], &mut |_| Ok(1)).unwrap();
        digit_trie.insert(&[0, 1, 2], &mut |_| Ok(2)).unwrap();
        let res = digit_trie.look_up(&[0, 1, 2]).unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(vec![0, 1, 2], res[0].path);
    }

    #[test]
    fn digit_trie_insert_on_common_prefix_query_longer_non_existing_returns_single() {
        let mut digit_trie = DigitTrie::new(5);
        digit_trie.insert(&[0, 1, 2, 3], &mut |_| Ok(1)).unwrap();
        digit_trie.insert(&[0, 1, 2], &mut |_| Ok(2)).unwrap();
        let res = digit_trie.look_up(&[0, 1, 2, 4]).unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(vec![0, 1, 2], res[0].path);
    }

    #[test]
    fn digit_trie_insert_on_leaf_returns_both() {
        let mut digit_trie = DigitTrie::new(5);
        digit_trie.insert(&[0, 1, 2], &mut |_| Ok(1)).unwrap();
        digit_trie.insert(&[0, 1, 2, 3], &mut |_| Ok(2)).unwrap();
        let res = digit_trie.look_up(&[0, 1, 2, 3]).unwrap();

        assert_eq!(res.len(), 2);
        assert_eq!(vec![0, 1, 2], res[0].path);
        assert_eq!(vec![0, 1, 2, 3], res[1].path);
    }

    #[test]
    fn digit_trie_query_non_inserted_returns_not_found() {
        let mut digit_trie = DigitTrie::new(5);
        digit_trie.insert(&[0, 1, 2], &mut |_| Ok(1)).unwrap();
        digit_trie.insert(&[1, 2, 3], &mut |_| Ok(2)).unwrap();
        assert!(digit_trie.look_up(&[0, 1, 3]).is_none());
        assert!(digit_trie.look_up(&[1, 2, 5]).is_none());
        assert!(digit_trie.look_up(&[0, 0, 0]).is_none());
    }

    #[test]
    fn digit_trie_replace_data_when_insert_on_existing_path() {
        let mut digit_trie = DigitTrie::new(5);
        let path = &[0, 1, 2, 3];
        digit_trie.insert(path, &mut |_| Ok(1)).unwrap();
        digit_trie.insert(path, &mut |_| Ok(2)).unwrap();
        let res = digit_trie.look_up(path);
        match res {
            None => panic!(),
            Some(l_res) => assert_eq!(*l_res[0].value, 2),
        }
    }

    #[test]
    fn digit_trie_insert_on_mid_node_returns_all() {
        let mut digit_trie = DigitTrie::new(5);
        digit_trie.insert(&[0, 1, 2, 3], &mut |_| Ok(1)).unwrap();
        digit_trie.insert(&[0, 1, 2, 4], &mut |_| Ok(2)).unwrap();
        digit_trie.insert(&[0, 1, 2], &mut |_| Ok(3)).unwrap();

        let res = digit_trie.look_up(&[0, 1, 2, 3]).unwrap();

        assert_eq!(2, res.len());
        assert_eq!(*res[0].value, 3);
        assert_eq!(*res[1].value, 1);

        let res = digit_trie.look_up(&[0, 1, 2, 4]).unwrap();

        assert_eq!(2, res.len());
        assert_eq!(*res[0].value, 3);
        assert_eq!(*res[1].value, 2);
    }

    fn assert_not_found<T>(res: Option<Vec<LookupResult<T, usize>>>)
    where
        T: Copy,
    {
        if res.is_some() {
            panic!();
        }
    }

    #[test]
    fn digit_trie_return_not_found_if_not_inserted() {
        let mut digit_trie = DigitTrie::new(5);
        digit_trie.insert(&[0, 1, 2], &mut |_| Ok(1)).unwrap();
        digit_trie.insert(&[0, 1, 3], &mut |_| Ok(2)).unwrap();
        digit_trie.insert(&[4, 1, 2], &mut |_| Ok(3)).unwrap();

        assert_not_found(digit_trie.look_up(&[1, 2, 5]));
        assert_not_found(digit_trie.look_up(&[2]));
        assert_not_found(digit_trie.look_up(&[1]));
        assert_not_found(digit_trie.look_up(&[1, 3]));
        assert_not_found(digit_trie.look_up(&[2, 1, 3]));
    }

    #[test]
    fn digit_trie_returns_inserted_values_when_iterating() {
        for test_case in digit_trie_test_cases() {
            let mut digit_trie = DigitTrie::<usize>::new(16);
            for (i, path) in test_case.iter().enumerate() {
                digit_trie.insert(path, &mut |_| Ok(i)).unwrap();
            }

            let digit_trie_iter = DigitTrieIter::new(&digit_trie);

            let mut count = 0;
            for (i, res) in digit_trie_iter.enumerate() {
                assert_eq!(test_case[i], res.path);
                assert_eq!(i, *res.value);
                count += 1;
            }

            assert_eq!(test_case.len(), count);
        }
    }

    #[test]
    fn digit_trie_returns_node_values_when_iterating() {
        let mut digit_trie = DigitTrie::new(5);
        let test_cases = vec![
            vec![vec![0, 1, 2, 3], vec![0, 1, 2, 4], vec![0, 1, 2]],
            vec![vec![0, 1, 2], vec![0, 1, 2, 3], vec![0, 1, 2, 4]],
            vec![
                vec![0, 1],
                vec![0, 1, 2],
                vec![0, 1, 2, 3],
                vec![0, 1, 2, 4],
            ],
            vec![
                vec![0, 1, 2],
                vec![0, 1, 2, 3],
                vec![0, 1],
                vec![0, 1, 2, 4],
            ],
            vec![
                vec![0, 1, 2, 3],
                vec![0, 1, 2, 4],
                vec![0, 1],
                vec![0, 1, 2],
            ],
        ];
        for test_case in test_cases {
            for (i, test_path) in test_case.iter().enumerate() {
                digit_trie.insert(test_path, &mut |_| Ok(i)).unwrap();
            }

            let digit_trie_iter = DigitTrieIter::new(&digit_trie);

            let mut count = 0;
            for res in digit_trie_iter {
                assert_eq!(
                    *res.value,
                    test_case.iter().position(|x| x == &res.path).unwrap()
                );
                count += 1;
            }

            assert_eq!(test_case.len(), count);
        }
    }

    #[test]
    fn digit_trie_iterate_gets_all_inserted_values() {
        let mut digit_trie = DigitTrie::new(2);
        let paths = vec![vec![0, 0], vec![0, 1], vec![1, 0, 0], vec![0, 1, 0]];
        let mut counter = 0;
        let mut get_value = |_: Option<usize>| -> Result<usize, Error> {
            let res = counter;
            counter += 1;
            Ok(res)
        };

        for path in &paths {
            digit_trie.insert(path, &mut get_value).unwrap();
        }

        let iter = DigitTrieIter::new(&digit_trie);

        let mut unordered = iter.map(|x| *x.value).collect::<Vec<_>>();

        assert_eq!(paths.len(), unordered.len());

        unordered.sort_unstable();

        for (prev_index, i) in unordered.iter().skip(1).enumerate() {
            assert_eq!(*i, prev_index + 1);
        }
    }
}
