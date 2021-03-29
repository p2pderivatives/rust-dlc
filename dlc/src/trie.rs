//! Common trie

/// Structure containing a reference to a looked-up value and the
/// path at which it was found.
#[derive(Debug)]
pub struct LookupResult<'a, TValue, TPath> {
    /// The path at which the `value` was found.
    pub path: Vec<TPath>,
    /// The value that was returned.
    pub value: &'a TValue,
}

/// Enum representing the different type of nodes in a tree
#[derive(Debug, Clone)]
pub enum Node<TLeaf, TNode> {
    /// None is only used as a placeholder when taking mutable ownership of a
    /// node during insertion.
    None,
    /// A leaf is a node in the tree that does not have any children.
    Leaf(TLeaf),
    /// A node is parent to at least one other node in a tree.
    Node(TNode),
}
