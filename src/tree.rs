use std::cell::UnsafeCell;
use digest::{
    Digest,
    FixedOutputReset,
    Output,
    generic_array::GenericArray,
};

use std::default::Default;
use std::fmt::{
    Display,
    Formatter,
    Result,
};

use crate::errors::AsHex;

/* ************************************************************************** */
/* Merkle Hash */

/// The type of Merkle hash values
///
pub struct MerkleHash<H>(Output<H>)
where
    H: Digest;
    // Backed by GenericArray, which has static layout

impl<H> PartialEq for MerkleHash<H>
where
    H: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<H> std::fmt::Debug for MerkleHash<H>
where
    H: Digest,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_tuple("MerkleHash").field(&AsHex(&self.0)).finish()
    }
}

impl<H> Clone for MerkleHash<H>
where
    H: Digest,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<H: Digest> Default for MerkleHash<H> {
    fn default() -> Self {
        MerkleHash(GenericArray::default())
    }
}

impl<H: Digest> Display for MerkleHash<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let Self(v) = self;
        write!(f, "{}", AsHex(v))
    }
}

impl<H: Digest> From<MerkleHash<H>> for Output<H> {
    fn from(value: MerkleHash<H>) -> Self {
        let MerkleHash(v) = value;
        v
    }
}

impl<H: Digest> AsRef<[u8]> for MerkleHash<H> {
    fn as_ref(&self) -> &[u8] {
        let MerkleHash(v) = self;
        v.as_ref()
    }
}

#[must_use]
pub fn null_hash<H: Digest>() -> MerkleHash<H> {
    MerkleHash::default()
}

/* ************************************************************************** */
/* Merkle Log Entry */

/// A Merkle tree leaf is either some data or the root of another Merkle tree.
///
#[derive(Debug, Clone, PartialEq)]
pub enum MerkleLogEntry<H: Digest> {
    TreeLeaf(MerkleHash<H>),
    DataLeaf(Vec<u8>),
}

impl<'a, H: Digest> From<&'a MerkleLogEntry<H>> for &'a [u8] {
    fn from(h: &'a MerkleLogEntry<H>) -> Self {
        match h {
            MerkleLogEntry::TreeLeaf(a) => a.as_ref(),
            MerkleLogEntry::DataLeaf(b) => b.as_ref(),
        }
    }
}

impl<H: Digest> From<MerkleLogEntry<H>> for Vec<u8> {
    fn from(h: MerkleLogEntry<H>) -> Self {
        match h {
            MerkleLogEntry::TreeLeaf(a) => a.as_ref().into(),
            MerkleLogEntry::DataLeaf(a) => a,
        }
    }
}

impl<H: Digest> Display for MerkleLogEntry<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            MerkleLogEntry::TreeLeaf(a) => write!(f, "TREE[{}]", AsHex(a)),
            MerkleLogEntry::DataLeaf(a) => write!(f, "DATA[{}]", AsHex(a)),
        }
    }
}

impl<H: Digest> AsRef<[u8]> for MerkleLogEntry<H> {
    fn as_ref(&self) -> &[u8] {
        match self {
            MerkleLogEntry::TreeLeaf(a) => a.as_ref(),
            MerkleLogEntry::DataLeaf(a) => a,
        }
    }
}


/* ************************************************************************** */
/* Merkle Hashing */

const LEAF_TAG: &[u8; 1] = &[0x0];
const NODE_TAG: &[u8; 1] = &[0x1];

// The context is expected to be new or reset
//
pub(crate) fn merkle_leaf_<H>(ctx: &mut H, result: &mut MerkleHash<H>, leaf: &MerkleLogEntry<H>)
where
    H: Digest + FixedOutputReset,
{
    match leaf {
        MerkleLogEntry::TreeLeaf(a) => {
            (*a).clone_into(result);
        }
        MerkleLogEntry::DataLeaf(a) => {
            Digest::update(ctx, LEAF_TAG);
            Digest::update(ctx, a);
            Digest::finalize_into_reset(ctx, &mut result.0);
        }
    }
}

pub(crate) fn merkle_leaf<H>(leaf: &MerkleLogEntry<H>) -> MerkleHash<H>
where
    H: Digest + FixedOutputReset,
{
    let mut result = MerkleHash::<H>::default();
    let mut ctx = H::new();
    merkle_leaf_(&mut ctx, &mut result, leaf);
    result
}

pub(crate) fn merkle_node_<H: FixedOutputReset + Digest>(
    ctx: &mut H,
    result: &mut MerkleHash<H>,
    left: &MerkleHash<H>,
    right: &MerkleHash<H>,
) {
    digest::Digest::update(ctx, NODE_TAG);
    digest::Digest::update(ctx, left);
    digest::Digest::update(ctx, right);
    digest::Digest::finalize_into_reset(ctx, &mut result.0);
}

/* ************************************************************************** */
/* MerkleTree */

/// A balanced binary Merkle tree.
///
#[derive(Debug)]
pub struct MerkleTree<H: Digest> {
    tree: Vec<MerkleHash<H>>,
}

/// A Merkle log consists of a list of entries along with the the corresponding
/// Merkle tree
///
pub struct MerkleLog<H: Digest> {
    pub entries: Vec<MerkleLogEntry<H>>,
    pub merkle_tree: MerkleTree<H>,
}

/* ************************************************************************** */
/* Internal Utils */

impl<H: Digest + FixedOutputReset> MerkleTree<H> {
    /// Compute length of the log from the size of the tree.
    ///
    pub(crate) fn log_len_from_len(tree_len: u64) -> u64 {
        1 + tree_len / 2
    }

    #[cfg(test)]
    pub(crate) fn len_from_log_len(log_len: u64) -> u64 {
        2 * log_len - 1
    }

    /// tree index from log index (all indexes are zero based).
    ///
    pub(crate) fn tree_idx_from_log_idx(lidx: u64) -> u64 {
        let mut acc: u64 = 0;
        let mut n: u64 = 1;

        // add tree levels, starting with the bottom level
        while n <= lidx {
            acc += lidx / n;
            n *= 2;
        }
        acc
    }

    pub(crate) fn log_idx(&self, lidx: u64) -> &MerkleHash<H> {
        // can't handle trees that don't fit into memory...
        &self.tree[Self::tree_idx_from_log_idx(lidx) as usize]
    }

    pub(crate) fn tree_idx(&self, tidx: u64) -> &MerkleHash<H> {
        // can't handle trees that don't fit into memory...
        &self.tree[tidx as usize]
    }

    /// Number of nodes (including leaf nodes) in the tree.
    ///
    pub(crate) fn len(&self) -> u64 {
        self.tree.len().try_into().unwrap()
    }

    /// Length of the log, i.e. the number of leafs in the tree.
    ///
    pub(crate) fn log_len(&self) -> u64 {
        Self::log_len_from_len(self.len())
    }

}

/* ************************************************************************** */
/* Public API */

impl<H: Digest + FixedOutputReset> MerkleTree<H> {

    /// Return the root hash of a Merkle tree.
    ///
    #[must_use]
    pub fn root(&self) -> &MerkleHash<H> {
        match self.tree.last() {
            Some(a) => a,
            None => {
                unreachable!("MerkleTree must not be empty. This is a bug in the merkle-log library.")
            }
        }
    }

    /// Create Merkle tree where all leafs are data leafs, i.e. there
    /// are no nested Merkle trees.
    ///
    pub fn from_data_leafs<T: AsRef<[u8]>>(leafs: &[T]) -> MerkleTree<H> {
        let entries: Vec<MerkleLogEntry<H>> = leafs
            .iter()
            .map(|i| MerkleLogEntry::DataLeaf(i.as_ref().to_vec()))
            .collect();
        Self::new(&entries)
    }

    // TODO: consider a parallel version of this (which would, however, only pay off for
    // very large trees)
    // TODO: use a more generic collection type of input leafs
    //

    /// Construct a balanced binary Merkle tree.
    ///
    /// If the number of leafs is not a power of two, increasingly
    /// smaller full sub-trees are build left to right first. Once all leafs
    /// are consumed the sub-trees are connected unbalanced right to left.
    ///
    /// There is at most a single full sub-tree of each size and the size of
    /// each full sub-tree is a power two. So, there's a logarithmic number
    /// of full sub-trees. Also the longest path in the unbalanced part of
    /// the tree is still bounded by the number of full sub-trees and thus
    /// of logarithmic length.
    ///
    pub fn new(leafs: &[MerkleLogEntry<H>]) -> MerkleTree<H> {
        // The MerkleTree of the empty log is the hash of the empty string
        if leafs.is_empty() {
            return MerkleTree {
                tree: vec![MerkleHash(H::digest(""))],
            };
        }
        let isize: usize = leafs.len();
        let mut ctx = H::new();

        // wrap hashes in UnsafeCell in order to be able to read from existing hashes while
        // creating new hashes.
        // We could also use some append-only vector, but all existing crates seem to target
        // multithreaded scenarioes, which adds overhead that we don't need here.
        let mut result: Vec<UnsafeCell<MerkleHash<H>>> = Vec::with_capacity(2 * isize - 1);

        // Stack of the level and the index of a node in the tree
        let mut stack: Vec<(usize, usize)> = Vec::new();

        for l in leafs {
            // process next leaf
            let cur = result.len();
            unsafe {
                result.set_len(cur + 1);
                merkle_leaf_(&mut ctx, result[cur].get_mut(), l);
            }
            stack.push((0, cur));

            // process stack
            while let [.., (a, ia), (b, ib)] = stack[..] {
                if a == b {
                    let cur = result.len();
                    unsafe {
                        result.set_len(cur + 1); // this is unsafe
                        merkle_node_(
                            &mut ctx,
                            &mut *result[cur].get(),
                            &*result[ia].get(),
                            &*result[ib].get(),
                        );
                    }
                    stack.pop();
                    stack.pop();
                    stack.push((a + 1, cur));
                } else {
                    break;
                }
            }
        }

        // process stack after all leafs are processed
        loop {
            match stack[..] {
                [.., (a, ia), (_, ib)] => {
                    let cur = result.len();
                    unsafe {
                        result.set_len(cur + 1); // this is unsafe
                        merkle_node_(
                            &mut ctx,
                            &mut *result[cur].get(),
                            &*result[ia].get(),
                            &*result[ib].get(),
                        );
                    }
                    stack.pop();
                    stack.pop();
                    stack.push((a + 1, cur));
                }
                [_] => break,
                [] => unreachable!("code invariant violation"),
            }
        }

        // Cast result vector to merkle tree (dropping UnsafeCell)
        // TODO: use into_raw_parts when it becomes available in future versions of rust
        unsafe {
            // make sure the original vector isn't dropped
            let mut x = std::mem::ManuallyDrop::new(result);
            let hashes = Vec::<MerkleHash<H>>::from_raw_parts(
                x.as_mut_ptr().cast::<MerkleHash<H>>(),
                x.len(),
                x.capacity(),
            );
            MerkleTree::<H> { tree: hashes }
        }
    }

    // TODO: online extensible trees.
    //
    // *   extending a tree means to discard unbalanced parts of the
    //    tree as necessary and replace those by permanent
    //    balanced subtrees.
    // *  The online construction of the tree is possible logarithmic
    //    space without access to the full tree. One only has to
    //    store the (logarithmic number) of the roots of maximal
    //    full subtrees, i.e. the roots of of all permanent
    //    subtrees.

}

/* ************************************************************************** */
/* Tests */

#[cfg(test)]
use sha2::Sha512;

#[cfg(test)]
pub(crate) fn test_merklelog<H>(s: u32) -> MerkleLog<H>
where
    H: Digest + FixedOutputReset,
{
    let data: Vec<[u8; 4]> = (0u32..s).map(|i| i.to_be_bytes()).collect();
    let entries: Vec<MerkleLogEntry<H>> = data
        .iter()
        .map(|i| MerkleLogEntry::DataLeaf(i.to_vec()))
        .collect();
    let merkle_tree = MerkleTree::<H>::new(&entries);
    MerkleLog {
        entries,
        merkle_tree,
    }
}

#[test]
fn s_test() {
    // verify that MerkleTree is stored as continous array
    use sha2::Sha512;
    println!("size: {}", std::mem::size_of::<MerkleHash<Sha512>>());

    let v: Vec<MerkleHash<Sha512>> = vec![MerkleHash::default(); 100];
    println!(
        "size: {}, len: {}",
        std::mem::size_of_val(v.as_slice()),
        v.len()
    );
    assert!(
        std::mem::size_of_val(v.as_slice())
            == v.len() * std::mem::size_of::<MerkleHash<Sha512>>()
    );

    use std::cell::UnsafeCell;
    let v: Vec<UnsafeCell<MerkleHash<Sha512>>> = (0..100)
        .map(|_| UnsafeCell::new(MerkleHash::default()))
        .collect();
    println!(
        "size: {}, len: {}",
        std::mem::size_of_val(v.as_slice()),
        v.len()
    );
    assert!(
        std::mem::size_of_val(v.as_slice())
            == v.len() * std::mem::size_of::<MerkleHash<Sha512>>()
    );
}

#[test]
fn merke_tree_test() {
    let l: u32 = 10;
    let MerkleLog { merkle_tree, .. } = test_merklelog::<Sha512>(l);
    assert_eq!(merkle_tree.log_len(), l as u64);
    assert_eq!(
        MerkleTree::<Sha512>::len_from_log_len(merkle_tree.log_len()),
        merkle_tree.len()
    )
}

#[test]
fn leaf_index_tests() {
    // 0 1 2 3 4 5 6 7
    // x x x x x x x x
    //  x   x   x   x
    //    x       x
    //        x

    assert_eq!(MerkleTree::<Sha512>::tree_idx_from_log_idx(0), 0);
    assert_eq!(MerkleTree::<Sha512>::tree_idx_from_log_idx(1), 1);
    assert_eq!(MerkleTree::<Sha512>::tree_idx_from_log_idx(2), 3);
    assert_eq!(MerkleTree::<Sha512>::tree_idx_from_log_idx(3), 4);
    assert_eq!(MerkleTree::<Sha512>::tree_idx_from_log_idx(4), 7);
    assert_eq!(MerkleTree::<Sha512>::tree_idx_from_log_idx(5), 8);
    assert_eq!(MerkleTree::<Sha512>::tree_idx_from_log_idx(6), 10);
    assert_eq!(MerkleTree::<Sha512>::tree_idx_from_log_idx(7), 11);
    assert_eq!(MerkleTree::<Sha512>::tree_idx_from_log_idx(8), 15);
}

