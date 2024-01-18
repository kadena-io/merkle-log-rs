use digest::{Digest, FixedOutputReset};

use std::default::Default;
use std::fmt::{Display, Formatter, Result};

use crate::errors::{Actual, Expected, MerkleTreeError};
use crate::tree::{
    MerkleHash,
    MerkleLogEntry,
    MerkleTree,
    merkle_leaf,
    merkle_leaf_,
    merkle_node_,
};

/* ************************************************************************** */
/* Proof Step */

#[derive(Debug, PartialEq)]
enum ProofStep<T> {
    Left(T),
    Right(T),
}

impl<T> ProofStep<T> {
    fn map<T2>(&self, f: impl Fn(&T) -> T2) -> ProofStep<T2> {
        match self {
            ProofStep::Left(a) => ProofStep::<T2>::Left(f(a)),
            ProofStep::Right(a) => ProofStep::<T2>::Right(f(a)),
        }
    }
}

impl<T: Display> Display for ProofStep<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            ProofStep::Left(a) => write!(f, "ProofStep::Left({a})"),
            ProofStep::Right(a) => write!(f, "ProofStep::Right({a})"),
        }
    }
}

/* ************************************************************************** */
/* MerkleProof */

/// A Merkle proof provides evidence that the included Merkle log entry is
/// contained in the Merkle root of the proof. The root is not included in the
/// proof but obtained as the result of validating the proof.
///
#[derive(Debug)]
pub struct MerkleProof<H: Digest> {
    /// Position of subject within the log
    pub index: u64,
    /// The log entry
    pub entry: MerkleLogEntry<H>,
    /// The binary proof object
    path: Vec<ProofStep<MerkleHash<H>>>,
}

impl<H: Digest> MerkleProof<H> {

    // User in serialization of proofs
    const SIDE_L: u8 = 0x00;
    const SIDE_R: u8 = 0x01;

    /// Serializes a proof into a byte array.
    ///
    pub fn path_to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(self.path.len() * (1 + <H as digest::Digest>::output_size()));
        for i in &self.path {
            match i {
                ProofStep::Left(a) => {
                    vec.push(Self::SIDE_L);
                    vec.extend_from_slice(a.as_ref());
                },
                ProofStep::Right(a) => {
                    vec.push(Self::SIDE_R);
                    vec.extend_from_slice(a.as_ref());
                },
            }
        }
        vec
    }
}

/* ************************************************************************** */
/* Proof Validation */

impl<'a, H: Digest + FixedOutputReset> MerkleProof<H> {

    /// Running a Merkle proof results in a Merkle root and validates the claim
    /// that the entry in the proof is contained in the preimage of of the root.
    ///
    pub fn run(&'a self) -> MerkleHash<H> {
        let mut ctx = H::new();

        let cur: MerkleHash<H> = MerkleHash::default();
        let mut new: MerkleHash<H> = MerkleHash::default();
        merkle_leaf_(&mut ctx, &mut new, &self.entry);

        let mut cur_box: Box<MerkleHash<H>> = Box::new(cur);
        let mut new_box: Box<MerkleHash<H>> = Box::new(new);
        for i in &self.path {
            // This swaps only the pointers
            std::mem::swap(&mut cur_box, &mut new_box);
            match i {
                ProofStep::Left(x) => {
                    merkle_node_(&mut ctx, &mut new_box, x, &cur_box);
                }
                ProofStep::Right(x) => {
                    merkle_node_(&mut ctx, &mut new_box, &cur_box, x);
                }
            }
        }
        *new_box
    }

    /// Extend a proof with another proof, consuming the other proof. The root
    /// of the extended proof must match the entry of the other proof. In
    /// particular the entry of the second proof must be a
    /// `MerkleLogEntry::TreeLeaf`.
    ///
    /// # Errors
    /// - `MerkleTreeError::AppendOfDataLeafError` when the entry of the other
    ///    is not a `MerkleLogEntry::TreeLeaf`.
    /// - `MerkleTreeError::AppendMismatchError` when the root of the extended
    ///   proof does not match the entry of the other proof.
    ///
    pub fn append(&mut self, mut p: MerkleProof<H>) -> std::result::Result<(), MerkleTreeError> {
        match p.entry {
            MerkleLogEntry::DataLeaf(_) => {
                Err(MerkleTreeError::AppendOfDataLeafError {
                    msg: "MerkleProof::append: can not append a data leaf proof.".into(),
                })
            },
            MerkleLogEntry::TreeLeaf(a) => {
                let r = self.run();
                if r == a {
                    self.path.append(&mut p.path);
                    Ok(())
                } else {
                    Err(MerkleTreeError::AppendMismatchError {
                        msg: "MerkleProof::append: root does not match appended entry".into(),
                        expected: Expected::new(r.as_ref().to_vec()),
                        actual: Actual::new(a.as_ref().to_vec()),
                    })
                }
            },
        }
    }
}

/* ************************************************************************** */
/* Proof Creation */

impl<H: Digest + FixedOutputReset> MerkleTree<H> {

    /// Compute the shape of a proof.
    ///
    /// The result is tree position of the target and the tree positions and
    /// directions of the audit proof.
    ///
    /// ## TODO
    ///
    /// * extend this for proofs with multiple targets
    /// * would this algorithm be simpler when starting from the leaf?
    ///
    fn proof_shape(tree_size: u64, log_idx: u64) -> (u64, Vec<ProofStep<u64>>) {
        let mut tree_off: u64 = 0;
        let mut m: u64 = log_idx;
        let mut n: u64 = Self::log_len_from_len(tree_size);
        let mut result: Vec<ProofStep<u64>> = Vec::new();
        while n > 1 {
            let k: u64 = 2_u64.pow((n - 1).ilog2());
            if m < k {
                result.push(ProofStep::Right(tree_off + 2 * n - 3));
                n = k;
            } else {
                result.push(ProofStep::Left(tree_off + 2 * k - 2));
                tree_off += 2 * k - 1;
                m -= k;
                n -= k;
            }
        }
        result.reverse();
        (tree_off, result)
    }

    /// Construct a self-contained Merkle inclusion proof for a data leaf.
    ///
    /// # Errors
    /// - `MerkleTreeError::IndexOutOfBoundsError`
    /// - `MerkleTreeError::InputNotInTreeError`
    ///
    pub fn proof_data_leaf(
        &self,
        leaf: &[u8],
        lidx: usize,
    ) -> std::result::Result<MerkleProof<H>, MerkleTreeError> {
        self.proof(MerkleLogEntry::DataLeaf(leaf.to_vec()), lidx)
    }

    /// Construct a self-contained Merkle inclusion proof.
    ///
    /// # Errors
    /// - `MerkleTreeError::IndexOutOfBoundsError`
    /// - `MerkleTreeError::InputNotInTreeError`
    ///
    pub fn proof(
        &self,
        leaf: MerkleLogEntry<H>,
        lidx: usize,
    ) -> std::result::Result<MerkleProof<H>, MerkleTreeError> {
        let idx: u64 = lidx.try_into().unwrap();
        if idx > self.log_len() {
            Err(MerkleTreeError::IndexOutOfBoundsError {
                msg: "MerkleTree::proof".into(),
                expected: Expected::new((0, self.log_len() - 1)),
                actual: Actual::new(idx),
            })
        } else if *self.log_idx(idx) != merkle_leaf(&leaf) {
            Err(MerkleTreeError::InputNotInTreeError {
                msg: "MerkleTree<H>::proof".into(),
                idx,
                data: leaf.into(),
            })
        } else {
            let (_, path_shape) = Self::proof_shape(self.len(), idx);
            let mut path = Vec::<ProofStep<MerkleHash<H>>>::new();
            for i in path_shape {
                path.push(i.map(|x| self.tree_idx(*x).clone()));
            }
            Ok(MerkleProof {
                index: idx,
                entry: leaf,
                path,
            })
        }
    }
}

/* ************************************************************************** */
/* Tests */

#[cfg(test)]
use sha2::Sha512;

#[cfg(test)]

#[cfg(test)]
use crate::tree::{
    MerkleLog,
    test_merklelog,
};

#[test]
fn proof_shape_tests() {
    // 0 1 2 3 4 5 6
    // x x x x x x x
    //  x   x   x
    //    x       x
    //        x

    let l: u64 = 7;
    let tsize = MerkleTree::<Sha512>::len_from_log_len(l);

    let (s, p) = MerkleTree::<Sha512>::proof_shape(tsize, 5);
    assert_eq!(s, 8);
    assert_eq!(
        p,
        vec![
            ProofStep::<u64>::Left(7),
            ProofStep::Right(10),
            ProofStep::Left(6)
        ]
    );

    let (s2, p2) = MerkleTree::<Sha512>::proof_shape(tsize, 0);
    assert_eq!(s2, 0);
    assert_eq!(
        p2,
        vec![
            ProofStep::<u64>::Right(1),
            ProofStep::Right(5),
            ProofStep::Right(11)
        ]
    );

    let (s3, p3) = MerkleTree::<Sha512>::proof_shape(tsize, 6);
    assert_eq!(s3, 10);
    assert_eq!(p3, vec![ProofStep::<u64>::Left(9), ProofStep::Left(6)]);
}

#[test]
fn proof_tests() {
    let l: u32 = 7;
    let MerkleLog {
        entries,
        merkle_tree,
    } = test_merklelog::<Sha512>(l);
    match merkle_tree.proof(entries[0].clone(), 0) {
        Err(e) => panic!("proof_tests failed with {}", e),
        Ok(p) => {
            assert_eq!(p.index, 0);
            assert_eq!(p.path.len(), 3);
        }
    }
}

#[test]
fn verify_tests() {
    let l: u32 = 7;
    let MerkleLog {
        entries,
        merkle_tree,
    } = test_merklelog::<Sha512>(l);
    match merkle_tree.proof(entries[0].clone(), 0) {
        Err(e) => panic!("proof_tests failed with {}", e),
        Ok(p) => {
            // verify proof
            let v = p.run();
            assert_eq!(&v, merkle_tree.root());
        }
    }
}

#[test]
fn append_test_fail() {
    // tree 1
    let l1: u32 = 7;
    let MerkleLog {
        entries: entries1,
        merkle_tree: merkle_tree1,
    } = test_merklelog::<Sha512>(l1);
    let mut p1 = merkle_tree1.proof(entries1[0].clone(), 0).expect("merkle_tree1.proof succeeds");

    // this should fail
    let p1_ = merkle_tree1.proof(entries1[0].clone(), 0).expect("merkle_tree1.proof succeeds");

    match p1.append(p1_) {
        Err(MerkleTreeError::AppendOfDataLeafError{ .. }) => (),
        e => assert!(false, "expected MerkleTreeError::AppendOfDataLeafError but got {:?}", e),
    };
}

#[test]
fn append_tests() {
    // tree 1
    let l1: u32 = 7;
    let MerkleLog {
        entries: entries1,
        merkle_tree: merkle_tree1,
    } = test_merklelog::<Sha512>(l1);
    let mut p1 = merkle_tree1.proof(entries1[0].clone(), 0).expect("merkle_tree1.proof succeeds");

    // tree 2
    let l2: u32 = 7;
    let data2: Vec<[u8; 4]> = (0u32..l2).map(|i| i.to_be_bytes()).collect();
    let entries2: Vec<MerkleLogEntry<Sha512>> = data2
        .iter()
        .enumerate()
        .map(|(i, x)| {
            if i == 0 {
                MerkleLogEntry::TreeLeaf(merkle_tree1.root().clone())
            } else {
                MerkleLogEntry::DataLeaf(x.to_vec())
            }
        })
        .collect();
    let t2 = MerkleTree::<Sha512>::new(&entries2);
    let p2 = t2.proof(entries2[0].clone(), 0).expect("");
    p1.append(p2).expect("p1.append(p2) succeeds");

    // verify proof
    let v = p1.run();
    assert_eq!(&v, t2.root());
}

#[test]
fn serialization_test() {

}

