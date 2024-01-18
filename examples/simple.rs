extern crate merkle_log;
extern crate sha2;

use sha2::Sha512;
use merkle_log::tree::MerkleTree;

fn main () {

    // some test data
    let n = 100;
    let data: Vec<[u8; 4]> = (0u32..n).map(|i| i.to_be_bytes()).collect();

    // create a Merkle tree
    let tree = MerkleTree::<Sha512>::from_data_leafs(&data);

    // create an inclusion proof for item at index 24
    let pos: usize = 24;
    let p = tree.proof_data_leaf(&data[pos], pos).unwrap();

    // verify the proof
    let v = p.run();
    assert_eq!(&v, tree.root());
}


