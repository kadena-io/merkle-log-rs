extern crate merkle_log;
extern crate sha2;

use sha2::Sha512;
use merkle_log::tree::MerkleTree;
use std::{
    io,
    io::prelude::*,
};

fn main () {

    let mut data: Vec<Vec<u8>> = Vec::new();

    for line in io::stdin().lock().lines() {
        data.push(line.unwrap().into());
    }

    let tree = MerkleTree::<Sha512>::from_data_leafs(&data);
    println!("root: {}", tree.root());
}

