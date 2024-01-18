mod sha512_256t;

use criterion::{
    black_box,
    criterion_main,
    criterion_group,
    Criterion,
    BenchmarkGroup,
    measurement::Measurement,
    BenchmarkId,
};

use digest::{
    Digest,
    FixedOutputReset,
};

use sha2::Sha512;

use rand::{
    distributions::Distribution,
    distributions::Uniform,
    Fill,
    rngs::SmallRng,
    SeedableRng,
};

use merkle_log::tree::MerkleTree;

use sha512_256t::Sha512_256t;

const LEAF_COUNT : usize = 10000;
const LEAF_MAX_SIZE : usize = 1000;

fn mk_bench_data() -> Vec<Vec<u8>> {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut result : Vec<Vec<u8>> = Vec::with_capacity(LEAF_COUNT);
    let u = Uniform::from(0 .. LEAF_MAX_SIZE);

    for _ in 0 .. LEAF_COUNT-1 {
        let s : usize = u.sample(&mut rng);
        let mut leaf : Vec<u8> = Vec::with_capacity(s);
        unsafe { leaf.set_len(s); }
        leaf.try_fill(&mut rng).unwrap();
        result.push(leaf);
    }
    result
}

fn bench_create(c: &mut Criterion) {
    let data = mk_bench_data();
    let mut group = c.benchmark_group("create tree");
    create_tree::<Sha512, _, _>(&mut group, "Sha512", &data);
    create_tree::<Sha512_256t, _, _>(&mut group, "Sha512_256t", &data);
    group.finish();
}

fn bench_proof(c : &mut Criterion) {
    let data = mk_bench_data();
    let mut group = c.benchmark_group("create proof");
    create_proof::<Sha512, _, _>(&mut group, "Sha512", &data);
    create_proof::<Sha512_256t, _, _>(&mut group, "Sha512_256t", &data);
    group.finish();
}

fn bench_verify(c : &mut Criterion) {
    let data = mk_bench_data();
    let mut group = c.benchmark_group("verify proof");
    verify_proof::<Sha512, _, _>(&mut group, "Sha512", &data);
    verify_proof::<Sha512_256t, _, _>(&mut group, "Sha512_256t", &data);
    group.finish();
}

fn create_tree<H, T, R> (group : &mut BenchmarkGroup<T>, n: &str, data: &[R])
    where
        H: Digest + FixedOutputReset + Clone,
        T: Measurement,
        R: AsRef<[u8]>,
{
    group.bench_function(BenchmarkId::from_parameter(n), |b| {
        b.iter(|| {
            let _ = MerkleTree::<H>::from_data_leafs(black_box(&data));
        })
    });
}

fn create_proof<H, T, R>(group: &mut BenchmarkGroup<T>, n: &str, data: &[R])
    where
        H: Digest + FixedOutputReset + Clone,
        T: Measurement,
        R: AsRef<[u8]>,
{
    let merkle_tree = MerkleTree::<H>::from_data_leafs(&data);
    let pos : usize = LEAF_COUNT / 3;

    group.bench_function(BenchmarkId::from_parameter(n), |b| {
        b.iter(|| {
            let p = merkle_tree.proof_data_leaf(
                black_box(data[pos].as_ref()),
                black_box(pos),
            ).unwrap();
            let v = p.run();
            assert_eq!(&v, merkle_tree.root());
        })
    });
}

fn verify_proof<H, T, R>(group: &mut BenchmarkGroup<T>, n: &str, data: &[R])
    where
        H: Digest + FixedOutputReset + Clone,
        T: Measurement,
        R: AsRef<[u8]>,
{
    let merkle_tree = MerkleTree::<H>::from_data_leafs(&data);
    let pos : usize = LEAF_COUNT / 3;
    let p = merkle_tree.proof_data_leaf(&data[pos].as_ref(), pos).unwrap();

    group.bench_function(BenchmarkId::from_parameter(n), |b| {
        b.iter(|| {
            let v = black_box(&p).run();
            assert_eq!(&v, merkle_tree.root());
        })
    });
}

criterion_group!{
    name = benches;
    config = Criterion::default();
    targets = bench_create, bench_proof, bench_verify
}

criterion_main!(benches);

