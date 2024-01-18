use digest::{
    FixedOutputReset,
    FixedOutput,
    Reset,
    Output,
    OutputSizeUser,
    Update,
    HashMarker,
    consts::U32,
    typenum::Unsigned,
};

use sha2::Sha512;

/// SHA512 hash truncated to 256 bits. This is not NIST standardized
/// version of SHA512/256, which uses a different IV. This implementation
/// returns the first 256 bits of a a standard SHA512 hash.
///
#[derive(Clone)]
pub struct Sha512_256t(Sha512);

impl OutputSizeUser for Sha512_256t {
    type OutputSize = U32;

    fn output_size() -> usize {
        Self::OutputSize::USIZE
    }

}

impl Reset for Sha512_256t {
    fn reset(&mut self) {
        self.0.reset()
    }
}

impl FixedOutputReset for Sha512_256t {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        let mut tmp : Output<Sha512> = Default::default();
        self.0.finalize_into_reset(&mut tmp);
        out.copy_from_slice(&tmp[0..32])
    }
}

impl FixedOutput for Sha512_256t {
    fn finalize_into(self, out: &mut Output<Self>) {
        let mut tmp : Output<Sha512> = Default::default();
        self.0.finalize_into(&mut tmp);
        out.copy_from_slice(&tmp[0..32]);
    }

}

impl Default for Sha512_256t {
    fn default() -> Self {
        Sha512_256t(Sha512::default())
    }
}

impl Update for Sha512_256t {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
}

impl HashMarker for Sha512_256t { }

