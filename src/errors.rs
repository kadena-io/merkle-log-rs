use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;


/* ************************************************************************** */
/* Utils */

/// Type for tagging expected values in error messages.
///
#[derive(Debug, Clone, Copy)]
pub struct Expected<T> {
    expected: T,
}

impl<T: Display> Display for Expected<T> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Expected: {}", self.expected)
    }
}

impl<T> Expected<T> {
    pub fn new(t: T) -> Expected<T> {
        Expected { expected: t }
    }
}

/// Type for tagging actual values in error messages.
///
#[derive(Debug, Clone, Copy)]
pub struct Actual<T> {
    actual: T,
}

impl<T: Display> Display for Actual<T> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Actual: {}", self.actual)
    }
}

impl<T> Actual<T> {
    pub fn new(t: T) -> Actual<T> {
        Actual { actual: t }
    }
}

#[derive(Clone, Copy)]
pub struct AsHex<T>(pub T);

impl<T: AsRef<[u8]>> Display for AsHex<T> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "0x")?;
        for &byte in self.0.as_ref() {
            write!(f, "{:0>2x}", byte)?;
        }
        Ok(())
    }
}

impl<T: AsRef<[u8]>> std::fmt::Debug for AsHex<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", &AsHex(&self.0))
    }
}

/* ************************************************************************** */
/* MerkleTreeError */

/// Type of errors that the library can emit.
///
#[derive(Debug, Clone)]
pub enum MerkleTreeError {
    EncodingSizeError {
        msg: String,
        expected: Expected<u64>,
        actual: Actual<u64>,
    },
    EncodingSizeConstraintError {
        msg: String,
        expected: Expected<u64>,
        actual: Actual<u64>,
    },
    IndexOutOfBoundsError {
        msg: String,
        expected: Expected<(u64, u64)>,
        actual: Actual<u64>,
    },
    InputNotInTreeError {
        msg: String,
        idx: u64,
        data: Vec<u8>,
    },
    MerkleRootNotInTreeError {
        msg: String,
        idx: u64,
        data: Vec<u8>,
    },
    InvalidProofObjectError {
        msg: String,
    },
    AppendOfDataLeafError {
        msg: String,
    },
    AppendMismatchError {
        msg: String,
        expected: Expected<Vec<u8>>,
        actual: Actual<Vec<u8>>,
    },
}

impl Display for MerkleTreeError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            MerkleTreeError::EncodingSizeError {
                msg,
                expected,
                actual,
            } => write!(
                f,
                "MerkleTreeError::EncodingSizeError: {msg}. {expected}. {actual}"
            ),
            MerkleTreeError::EncodingSizeConstraintError {
                msg,
                expected,
                actual,
            } => write!(
                f,
                "MerkleTreeError::EncodingSizeConstraintError: {msg}. {expected}. {actual}"
            ),
            MerkleTreeError::IndexOutOfBoundsError {
                msg,
                expected,
                actual,
            } => write!(
                f,
                "MerkleTreeError::IndexOutOfBoundsError: {}. ({}, {}). {} ",
                msg, expected.expected.0, expected.expected.1, actual
            ),
            MerkleTreeError::InputNotInTreeError { msg, idx, data } => write!(
                f,
                "MerkleTreeError::InputNotInTreeError: {msg}. Index: {idx}. Data: {}",
                AsHex(data),
            ),
            MerkleTreeError::MerkleRootNotInTreeError { msg, idx, data } => write!(
                f,
                "MerkleTreeError::MerkleRootNotInTreeError: {msg}. Index: {idx}. Data: {}",
                AsHex(data),
            ),
            MerkleTreeError::InvalidProofObjectError { msg } => {
                write!(f, "MerkleTreeError::InvalidProofObjectError: {msg}")
            },
            MerkleTreeError::AppendOfDataLeafError { msg } => {
                write!(f, "MerkleTreeError::AppendOfDataLeafError: {msg}")
            },
            MerkleTreeError::AppendMismatchError {
                msg,
                expected,
                actual,
            } => write!(
                f,
                "MerkleTreeError::EncodingSizeConstraintError: {msg}. {}. {}",
                Expected::new(AsHex(&expected.expected)),
                Actual::new(AsHex(&actual.actual)),
            ),
        }
    }
}

impl Error for MerkleTreeError {}
