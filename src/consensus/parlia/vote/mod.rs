mod attestation;
mod journal;
mod manager;
mod pool;
mod signer;

pub use attestation::*;
pub use journal::*;
pub use manager::*;
pub use pool::*;
pub use signer::*;

use crate::{
    consensus::DuoError,
    models::{BLSPublicKey, BlockNumber, H256},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParliaVoteError {
    Internal(String),
    InvalidVoteSig,
    UnknownLatestHeader {
        msg: String,
    },
    ExceedAllowedVoteRange {
        target: u64,
        latest: u64,
    },
    ReceivedDupVote {
        target: u64,
        hash: H256,
        validator: BLSPublicKey,
    },
    ExceedVotesCap {
        cap: usize,
    },
    YouAreNotInValidators {
        target: u64,
        hash: H256,
        validator: BLSPublicKey,
    },
    UnsatisfiedVoteRule {
        target: u64,
        hash: H256,
        msg: String,
    },
    CannotFetchMsg,
    UnknownPoSA,
}
