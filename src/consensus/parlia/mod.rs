//! Implementation of the BSC's POSA Engine.
#![allow(missing_docs)]
pub mod contract_upgrade;
mod snapshot;
mod state;
mod util;
pub mod vote;

pub use snapshot::Snapshot;
pub use state::ParliaNewBlockState;
pub use util::*;

use super::*;
use crate::execution::{analysis_cache::AnalysisCache, evmglue, tracer::NoopTracer};
use std::str;
use vote::*;

use crate::{
    consensus::{ParliaError, ValidationError},
    crypto::{
        go_rng::{RngSource, Shuffle},
        signer::ECDSASigner,
    },
    models::*,
    p2p::node::Node,
    HeaderReader, StageId,
};
use bitset::BitSet;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ethabi::FunctionOutputDecoder;
use ethabi_contract::use_contract;
use ethereum_types::{Address, H256};
use fastrlp::Encodable;
use lru_cache::LruCache;
use milagro_bls::{AggregateSignature, PublicKey};
use parking_lot::RwLock;
use rand::prelude::*;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::Add,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch::Receiver as WatchReceiver;
use tracing::*;
use TransactionAction;

pub const EXTRA_VANITY: usize = 32;
/// Fixed number of extra-data prefix bytes reserved for signer vanity
pub const EXTRA_VANITY_LEN: usize = 32;
/// Fixed number of extra-data prefix bytes reserved for signer vanity, in boneh add validator num
pub const EXTRA_VANITY_LEN_WITH_NUM_IN_BONEH: usize = 33;
/// Fixed number of extra-data suffix bytes reserved for signer seal
pub const EXTRA_SEAL_LEN: usize = 65;
/// Address length of signer
pub const ADDRESS_LENGTH: usize = 20;
/// Fixed number of extra-data suffix bytes reserved before boneh validator
pub const EXTRA_VALIDATOR_LEN: usize = ADDRESS_LENGTH;
/// Fixed number of extra-data suffix bytes reserved for boneh validator
pub const EXTRA_VALIDATOR_LEN_IN_BONEH: usize = EXTRA_VALIDATOR_LEN + BLS_PUBLIC_KEY_LEN;
/// Difficulty for INTURN block
pub const DIFF_INTURN: U256 = U256([2, 0]);
/// Difficulty for NOTURN block
pub const DIFF_NOTURN: U256 = U256([1, 0]);
/// Default value for mixhash
pub const NULL_MIXHASH: H256 = H256([0; 32]);
/// Default value for uncles hash
pub const NULL_UNCLES_HASH: H256 = H256([
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
]);
/// Default noturn block wiggle factor defined in spec.
pub const SIGNING_DELAY_NOTURN_MS: u64 = 500;
/// How many snapshot to cache in the memory.
pub const SNAP_CACHE_NUM: usize = 2048;
/// Number of blocks after which to save the snapshot to the database
pub const CHECKPOINT_INTERVAL: u64 = 1024;
/// Percentage to system reward.
pub const SYSTEM_REWARD_PERCENT: usize = 4;
pub const NEXT_FORK_HASH_SIZE: usize = 4;
/// The max reward in system reward contract
const MAX_SYSTEM_REWARD: &str = "0x56bc75e2d63100000";
/// The block one init system contacts txs, will skip in header validation
const INIT_TX_NUM: usize = 7;
/// Default delay (per signer) to allow concurrent signers, second
const BACKOFF_TIME_OF_INITIAL: u64 = 1_u64;
/// Random additional delay (per signer) to allow concurrent signers, second
const BACKOFF_TIME_OF_WIGGLE: u64 = 1_u64;
/// Default delay (per signer) to allow concurrent signers before ramanujan fork, millisecond
const BACKOFF_MILL_TIME_OF_FIXED_BEFORE_FORK: u64 = 200_u64;
/// Random additional delay (per signer) to allow concurrent signers before ramanujan fork, millisecond
const BACKOFF_MILL_TIME_OF_WIGGLE_BEFORE_FORK: u64 = 500_u64;
/// process delay (per signer) to allow concurrent signers, second
const BACKOFF_TIME_OF_PROCESS: u64 = 1_u64;
/// Maximum the gas limit may ever be.
const MAX_GAS_LIMIT_CAP: u64 = 0x7fffffffffffffff_u64;
/// The bound divisor of the gas limit, used in update calculations.
const GAS_LIMIT_BOUND_DIVISOR: u64 = 256_u64;
/// Minimum the gas limit may ever be.
const MIN_GAS_LIMIT: u64 = 5000_u64;
/// The distance to naturally justify a block
const NATURALLY_JUSTIFIED_DIST: u64 = 15;
/// The minimum pack vote attestation allow height
const MIN_VOTE_ATTESTATION_HEIGHT: u64 = 2;

use_contract!(
    validator_ins,
    "src/consensus/parlia/contracts/bsc_validators.json"
);
use_contract!(slash_ins, "src/consensus/parlia/contracts/bsc_slash.json");
use_contract!(
    validator_set_in_boneh,
    "src/consensus/parlia/contracts/validator_set_in_boneh.json"
);

pub trait PoSA: Debug + Send + Sync + 'static {
    /// get_justified_header, returns highest justified block's header before the specific block.
    /// the attestation within the specific block will be taken into account.
    fn get_justified_header(
        &self,
        header_reader: &dyn HeaderReader,
        header: &BlockHeader,
    ) -> anyhow::Result<BlockHeader, DuoError>;

    /// GetFinalizedHeader returns highest finalized block header before the specific block.
    /// It will first to find vote finalized block within the specific backward blocks, the suggested backward blocks is 21.
    /// If the vote finalized block not found, return its previous backward block.
    fn get_finalized_header(
        &self,
        header_reader: &dyn HeaderReader,
        header: &BlockHeader,
        backward: u64,
    ) -> anyhow::Result<BlockHeader, DuoError>;

    /// verify_vote, check if vote from valid validators, check if vote's source number and hash is correct.
    fn verify_vote(
        &self,
        header_reader: &dyn HeaderReader,
        vote: &VoteEnvelope,
    ) -> anyhow::Result<(), DuoError>;

    /// is_active_validator_set, check if you are in validators set
    fn is_active_validator_at(
        &self,
        header_reader: &dyn HeaderReader,
        header: &BlockHeader,
    ) -> anyhow::Result<bool, DuoError>;
}

#[derive(Debug, Clone, Default)]
pub struct ParliaInitialParams {
    pub bls_prv_key: Option<String>,
    pub bls_pub_key: Option<String>,
    pub node: Option<Arc<Node>>,
    pub sync_stage: Option<WatchReceiver<Option<StageId>>>,
}

/// Parlia Engine implementation
#[derive(Debug)]
pub struct Parlia {
    chain_spec: ChainSpec,
    chain_id: ChainId,
    epoch: u64,
    period: u64,
    recent_snaps: RwLock<LruCache<H256, Snapshot>>,
    fork_choice_graph: Arc<Mutex<ForkChoiceGraph>>,
    new_block_state: ParliaNewBlockState,
    miner: Address,
    vote_pool: Option<Arc<Mutex<VotePool>>>,
    signer: Option<ECDSASigner>,
}

impl Parlia {
    /// new parlia engine
    pub fn new(
        db: Option<Arc<MdbxWithDirHandle<WriteMap>>>,
        chain_id: ChainId,
        chain_spec: ChainSpec,
        epoch: u64,
        period: u64,
        other: InitialParams,
    ) -> Self {
        let vote_pool = None;
        if let InitialParams::Parlia(other) = other {
            if let (Some(prv_key), Some(pub_key)) = (other.bls_prv_key, other.bls_pub_key) {
                // start vote manager
                let node = other.node.unwrap();
                let pool = VotePool::new(None, Arc::clone(&node));
                let parlia = Arc::new(Self {
                    chain_spec: chain_spec.clone(),
                    chain_id,
                    epoch,
                    period,
                    recent_snaps: RwLock::new(LruCache::new(SNAP_CACHE_NUM)),
                    fork_choice_graph: Arc::new(Mutex::new(Default::default())),
                    new_block_state: ParliaNewBlockState::new(None),
                    miner: Default::default(),
                    vote_pool: Some(Arc::clone(&pool)),
                    signer: None,
                });
                let posa = Arc::clone(&(parlia as Arc<dyn PoSA>));
                pool.lock().set_engine(Arc::clone(&posa));

                let vm = VoteManager::new(
                    chain_spec.clone(),
                    posa,
                    pool,
                    node,
                    Arc::clone(&db.unwrap()),
                    other.sync_stage.unwrap(),
                    prv_key,
                    pub_key,
                )
                .unwrap();
                VoteManager::start(vm);
            }
        }

        Self {
            chain_spec,
            chain_id,
            epoch,
            period,
            recent_snaps: RwLock::new(LruCache::new(SNAP_CACHE_NUM)),
            fork_choice_graph: Arc::new(Mutex::new(Default::default())),
            new_block_state: ParliaNewBlockState::new(None),
            miner: Default::default(),
            vote_pool,
            signer: None,
        }
    }

    /// check if extra len is correct
    fn check_header_extra_len(&self, header: &BlockHeader) -> anyhow::Result<(), DuoError> {
        let extra_data_len = header.extra_data.len();

        if extra_data_len < EXTRA_VANITY_LEN {
            return Err(ParliaError::WrongHeaderExtraLen {
                expected: EXTRA_VANITY_LEN,
                got: extra_data_len,
            }
            .into());
        }

        if extra_data_len < EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
            return Err(ParliaError::WrongHeaderExtraLen {
                expected: EXTRA_VANITY_LEN + EXTRA_SEAL_LEN,
                got: extra_data_len,
            }
            .into());
        }

        let bytes_len = get_validator_len_from_header(header, &self.chain_spec, self.epoch)?;
        let epoch_chg = header.number.0 % self.epoch == 0;
        if !epoch_chg && bytes_len != 0 {
            return Err(ParliaError::WrongHeaderExtraSignersLen {
                expected: 0,
                got: bytes_len,
                msg: "cannot set singers without epoch change!".to_string(),
            }
            .into());
        }
        if epoch_chg && bytes_len == 0 {
            return Err(ParliaError::WrongHeaderExtraSignersLen {
                expected: 0,
                got: bytes_len,
                msg: "signers must correct in epoch change!".to_string(),
            }
            .into());
        }

        Ok(())
    }

    /// If the block is an epoch end block, verify the validator list
    /// The verification can only be done in finalize, cannot in VerifyHeader.
    fn verify_epoch_chg(&self, header: &BlockHeader) -> anyhow::Result<()> {
        // when not set new block state, just ignore, because it's necessary in sync and mining,
        // but optional in other scenario
        if !self.new_block_state.parsed_validators() {
            return Ok(());
        }

        let (expect_validators, bls_key_map) = self
            .new_block_state
            .get_validators()
            .ok_or(ParliaError::CacheValidatorsUnknown)?;

        if !self.chain_spec.is_boneh(&header.number) {
            let actual_validators = parse_epoch_validators(
                &header.extra_data[EXTRA_VANITY_LEN..(header.extra_data.len() - EXTRA_SEAL_LEN)],
            )?;
            debug!(
                "epoch validators check {:?}, {}:{}",
                header.number,
                actual_validators.len(),
                expect_validators.len()
            );
            if actual_validators != *expect_validators {
                return Err(ParliaError::EpochChgWrongValidators {
                    expect: expect_validators.clone(),
                    got: actual_validators,
                }
                .into());
            }
            return Ok(());
        }

        let validator_count = expect_validators.len();
        if header.extra_data[EXTRA_VANITY_LEN_WITH_NUM_IN_BONEH - 1] as usize != validator_count {
            return Err(ParliaError::EpochChgWrongValidatorsInBoneh {
                expect: expect_validators.clone(),
                err: format!(
                    "wrong validator num, expect {}, got {}",
                    validator_count, header.extra_data[EXTRA_VANITY_LEN]
                ),
            }
            .into());
        }
        let mut expect_bytes = Vec::with_capacity(validator_count * EXTRA_VALIDATOR_LEN_IN_BONEH);
        for val in expect_validators.iter() {
            let bls_key = bls_key_map
                .get(val)
                .ok_or(ParliaError::UnknownTargetBLSKey {
                    block: header.number,
                    account: *val,
                })?;
            expect_bytes.extend_from_slice(&val[..]);
            expect_bytes.extend_from_slice(&bls_key[..]);
        }
        let got_bytes = get_validator_bytes_from_header(header, &self.chain_spec, self.epoch)?;
        if *expect_bytes.as_slice() != *got_bytes {
            return Err(ParliaError::EpochChgWrongValidatorsInBoneh {
                expect: expect_validators.clone(),
                err: format!(
                    "wrong validator bytes, expect {}, got {}",
                    hex::encode(expect_bytes),
                    hex::encode(got_bytes)
                ),
            }
            .into());
        }
        Ok(())
    }

    /// verify_block_seal checks whether the signature contained in the header satisfies the
    /// consensus protocol requirements. The method accepts an optional list of parent
    /// headers that aren't yet part of the local blockchain to generate the snapshots
    /// from.
    fn verify_block_seal(&self, header: &BlockHeader, snap: Snapshot) -> Result<(), DuoError> {
        let block_number = header.number;
        let proposer = recover_creator(header, self.chain_id)?;
        if proposer != header.beneficiary {
            return Err(ParliaError::WrongHeaderSigner {
                number: block_number,
                expected: header.beneficiary,
                got: proposer,
            }
            .into());
        }
        if !snap.validators.contains(&proposer) {
            return Err(ParliaError::SignerUnauthorized {
                number: block_number,
                signer: proposer,
            }
            .into());
        }
        for (seen, recent) in snap.recent_proposers.iter() {
            if *recent == proposer {
                // Signer is among recent_proposers, only fail if the current block doesn't shift it out
                let limit = self.get_recently_proposal_limit(header, snap.validators.len());
                if *seen > block_number.0 - limit {
                    return Err(ParliaError::SignerOverLimit { signer: proposer }.into());
                }
            }
        }
        let inturn_proposer = snap.inturn(&proposer);
        if (inturn_proposer && header.difficulty != DIFF_INTURN)
            || (!inturn_proposer && header.difficulty != DIFF_NOTURN)
        {
            return Err(ValidationError::WrongDifficulty.into());
        }
        Ok(())
    }

    /// Verify that the gas limit remains within allowed bounds
    fn verify_block_gas(&self, header: &BlockHeader, parent: &BlockHeader) -> Result<(), DuoError> {
        if header.gas_used > header.gas_limit {
            return Err(ValidationError::GasAboveLimit {
                used: header.gas_used,
                limit: header.gas_limit,
            }
            .into());
        }
        if header.gas_limit > MAX_GAS_LIMIT_CAP {
            return Err(ParliaError::WrongGasLimit {
                expect: MAX_GAS_LIMIT_CAP,
                got: header.gas_limit,
            }
            .into());
        }
        if header.gas_limit < MIN_GAS_LIMIT {
            return Err(ParliaError::WrongGasLimit {
                expect: MIN_GAS_LIMIT,
                got: header.gas_limit,
            }
            .into());
        }
        let diff_gas_limit = parent.gas_limit.abs_diff(header.gas_limit);
        let max_limit_gap = parent.gas_limit / GAS_LIMIT_BOUND_DIVISOR;
        if diff_gas_limit >= max_limit_gap {
            return Err(ParliaError::WrongGasLimit {
                expect: parent.gas_limit + max_limit_gap,
                got: header.gas_limit,
            }
            .into());
        }

        Ok(())
    }

    /// verify_vote_attestation checks whether the vote attestation is valid only for fast finality fork.
    fn verify_vote_attestation(
        &self,
        header_reader: &dyn HeaderReader,
        header: &BlockHeader,
        parent: &BlockHeader,
    ) -> Result<(), DuoError> {
        let attestation = get_vote_attestation_from_header(header, &self.chain_spec, self.epoch)?;
        if let Some(attestation) = attestation {
            if attestation.extra.len() > MAX_ATTESTATION_EXTRA_LENGTH {
                return Err(ParliaError::TooLargeAttestationExtraLen {
                    expect: MAX_ATTESTATION_EXTRA_LENGTH,
                    got: attestation.extra.len(),
                }
                .into());
            }

            info!("got attestation {}, {:?}", header.number, attestation);
            // the attestation target block should be direct parent.
            let target_block = attestation.data.target_number;
            let target_hash = attestation.data.target_hash;
            if target_block != parent.number || target_hash != header.parent_hash {
                return Err(ParliaError::InvalidAttestationTarget {
                    expect_block: parent.number,
                    expect_hash: header.parent_hash,
                    got_block: target_block,
                    got_hash: target_hash,
                }
                .into());
            }

            // the attestation source block should be the highest justified block.
            let source_block = attestation.data.source_number;
            let source_hash = attestation.data.source_hash;
            let justified: BlockHeader = self.query_justified_header(header_reader, parent)?;
            if source_block != justified.number || source_hash != justified.hash() {
                return Err(ParliaError::InvalidAttestationSource {
                    expect_block: justified.number,
                    expect_hash: justified.hash(),
                    got_block: source_block,
                    got_hash: source_hash,
                }
                .into());
            }

            // query bls keys from snapshot.
            let snap = self.find_snapshot(
                header_reader,
                BlockNumber(parent.number.0 - 1),
                parent.parent_hash,
            )?;
            let validators_count = snap.validators.len();
            let vote_bit_set = BitSet::from_u64(attestation.vote_address_set);
            let bit_set_count = vote_bit_set.count() as usize;

            if bit_set_count > validators_count {
                return Err(ParliaError::InvalidAttestationVoteCount {
                    expect: validators_count,
                    got: bit_set_count,
                }
                .into());
            }
            let mut vote_addrs: Vec<PublicKey> = Vec::with_capacity(bit_set_count);
            for (i, val) in snap.validators.iter().enumerate() {
                if !vote_bit_set.test(i) {
                    continue;
                }

                let x = snap
                    .validators_map
                    .get(val)
                    .ok_or(ParliaError::SnapNotFoundVoteAddr {
                        index: i,
                        addr: *val,
                    })?;
                vote_addrs.push(PublicKey::from_bytes(&x.vote_addr[..])?);
            }

            // check if voted validator count satisfied 2/3+1
            let at_least_votes = validators_count * 2 / 3;
            if vote_addrs.len() < at_least_votes {
                return Err(ParliaError::InvalidAttestationVoteCount {
                    expect: at_least_votes,
                    got: vote_addrs.len(),
                }
                .into());
            }

            // check bls aggregate sig
            let vote_addrs = vote_addrs.iter().collect::<Vec<_>>();
            let agg_sig = AggregateSignature::from_bytes(&attestation.agg_signature[..])?;
            info!(
                "fast_aggregate_verify {}, vote_addrs {:?}:{}, hash {:?}",
                header.number,
                snap.validators_map,
                vote_addrs.len(),
                attestation.data.hash()
            );
            if !agg_sig.fast_aggregate_verify(attestation.data.hash().as_bytes(), &vote_addrs) {
                return Err(ParliaError::InvalidAttestationAggSig.into());
            }
        }

        Ok(())
    }

    /// query_justified_header returns highest justified block's header before the specific block,
    fn query_justified_header(
        &self,
        header_reader: &dyn HeaderReader,
        header: &BlockHeader,
    ) -> Result<BlockHeader, DuoError> {
        let snap = self.find_snapshot(header_reader, header.number, header.hash())?;

        // If there has vote justified block, find it or return naturally justified block.
        if let Some(vote) = snap.vote_data {
            if snap.block_number - vote.target_number.0 > NATURALLY_JUSTIFIED_DIST {
                return find_ancient_header(header_reader, header, NATURALLY_JUSTIFIED_DIST);
            }
            return Ok(header_reader
                .read_header(vote.target_number, vote.target_hash)?
                .ok_or_else(|| ParliaError::UnknownHeader {
                    number: BlockNumber(0),
                    hash: Default::default(),
                })?);
        }

        // If there is no vote justified block, then return root or naturally justified block.
        if header.number.0 < NATURALLY_JUSTIFIED_DIST {
            return Ok(header_reader
                .read_header_by_number(BlockNumber(0))?
                .ok_or_else(|| ParliaError::UnknownHeader {
                    number: BlockNumber(0),
                    hash: Default::default(),
                })?);
        }

        find_ancient_header(header_reader, header, NATURALLY_JUSTIFIED_DIST)
    }

    fn verify_block_time_for_ramanujan_fork(
        &self,
        snap: &Snapshot,
        header: &BlockHeader,
        parent: &BlockHeader,
    ) -> anyhow::Result<(), DuoError> {
        if self.chain_spec.is_ramanujan(&header.number)
            && header.timestamp < parent.timestamp + self.period + self.back_off_time(snap, header)
        {
            return Err(ValidationError::InvalidTimestamp {
                parent: parent.timestamp,
                current: header.timestamp,
            }
            .into());
        }
        Ok(())
    }

    fn block_time_for_ramanujan_fork(
        &self,
        snap: &Snapshot,
        header: &BlockHeader,
        parent: &BlockHeader,
    ) -> u64 {
        let mut block_timestamp = parent.timestamp + self.period;
        if self.chain_spec.is_ramanujan(&header.number) {
            block_timestamp += self.back_off_time(snap, header);
        }
        block_timestamp
    }

    fn delay_for_ramanujan_fork(&self, snap: &Snapshot, header: &BlockHeader) -> Duration {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let delay = Duration::from_secs(header.timestamp).checked_sub(now);
        match delay {
            Some(mut delay) => {
                info!(
                    "delay_for_Ramanujan_fork now {:?}, header.timestamp {}, delay {:?}",
                    now, header.timestamp, delay
                );
                if self.chain_spec.is_ramanujan(&header.number) {
                    return delay;
                }

                if header.difficulty == DIFF_NOTURN {
                    // It's not our turn explicitly to sign, delay it a bit
                    let wiggle = ((snap.validators.len() / 2 + 1) as u64)
                        * BACKOFF_MILL_TIME_OF_WIGGLE_BEFORE_FORK;
                    let mut rng = RngSource::new(1);
                    delay = delay.add(Duration::from_millis(
                        BACKOFF_MILL_TIME_OF_FIXED_BEFORE_FORK + (rng.int63n(wiggle as i64)) as u64,
                    ));
                }

                delay
            }
            None => Duration::from_millis(1),
        }
    }

    fn back_off_time(&self, snap: &Snapshot, header: &BlockHeader) -> u64 {
        let validator = &(header.beneficiary as Address);
        if snap.inturn(validator) {
            return 0;
        }
        let idx = match snap.index_of(validator) {
            Some(i) => i,
            None => {
                // The backOffTime does not matter when a validator is not authorized.
                return 0;
            }
        };

        let mut rng = RngSource::new(snap.block_number as i64);
        let validator_count = snap.validators.len();

        if !self.chain_spec.is_boneh(&header.number) {
            // select a random step for delay, range 0~(proposer_count-1)
            let mut backoff_steps = Vec::new();
            for i in 0..validator_count {
                backoff_steps.push(i);
            }
            backoff_steps.shuffle(&mut rng);
            return BACKOFF_TIME_OF_INITIAL + (backoff_steps[idx] as u64) * BACKOFF_TIME_OF_WIGGLE;
        }

        // Exclude the recently signed validators first
        let mut recents = HashMap::new();
        let limit = self.get_recently_proposal_limit(header, validator_count);
        let block_number = header.number.0;
        for (seen, proposer) in snap.recent_proposers.iter() {
            if block_number < limit || *seen > block_number - limit {
                if *validator == *proposer {
                    // The backOffTime does not matter when a validator has signed recently.
                    return 0;
                }
                recents.insert(*proposer, true);
            }
        }
        let mut index = idx;
        let mut backoff_steps = Vec::new();
        for i in 0..validator_count {
            if recents.get(&snap.validators[i]).is_some() {
                if i < idx {
                    index -= 1;
                }
                continue;
            }
            backoff_steps.push(backoff_steps.len())
        }

        // select a random step for delay in left validators
        backoff_steps.shuffle(&mut rng);
        let mut delay =
            BACKOFF_TIME_OF_INITIAL + (backoff_steps[index] as u64) * BACKOFF_TIME_OF_WIGGLE;
        // If the current validator has recently signed, reduce initial delay.
        if recents.get(&snap.suppose_validator()).is_some() {
            delay -= BACKOFF_TIME_OF_INITIAL;
        }
        delay
    }

    fn get_recently_proposal_limit(&self, header: &BlockHeader, validator_count: usize) -> u64 {
        let validator_count = validator_count as u64;
        if self.chain_spec.is_boneh(&header.number) {
            validator_count * 2 / 3 + 1
        } else {
            validator_count / 2 + 1
        }
    }

    /// distribute_finality_reward accumulate voter reward from whole epoch
    fn distribute_finality_reward(
        &self,
        header_reader: &dyn HeaderReader,
        header: &BlockHeader,
    ) -> anyhow::Result<Option<Bytes>, DuoError> {
        if header.number.0 % self.epoch != 0 {
            return Ok(None);
        }

        // find the epoch block, and collect voters, calculate rewards
        let mut accum_weight_map = BTreeMap::new();
        let epoch_block = header.number.0;
        let mut parent =
            header_reader
                .read_parent_header(header)?
                .ok_or(ParliaError::UnknownHeader {
                    number: BlockNumber(header.number.0 - 1),
                    hash: header.parent_hash,
                })?;
        while parent.number.0 + self.epoch >= epoch_block && parent.number.0 > 0 {
            let attestation =
                get_vote_attestation_from_header(&parent, &self.chain_spec, self.epoch)?;
            if let Some(attestation) = attestation {
                // find attestation, and got who vote correctly
                let justified_block = header_reader
                    .read_header(attestation.data.target_number, attestation.data.target_hash)?
                    .ok_or_else(|| {
                        error!(
                            "justified_block unknown at block {}:{:?}",
                            attestation.data.target_number, attestation.data.target_hash
                        );
                        ParliaError::UnknownHeader {
                            number: Default::default(),
                            hash: Default::default(),
                        }
                    })?;

                // got valid justified_block snap info, to accumulate validators reward
                let snap = self.find_snapshot(
                    header_reader,
                    BlockNumber(justified_block.number.0 - 1),
                    justified_block.parent_hash,
                )?;
                let vote_bit_set = BitSet::from_u64(attestation.vote_address_set);
                let bit_set_count = vote_bit_set.count() as usize;

                // if got wrong data, just skip
                if bit_set_count > snap.validators.len() {
                    error!("invalid attestation, vote number large than validators number, snap block {}:{:?}, expect:got {}:{}",
                            snap.block_number, snap.block_hash, snap.validators.len(), bit_set_count);
                    return Err(ParliaError::InvalidAttestationVoteCount {
                        expect: snap.validators.len(),
                        got: bit_set_count,
                    }
                    .into());
                }

                // finally, accumulate validators votes weight
                for (index, addr) in snap.validators.iter().enumerate() {
                    if vote_bit_set.test(index) {
                        *accum_weight_map.entry(*addr).or_insert(0_u64) += 1;
                    }
                }
            }

            // try accumulate parent
            parent =
                header_reader
                    .read_parent_header(&parent)?
                    .ok_or(ParliaError::UnknownHeader {
                        number: BlockNumber(header.number.0 - 1),
                        hash: header.parent_hash,
                    })?;
        }

        // stats reward, and construct reward system tx
        let validators = accum_weight_map.keys().copied().collect::<Vec<Address>>();
        let weights = accum_weight_map.values().copied().collect::<Vec<u64>>();
        let input_data =
            validator_set_in_boneh::functions::distribute_finality_reward::encode_input(
                validators, weights,
            );

        Ok(Some(Bytes::from(input_data)))
    }

    fn find_snapshot(
        &self,
        header_reader: &dyn HeaderReader,
        block_number: BlockNumber,
        block_hash: H256,
    ) -> Result<Snapshot, DuoError> {
        let mut snap_cache = self.recent_snaps.write();

        let mut block_number = block_number;
        let mut block_hash = block_hash;
        let mut skip_headers = Vec::new();

        let mut snap: Snapshot;
        loop {
            debug!("try find snapshot in mem {}:{}", block_number, block_hash);
            if let Some(cached) = snap_cache.get_mut(&block_hash) {
                snap = cached.clone();
                break;
            }
            // TODO could read snap
            if block_number == 0 || block_number % self.epoch == 0 {
                let header = header_reader.read_header(block_number, block_hash)?.ok_or(
                    ParliaError::UnknownHeader {
                        number: block_number,
                        hash: block_hash,
                    },
                )?;

                let (next_validators, bls_keys) =
                    parse_validators_from_header(&header, &self.chain_spec, self.epoch)?;
                snap = Snapshot::new(
                    next_validators,
                    block_number.0,
                    block_hash,
                    self.epoch,
                    bls_keys,
                )?;
                break;
            }
            let header = header_reader.read_header(block_number, block_hash)?.ok_or(
                ParliaError::UnknownHeader {
                    number: block_number,
                    hash: block_hash,
                },
            )?;
            block_hash = header.parent_hash;
            block_number = BlockNumber(header.number.0 - 1);
            skip_headers.push(header);
        }
        for h in skip_headers.iter().rev() {
            snap = snap.apply(header_reader, h, &self.chain_spec, self.chain_id)?;
        }

        snap_cache.insert(snap.block_hash, snap.clone());
        Ok(snap)
    }

    /// prepare_validators, pack current validators into header when epoch block.
    fn prepare_validators(
        &self,
        header: &BlockHeader,
        extra: &mut BytesMut,
    ) -> anyhow::Result<(), DuoError> {
        if header.number.0 % self.epoch != 0 {
            return Ok(());
        }

        let (vals, bls_keys) = self
            .new_block_state
            .get_validators()
            .ok_or(ParliaError::CacheValidatorsUnknown)?;
        if !self.chain_spec.is_boneh(&header.number) {
            extra.extend_from_slice(&header.extra_data[..]);
            for v in vals.iter() {
                extra.extend_from_slice(v.as_bytes());
            }
        } else {
            extra.extend_from_slice(&header.extra_data[..]);
            extra.extend_from_slice(&vals.len().to_be_bytes());
            for v in vals.iter() {
                extra.extend_from_slice(v.as_bytes());
                let bk = bls_keys.get(v).ok_or(ParliaError::CacheValidatorsUnknown)?;
                extra.extend_from_slice(bk.as_bytes());
            }
        }

        Ok(())
    }

    /// assemble_vote_attestation, alloc vote attestation if exist
    fn assemble_vote_attestation(
        &self,
        header_reader: &dyn HeaderReader,
        header: &mut BlockHeader,
    ) -> anyhow::Result<(), DuoError> {
        if !self.chain_spec.is_boneh(&header.number)
            || header.number.0 < MIN_VOTE_ATTESTATION_HEIGHT
        {
            return Ok(());
        }

        let parent =
            header_reader
                .read_parent_header(header)?
                .ok_or(ParliaError::UnknownHeader {
                    number: BlockNumber(header.number.0 - 1),
                    hash: header.parent_hash,
                })?;
        let snap = self.find_snapshot(
            header_reader,
            BlockNumber(parent.number.0 - 1),
            parent.parent_hash,
        )?;

        if let Some(votes) = self
            .vote_pool
            .as_ref()
            .ok_or(ParliaError::UnknownVotePool)?
            .lock()
            .get_vote_by_block_hash(header.parent_hash)
        {
            if votes.len() <= snap.validators.len() / 3 * 2 {
                return Ok(());
            }

            let justified = self.get_justified_header(header_reader, &parent)?;
            let vote_data = VoteData {
                source_number: justified.number,
                source_hash: justified.hash(),
                target_number: parent.number,
                target_hash: header.parent_hash,
            };

            let vote_hash = vote_data.hash();
            let mut sigs = Vec::with_capacity(votes.len());
            let mut val_set = 0;
            for ve in votes.iter() {
                if ve.data.hash() != vote_hash {
                    return Err(ParliaError::WrongVote {
                        vote: (*ve).clone(),
                    }
                    .into());
                }
                let info = snap
                    .validators_map
                    .values()
                    .find(|i| i.vote_addr == ve.vote_address)
                    .ok_or(ParliaError::NotFoundBLSKeyInValidators {
                        vote: (*ve).clone(),
                    })?;
                val_set |= 1 << (info.index - 1);
                sigs.push(milagro_bls::Signature::from_bytes(&ve.signature[..])?);
            }

            let sigs: Vec<&milagro_bls::Signature> = sigs.iter().collect();
            let attestation = VoteAttestation {
                vote_address_set: val_set,
                agg_signature: BLSSignature::from(
                    AggregateSignature::aggregate(sigs.as_slice()).as_bytes(),
                ),
                data: vote_data,
                extra: Default::default(),
            };

            let mut buf = BytesMut::with_capacity(attestation.length());
            Encodable::encode(&attestation, &mut buf);

            let seal_start = header.extra_data.len() - EXTRA_SEAL_LEN;
            let mut new_extra = BytesMut::with_capacity(header.extra_data.len() + buf.len());
            new_extra.extend_from_slice(&header.extra_data[..seal_start]);
            new_extra.extend_from_slice(&buf);
            new_extra.extend_from_slice(&header.extra_data[seal_start..]);

            // replace with new extra data
            header.extra_data = new_extra.freeze();
        }

        Ok(())
    }

    /// construct a parlia necessary system tx into blocks.
    fn construct_sys_tx(
        &self,
        nonce: &mut u64,
        to: Address,
        value: U256,
        input: Bytes,
        is_mining: bool,
        tx_iter: &mut std::slice::Iter<&MessageWithSender>,
    ) -> anyhow::Result<MessageWithSender, DuoError> {
        let msg = Message::Legacy {
            chain_id: Some(self.chain_id),
            nonce: *nonce,
            gas_price: U256::ZERO,
            gas_limit: u64::MAX / 2,
            value,
            action: TransactionAction::Call(to),
            input,
        };

        // increment consensus signer's nonce.
        *nonce += 1;

        if is_mining {
            // if mining, construct miner's systemTx, and sign it.
            let signer = self.signer.as_ref().ok_or(ParliaError::UnknownSigner)?;
            let signature = signer.sign_tx(&msg)?;
            Ok(MessageWithSender {
                message: msg,
                sender: signer.addr(),
                signature,
            })
        } else {
            // if not mining, compare with source systemTx
            let src = tx_iter.next().ok_or(ParliaError::UnknownSystemTx)?;
            if src.message.hash() != msg.hash() {
                return Err(ParliaError::SystemTxWrong {
                    expect: src.message.clone(),
                    got: msg,
                }
                .into());
            }
            Ok(MessageWithSender {
                message: msg,
                sender: src.sender,
                signature: src.signature.clone(),
            })
        }
    }

    fn finalize_the_block(
        &self,
        header: &BlockHeader,
        transactions: Option<&Vec<MessageWithSender>>,
        state: &dyn StateReader,
        header_reader: &dyn HeaderReader,
        is_mining: bool,
    ) -> anyhow::Result<Vec<MessageWithSender>> {
        // attach epoch info when epoch chg
        if header.number % self.epoch == 0 {
            self.verify_epoch_chg(header)?;
        }

        let mut expect_txs = Vec::new();
        if let Some(transactions) = transactions {
            let system_txs: Vec<&MessageWithSender> = transactions
                .iter()
                .filter(|tx| is_system_transaction(&tx.message, &tx.sender, &header.beneficiary))
                .collect();
            let mut nonce = state
                .read_account(header.beneficiary)?
                .map(|a| a.nonce)
                .unwrap_or(0_u64);
            let mut sys_tx_iter = system_txs.iter();

            // attach initContracts txs when block=1
            if header.number == 1 {
                let contracts = vec![
                    *VALIDATOR_CONTRACT,
                    *SLASH_CONTRACT,
                    *LIGHT_CLIENT_CONTRACT,
                    *RELAYER_HUB_CONTRACT,
                    *TOKEN_HUB_CONTRACT,
                    *RELAYER_INCENTIVIZE_CONTRACT,
                    *CROSS_CHAIN_CONTRACT,
                ];
                let input = validator_ins::functions::init::encode_input();
                for c in contracts {
                    expect_txs.push(self.construct_sys_tx(
                        &mut nonce,
                        c,
                        U256::ZERO,
                        Bytes::copy_from_slice(&input[..]),
                        is_mining,
                        &mut sys_tx_iter,
                    )?);
                }
            }

            // attach slash system tx
            if header.difficulty != DIFF_INTURN {
                let snap =
                    self.find_snapshot(header_reader, header.number.parent(), header.parent_hash)?;
                let proposer = snap.suppose_validator();
                let had_proposed = snap
                    .recent_proposers
                    .iter()
                    .find(|(_, v)| **v == proposer)
                    .map(|_| true)
                    .unwrap_or(false);

                if !had_proposed {
                    let slash_data: Vec<u8> = slash_ins::functions::slash::encode_input(proposer);
                    expect_txs.push(self.construct_sys_tx(
                        &mut nonce,
                        *SLASH_CONTRACT,
                        U256::ZERO,
                        Bytes::from(slash_data),
                        is_mining,
                        &mut sys_tx_iter,
                    )?);
                }
            }

            // attach reward system tx
            let mut total_reward = state
                .read_account(*SYSTEM_ACCOUNT)?
                .map(|a| a.balance)
                .unwrap_or(U256::ZERO);
            let sys_reward_collected = state
                .read_account(*SYSTEM_REWARD_CONTRACT)?
                .map(|a| a.balance)
                .unwrap_or(U256::ZERO);

            if total_reward > U256::ZERO {
                // check if contribute to SYSTEM_REWARD_CONTRACT
                let to_sys_reward = total_reward >> SYSTEM_REWARD_PERCENT;
                let max_reward = U256::from_str_hex(MAX_SYSTEM_REWARD)?;
                if to_sys_reward > U256::ZERO && sys_reward_collected < max_reward {
                    expect_txs.push(self.construct_sys_tx(
                        &mut nonce,
                        *SYSTEM_REWARD_CONTRACT,
                        to_sys_reward,
                        Bytes::new(),
                        is_mining,
                        &mut sys_tx_iter,
                    )?);
                    total_reward -= to_sys_reward;
                    debug!(
                        "SYSTEM_REWARD_CONTRACT, block {}, reward {}",
                        header.number, to_sys_reward
                    );
                }

                // left reward contribute to VALIDATOR_CONTRACT
                debug!(
                    "VALIDATOR_CONTRACT, block {}, reward {}",
                    header.number, total_reward
                );
                let input_data =
                    validator_ins::functions::deposit::encode_input(header.beneficiary);
                expect_txs.push(self.construct_sys_tx(
                    &mut nonce,
                    *VALIDATOR_CONTRACT,
                    total_reward,
                    Bytes::from(input_data),
                    is_mining,
                    &mut sys_tx_iter,
                )?);
            }

            // if after lynn, distribute fast finality reward
            if self.chain_spec.is_lynn(&header.number) {
                let reward_data = self.distribute_finality_reward(header_reader, header)?;
                if let Some(reward_data) = reward_data {
                    expect_txs.push(self.construct_sys_tx(
                        &mut nonce,
                        *VALIDATOR_CONTRACT,
                        U256::ZERO,
                        reward_data,
                        is_mining,
                        &mut sys_tx_iter,
                    )?);
                }
            }

            if sys_tx_iter.len() > 0 {
                return Err(ParliaError::SystemTxWrongCount {
                    expect: expect_txs.len(),
                    got: system_txs.len(),
                }
                .into());
            }
        }

        Ok(expect_txs)
    }
}

impl Consensus for Parlia {
    fn fork_choice_mode(&self) -> ForkChoiceMode {
        ForkChoiceMode::Difficulty(self.fork_choice_graph.clone())
    }

    fn pre_validate_block(&self, _block: &Block, _state: &dyn BlockReader) -> Result<(), DuoError> {
        Ok(())
    }

    fn prepare(
        &mut self,
        header_reader: &dyn HeaderReader,
        header: &mut BlockHeader,
    ) -> anyhow::Result<(), DuoError> {
        let snap = self.find_snapshot(
            header_reader,
            BlockNumber(header.number.0 - 1),
            header.parent_hash,
        )?;
        header.difficulty = calculate_difficulty(&snap, &header.beneficiary);

        // build header extra
        let mut extra = BytesMut::from(&header.extra_data[..]);
        if extra.len() < VANITY_LENGTH - NEXT_FORK_HASH_SIZE {
            for _ in 0..VANITY_LENGTH - NEXT_FORK_HASH_SIZE - extra.len() {
                extra.put_u8(0);
            }
        }
        // TODO attach fork hash
        // nextForkHash := forkid.NextForkHashFromForks(p.forks, p.genesisHash, number)
        // header.Extra = append(header.Extra, nextForkHash[:]...)
        if extra.len() < VANITY_LENGTH {
            for _ in 0..VANITY_LENGTH - extra.len() {
                extra.put_u8(0);
            }
        }
        // attach validators
        self.prepare_validators(header, &mut extra)?;

        // add extra seal space
        extra.extend_from_slice([0_u8; EXTRA_SEAL_LEN].as_slice());
        header.extra_data = extra.freeze();

        // Mix digest is reserved for now, set to empty
        header.mix_hash = H256::zero();

        let parent =
            header_reader
                .read_parent_header(header)?
                .ok_or(ParliaError::UnknownHeader {
                    number: header.number.parent(),
                    hash: header.parent_hash,
                })?;
        // Ensure the timestamp has the correct delay
        header.timestamp = self.block_time_for_ramanujan_fork(&snap, header, &parent);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if header.timestamp < now {
            header.timestamp = now
        }

        Ok(())
    }

    fn validate_block_header(
        &self,
        header: &BlockHeader,
        parent: &BlockHeader,
        _with_future_timestamp_check: bool,
        header_reader: &dyn HeaderReader,
    ) -> Result<(), DuoError> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        if header.timestamp > timestamp {
            return Err(ParliaError::WrongHeaderTime {
                now: timestamp,
                got: header.timestamp,
            }
            .into());
        }

        if header.parent_hash != parent.hash() {
            return Err(ValidationError::UnknownParent {
                number: header.number,
                parent_hash: header.parent_hash,
            }
            .into());
        }

        self.check_header_extra_len(header)?;
        // Ensure that the block with no uncles
        if header.ommers_hash != NULL_UNCLES_HASH {
            return Err(ValidationError::NotAnOmmer.into());
        }

        // Ensure that the block's difficulty is DIFF_INTURN or DIFF_NOTURN
        if header.difficulty != DIFF_INTURN && header.difficulty != DIFF_NOTURN {
            return Err(ValidationError::WrongDifficulty.into());
        }

        self.verify_block_gas(header, parent)?;
        // Verify vote attestation just for fast finality.
        if self.chain_spec.is_boneh(&header.number) {
            let res = self.verify_vote_attestation(header_reader, header, parent);
            if let Err(err) = res {
                if self.chain_spec.is_lynn(&header.number) {
                    return Err(err);
                }
                warn!(
                    "verify_vote_attestation err, block {:?}:{:?}, err: {:?}",
                    header.number,
                    header.hash(),
                    err
                );
            }
        }

        let snap = self.find_snapshot(header_reader, parent.number, parent.hash())?;
        self.verify_block_time_for_ramanujan_fork(&snap, header, parent)?;
        self.verify_block_seal(header, snap)?;

        Ok(())
    }

    /// parlia's finalize not effect any state, must set transaction and ConsensusFinalizeState in sync
    fn finalize(
        &self,
        header: &BlockHeader,
        _ommers: &[BlockHeader],
        transactions: Option<&Vec<MessageWithSender>>,
        state: &dyn StateReader,
        header_reader: &dyn HeaderReader,
    ) -> anyhow::Result<Vec<FinalizationChange>> {
        self.finalize_the_block(header, transactions, state, header_reader, false)?;
        Ok(Vec::new())
    }

    fn finalize_and_assemble(
        &self,
        header: &BlockHeader,
        _ommers: &[BlockHeader],
        transactions: Option<&Vec<MessageWithSender>>,
        state: &dyn StateReader,
        header_reader: &dyn HeaderReader,
    ) -> anyhow::Result<(Option<Vec<MessageWithSender>>, Vec<FinalizationChange>)> {
        Ok((
            Some(self.finalize_the_block(header, transactions, state, header_reader, true)?),
            Vec::new(),
        ))
    }

    fn new_block(
        &mut self,
        _header: &BlockHeader,
        state: ConsensusNewBlockState,
    ) -> Result<(), DuoError> {
        if let ConsensusNewBlockState::Parlia(state) = state {
            self.new_block_state = state;
            return Ok(());
        }
        Err(ParliaError::WrongConsensusParam.into())
    }

    fn seal(
        &mut self,
        node: Arc<Node>,
        header_reader: &dyn HeaderReader,
        mut block: Block,
    ) -> anyhow::Result<bool, DuoError> {
        let header = &block.header;
        let block_number = header.number;
        let block_hash = header.hash();

        if block_number.0 == 0 {
            return Err(ParliaError::UnknownBlockWhenSeal {
                number: header.number,
                hash: block_hash,
            }
            .into());
        }

        // For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
        if self.period == 0 && block.transactions.is_empty() {
            info!(
                "cannot sealing, waiting for transactions, block {:?}:{:?}",
                block_number, block_hash
            );
            return Ok(false);
        }

        let snap = self.find_snapshot(header_reader, block_number.parent(), header.parent_hash)?;
        let signer = self.signer.as_ref().ok_or(ParliaError::UnknownSigner)?;
        let proposer = signer.addr();
        if !snap.validators.contains(&proposer) {
            return Err(ParliaError::SignerUnauthorized {
                number: block_number,
                signer: proposer,
            }
            .into());
        }

        // if we're amongst the recent signers, wait for the next block
        for (last, val) in &snap.recent_proposers {
            if proposer == *val {
                let limit = (snap.validators.len() / 2 + 1) as u64;
                if block_number.0 < limit || *last > block_number.0 - limit {
                    info!(
                        "signed recently, must wait for others, block {:?}:{:?}",
                        block_number, block_hash
                    );
                    return Ok(false);
                }
            }
        }

        // Sweet, the protocol permits us to sign the block, wait for our time
        let delay = self.delay_for_ramanujan_fork(&snap, header);

        info!("consensus seal the block {:?}:{:?}, proposer: {:?}, delay: {:?}, difficulty: {}, gasUsed: {}, txsRoot: {:?}, stateRoot: {:?}",
            block_number, block_hash, proposer, delay, header.difficulty, header.gas_used, header.transactions_root, header.state_root
        );

        // sign and attach to extra_data
        let mut sign_header = header.clone();
        sign_header.extra_data =
            Bytes::copy_from_slice(&header.extra_data[..header.extra_data.len() - EXTRA_SEAL_LEN]);
        let sig = signer.sign_block(&sign_header, self.chain_id)?;
        let mut tmp = BytesMut::with_capacity(header.extra_data.len());
        tmp.extend_from_slice(&header.extra_data[..header.extra_data.len() - EXTRA_SEAL_LEN]);
        tmp.extend_from_slice(&sig[..]);
        block.header.extra_data = tmp.freeze();

        // Wait until sealing is terminated or delay timeout.
        tokio::spawn(async move {
            let header = &block.header;
            info!("waiting to propagate, delay {:?}", delay);
            tokio::time::sleep(delay).await;
            if should_wait_current_block_process(node.clone(), header) {
                info!(
                    "waiting for received in turn block to process, block {:?}:{:?}",
                    block_number, block_hash
                );
                tokio::time::sleep(Duration::from_secs(BACKOFF_TIME_OF_PROCESS)).await;
            }
            // TODO set correct TD
            let td = node.status.read().td + header.difficulty;
            // Broadcast the mined block to other p2p nodes.
            let sent_request_id = rand::thread_rng().gen();
            // TODO add mined block into stageSync
            info!(
                "finally, we could send_new_mining_block to others, block: {:?}:{:?}, {:?}",
                block_number, block_hash, block
            );
            node.send_new_mining_block(sent_request_id, block, td).await;
        });
        Ok(true)
    }

    fn snapshot(
        &self,
        snap_db: &dyn SnapDB,
        header_reader: &dyn HeaderReader,
        block_number: BlockNumber,
        block_hash: H256,
    ) -> anyhow::Result<(), DuoError> {
        let mut snap_cache = self.recent_snaps.write();

        let mut block_number = block_number;
        let mut block_hash = block_hash;
        let mut skip_headers = Vec::new();

        let mut snap: Snapshot;
        loop {
            if let Some(cached) = snap_cache.get_mut(&block_hash) {
                snap = cached.clone();
                break;
            }
            if block_number % CHECKPOINT_INTERVAL == 0 {
                if let Some(cached) = snap_db.read_parlia_snap(block_hash)? {
                    debug!("snap find from db {} {:?}", block_number, block_hash);
                    snap = cached;
                    break;
                }
            }
            if block_number == 0 {
                let header = header_reader.read_header(block_number, block_hash)?.ok_or(
                    ParliaError::UnknownHeader {
                        number: block_number,
                        hash: block_hash,
                    },
                )?;

                let (next_validators, bls_keys) =
                    parse_validators_from_header(&header, &self.chain_spec, self.epoch)?;
                snap = Snapshot::new(
                    next_validators,
                    block_number.0,
                    block_hash,
                    self.epoch,
                    bls_keys,
                )?;
                break;
            }
            let header = header_reader.read_header(block_number, block_hash)?.ok_or(
                ParliaError::UnknownHeader {
                    number: block_number,
                    hash: block_hash,
                },
            )?;
            block_hash = header.parent_hash;
            block_number = BlockNumber(header.number.0 - 1);
            skip_headers.push(header);
        }
        for h in skip_headers.iter().rev() {
            snap = snap.apply(header_reader, h, &self.chain_spec, self.chain_id)?;
        }

        snap_cache.insert(snap.block_hash, snap.clone());
        if snap.block_number % CHECKPOINT_INTERVAL == 0 {
            debug!("snap save {} {:?}", snap.block_number, snap.block_hash);
            snap_db.write_parlia_snap(&snap)?;
        }
        Ok(())
    }

    fn authorize(&mut self, signer: ECDSASigner) {
        self.signer = Some(signer);
    }
}

impl PoSA for Parlia {
    fn get_justified_header(
        &self,
        header_reader: &dyn HeaderReader,
        header: &BlockHeader,
    ) -> anyhow::Result<BlockHeader, DuoError> {
        let snap = self.find_snapshot(header_reader, header.number, header.hash())?;
        if let Some(vote) = snap.vote_data {
            // If there is justified block, return target header when block within NATURALLY_JUSTIFIED_DIST range.
            if snap.block_number - vote.target_number.0 <= NATURALLY_JUSTIFIED_DIST {
                return Ok(header_reader
                    .read_header(vote.target_number, vote.target_hash)?
                    .ok_or(ParliaError::UnknownHeader {
                        number: vote.target_number,
                        hash: vote.target_hash,
                    })?);
            }
        }

        // If there is no vote justified block, return genesis when block number is less than NATURALLY_JUSTIFIED_DIST.
        if header.number.0 <= NATURALLY_JUSTIFIED_DIST {
            return Ok(header_reader.read_header_by_number(BlockNumber(0))?.ok_or(
                ParliaError::UnknownHeader {
                    number: BlockNumber(0),
                    hash: Default::default(),
                },
            )?);
        }

        // otherwise
        find_ancient_header(header_reader, header, NATURALLY_JUSTIFIED_DIST)
    }

    fn get_finalized_header(
        &self,
        header_reader: &dyn HeaderReader,
        header: &BlockHeader,
        mut backward: u64,
    ) -> anyhow::Result<BlockHeader, DuoError> {
        if !self.chain_spec.is_lynn(&header.number) {
            return Ok(header_reader.read_header_by_number(BlockNumber(0))?.ok_or(
                ParliaError::UnknownHeader {
                    number: BlockNumber(0),
                    hash: Default::default(),
                },
            )?);
        }
        if header.number.0 < backward {
            backward = header.number.0;
        }

        let mut snap = self.find_snapshot(header_reader, header.number, header.hash())?;
        while let Some(vote) = &snap.vote_data {
            if vote.source_number.0 < header.number.0 - backward {
                break;
            }
            if vote.target_number.0 == vote.source_number.0 + 1 {
                return Ok(header_reader
                    .read_header(vote.source_number, vote.source_hash)?
                    .ok_or(ParliaError::UnknownHeader {
                        number: vote.source_number,
                        hash: vote.source_hash,
                    })?);
            }
            snap = self.find_snapshot(header_reader, vote.source_number, vote.source_hash)?;
        }

        find_ancient_header(header_reader, header, backward)
    }

    fn verify_vote(
        &self,
        header_reader: &dyn HeaderReader,
        vote: &VoteEnvelope,
    ) -> anyhow::Result<(), DuoError> {
        let target_number = vote.data.target_number;
        let target_hash = vote.data.target_hash;

        let target_header = header_reader
            .read_header(target_number, target_hash)?
            .ok_or(ParliaError::UnknownHeader {
                number: target_number,
                hash: target_hash,
            })?;

        let source_number = vote.data.source_number;
        let source_hash = vote.data.source_hash;
        let justified_header = self.get_justified_header(header_reader, &target_header)?;
        if source_number != justified_header.number || source_hash != justified_header.hash() {
            return Err(ParliaError::InvalidVoteSource {
                expect_number: justified_header.number,
                got_number: source_number,
                expect_hash: justified_header.hash(),
                got_hash: source_hash,
            }
            .into());
        }

        let snap = self.find_snapshot(
            header_reader,
            target_number.parent(),
            target_header.parent_hash,
        )?;
        snap.validators_map
            .values()
            .find(|info| info.vote_addr == vote.vote_address)
            .ok_or(ParliaError::VoterNotInValidators {
                addr: vote.vote_address,
            })?;
        Ok(())
    }

    fn is_active_validator_at(
        &self,
        header_reader: &dyn HeaderReader,
        header: &BlockHeader,
    ) -> anyhow::Result<bool, DuoError> {
        let snap = self.find_snapshot(header_reader, header.number.parent(), header.parent_hash)?;
        Ok(snap.validators.contains(&self.miner))
    }
}

pub fn parse_parlia_new_block_state<'r, S>(
    chain_spec: &ChainSpec,
    header: &BlockHeader,
    state: &mut IntraBlockState<'r, S>,
) -> anyhow::Result<ParliaNewBlockState>
where
    S: StateReader + HeaderReader,
{
    debug!("new_block {} {:?}", header.number, header.hash());
    let (_period, epoch) = match chain_spec.consensus.seal_verification {
        SealVerificationParams::Parlia { period, epoch } => (period, epoch),
        _ => {
            return Err(ParliaError::WrongConsensusParam.into());
        }
    };
    contract_upgrade::upgrade_build_in_system_contract(chain_spec, &header.number, state)?;
    // cache before executed, then validate epoch
    if header.number % epoch == 0 {
        let parent_header =
            state
                .db()
                .read_parent_header(header)?
                .ok_or(ParliaError::UnknownHeader {
                    number: BlockNumber(header.number.0 - 1),
                    hash: header.parent_hash,
                })?;
        return Ok(ParliaNewBlockState::new(Some(query_validators(
            chain_spec,
            &parent_header,
            state,
        )?)));
    }
    Ok(ParliaNewBlockState::new(None))
}

/// query_validators query validators from VALIDATOR_CONTRACT
fn query_validators<'r, S>(
    chain_spec: &ChainSpec,
    header: &BlockHeader,
    state: &mut IntraBlockState<'r, S>,
) -> anyhow::Result<(Vec<Address>, HashMap<Address, BLSPublicKey>), DuoError>
where
    S: StateReader + HeaderReader,
{
    if chain_spec.is_boneh(&header.number) {
        return query_validators_in_boneh(chain_spec, header, state);
    }

    let input_bytes = Bytes::from(if chain_spec.is_euler(&header.number) {
        let (input, _) = validator_ins::functions::get_mining_validators::call();
        input
    } else {
        let (input, _) = validator_ins::functions::get_validators::call();
        input
    });

    let message = Message::Legacy {
        chain_id: Some(chain_spec.params.chain_id),
        nonce: header.nonce.to_low_u64_be(),
        gas_price: U256::ZERO,
        gas_limit: 50000000,
        action: TransactionAction::Call(*VALIDATOR_CONTRACT),
        value: U256::ZERO,
        input: input_bytes,
    };

    let mut analysis_cache = AnalysisCache::default();
    let mut tracer = NoopTracer;
    let block_spec = chain_spec.collect_block_spec(header.number);
    let res = evmglue::execute(
        state,
        &mut tracer,
        &mut analysis_cache,
        header,
        &block_spec,
        &message,
        *VALIDATOR_CONTRACT,
        *VALIDATOR_CONTRACT,
        message.gas_limit(),
    )?;

    let validator_addrs = if chain_spec.is_euler(&header.number) {
        let (_, decoder) = validator_ins::functions::get_mining_validators::call();
        decoder.decode(res.output_data.chunk())
    } else {
        let (_, decoder) = validator_ins::functions::get_validators::call();
        decoder.decode(res.output_data.chunk())
    }?;

    let mut validators = BTreeSet::new();
    for addr in validator_addrs {
        validators.insert(addr);
    }
    Ok((validators.into_iter().collect(), HashMap::new()))
}

/// query_validators_in_boneh query validators from VALIDATOR_CONTRACT after boneh fork
fn query_validators_in_boneh<'r, S>(
    chain_spec: &ChainSpec,
    header: &BlockHeader,
    state: &mut IntraBlockState<'r, S>,
) -> anyhow::Result<(Vec<Address>, HashMap<Address, BLSPublicKey>), DuoError>
where
    S: StateReader + HeaderReader,
{
    let (input, decoder) = validator_set_in_boneh::functions::get_mining_validators::call();
    let input_bytes = Bytes::from(input);

    let message = Message::Legacy {
        chain_id: Some(chain_spec.params.chain_id),
        nonce: header.nonce.to_low_u64_be(),
        gas_price: U256::ZERO,
        gas_limit: 50000000,
        action: TransactionAction::Call(*VALIDATOR_CONTRACT),
        value: U256::ZERO,
        input: input_bytes,
    };

    let mut analysis_cache = AnalysisCache::default();
    let mut tracer = NoopTracer;
    let block_spec = chain_spec.collect_block_spec(header.number);
    let res = evmglue::execute(
        state,
        &mut tracer,
        &mut analysis_cache,
        header,
        &block_spec,
        &message,
        *VALIDATOR_CONTRACT,
        *VALIDATOR_CONTRACT,
        message.gas_limit(),
    )?;

    let (validator_addrs, bls_keys) = decoder.decode(res.output_data.chunk())?;

    // // TODO tmp for mock, because dev0net fast-finality cannot recv BC cross chain msg, to set epoch keys
    // let validator_addrs: Vec<[u8; 20]> = vec![
    //     hex!("9454cf9380bbf3c0e0bd15cdc8d2506ca18b005a"),
    //     hex!("0077f969595083a39a71ef6c050508ff99886b73"),
    //     hex!("31cf5a8d2e6a5e6a9cff2f2953152d2cf7a1050e"),
    //     hex!("0f5dbf29a272264b169f96c76e5b07d49f76db4d"),
    //     hex!("6d3d3fb1020a50f2c7b5e73c5332636b0163b707"),
    // ];
    // let bls_keys: Vec<[u8; 48]> = vec![
    //     hex!("85e6972fc98cd3c81d64d40e325acfed44365b97a7567a27939c14dbc7512ddcf54cb1284eb637cfa308ae4e00cb5588"),
    //     hex!("8addebd6ef7609df215e006987040d0a643858f3a4d791beaa77177d67529160e645fac54f0d8acdcd5a088393cb6681"),
    //     hex!("89abcc45efe76bec679ca35c27adbd66fb9712a278e3c8530ab25cfaf997765aee574f5c5745dbb873dbf7e961684347"),
    //     hex!("a1484f2b97137fb957daad064ca6cbe5b99549249ceb51f42e928ec091f94fed642ddffe3a9916769538decd0a9937bf"),
    //     hex!("8b20e24ad933b9af0a55a6d34a08e10b832a10f389154dc0dec79b63a38b79ea2f0d9f4fa664b3c06b1b2437cb58236f"),
    // ];

    let mut validators = BTreeSet::new();
    let mut bls_key_map = HashMap::new();
    info!(
        "query_validators_in_boneh block {}, {:?} {:?}, raw {:?}",
        header.number,
        validator_addrs,
        bls_keys,
        hex::encode(res.output_data.chunk())
    );
    for i in 0..validator_addrs.len() {
        let addr = validator_addrs[i];
        validators.insert(addr);
        if bls_keys[i].len() != BLS_PUBLIC_KEY_LEN {
            bls_key_map.insert(addr, BLSPublicKey::zero());
            continue;
        }
        bls_key_map.insert(addr, BLSPublicKey::from_slice(&bls_keys[i]));
    }
    Ok((validators.into_iter().collect(), bls_key_map))
}

fn calculate_difficulty(snap: &Snapshot, signer: &Address) -> U256 {
    if snap.inturn(signer) {
        return DIFF_INTURN;
    }
    DIFF_NOTURN
}

fn should_wait_current_block_process(node: Arc<Node>, header: &BlockHeader) -> bool {
    if header.difficulty == DIFF_INTURN {
        return false;
    }

    let status = node.status.read();
    if status.parent_hash == header.parent_hash {
        return true;
    }

    false
}
