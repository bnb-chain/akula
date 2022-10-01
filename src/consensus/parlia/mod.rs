//! Implementation of the BSC's POSA Engine.
#![allow(missing_docs)]
pub mod contract_upgrade;
mod snapshot;
mod state;
mod util;
mod vote;

pub use snapshot::Snapshot;
pub use state::ParliaNewBlockState;
pub use util::*;
pub use vote::*;

use super::*;
use crate::execution::{analysis_cache::AnalysisCache, evmglue, tracer::NoopTracer};
use std::str;

use crate::{
    consensus::{ParliaError, ValidationError},
    crypto::go_rng::{RngSource, Shuffle},
    models::*,
    HeaderReader,
};
use bitset::BitSet;
use bytes::{Buf, Bytes};
use ethabi::FunctionOutputDecoder;
use ethabi_contract::use_contract;
use ethereum_types::{Address, H256};
use fastrlp::Decodable;
use hex_literal::hex;
use lru_cache::LruCache;
use milagro_bls::{AggregateSignature, PublicKey};
use parking_lot::RwLock;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::SystemTime,
};
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
/// Maximum the gas limit may ever be.
const MAX_GAS_LIMIT_CAP: u64 = 0x7fffffffffffffff_u64;
/// The bound divisor of the gas limit, used in update calculations.
const GAS_LIMIT_BOUND_DIVISOR: u64 = 256_u64;
/// Minimum the gas limit may ever be.
const MIN_GAS_LIMIT: u64 = 5000_u64;
/// The distance to naturally justify a block
const NATURALLY_JUSTIFIED_DIST: u64 = 15;

use_contract!(
    validator_ins,
    "src/consensus/parlia/contracts/bsc_validators.json"
);
use_contract!(slash_ins, "src/consensus/parlia/contracts/bsc_slash.json");
use_contract!(
    validator_set_in_boneh,
    "src/consensus/parlia/contracts/validator_set_in_boneh.json"
);

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
}

impl Parlia {
    /// new parlia engine
    pub fn new(chain_id: ChainId, chain_spec: ChainSpec, epoch: u64, period: u64) -> Self {
        Self {
            chain_spec,
            chain_id,
            epoch,
            period,
            recent_snaps: RwLock::new(LruCache::new(SNAP_CACHE_NUM)),
            fork_choice_graph: Arc::new(Mutex::new(Default::default())),
            new_block_state: ParliaNewBlockState::new(None),
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
                msg: format!("cannot set singers without epoch change!"),
            }
            .into());
        }
        if epoch_chg && bytes_len == 0 {
            return Err(ParliaError::WrongHeaderExtraSignersLen {
                expected: 0,
                got: bytes_len,
                msg: format!("signers must correct in epoch change!"),
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
            .ok_or_else(|| ParliaError::CacheValidatorsUnknown)?;

        if !self.chain_spec.is_boneh(&header.number) {
            let actual_validators = parse_epoch_validators(
                &header.extra_data[EXTRA_VANITY_LEN..(header.extra_data.len() - EXTRA_SEAL_LEN)],
            )?;
            debug!(
                "epoch validators check {}, {}:{}",
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
                .ok_or_else(|| ParliaError::UnknownTargetBLSKey {
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
        if inturn_proposer && header.difficulty != DIFF_INTURN {
            return Err(ValidationError::WrongDifficulty.into());
        } else if !inturn_proposer && header.difficulty != DIFF_NOTURN {
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

                let x = snap.validators_map.get(val).ok_or_else(|| {
                    ParliaError::SnapNotFoundVoteAddr {
                        index: i,
                        addr: *val,
                    }
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
            let vote_addrs = vote_addrs.iter().map(|pk| pk).collect::<Vec<_>>();
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
        if self.chain_spec.is_ramanujan(&header.number) {
            if header.timestamp < parent.timestamp + self.period + self.back_off_time(snap, &header)
            {
                return Err(ValidationError::InvalidTimestamp {
                    parent: parent.timestamp,
                    current: header.timestamp,
                }
                .into());
            }
        }
        Ok(())
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
            if let Some(_) = recents.get(&snap.validators[i]) {
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
        if let Some(_) = recents.get(&snap.suppose_validator()) {
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
    ) -> anyhow::Result<Option<Message>, DuoError> {
        if header.number.0 % self.epoch != 0 {
            return Ok(None);
        }

        // find the epoch block, and collect voters, calculate rewards
        let mut accum_weight_map = BTreeMap::new();
        let epoch_block = header.number.0;
        let mut parent = header_reader.read_parent_header(header)?.ok_or_else(|| {
            ParliaError::UnknownHeader {
                number: BlockNumber(header.number.0 - 1),
                hash: header.parent_hash,
            }
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
            parent = header_reader.read_parent_header(&parent)?.ok_or_else(|| {
                ParliaError::UnknownHeader {
                    number: BlockNumber(header.number.0 - 1),
                    hash: header.parent_hash,
                }
            })?;
        }

        // stats reward, and construct reward system tx
        let validators = accum_weight_map
            .keys()
            .map(|x| *x)
            .collect::<Vec<Address>>();
        let weights = accum_weight_map.values().map(|x| *x).collect::<Vec<u64>>();
        let input_data =
            validator_set_in_boneh::functions::distribute_finality_reward::encode_input(
                validators, weights,
            );
        Ok(Some(Message::Legacy {
            chain_id: Some(self.chain_id),
            nonce: Default::default(),
            gas_price: U256::ZERO,
            gas_limit: (std::u64::MAX / 2).into(),
            value: U256::ZERO,
            action: TransactionAction::Call(*VALIDATOR_CONTRACT),
            input: Bytes::from(input_data),
        }))
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
                let header = header_reader
                    .read_header(block_number, block_hash)?
                    .ok_or_else(|| ParliaError::UnknownHeader {
                        number: block_number,
                        hash: block_hash,
                    })?;

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
            let header = header_reader
                .read_header(block_number, block_hash)?
                .ok_or_else(|| ParliaError::UnknownHeader {
                    number: block_number,
                    hash: block_hash,
                })?;
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

        if header.extra_data.len() < VANITY_LENGTH - NEXT_FORK_HASH_SIZE {
            let mut extra = header.extra_data.clone().slice(..).to_vec();
            while extra.len() < EXTRA_VANITY {
                extra.push(0);
            }
            header.extra_data = Bytes::copy_from_slice(extra.clone().as_slice());
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
                    "verify_vote_attestation err, block {}:{:?}, err: {}",
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
        // check epoch validators chg correctly
        if header.number % self.epoch == 0 {
            self.verify_epoch_chg(header)?;
        }

        // if set transactions, check systemTxs and reward if correct
        // must set transactions in sync
        if let Some(transactions) = transactions {
            let mut system_txs: Vec<&MessageWithSender> = transactions
                .iter()
                .filter(|tx| is_system_transaction(&tx.message, &tx.sender, &header.beneficiary))
                .collect();
            if header.number == 1 {
                // skip block=1, first 7 init system transactions
                system_txs = system_txs[INIT_TX_NUM..].to_vec();
            }

            let mut expect_txs = Vec::new();
            if header.difficulty != DIFF_INTURN {
                debug!("check in turn {}", header.number);
                let snap = self.find_snapshot(
                    header_reader,
                    BlockNumber(header.number.0 - 1),
                    header.parent_hash,
                )?;
                let proposer = snap.suppose_validator();
                let had_proposed = snap
                    .recent_proposers
                    .iter()
                    .find(|(_, v)| **v == proposer)
                    .map(|_| true)
                    .unwrap_or(false);

                if !had_proposed {
                    let slash_data: Vec<u8> = slash_ins::functions::slash::encode_input(proposer);
                    expect_txs.push(Message::Legacy {
                        chain_id: Some(self.chain_id),
                        nonce: Default::default(),
                        gas_price: U256::ZERO,
                        gas_limit: (std::u64::MAX / 2).into(),
                        value: U256::ZERO,
                        action: TransactionAction::Call(*SLASH_CONTRACT),
                        input: Bytes::from(slash_data),
                    });
                }
            }

            let mut total_reward = state
                .read_account(*SYSTEM_ACCOUNT)?
                .and_then(|a| Some(a.balance))
                .unwrap_or(U256::ZERO);
            let sys_reward_collected = state
                .read_account(*SYSTEM_REWARD_CONTRACT)?
                .and_then(|a| Some(a.balance))
                .unwrap_or(U256::ZERO);

            if total_reward > U256::ZERO {
                // check if contribute to SYSTEM_REWARD_CONTRACT
                let to_sys_reward = total_reward >> SYSTEM_REWARD_PERCENT;
                let max_reward = U256::from_str_hex(MAX_SYSTEM_REWARD)?;
                if to_sys_reward > U256::ZERO && sys_reward_collected < max_reward {
                    expect_txs.push(Message::Legacy {
                        chain_id: Some(self.chain_id),
                        nonce: Default::default(),
                        gas_price: U256::ZERO,
                        gas_limit: (std::u64::MAX / 2).into(),
                        value: to_sys_reward,
                        action: TransactionAction::Call(SYSTEM_REWARD_CONTRACT.clone()),
                        input: Bytes::new(),
                    });
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
                expect_txs.push(Message::Legacy {
                    chain_id: Some(self.chain_id),
                    nonce: Default::default(),
                    gas_price: U256::ZERO,
                    gas_limit: (std::u64::MAX / 2).into(),
                    value: total_reward,
                    action: TransactionAction::Call(*VALIDATOR_CONTRACT),
                    input: Bytes::from(input_data),
                });
            }

            // if after lynn, distribute fast finality reward
            if self.chain_spec.is_lynn(&header.number) {
                let reward_tx = self.distribute_finality_reward(header_reader, header)?;
                if let Some(tx) = reward_tx {
                    expect_txs.push(tx);
                }
            }

            if system_txs.len() != expect_txs.len() {
                return Err(ParliaError::SystemTxWrongCount {
                    expect: expect_txs.len(),
                    got: system_txs.len(),
                }
                .into());
            }
            for (i, expect) in expect_txs.iter().enumerate() {
                let actual = system_txs.get(i).unwrap();
                if !is_similar_tx(expect, &actual.message) {
                    return Err(ParliaError::SystemTxWrong {
                        expect: expect.clone(),
                        got: actual.message.clone(),
                    }
                    .into());
                }
            }
        }
        Ok(Vec::new())
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
                let header = header_reader
                    .read_header(block_number, block_hash)?
                    .ok_or_else(|| ParliaError::UnknownHeader {
                        number: block_number,
                        hash: block_hash,
                    })?;

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
            let header = header_reader
                .read_header(block_number, block_hash)?
                .ok_or_else(|| ParliaError::UnknownHeader {
                    number: block_number,
                    hash: block_hash,
                })?;
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
        return Ok(());
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
                .ok_or_else(|| ParliaError::UnknownHeader {
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
        action: TransactionAction::Call(VALIDATOR_CONTRACT.clone()),
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
        &header,
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
        validators.insert(Address::from(addr));
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
        action: TransactionAction::Call(VALIDATOR_CONTRACT.clone()),
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
        &header,
        &block_spec,
        &message,
        *VALIDATOR_CONTRACT,
        *VALIDATOR_CONTRACT,
        message.gas_limit(),
    )?;

    // let (validator_addrs, bls_keys) = decoder.decode(res.output_data.chunk())?;

    // TODO mock it
    let validator_addrs: Vec<[u8; 20]> = vec![
        hex!("9454cf9380bbf3c0e0bd15cdc8d2506ca18b005a").into(),
        hex!("0077f969595083a39a71ef6c050508ff99886b73").into(),
        hex!("31cf5a8d2e6a5e6a9cff2f2953152d2cf7a1050e").into(),
        hex!("0f5dbf29a272264b169f96c76e5b07d49f76db4d").into(),
        hex!("6d3d3fb1020a50f2c7b5e73c5332636b0163b707").into(),
    ];
    let bls_keys: Vec<[u8; 48]> = vec![
        hex!("85e6972fc98cd3c81d64d40e325acfed44365b97a7567a27939c14dbc7512ddcf54cb1284eb637cfa308ae4e00cb5588").into(),
        hex!("8addebd6ef7609df215e006987040d0a643858f3a4d791beaa77177d67529160e645fac54f0d8acdcd5a088393cb6681").into(),
        hex!("89abcc45efe76bec679ca35c27adbd66fb9712a278e3c8530ab25cfaf997765aee574f5c5745dbb873dbf7e961684347").into(),
        hex!("a1484f2b97137fb957daad064ca6cbe5b99549249ceb51f42e928ec091f94fed642ddffe3a9916769538decd0a9937bf").into(),
        hex!("8b20e24ad933b9af0a55a6d34a08e10b832a10f389154dc0dec79b63a38b79ea2f0d9f4fa664b3c06b1b2437cb58236f").into(),
    ];

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
        let addr = Address::from(validator_addrs[i]);
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
