pub mod clique_util;
pub mod snapshot;
pub mod state;
pub use state::CliqueState;

use crate::{
    consensus::{
        clique::snapshot::Snapshot, fork_choice_graph::ForkChoiceGraph, state::CliqueBlock,
        CliqueError, Consensus, ConsensusEngineBase, ConsensusState, DuoError,
        DuoError::Validation, FinalizationChange, ForkChoiceMode, ValidationError, *,
    },
    kv::{mdbx::*, tables},
    models::{
        Block, BlockHeader, BlockNumber, ChainConfig, ChainId, ChainSpec, MessageWithSender,
        Receipt, Seal,
    },
    state::{IntraBlockState, StateReader},
    BlockReader, HeaderReader,
};
use anyhow::bail;
use byte_unit::Byte;
use bytes::Bytes;
use cipher::typenum::private::IsEqualPrivate;
//use ethabi::Bytes;
use ethereum_types::{Address, H256, H64};
use lru_cache::LruCache;
use mdbx::{EnvironmentKind, TransactionKind};
use parking_lot::{Mutex, RwLock};
use rlp::RlpStream;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message as SecpMessage, SECP256K1,
};
use sha3::{Digest, Keccak256};
use std::{
    io::Read,
    sync::Arc,
    time::{Duration, SystemTime},
    unreachable,
};
use tendermint::signature::Signer;
use tracing::{debug, info};
use trust_dns_resolver::proto::{serialize::binary::BinEncodable, Time};

const EXTRA_VANITY: usize = 32;
const EXTRA_SEAL: usize = 65;
/// How many snapshot to cache in the memory.
pub const SNAP_CACHE_NUM: usize = 2048;
/// Number of blocks after which to save the snapshot to the database
pub const CHECKPOINT_INTERVAL: u64 = 1024;
/// Difficulty for INTURN block
pub const DIFF_INTURN: ethnum::U256 = ethnum::U256([2, 0]);
/// Difficulty for NOTURN block
pub const DIFF_NOTURN: ethnum::U256 = ethnum::U256([1, 0]);
/// Address length of signer
pub const ADDRESS_LENGTH: usize = 20;
/// Fixed number of extra-data suffix bytes reserved for signer signature
pub const SIGNATURE_LENGTH: usize = 65;
/// Fixed number of extra-data prefix bytes reserved for signer vanity
pub const VANITY_LENGTH: usize = 32;

pub fn recover_signer(header: &BlockHeader) -> Result<Address, anyhow::Error> {
    let signature_offset = header.extra_data.len() - EXTRA_SEAL;

    let sig = &header.extra_data[signature_offset..signature_offset + 64];
    let rec = RecoveryId::from_i32(header.extra_data[signature_offset + 64] as i32)?;
    let signature = RecoverableSignature::from_compact(sig, rec)?;

    let mut sig_hash_header = header.clone();
    sig_hash_header.extra_data = Bytes::copy_from_slice(&header.extra_data[..signature_offset]);
    let message = &SecpMessage::from_slice(sig_hash_header.hash().as_bytes())?;

    let public = &SECP256K1.recover_ecdsa(message, &signature)?;
    let address_slice = &Keccak256::digest(&public.serialize_uncompressed()[1..])[12..];

    Ok(Address::from_slice(address_slice))
}

fn parse_checkpoint(extra_data: &[u8]) -> Result<Vec<Address>, DuoError> {
    let addresses_length = extra_data.len() as isize - (EXTRA_VANITY + EXTRA_SEAL) as isize;

    if addresses_length < 0 || addresses_length % 20 != 0 {
        return Err(CliqueError::WrongExtraData.into());
    };

    let mut addresses = vec![];

    for offset in (EXTRA_VANITY..(EXTRA_VANITY + addresses_length as usize)).step_by(20) {
        let next_address = Address::from_slice(&extra_data[offset..offset + 20]);
        addresses.push(next_address);
    }

    for index in 1..addresses.len() {
        if addresses[index - 1].ge(&addresses[index]) {
            return Err(CliqueError::InvalidCheckpoint.into());
        }
    }

    Ok(addresses)
}

fn get_header<K: TransactionKind>(
    cursor: &mut MdbxCursor<'_, K, tables::Header>,
    height: BlockNumber,
) -> anyhow::Result<BlockHeader> {
    Ok(match cursor.seek(height)? {
        Some(((found_height, _), header)) if found_height == height => header,
        _ => bail!("Header for block {} missing from database.", height),
    })
}

pub fn recover_signers_from_epoch_block<T: TransactionKind, E: EnvironmentKind>(
    tx: &MdbxTransaction<'_, T, E>,
    current_epoch: BlockNumber,
) -> anyhow::Result<Vec<Address>> {
    let mut cursor = tx.cursor(tables::Header)?;
    let epoch_header = get_header(&mut cursor, current_epoch)?;
    Ok(parse_checkpoint(epoch_header.extra_data.as_ref())?)
}

pub fn fast_forward_within_epoch<T: TransactionKind, E: EnvironmentKind>(
    state: &mut CliqueState,
    tx: &MdbxTransaction<'_, T, E>,
    latest_epoch: BlockNumber,
    starting_block: BlockNumber,
) -> anyhow::Result<()> {
    let mut cursor = tx.cursor(tables::Header)?;

    for height in latest_epoch + 1..starting_block {
        state.finalize(CliqueBlock::from_header(&get_header(&mut cursor, height)?)?);
    }

    Ok(())
}

pub fn recover_clique_state<T: TransactionKind, E: EnvironmentKind>(
    tx: &MdbxTransaction<'_, T, E>,
    chain_spec: &ChainSpec,
    epoch: u64,
    starting_block: BlockNumber,
) -> anyhow::Result<CliqueState> {
    let mut state = CliqueState::new(epoch);

    let blocks_into_epoch = starting_block % epoch;
    let latest_epoch = starting_block - blocks_into_epoch;

    let begin_of_epoch_signers = if latest_epoch == 0 {
        if let Seal::Clique {
            vanity: _,
            score: _,
            signers,
        } = &chain_spec.genesis.seal
        {
            signers.clone()
        } else {
            unreachable!("This should only be called if consensus algorithm is Clique.");
        }
    } else {
        recover_signers_from_epoch_block(tx, latest_epoch)?
    };

    state.set_signers(begin_of_epoch_signers);

    if blocks_into_epoch > 0 {
        fast_forward_within_epoch(&mut state, tx, latest_epoch, starting_block)?;
    }

    if starting_block > 1 {
        let mut cursor = tx.cursor(tables::Header)?;
        let header = get_header(&mut cursor, starting_block - BlockNumber(1))?;
        state.set_block_hash(header.hash());
    } else {
        let config = ChainConfig::from(chain_spec.clone());
        state.set_block_hash(config.genesis_hash);
    };

    Ok(state)
}

#[derive(Debug)]
pub struct Clique {
    base: ConsensusEngineBase,
    state: Mutex<CliqueState>,
    period: u64,
    fork_choice_graph: Arc<Mutex<ForkChoiceGraph>>,
    recent_snaps: RwLock<LruCache<H256, Snapshot>>,
    /// Ethereum address of the signing key.
    signer: Address,
}

impl Clique {
    pub(crate) fn new(
        chain_id: ChainId,
        eip1559_block: Option<BlockNumber>,
        period: Duration,
        epoch: u64,
        initial_signers: Vec<Address>,
    ) -> Self {
        let mut state = CliqueState::new(epoch);
        state.set_signers(initial_signers);
        Self {
            base: ConsensusEngineBase::new(chain_id, eip1559_block, None),
            state: Mutex::new(state),
            period: period.as_secs(),
            fork_choice_graph: Arc::new(Mutex::new(Default::default())),
            recent_snaps: RwLock::new(LruCache::new(SNAP_CACHE_NUM)),
            signer: Address::zero(),
        }
    }

    // Preparing all the consensus fields of the header for running the transactions on top.
    pub fn prepare<E>(
        &mut self,
        tx: &mut MdbxTransaction<'_, RW, E>,
        header: &mut BlockHeader,
    ) -> anyhow::Result<(), DuoError>
    where
        E: EnvironmentKind,
    {
        // If the block isn't a checkpoint, cast a random vote (good enough for now)
        header.beneficiary = Address::zero();
        header.nonce = H64::zero();

        let number = header.number;
        // Assemble the voting snapshot to check which votes make sense
        let snap = self.snapshot(tx, BlockNumber(number.0 - 1), header.parent_hash)?;

        // Set the correct difficulty
        header.difficulty = calculate_difficulty(&snap, self.signer);

        // Ensure the extra data has all its components
        if header.extra_data.len() < EXTRA_VANITY {
            let mut left = EXTRA_VANITY - header.extra_data.len();
            while left > 0 {
                //TODO Frank: header.extra_data = [header.extra_data, Bytes::new()].concat().to_bytes();
                left -= 1;
            }
            // let out = s.out();
            // header.extra_data = out;
        }
        //TODO Frank: header.extra_data = Bytes::from(header.extra_data.get(0..EXTRA_VANITY).unwrap());

        if self.state.lock().is_epoch(number) {
            for signer in snap.validators {
                // TODO Frank: [header.extra_data, signer.as_bytes()].concat();
            }
        }
        // TODO: frank let extra_seal = [Bytes::new(); EXTRA_SEAL];
        //  [header.extra_data, extra_seal].concat();

        // Mix digest is reserved for now, set to empty
        header.mix_hash = H256::zero();

        // Ensure the timestamp has the correct delay
        let mut cursor = tx.cursor(tables::Header)?;
        let parent = get_header(&mut cursor, BlockNumber(number.0 - 1))?;
        header.timestamp = parent.timestamp + self.period;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if header.timestamp < now {
            header.timestamp = now;
        }
        Ok(())
    }

    // snapshot retrieves the authorization snapshot at a given point in time.
    pub fn snapshot<E>(
        &mut self,
        txn: &mut MdbxTransaction<'_, RW, E>,
        mut block_number: BlockNumber,
        mut block_hash: H256,
    ) -> anyhow::Result<Snapshot, DuoError>
    where
        E: EnvironmentKind,
    {
        debug!("snapshot header {}", block_number);
        let mut snap_by_hash = self.recent_snaps.write();
        let mut headers = Vec::new();
        let mut snap: Snapshot;

        loop {
            debug!("snap loop header {} {:?}", block_number, block_hash);
            if let Some(new_snap) = snap_by_hash.get_mut(&block_hash) {
                snap = new_snap.clone();
                break;
            }
            if block_number % CHECKPOINT_INTERVAL == 0 {
                if let Some(new_snap) = Snapshot::load(txn, block_hash)? {
                    snap = new_snap;
                    info!("snap find from db {} {:?}", block_number, block_hash);
                    break;
                }
            }
            if block_number == 0 {
                let header = txn.read_header(block_number, block_hash)?;
                if header.is_none() {
                    return Err(Validation(ValidationError::UnknownHeader {
                        number: block_number,
                        hash: block_hash,
                    }));
                }
                let genesis = header.unwrap();
                let validator_bytes = &genesis.extra_data
                    [VANITY_LENGTH..(genesis.extra_data.len() - SIGNATURE_LENGTH)];
                let validators = snapshot::parse_validators(validator_bytes)?;
                snap = Snapshot::new(
                    validators,
                    block_number.0,
                    block_hash,
                    self.state.lock().get_epoch(),
                );
                break;
            }
            if let Some(header) = txn.read_header(block_number, block_hash)? {
                block_hash = header.parent_hash;
                block_number = BlockNumber(header.number.0 - 1);
                headers.push(header);
            } else {
                return Err(Validation(ValidationError::UnknownHeader {
                    number: block_number,
                    hash: block_hash,
                }));
            }
        }
        for h in headers.iter().rev() {
            snap = snap.apply(txn, h, self.base.chain_id)?;
        }

        debug!("snap insert {} {:?}", snap.number, snap.hash);
        snap_by_hash.insert(snap.hash, snap.clone());
        if snap.number % CHECKPOINT_INTERVAL == 0 {
            snap.store(txn)?;
        }
        return Ok(snap);
    }
}

/// whether it is a clique engine
pub fn is_clique(engine: &str) -> bool {
    engine == "Clique"
}

impl Consensus for Clique {
    fn pre_validate_block(&self, block: &Block, state: &dyn BlockReader) -> Result<(), DuoError> {
        if !block.ommers.is_empty() {
            return Err(ValidationError::TooManyOmmers.into());
        }

        self.base.pre_validate_block(block)?;

        if state.read_parent_header(&block.header)?.is_none() {
            return Err(ValidationError::UnknownParent {
                number: block.header.number,
                parent_hash: block.header.parent_hash,
            }
            .into());
        }

        Ok(())
    }

    fn validate_block_header(
        &self,
        header: &BlockHeader,
        parent: &BlockHeader,
        with_future_timestamp_check: bool,
    ) -> Result<(), DuoError> {
        self.base
            .validate_block_header(header, parent, with_future_timestamp_check)?;

        if header.timestamp - parent.timestamp < self.period {
            return Err(ValidationError::InvalidTimestamp {
                parent: parent.timestamp,
                current: header.timestamp,
            }
            .into());
        };

        Ok(())
    }

    fn finalize(
        &self,
        block: &BlockHeader,
        _ommers: &[BlockHeader],
        _transactions: Option<&Vec<MessageWithSender>>,
        _state: &dyn StateReader,
    ) -> anyhow::Result<Vec<FinalizationChange>> {
        let clique_block = CliqueBlock::from_header(block)?;

        let mut state = self.state.lock();

        state
            .validate(&clique_block, false)
            .map_err(DuoError::Validation)?;
        state.finalize(clique_block);

        state.set_block_hash(block.hash());

        Ok(vec![])
    }

    fn set_state(&mut self, state: ConsensusState) {
        if let ConsensusState::Clique(state) = state {
            self.state = Mutex::new(state);
        } else {
            unreachable!("Expected clique ConsensusState.");
        }
    }

    fn is_state_valid(&self, next_header: &BlockHeader) -> bool {
        self.state.lock().match_block_hash(next_header.parent_hash)
    }

    fn get_beneficiary(&self, header: &BlockHeader) -> Address {
        recover_signer(header).unwrap()
    }

    fn fork_choice_mode(&self) -> ForkChoiceMode {
        ForkChoiceMode::Difficulty(self.fork_choice_graph.clone())
    }
}

pub fn calculate_difficulty(snap: &snapshot::Snapshot, signer: Address) -> ethnum::U256 {
    if snap.inturn(snap.number + 1, &signer) {
        return DIFF_INTURN;
    }
    return DIFF_NOTURN;
}
