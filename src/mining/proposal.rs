use crate::{
    mining::state::MiningConfig,
    models::{BlockHeader, BlockNumber},
};
use anyhow::bail;
use bytes::Bytes;
use ethereum_types::Address;
use ethnum::U256;
use primitive_types::H256;
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tendermint::serializers::timestamp;

// The bound divisor of the gas limit, used in update calculations.
pub const GASLIMITBOUNDDIVISOR: u64 = 1024;
// Minimum the gas limit may ever be.
pub const MINGASLIMIT: u64 = 5000;
// Minimum the gas limit may ever be.
#[derive(Debug)]
pub struct BlockProposal {
    pub parent_hash: H256,
    pub number: BlockNumber,
    pub beneficiary: Address,
    pub difficulty: U256,
    pub extra_data: Bytes,
    pub timestamp: u64,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn get_difficulty(parent_header: &BlockHeader, _config: &MiningConfig) -> anyhow::Result<U256> {
    Ok(parent_header.difficulty + 1) // TODO
}

pub fn create_proposal(
    parent_header: &BlockHeader,
    config: &MiningConfig,
) -> anyhow::Result<BlockProposal> {
    let timestamp = now();
    if timestamp <= parent_header.timestamp {
        bail!("Current system time is earlier than existing block timestamp.");
    }

    //let difficulty = get_difficulty(parent_header, config)?;

    Ok(BlockProposal {
        parent_hash: parent_header.hash(),
        number: parent_header.number + 1,
        beneficiary: config.get_ether_base(),
        /// Update in the prepare func.
        difficulty: U256::ZERO,
        extra_data: config.get_extra_data(),
        timestamp,
    })
}

pub fn create_block_header(
    parent_header: &BlockHeader,
    config: Arc<Mutex<MiningConfig>>,
) -> anyhow::Result<BlockHeader> {
    let timestamp = now();
    if timestamp <= parent_header.timestamp {
        bail!("Current system time is earlier than existing block timestamp.");
    }

    let parent_gas_limit = parent_header.gas_limit;
    let config = config.lock().unwrap();
    let target_gas_limit = config.gas_limit;
    let gas_limit = calc_gas_limit(parent_gas_limit, target_gas_limit);
    Ok(BlockHeader {
        parent_hash: parent_header.hash(),
        number: parent_header.number + 1,
        beneficiary: config.get_ether_base(),
        difficulty: U256::ZERO,
        extra_data: config.get_extra_data(),
        timestamp: timestamp,
        ommers_hash: H256::zero(),
        state_root: H256::zero(),
        transactions_root: H256::zero(),
        receipts_root: H256::zero(),
        logs_bloom: ethereum_types::Bloom::zero(),
        gas_limit: gas_limit,
        gas_used: 0,
        mix_hash: H256::zero(),
        nonce: ethereum_types::H64::zero(),
        base_fee_per_gas: None,
    })
}

pub fn calc_gas_limit(parent_gas_limit: u64, desired_limit: u64) -> u64 {
    let delta = parent_gas_limit / GASLIMITBOUNDDIVISOR - 1;
    let mut limit = parent_gas_limit;
    let mut desired_limit = desired_limit;
    if desired_limit < MINGASLIMIT {
        desired_limit = MINGASLIMIT;
    }
    // If we're outside our allowed gas range, we try to hone towards them
    if limit < desired_limit {
        limit = parent_gas_limit + delta;
        if limit > desired_limit {
            limit = desired_limit;
        }
        return limit;
    }
    if limit > desired_limit {
        limit = parent_gas_limit - delta;
        if limit < desired_limit {
            limit = desired_limit;
        }
    }
    return limit;
}
