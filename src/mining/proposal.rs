use crate::{
    mining::state::MiningConfig,
    models::{BlockHeader, BlockNumber},
};
use anyhow::bail;
use bytes::Bytes;
use ethereum_types::Address;
use ethnum::U256;
use primitive_types::H256;
use std::time::{SystemTime, UNIX_EPOCH};

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
    config: &MiningConfig,
) -> anyhow::Result<BlockHeader> {
    let timestamp = now();
    if timestamp <= parent_header.timestamp {
        bail!("Current system time is earlier than existing block timestamp.");
    }

    Ok(BlockHeader {
        parent_hash: parent_header.hash(),
        number: parent_header.number + 1,
        beneficiary: config.get_ether_base(),
        /// Update in the prepare func.
        difficulty: U256::ZERO,
        extra_data: config.get_extra_data(),
        timestamp,
        ommers_hash: H256::zero(),
        state_root: H256::zero(),
        transactions_root: H256::zero(),
        receipts_root: H256::zero(),
        logs_bloom: ethereum_types::Bloom::zero(),
        gas_limit: 0,
        gas_used: 0,
        mix_hash: H256::zero(),
        nonce: ethereum_types::H64::zero(),
        base_fee_per_gas: None,
    })
}
