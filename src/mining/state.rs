use crate::consensus::Consensus;
use bytes::Bytes;
use ethereum_types::Address;
use num_bigint::BigInt;
use primitive_types::H256;
use secp256k1::SecretKey;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
fn default_extra_data() -> Bytes {
    // TODO replace by version string once we have versioned releases
    Bytes::from("Akula preview")
}

struct BlockProposerParameters {
    random: H256,
    suggested_ether_base: Address,
    timestamp: u64,
}

#[derive(Debug)]
pub struct MiningConfig {
    pub enabled: bool,
    pub ether_base: Address,
    pub secret_key: SecretKey,
    pub extra_data: Option<Bytes>,
    pub consensus: Box<dyn Consensus>, //Arc<dyn Consensus>,
    pub dao_fork_block: Option<BigInt>,
    pub dao_fork_support: bool,
}

impl MiningConfig {
    pub fn get_ether_base(&self) -> Address {
        self.ether_base
    }

    pub fn get_extra_data(&self) -> Bytes {
        match &self.extra_data {
            Some(custom) => custom.clone(),
            None => default_extra_data(),
        }
    }
}

#[derive(Debug)]
pub struct MiningStatus {
    pub pending_result_ch: mpsc::Sender<MiningBlock>,
    pub mining_result_ch: mpsc::Sender<MiningBlock>,
    pub mining_result_pos_ch: mpsc::Sender<MiningBlock>,
}
