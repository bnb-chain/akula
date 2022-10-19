use crate::{
    consensus::parlia::{vote::VoteData, *},
    models::BLSPublicKey,
};
use ethereum_types::Address;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// record validators infomation
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidatorInfo {
    /// The index should offset by 1
    pub index: usize,
    pub vote_addr: BLSPublicKey,
}
/// Snapshot, record validators and proposal from epoch chg.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    /// record current epoch number
    pub epoch_num: u64,
    /// record block number when epoch chg
    pub block_number: u64,
    /// record block hash when epoch chg
    pub block_hash: H256,
    /// record epoch validators when epoch chg, sorted by ascending order.
    pub validators: Vec<Address>,
    /// record every validator's information
    pub validators_map: HashMap<Address, ValidatorInfo>,
    /// record recent block proposers
    pub recent_proposers: BTreeMap<u64, Address>,
    /// record the block attestation's vote data
    pub vote_data: Option<VoteData>,
}

impl Snapshot {
    pub fn new(
        mut validators: Vec<Address>,
        block_number: u64,
        block_hash: H256,
        epoch_num: u64,
        val_info_map: Option<HashMap<Address, ValidatorInfo>>,
    ) -> Result<Self, ParliaError> {
        // notice: the validators should be sorted by ascending order.
        validators.sort();
        Ok(Snapshot {
            block_number,
            block_hash,
            epoch_num,
            validators,
            validators_map: val_info_map.unwrap_or(Default::default()),
            recent_proposers: Default::default(),
            vote_data: None,
        })
    }

    pub fn apply(
        &mut self,
        header_reader: &dyn HeaderReader,
        header: &BlockHeader,
        chain_spec: &ChainSpec,
        chain_id: ChainId,
    ) -> Result<Snapshot, DuoError> {
        let block_number = header.number.0;
        if self.block_number + 1 != block_number {
            return Err(ParliaError::SnapFutureBlock {
                expect: BlockNumber(self.block_number + 1),
                got: BlockNumber(block_number),
            }
            .into());
        }

        let mut snap = self.clone();
        snap.block_hash = header.hash();
        snap.block_number = block_number;
        let limit = (snap.validators.len() / 2 + 1) as u64;
        if block_number >= limit {
            snap.recent_proposers.remove(&(block_number - limit));
        }

        let proposer = recover_creator(header, chain_id)?;
        if !snap.validators.contains(&proposer) {
            return Err(ParliaError::SignerUnauthorized {
                number: BlockNumber(block_number),
                signer: proposer,
            }
            .into());
        }
        if snap
            .recent_proposers
            .iter()
            .find(|(_, addr)| **addr == proposer)
            .is_some()
        {
            return Err(ParliaError::SignerOverLimit { signer: proposer }.into());
        }
        snap.recent_proposers.insert(block_number, proposer);

        let check_epoch_num = (snap.validators.len() / 2) as u64;
        if block_number > 0 && block_number % snap.epoch_num == check_epoch_num {
            let epoch_header = find_ancient_header(header_reader, header, check_epoch_num)?;
            let (mut next_validators, val_info_map) =
                parse_validators_from_header(&epoch_header, chain_spec, snap.epoch_num)?;

            let pre_limit = snap.validators.len() / 2 + 1;
            let next_limit = next_validators.len() / 2 + 1;
            if next_limit < pre_limit {
                for i in 0..(pre_limit - next_limit) {
                    snap.recent_proposers
                        .remove(&(block_number - ((next_limit + i) as u64)));
                }
            }

            // notice: the validators should be sorted by ascending order.
            next_validators.sort();
            snap.validators = next_validators;
            snap.validators_map = val_info_map.unwrap_or(Default::default());
        }

        // after boneh fork, try parse header attestation
        if chain_spec.is_boneh(&header.number) {
            let attestation = get_vote_attestation_from_header(header, chain_spec, snap.epoch_num)?;
            if let Some(attestation) = attestation {
                snap.vote_data = Some(attestation.data);
            }
        }
        Ok(snap)
    }

    /// Returns true if the block difficulty should be `inturn`
    pub fn inturn(&self, author: &Address) -> bool {
        self.suppose_validator() == *author
    }

    pub fn suppose_validator(&self) -> Address {
        self.validators[((self.block_number + 1) as usize) % self.validators.len()]
    }

    /// index_of find validator's index in validators list
    pub fn index_of(&self, validator: &Address) -> Option<usize> {
        for (i, addr) in self.validators.iter().enumerate() {
            if *validator == *addr {
                return Some(i);
            }
        }
        None
    }
}
