use crate::{
    consensus::clique::*,
    consensus::SnapDB,
    kv::{mdbx::*, tables, MdbxWithDirHandle},
    p2p::types::GetBlockHeadersParams,
    HeaderReader,
};
use ethereum_types::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::*;

/// Snapshot, record validators and proposal from epoch chg.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CliqueSnapshot {
    /// record current epoch number
    pub epoch_num: u64,
    /// record block number when epoch chg
    pub block_number: u64,
    /// record block hash when epoch chg
    pub block_hash: H256,
    /// record epoch validators when epoch chg, sorted by ascending order.
    pub validators: Vec<Address>,
    /// record recent block proposers
    pub recent_proposers: BTreeMap<u64, Address>,
}

impl CliqueSnapshot {
    pub fn new(
        validators: Vec<Address>,
        block_number: u64,
        block_hash: H256,
        epoch_num: u64,
    ) -> Self {
        CliqueSnapshot {
            block_number,
            block_hash,
            epoch_num,
            validators,
            recent_proposers: Default::default(),
        }
    }

    pub fn apply(
        &mut self,
        db: &dyn SnapDB,
        header: &BlockHeader,
        chain_id: ChainId,
    ) -> Result<CliqueSnapshot, DuoError> {
        let block_number = header.number.0;
        if self.block_number + 1 != block_number {
            return Err(CliqueError::SnapFutureBlock {
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

        let proposer = clique_util::recover_creator(header, chain_id)?;
        if !snap.validators.contains(&proposer) {
            return Err(CliqueError::SignerUnauthorized {
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
            return Err(CliqueError::SignerOverLimit { signer: proposer }.into());
        }
        snap.recent_proposers.insert(block_number, proposer);

        let check_epoch_num = (snap.validators.len() / 2) as u64;
        if block_number > 0 && block_number % snap.epoch_num == check_epoch_num {
            let epoch_header = clique_util::find_ancient_header(db, header, check_epoch_num)?;
            let epoch_extra = epoch_header.extra_data;
            let next_validators = clique_util::parse_epoch_validators(
                &epoch_extra[VANITY_LENGTH..(epoch_extra.len() - SIGNATURE_LENGTH)],
            )?;

            let pre_limit = snap.validators.len() / 2 + 1;
            let next_limit = next_validators.len() / 2 + 1;
            if next_limit < pre_limit {
                for i in 0..(pre_limit - next_limit) {
                    snap.recent_proposers
                        .remove(&(block_number - ((next_limit + i) as u64)));
                }
            }
            snap.validators = next_validators;
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
    pub fn index_of(&self, validator: &Address) -> i32 {
        for (i, addr) in self.validators.iter().enumerate() {
            if *validator == *addr {
                return i as i32;
            }
        }
        -1
    }
}

/// to handle snap from db
pub trait CliqueSnapRW: HeaderReader {
    /// read snap from db
    fn read_snap(&self, block_hash: H256) -> anyhow::Result<Option<CliqueSnapshot>>;
    /// write snap into db
    fn write_snap(&self, snap: &CliqueSnapshot) -> anyhow::Result<()>;
}

impl<E: EnvironmentKind> CliqueSnapRW for MdbxTransaction<'_, RW, E> {
    fn read_snap(&self, block_hash: H256) -> anyhow::Result<Option<CliqueSnapshot>> {
        let snap_op = self.get(tables::ColCliqueSnapshot, block_hash)?;
        Ok(match snap_op {
            None => None,
            Some(val) => Some(serde_json::from_slice(&val)?),
        })
    }

    fn write_snap(&self, snap: &CliqueSnapshot) -> anyhow::Result<()> {
        debug!("snap store {}, {}", snap.block_number, snap.block_hash);
        let value = serde_json::to_vec(snap)?;
        self.set(tables::ColCliqueSnapshot, snap.block_hash, value)
    }
}

fn find_ancient_header<E>(
    txn: &MdbxTransaction<'_, RW, E>,
    header: &BlockHeader,
    ite: u64,
) -> Result<BlockHeader, DuoError>
where
    E: EnvironmentKind,
{
    let cur_header_op = Some(header.clone());
    let mut cur_header = cur_header_op.unwrap();

    for _ in 0..ite {
        let cur_header_op =
            txn.read_header(BlockNumber(cur_header.number.0 - 1), cur_header.parent_hash)?;
        if cur_header_op.is_none() {
            return Err(ValidationError::UnknownHeader {
                number: BlockNumber(header.number.0 - 1),
                hash: header.parent_hash,
            }
            .into());
        }
        cur_header = cur_header_op.unwrap();
    }
    Ok(cur_header)
}

// pub fn parse_validators(validators_bytes: &[u8]) -> Result<BTreeSet<Address>, DuoError> {
//     if validators_bytes.len() % ADDRESS_LENGTH != 0 {
//         return Err(CliqueError::WrongHeaderExtraSignersLen {
//             expected: 0,
//             got: validators_bytes.len() % ADDRESS_LENGTH,
//         }
//         .into());
//     }
//     let n = validators_bytes.len() / ADDRESS_LENGTH;
//     let mut validators = BTreeSet::new();
//     for i in 0..n {
//         let s: &[u8] = &validators_bytes[(i * ADDRESS_LENGTH)..((i + 1) * ADDRESS_LENGTH)];
//         validators.insert(Address::from_slice(s) as Address);
//     }
//     Ok(validators)
// }
