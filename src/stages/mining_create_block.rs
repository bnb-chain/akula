use std::{cell::RefCell, cmp::Ordering};

use crate::{
    consensus::*,
    kv::{mdbx::MdbxTransaction, tables},
    mining::{
        proposal::{create_block_header, create_proposal},
        state::*,
    },
    models::*,
    stagedsync::stage::*,
    state::Buffer,
    StageId,
};
use anyhow::bail;
use async_trait::async_trait;
use bytes::Bytes;
use cipher::typenum::int;
use hex::FromHex;
use mdbx::{EnvironmentKind, RW};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use std::{
    rc::Rc,
    sync::{mpsc, Arc, Mutex},
};
use tokio::io::copy;
use tracing::debug;

pub const CREATE_BLOCK: StageId = StageId("CreateBlock");
// DAOForkExtraRange is the number of consecutive blocks from the DAO fork point
// to override the extra-data in to prevent no-fork attacks.
pub const DAOFORKEXTRARANG: i32 = 10;

#[derive(Debug)]
pub struct MiningBlock {
    pub header: BlockHeader,
    pub ommers: Vec<BlockHeader>,
    pub transactions: Vec<MessageWithSignature>,
}

impl MiningStatus {
    pub fn new() -> Self {
        Self {
            pending_result_ch: mpsc::channel().0,
            mining_result_ch: mpsc::channel().0,
            mining_result_pos_ch: mpsc::channel().0,
        }
    }
}

#[derive(Debug)]
pub struct CreateBlock {
    pub mining_status: Arc<Mutex<MiningStatus>>,
    pub mining_block: Arc<Mutex<MiningBlock>>,
    pub mining_config: Arc<Mutex<MiningConfig>>,
    pub chain_spec: ChainSpec,
}

#[async_trait]
impl<'db, E> Stage<'db, E> for CreateBlock
where
    E: EnvironmentKind,
{
    fn id(&self) -> StageId {
        CREATE_BLOCK
    }

    async fn execute<'tx>(
        &mut self,
        tx: &'tx mut MdbxTransaction<'db, RW, E>,
        input: StageInput,
    ) -> Result<ExecOutput, StageError>
    where
        'db: 'tx,
    {
        let mining_block = MiningBlock {
            header: BlockHeader {
                parent_hash: H256::zero(),
                ommers_hash: H256::zero(),
                beneficiary: Address::zero(),
                state_root: H256::zero(),
                transactions_root: H256::zero(),
                receipts_root: H256::zero(),
                logs_bloom: Bloom::zero(),
                difficulty: U256::ZERO,
                number: BlockNumber(0),
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                extra_data: Bytes::new(),
                mix_hash: H256::zero(),
                nonce: H64::zero(),
                base_fee_per_gas: None,
            },
            ommers: vec![],
            transactions: vec![],
        };
        let mining_block_mutex = Arc::new(Mutex::new(mining_block));
        self.mining_block = Arc::clone(&mining_block_mutex);
        let parent_number = input.stage_progress.unwrap();
        let parent_header = get_header(tx, parent_number)?;

        // TODO, complete the remaining tx related part after txpool ready.
        let mut proposal = create_block_header(&parent_header, Arc::clone(&self.mining_config))?;
        debug!("Empty block created: {:?}", proposal);

        let buffer = Buffer::new(tx, None);
        if self.chain_spec.consensus.is_parlia() {
            assert!(self
                .mining_config
                .lock()
                .unwrap()
                .consensus
                .prepare(&buffer, &mut proposal)
                .is_ok());

            // If we are care about TheDAO hard-fork check whether to override the extra-data or not
            if let Some(dao_block) = &self.mining_config.lock().unwrap().dao_fork_block {
                // Check whether the block is among the fork extra-override range
                let limit = BigInt::checked_add(&dao_block, &BigInt::from(DAOFORKEXTRARANG));
                if proposal.number.0.cmp(&DAOFORKEXTRARANG.to_u64().unwrap()) >= Ordering::Equal
                    && proposal.number.0.cmp(&limit.unwrap().to_u64().unwrap()) == Ordering::Less
                {
                    let dao_fork_block_extra =
                        hex::decode("0x64616f2d686172642d666f726b").unwrap().into();
                    // Depending whether we support or oppose the fork, override differently
                    if self.mining_config.lock().unwrap().dao_fork_support {
                        proposal.extra_data = dao_fork_block_extra;
                    } else if bytes::Bytes::eq(&proposal.extra_data, &dao_fork_block_extra) {
                        // If miner opposes, don't let it use the reserved extra-data
                        proposal.extra_data = bytes::Bytes::default();
                    }
                };
            }
        }

        self.mining_block.lock().unwrap().header = proposal;
        debug!("Miner created block with data");

        Ok(ExecOutput::Progress {
            stage_progress: parent_number + 1,
            done: true,
            reached_tip: true,
        })
    }

    async fn unwind<'tx>(
        &mut self,
        _tx: &'tx mut MdbxTransaction<'db, RW, E>,
        _input: UnwindInput,
    ) -> anyhow::Result<UnwindOutput>
    where
        'db: 'tx,
    {
        debug!("Miner create block unwind");
        Ok(UnwindOutput {
            stage_progress: _input.unwind_to,
        })
    }
}

fn get_header<E>(
    tx: &mut MdbxTransaction<'_, RW, E>,
    number: BlockNumber,
) -> anyhow::Result<BlockHeader>
where
    E: EnvironmentKind,
{
    let mut cursor = tx.cursor(tables::Header)?;
    Ok(match cursor.seek(number)? {
        Some(((found_number, _), header)) if found_number == number => header,
        _ => bail!("Expected header at block height {} not found.", number.0),
    })
}
