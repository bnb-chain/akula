use super::*;
use crate::{
    accessors,
    consensus::{parlia::contract_upgrade, *},
    execution::{
        analysis_cache::AnalysisCache,
        processor::ExecutionProcessor,
        tracer::{CallTracer, CallTracerFlags},
    },
    kv::{mdbx::MdbxTransaction, tables, tables::*},
    mining::{
        proposal::{create_block_header, create_proposal},
        state::*,
    },
    models::*,
    res::chainspec,
    stagedsync::stage::*,
    state::IntraBlockState,
    Buffer, StageId,
};
use anyhow::bail;
use anyhow::format_err;
use async_trait::async_trait;
use cipher::typenum::int;
use hex::FromHex;
use mdbx::{EnvironmentKind, RW};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use std::{
    cmp::Ordering,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::copy;
use tracing::debug;

pub const STAGE_FINISH_BLOCK: StageId = StageId("StageFinishBlock");
// DAOForkExtraRange is the number of consecutive blocks from the DAO fork point
// to override the extra-data in to prevent no-fork attacks.
pub const DAOFORKEXTRARANG: i32 = 10;

#[derive(Debug)]
pub struct MiningFinishBlock {
    pub mining_status: Arc<Mutex<MiningStatus>>,
    pub mining_block: Arc<Mutex<MiningBlock>>,
    pub mining_config: Arc<Mutex<MiningConfig>>,
    pub chain_spec: ChainSpec,
}

#[async_trait]
impl<'db, E> Stage<'db, E> for MiningFinishBlock
where
    E: EnvironmentKind,
{
    fn id(&self) -> StageId {
        STAGE_FINISH_BLOCK
    }

    async fn execute<'tx>(
        &mut self,
        tx: &'tx mut MdbxTransaction<'db, RW, E>,
        input: StageInput,
    ) -> Result<ExecOutput, StageError>
    where
        'db: 'tx,
    {
        let prev_stage = input
            .previous_stage
            .map(|(_, b)| b)
            .unwrap_or(BlockNumber(0));

        //let current = Arc::clone(&self.mining_block);
        let header = self.mining_block.lock().unwrap().header.clone();
        let transactions = self.mining_block.lock().unwrap().transactions.clone();
        let ommers = self.mining_block.lock().unwrap().ommers.clone();
        let partial_header = PartialHeader::from(header);
        let block = Block::new(partial_header, transactions, ommers);

        self.mining_status
            .lock()
            .unwrap()
            .mining_result_pos_ch
            .send(block.clone())
            .unwrap();

        if !block.header.nonce.0.is_empty() {
            self.mining_status
                .lock()
                .unwrap()
                .mining_result_ch
                .send(block.clone())
                .unwrap();
        }

        self.mining_status
            .lock()
            .unwrap()
            .pending_result_ch
            .send(block.clone())
            .unwrap();

        Ok(ExecOutput::Progress {
            stage_progress: prev_stage,
            done: true,
            reached_tip: true,
        })
    }

    async fn unwind<'tx>(
        &mut self,
        _: &'tx mut MdbxTransaction<'db, RW, E>,
        input: UnwindInput,
    ) -> anyhow::Result<UnwindOutput>
    where
        'db: 'tx,
    {
        Ok(UnwindOutput {
            stage_progress: input.unwind_to,
        })
    }
}
