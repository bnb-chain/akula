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
    p2p::node::Node,
    res::chainspec,
    stagedsync::stage::*,
    state::IntraBlockState,
    Buffer, StageId,
};
use anyhow::{bail, format_err};
use async_trait::async_trait;
use cipher::typenum::int;
use hex::FromHex;
use mdbx::{EnvironmentKind, RW};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use rand::Rng;
use std::{
    cmp::Ordering,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::copy;
use tracing::{debug, log::warn};

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
    pub node: Arc<Node>,
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

        let (mut header, block) = {
            let mining_block = self.mining_block.lock().unwrap();
            let header = mining_block.header.clone();
            let block = Block::new(
                PartialHeader::from(header.clone()),
                mining_block.transactions.clone(),
                mining_block.ommers.clone(),
            );
            (header, block)
        };

        if let Err(err) = self
            .mining_status
            .lock()
            .unwrap()
            .mining_result_pos_ch
            .send(block.clone())
        {
            warn!("mining finish send mining_result_pos_ch err: {:?}", err);
        }

        if !block.header.nonce.0.is_empty() {
            if let Err(err) = self
                .mining_status
                .lock()
                .unwrap()
                .mining_result_ch
                .send(block.clone())
            {
                warn!("mining finish send mining_result_ch err: {:?}", err);
            }
        }

        if let Err(err) = self
            .mining_status
            .lock()
            .unwrap()
            .pending_result_ch
            .send(block.clone())
        {
            warn!("mining finish send pending_result_ch err: {:?}", err);
        }

        self.mining_config
            .lock()
            .unwrap()
            .consensus
            .seal(tx, &mut header)?;

        // reconstruct, then broadcast
        let block = Block::new(
            PartialHeader::from(header),
            block.transactions.clone(),
            block.ommers.clone(),
        );

        // Broadcast the mined block to other p2p nodes.
        let sent_request_id = rand::thread_rng().gen();
        self.node
            .send_new_mining_block(
                sent_request_id,
                block.clone(),
                block.clone().header.difficulty,
            )
            .await;
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
