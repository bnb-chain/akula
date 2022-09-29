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
    models::{BlockHeader, BlockNumber, ChainSpec},
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
use std::{
    cmp::Ordering,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::copy;
use tracing::debug;

pub const STAGE_EXEC_BLOCK: StageId = StageId("StageExecBlock");
// DAOForkExtraRange is the number of consecutive blocks from the DAO fork point
// to override the extra-data in to prevent no-fork attacks.
pub const DAOFORKEXTRARANG: i32 = 10;

#[derive(Debug)]
pub struct MiningExecBlock {
    pub mining_status: Arc<Mutex<MiningStatus>>,
    pub mining_block: Arc<Mutex<MiningBlock>>,
    pub mining_config: Arc<Mutex<MiningConfig>>,
    pub chain_spec: ChainSpec,
}

#[async_trait]
impl<'db, E> Stage<'db, E> for MiningExecBlock
where
    E: EnvironmentKind,
{
    fn id(&self) -> crate::StageId {
        STAGE_EXEC_BLOCK
    }

    async fn execute<'tx>(
        &mut self,
        tx: &'tx mut MdbxTransaction<'db, RW, E>,
        input: StageInput,
    ) -> Result<ExecOutput, StageError>
    where
        'db: 'tx,
    {
        let parent_number = input.stage_progress.unwrap();
        let parent_header = get_header(tx, parent_number)?;

        let prev_progress = input.stage_progress.unwrap_or_default();
        let current = &self.mining_block.lock().unwrap();
        if self.chain_spec.consensus.is_parlia() {
            // If we are care about TheDAO hard-fork check whether to override the extra-data or not
            if self.mining_config.lock().unwrap().dao_fork_support
                && self
                    .mining_config
                    .lock()
                    .unwrap()
                    .dao_fork_block
                    .clone()
                    .unwrap()
                    .to_u64()
                    == (current.header.number.to_u64())
            {
                // TODO: Apply for DAO Fork!
            }
            let mut buffer = Buffer::new(tx, None);
            let mut state = IntraBlockState::new(&mut buffer);
            contract_upgrade::upgrade_build_in_system_contract(
                &self.chain_spec,
                &self.mining_block.lock().unwrap().header.number,
                &mut state,
            )?;
        }

        // TODO: Add transaction to mining block after txpool enabled!

        execute_mining_blocks(
            tx,
            self.chain_spec.clone(),
            current.header.number,
            input.first_started_at,
        )?;

        STAGE_EXEC_BLOCK.save_progress(tx, current.header.number)?;

        Ok(ExecOutput::Progress {
            stage_progress: prev_progress,
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
        debug!("Miner execute block unwind");
        Ok(UnwindOutput {
            stage_progress: _input.unwind_to,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_mining_blocks<E: EnvironmentKind>(
    tx: &MdbxTransaction<'_, RW, E>,
    chain_config: ChainSpec,
    starting_block: BlockNumber,
    first_started_at: (Instant, Option<BlockNumber>),
) -> Result<BlockNumber, StageError> {
    let mut consensus_engine = engine_factory(None, chain_config.clone(), None)?;
    consensus_engine.set_state(ConsensusState::recover(tx, &chain_config, starting_block)?);

    let mut buffer = Buffer::new(tx, None);
    let mut analysis_cache = AnalysisCache::default();

    let block_number = starting_block;

    let block_hash = tx
        .get(tables::CanonicalHeader, block_number)?
        .ok_or_else(|| format_err!("No canonical hash found for block {}", block_number))?;
    let header = tx
        .get(tables::Header, block_number)?
        .ok_or_else(|| format_err!("Header not found: {}/{:?}", block_number, block_hash))?;
    let block = accessors::chain::block_body::read_with_senders(tx, block_number)?
        .ok_or_else(|| format_err!("Block body not found: {}/{:?}", block_number, block_hash))?;

    let block_spec = chain_config.collect_block_spec(block_number);

    if !consensus_engine.is_state_valid(&header) {
        consensus_engine.set_state(ConsensusState::recover(tx, &chain_config, block_number)?);
    }

    if chain_config.consensus.is_parlia() && header.difficulty != DIFF_INTURN {
        consensus_engine.snapshot(tx, tx, BlockNumber(header.number.0 - 1), header.parent_hash)?;
    }

    let mut call_tracer = CallTracer::default();
    let receipts = ExecutionProcessor::new(
        &mut buffer,
        &mut call_tracer,
        &mut analysis_cache,
        &mut *consensus_engine,
        &header,
        &block,
        &block_spec,
        &chain_config,
    )
    .execute_and_write_block()
    .map_err(|e| match e {
        DuoError::Validation(error) => StageError::Validation {
            block: block_number,
            error,
        },
        DuoError::Internal(e) => StageError::Internal(e.context(format!(
            "Failed to execute block #{} ({:?})",
            block_number, block_hash
        ))),
    })?;

    buffer.insert_receipts(block_number, receipts);

    {
        let mut c = tx.cursor(tables::CallTraceSet)?;
        for (address, CallTracerFlags { from, to }) in call_tracer.into_sorted_iter() {
            c.append_dup(header.number, CallTraceSetEntry { address, from, to })?;
        }
    }
    buffer.write_to_db()?;
    Ok(block_number)
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
        Some((found_number, header)) if found_number == number => header,
        _ => bail!("Expected header at block height {} not found.", number.0),
    })
}

// ApplyDAOHardFork modifies the state database according to the DAO hard-fork
// rules, transferring all balances of a set of DAO accounts to a single refund
// contract.
// fn apply_dao_hardfork(&self, tx: &'tx mut MdbxTransaction<'db, RW, E>) -> Result<_, StageError>
// where
//     'db: 'tx,
// {
//     // //TODO!! Retrieve the contract to refund balances into
//     // if !statedb.Exist(params.DAORefundContract) {
//     // 	statedb.CreateAccount(params.DAORefundContract, false)
//     // }

//     // // Move every DAO account and extra-balance account funds into the refund contract
//     // for _, addr := range params.DAODrainList() {
//     // 	statedb.AddBalance(params.DAORefundContract, statedb.GetBalance(addr))
//     // 	statedb.SetBalance(addr, new(uint256.Int))
//     // }
//     Ok(())
// }
