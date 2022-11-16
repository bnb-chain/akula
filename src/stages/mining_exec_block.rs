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
    models::{
        BlockBodyWithSenders, BlockHeader, BlockNumber, ChainSpec, MessageWithSender,
        MessageWithSignature,
    },
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
use tracing::{debug, info};

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
        let (_, block_number) = input.previous_stage.unwrap();

        if self.chain_spec.consensus.is_parlia() {
            let current = &self.mining_block.lock().unwrap();
            // If we are care about TheDAO hard-fork check whether to override the extra-data or not
            let mining_config = self.mining_config.lock().unwrap();
            if mining_config.dao_fork_support
                && mining_config.dao_fork_block.clone().unwrap().to_u64()
                    == (current.header.number.to_u64())
            {
                // TODO: Apply for DAO Fork!
            }
            let mut buffer = Buffer::new(tx, None);
            let mut state = IntraBlockState::new(&mut buffer);
            contract_upgrade::upgrade_build_in_system_contract(
                &self.chain_spec,
                &current.header.number,
                &mut state,
            )?;
        }

        // TODO: Add transaction to mining block after txpool enabled!
        execute_mining_blocks(
            tx,
            self.chain_spec.clone(),
            self.mining_config.clone(),
            self.mining_block.clone(),
            input.first_started_at,
        )?;

        STAGE_EXEC_BLOCK.save_progress(tx, block_number)?;

        Ok(ExecOutput::Progress {
            stage_progress: block_number,
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
    mining_config: Arc<Mutex<MiningConfig>>,
    mining_block: Arc<Mutex<MiningBlock>>,
    first_started_at: (Instant, Option<BlockNumber>),
) -> Result<BlockNumber, StageError> {
    let mut current = mining_block.lock().unwrap();
    let header = &current.header;
    let block_hash = header.hash();
    let block_number = header.number;

    let mut mining_config = mining_config.lock().unwrap();
    let mut engine = mining_config.consensus.as_mut();

    if !engine.is_state_valid(header) {
        engine.set_state(ConsensusState::recover(tx, &chain_config, block_number)?);
    }
    if chain_config.consensus.is_parlia() {
        engine.snapshot(tx, tx, block_number.parent(), current.header.parent_hash)?;
    }

    let mut buffer = Buffer::new(tx, None);
    let mut analysis_cache = AnalysisCache::default();

    let block = BlockBodyWithSenders {
        transactions: current
            .transactions
            .iter()
            .map(|tx| {
                let sender = tx.recover_sender()?;
                Ok(MessageWithSender {
                    message: tx.message.clone(),
                    sender,
                    signature: tx.signature.clone(),
                })
            })
            .collect::<anyhow::Result<_>>()?,
        ommers: current.ommers.clone(),
    };

    let block_spec = chain_config.collect_block_spec(block_number);
    let mut call_tracer = CallTracer::default();
    let (more_txs, receipts) = ExecutionProcessor::new(
        &mut buffer,
        &mut call_tracer,
        &mut analysis_cache,
        engine,
        header,
        &block,
        &block_spec,
        &chain_config,
    )
    .execute_and_write_block_no_check()
    .map_err(|e| match e {
        DuoError::Validation(error) => StageError::Validation {
            block: block_number,
            error,
        },
        DuoError::Internal(e) => StageError::Internal(e.context(format!(
            "Failed to execute block #{:?} ({:?})",
            block_number, block_hash
        ))),
    })?;
    info!(
        "mining execute done, with receipts {}, moreTxs {:?}",
        receipts.len(),
        more_txs
    );

    buffer.insert_receipts(block_number, receipts);

    // TODO MDBX_EKEYMISMATCH: The given key value is mismatched to the current cursor position
    // {
    //     let mut c = tx.cursor(tables::CallTraceSet).unwrap();
    //     for (address, CallTracerFlags { from, to }) in call_tracer.into_sorted_iter() {
    //         c.append_dup(header.number, CallTraceSetEntry { address, from, to }).unwrap();
    //     }
    // }
    // buffer.write_to_db().unwrap();

    // replace mining block txs
    for tx in more_txs.unwrap_or(Vec::new()) {
        current.transactions.push(MessageWithSignature {
            message: tx.message,
            signature: tx.signature,
        });
    }

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
