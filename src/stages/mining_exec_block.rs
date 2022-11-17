use super::*;
use crate::{
    consensus::{parlia::contract_upgrade, *},
    execution::{analysis_cache::AnalysisCache, processor::ExecutionProcessor, tracer::CallTracer},
    kv::{mdbx::MdbxTransaction, tables},
    mining::state::*,
    models::{
        BlockBodyWithSenders, BlockHeader, BlockNumber, Bloom, ChainSpec, MessageWithSender,
        MessageWithSignature,
    },
    stagedsync::stage::*,
    state::IntraBlockState,
    trie::root_hash,
    Buffer, StageId,
};
use anyhow::bail;
use async_trait::async_trait;
use mdbx::{EnvironmentKind, RW};
use num_traits::ToPrimitive;
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use tracing::*;

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
    _first_started_at: (Instant, Option<BlockNumber>),
) -> Result<BlockNumber, StageError> {
    let mut current = mining_block.lock().unwrap();
    let header = &current.header;
    let block_hash = header.hash();
    let block_number = header.number;

    let mut mining_config = mining_config.lock().unwrap();
    let engine = mining_config.consensus.as_mut();

    if !engine.is_state_valid(header) {
        engine.set_state(ConsensusState::recover(tx, &chain_config, block_number)?);
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
    .execute_and_write_block_for_mining()
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

    // save header
    let mut cursor_header = tx.cursor(tables::Header).unwrap();
    cursor_header.put(header.number, header.clone()).unwrap();

    // calculate receipts root, bloom and gasUsed
    current.header.gas_used = receipts.last().map(|r| r.cumulative_gas_used).unwrap_or(0);
    current.header.logs_bloom = receipts
        .iter()
        .fold(Bloom::zero(), |bloom, r| bloom | r.bloom);
    current.header.receipts_root = root_hash(&receipts);
    buffer.insert_receipts(block_number, receipts);
    buffer.write_to_db().unwrap();

    // replace mining block txs
    for t in more_txs.unwrap_or_default() {
        current.transactions.push(MessageWithSignature {
            message: t.message,
            signature: t.signature,
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
