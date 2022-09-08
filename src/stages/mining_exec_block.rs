use super::*;
use crate::{
    consensus::{parlia::contract_upgrade, *},
    kv::{mdbx::MdbxTransaction, tables},
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
use anyhow::bail;
use async_trait::async_trait;
use cipher::typenum::int;
use hex::FromHex;
use mdbx::{EnvironmentKind, RW};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use parbytes::ToPretty;
use std::{
    cmp::Ordering,
    sync::{Arc, Mutex},
};
use tokio::io::copy;
use tracing::debug;

pub const STAGE_EXEC_BLOCK: StageId = StageId("StageExecBlock");
// DAOForkExtraRange is the number of consecutive blocks from the DAO fork point
// to override the extra-data in to prevent no-fork attacks.
pub const DAOFORKEXTRARANG: i32 = 10;

#[derive(Debug)]
pub struct ExecBlock {
    pub mining_status: Arc<Mutex<MiningStatus>>,
    pub mining_block: Arc<Mutex<MiningBlock>>,
    pub mining_config: Arc<Mutex<MiningConfig>>,
    pub chain_spec: ChainSpec,
}

#[async_trait]
impl<'db, E> Stage<'db, E> for ExecBlock
where
    E: EnvironmentKind,
{
    fn id(&self) -> StageId {
        STAGE_EXEC_BLOCK
    }

    // ApplyDAOHardFork modifies the state database according to the DAO hard-fork
    // rules, transferring all balances of a set of DAO accounts to a single refund
    // contract.
    // fn apply_dao_hardfork(&self, tx: &'tx mut MdbxTransaction<'db, RW, E>) -> Result<_, StageError>
    // where
    //     'db: 'tx,
    // {
    //     //TODO!! Retrieve the contract to refund balances into
    //     // if !statedb.Exist(params.DAORefundContract) {
    //     // 	statedb.CreateAccount(params.DAORefundContract, false)
    //     // }

    //     // // Move every DAO account and extra-balance account funds into the refund contract
    //     // for _, addr := range params.DAODrainList() {
    //     // 	statedb.AddBalance(params.DAORefundContract, statedb.GetBalance(addr))
    //     // 	statedb.SetBalance(addr, new(uint256.Int))
    //     // }
    // }

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

        let current = &self.mining_block.lock().unwrap();
        if is_clique(self.config.lock().unwrap().consensus.name()) {
            // If we are care about TheDAO hard-fork check whether to override the extra-data or not
            if self.config.lock().unwrap().dao_fork_support
                && self
                    .config
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
            );
        }

        // TODO: Add transaction to mining block!

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
        todo!()
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
