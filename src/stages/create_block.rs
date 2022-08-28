use crate::{
    consensus::*,
    kv::{mdbx::MdbxTransaction, tables},
    mining::{proposal::create_proposal, state::MiningConfig},
    models::{BlockHeader, BlockNumber},
    stagedsync::stage::*,
    StageId,
};
use anyhow::bail;
use async_trait::async_trait;
use mdbx::{EnvironmentKind, RW};
use num_bigint::BigInt;
use tracing::debug;

pub const CREATE_BLOCK: StageId = StageId("CreateBlock");
// DAOForkExtraRange is the number of consecutive blocks from the DAO fork point
// to override the extra-data in to prevent no-fork attacks.
// pub  DAOFORKEXTRARANG: BigInt = BigInt::from(10);

#[derive(Debug)]
pub struct CreateBlock {
    pub config: MiningConfig,
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
        let parent_number = input.stage_progress.unwrap();

        let parent_header = get_header(tx, parent_number)?;

        let mut proposal = create_proposal(&parent_header, &self.config).unwrap();
        if is_clique(self.config.consensus.name()) {
            //TODO frank: if let Some(cl) = self.config.consensus.clique() {
            //     //cl.prepare(tx, proposal);
            // }

            // If we are care about TheDAO hard-fork check whether to override the extra-data or not
            // if daoBlock := cfg.chainConfig.DAOForkBlock; daoBlock != nil {
            // 	// Check whether the block is among the fork extra-override range
            // 	limit := new(big.Int).Add(daoBlock, params.DAOForkExtraRange)
            // 	if header.Number.Cmp(daoBlock) >= 0 && header.Number.Cmp(limit) < 0 {
            // 		// Depending whether we support or oppose the fork, override differently
            // 		if cfg.chainConfig.DAOForkSupport {
            // 			header.Extra = libcommon.Copy(params.DAOForkBlockExtra)
            // 		} else if bytes.Equal(header.Extra, params.DAOForkBlockExtra) {
            // 			header.Extra = []byte{} // If miner opposes, don't let it use the reserved extra-data
            // 		}
            // 	}
            // }
            if let Some(dao_block) = self.config.dao_fork_block {
                let limit = BigInt::checked_add(dao_block, &DAOFORKEXTRARANG);
                //if proposal
            }
        }

        debug!("Proposal created: {:?}", proposal); // TODO save block proposal

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
