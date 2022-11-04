use crate::{
    kv::mdbx::MdbxTransaction,
    models::BlockNumber,
    stagedsync::{
        format_duration,
        stage::{ExecOutput, Stage, StageInput},
    },
};
use mdbx::{EnvironmentKind, RW};
use std::time::Instant;
use tracing::*;

pub mod proposal;
pub mod state;

#[derive(Debug)]
pub struct StagedMining<'db, E>
where
    E: EnvironmentKind,
{
    stages: Vec<Box<dyn Stage<'db, E>>>,
}

impl<'db, E> Default for StagedMining<'db, E>
where
    E: EnvironmentKind,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'db, E> StagedMining<'db, E>
where
    E: EnvironmentKind,
{
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    pub fn push<S>(&mut self, stage: S)
    where
        S: Stage<'db, E> + 'static,
    {
        self.stages.push(Box::new(stage));
    }

    pub async fn run<'tx>(
        &mut self,
        tx: &'tx mut MdbxTransaction<'db, RW, E>,
        last_block: BlockNumber,
    ) where
        'db: 'tx,
    {
        let num_stages = self.stages.len();

        let mut previous_stage = None;

        for (stage_index, stage) in self.stages.iter_mut().enumerate() {
            let stage_started = Instant::now();
            let stage_id = stage.id();
            let input = StageInput {
                restarted: false,
                first_started_at: (stage_started, Some(last_block)),
                previous_stage,
                stage_progress: Some(last_block),
            };
            let exec_output = async {
                info!(
                    "RUNNING from {}",
                    input
                        .stage_progress
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "genesis".to_string())
                );

                let output = stage.execute(tx, input).await;

                // Nothing here, pass along.
                match &output {
                    Ok(ExecOutput::Progress {
                        done,
                        stage_progress,
                        ..
                    }) => {
                        if *done {
                            info!(
                                "DONE @ {} in {}",
                                stage_progress,
                                format_duration(Instant::now() - stage_started, true)
                            );
                        } else {
                            warn!(
                                "Stage not done, with no reason @ {} in {}, exit...",
                                stage_progress,
                                format_duration(Instant::now() - stage_started, true)
                            );
                        }
                    }
                    Ok(ExecOutput::Unwind { unwind_to }) => {
                        warn!("Stage trigger unwind to {}, exit...", unwind_to);
                    }
                    Err(err) => {
                        warn!("mining err: {:?}, exit...", err);
                    }
                }

                output
            }
            .instrument(span!(
                Level::INFO,
                "",
                " {}/{} {} ",
                stage_index + 1,
                num_stages,
                AsRef::<str>::as_ref(&stage_id)
            ))
            .await;

            // Check how stage run went.
            let done_progress = match exec_output {
                Ok(ExecOutput::Progress {
                    stage_progress,
                    done,
                    ..
                }) => {
                    // Stage is "done", that is cannot make any more progress at this time.
                    if !done {
                        break;
                    }
                    stage_progress
                }
                _ => {
                    break;
                }
            };
            previous_stage = Some((stage_id, done_progress))
        }
    }
}
