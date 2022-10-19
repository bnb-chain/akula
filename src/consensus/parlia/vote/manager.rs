use super::*;
use crate::{
    consensus::{DuoError, PoSA},
    kv::{
        mdbx::{MdbxEnvironment, MdbxTransaction},
        MdbxWithDirHandle,
    },
    models::{BLSPrivateKey, BlockHeader, ChainSpec},
    p2p::{
        node::Node,
        types::{InboundMessage, Message, Message::Votes, Status},
    },
    HeaderReader, StageId,
};
use futures::{future::err, StreamExt};
use mdbx::{EnvironmentKind, WriteMap, RW};
use parking_lot::Mutex;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::ready,
};
use tokio::sync::watch::Receiver as WatchReceiver;
use tracing::*;

/// The distance to naturally justify a block
const NATURALLY_JUSTIFIED_DIST: u64 = 15;

pub struct VoteManager {
    pool: Arc<Mutex<VotePool>>,
    signer: VoteSigner,
    journal: VoteJournal,

    engine: Arc<dyn PoSA>,
    started: AtomicBool,
    node: Arc<Node>,
    chain_spec: ChainSpec,
    db: Arc<MdbxWithDirHandle<WriteMap>>,
    sync_stage: WatchReceiver<Option<StageId>>,
}

impl VoteManager {
    /// new, initial vote manager
    pub fn new(
        chain_spec: ChainSpec,
        engine: Arc<dyn PoSA>,
        pool: Arc<Mutex<VotePool>>,
        node: Arc<Node>,
        db: Arc<MdbxWithDirHandle<WriteMap>>,
        sync_stage: WatchReceiver<Option<StageId>>,
        prv_key: String,
        pub_key: String,
    ) -> anyhow::Result<Arc<Self>, DuoError> {
        let prv_key = BLSPrivateKey::from_slice(hex::decode(prv_key)?.as_slice());
        let pub_key = BLSPublicKey::from_slice(hex::decode(pub_key)?.as_slice());
        Ok(Arc::new(VoteManager {
            pool,
            signer: VoteSigner::new(prv_key, pub_key)?,
            journal: VoteJournal::new()?,
            engine,
            started: AtomicBool::from(false),
            node,
            chain_spec,
            db,
            sync_stage,
        }))
    }

    /// start, start main loop
    pub fn start(vm: Arc<VoteManager>) {
        if !vm.started.swap(true, Ordering::Release) {
            debug!("starting parlia vote manager...");
            tokio::spawn({
                let vm = Arc::clone(&vm);
                async move { vm.handle_new_header_loop().await }
            });
            tokio::spawn({
                let vm = Arc::clone(&vm);
                async move { vm.handle_new_vote_loop().await }
            });
        }
    }

    /// stop, stop the main loop
    pub fn stop(&self) {
        debug!("stop parlia vote manager...");
        self.started.store(false, Ordering::Release);
    }

    async fn handle_new_vote_loop(&self) {
        while self.started.load(Ordering::Acquire) {
            if let Err(err) = self.handle_new_vote().await {
                warn!("handle_new_vote err: {:?}", err);
            }
        }
    }

    async fn handle_new_vote(&self) -> anyhow::Result<(), DuoError> {
        let tx = self.db.begin()?;
        let mut stream = self.node.stream_votes().await;
        let msg = stream.next().await.ok_or(ParliaVoteError::CannotFetchMsg)?;
        if let Votes(votes) = msg.msg.clone() {
            for v in votes.votes {
                if let Err(err) = self.pool.lock().push_vote(&tx, v) {
                    warn!("handle_new_vote_loop push vote err: {:?}", err);
                }
            }
        }

        Ok(())
    }

    async fn handle_new_header_loop(&self) {
        let mut prev_status = Status {
            ..Default::default()
        };
        while self.started.load(Ordering::Acquire) {
            // received new header
            let current = *self.node.status.read();
            if prev_status != current {
                continue;
            }
            prev_status = current;
            match self.db.begin() {
                Ok(tx) => {
                    if let Err(err) = self.handle_new_header(&tx, current.height, current.hash) {
                        warn!("handle_new_header err: {:?}", err);
                    }
                }
                Err(err) => warn!("try got db tx err: {:?}", err),
            }
        }
    }

    fn handle_new_header(
        &self,
        reader: &dyn HeaderReader,
        number: BlockNumber,
        hash: H256,
    ) -> anyhow::Result<(), DuoError> {
        let header =
            reader
                .read_header(number, hash)?
                .ok_or(ParliaVoteError::UnknownLatestHeader {
                    msg: format!("got new head, but read none, block: {}:{:?}", number, hash),
                })?;

        if !self.chain_spec.is_boneh(&header.number) {
            return Ok(());
        }
        // clean vote pool
        self.pool.lock().clean_by_new_header(reader, &header)?;

        // TODO subscribe sync stage, if it's syncing skip
        if self.sync_stage.borrow().is_some() {
            return Ok(());
        }

        self.try_vote(reader, header)?;
        Ok(())
    }

    fn try_vote(
        &self,
        reader: &dyn HeaderReader,
        header: BlockHeader,
    ) -> anyhow::Result<(), DuoError> {
        let target_number = header.number;
        let target_hash = header.hash();
        if !self.engine.is_active_validator_at(reader, &header)? {
            return Err(ParliaVoteError::YouAreNotInValidators {
                target: target_number.0,
                hash: target_hash,
                validator: self.signer.addr(),
            }
            .into());
        }

        // try vote this block
        let (source_number, source_hash) = self.under_rules(reader, &header)?;
        let data = VoteData {
            source_number,
            source_hash,
            target_number,
            target_hash,
        };
        let new_vote = VoteEnvelope {
            vote_address: self.signer.addr(),
            signature: self.signer.sign(&data),
            data,
        };

        self.journal.write_vote(&new_vote)?;
        self.pool.lock().push_vote(reader, new_vote)?;
        Ok(())
    }

    /// under_rules checks if the produced header under the following rules:
    /// A validator must not publish two distinct votes for the same height. (Rule 1)
    /// A validator must not vote within the span of its other votes . (Rule 2)
    /// Validators always vote for their canonical chain’s latest block. (Rule 3)
    fn under_rules(
        &self,
        reader: &dyn HeaderReader,
        header: &BlockHeader,
    ) -> anyhow::Result<(BlockNumber, H256), DuoError> {
        let target_number = header.number.0;
        let target_hash = header.hash();

        //Rule 1:  A validator must not publish two distinct votes for the same height.
        if let Some(vote) = self.journal.get_vote(target_number) {
            return Err(ParliaVoteError::UnsatisfiedVoteRule {
                target: target_number,
                hash: target_hash,
                msg: format!("try vote the block, you just voted, prev vote: {:?}", vote),
            }
            .into());
        }
        let justified_header = self.engine.get_justified_header(reader, header)?;
        let (source_number, source_hash) = (justified_header.number.0, justified_header.hash());

        //Rule 2: A validator must not vote within the span of its other votes.
        for n in source_number + 1..target_number {
            if let Some(vote) = self.journal.get_vote(n) {
                if vote.data.source_number.0 > source_number {
                    return Err(ParliaVoteError::UnsatisfiedVoteRule {
                        target: target_number,
                        hash: target_hash,
                        msg: format!("try vote the block, span other votes, source: {}:{:?}, span vote: {:?}", source_number, source_hash, vote)
                    }.into());
                }
            }
        }

        for n in target_number..=target_number + NATURALLY_JUSTIFIED_DIST {
            if let Some(vote) = self.journal.get_vote(n) {
                if vote.data.source_number.0 < source_number {
                    return Err(ParliaVoteError::UnsatisfiedVoteRule {
                        target: target_number,
                        hash: target_hash,
                        msg: format!("try vote the block, other votes span, source: {}:{:?}, span vote: {:?}", source_number, source_hash, vote)
                    }.into());
                }
            }
        }

        // Rule 3: Validators always vote for their canonical chain’s latest block.
        // Since the header subscribed to is the canonical chain, so this rule is satisified by default.

        Ok((BlockNumber(source_number), source_hash))
    }
}
