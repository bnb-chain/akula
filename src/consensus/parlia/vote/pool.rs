use super::*;
use crate::{
    consensus::{DuoError, ParliaError, PoSA},
    models::{BlockHeader, BlockNumber, H256},
    p2p::node::Node,
    HeaderReader,
};
use hashbrown::{HashMap, HashSet};
use parking_lot::Mutex;
use std::{cmp::Ordering, collections::BinaryHeap, sync::Arc};
use tracing::debug;

/// limit max current vote amount per block
const MAX_CUR_VOTE_AMOUNT_PER_BLOCK: usize = 21;
/// limit max future vote amount per block
const MAX_FUTURE_VOTE_AMOUNT_PER_BLOCK: usize = 50;
/// vote cache init buffer size
const VOTE_BUFFER: usize = 256;
/// limit lower vote block number
const LOWER_LIMIT_VOTE_BLOCK_NUMBER: u64 = 256;
/// limit upper vote block number
const UPPER_LIMIT_VOTE_BLOCK_NUMBER: u64 = 11;

#[derive(Clone, Debug)]
pub struct VoteBoxInfo(u64, H256);

impl Eq for VoteBoxInfo {}

impl PartialEq<Self> for VoteBoxInfo {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

impl PartialOrd<Self> for VoteBoxInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VoteBoxInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(&other.0, &self.0)
    }
}

/// VoteBox, collect same height & hash block's votes from validators.
#[derive(Clone, Debug)]
pub struct VoteBox {
    block_number: BlockNumber,
    block_hash: H256,
    votes: Vec<VoteEnvelope>,
}

/// VotePool, maintain all received votes
#[derive(Debug)]
pub struct VotePool {
    latest_header: Option<BlockHeader>,

    cur_votes: HashMap<H256, VoteBox>,
    cur_votes_queue: BinaryHeap<VoteBoxInfo>,

    future_votes: HashMap<H256, VoteBox>,
    future_votes_queue: BinaryHeap<VoteBoxInfo>,

    received_vote_set: HashSet<H256>,
    engine: Option<Arc<dyn PoSA>>,
    node: Arc<Node>,
}

impl VotePool {
    pub fn new(engine: Option<Arc<dyn PoSA>>, node: Arc<Node>) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(VotePool {
            latest_header: None,
            cur_votes: Default::default(),
            future_votes: Default::default(),
            cur_votes_queue: BinaryHeap::new(),
            future_votes_queue: BinaryHeap::new(),
            received_vote_set: Default::default(),
            engine,
            node,
        }))
    }

    /// get_votes, get all current votes from pool.
    pub fn get_votes(&self) -> Vec<&VoteEnvelope> {
        let mut total = Vec::with_capacity(self.cur_votes.len() * MAX_CUR_VOTE_AMOUNT_PER_BLOCK);
        for vb in self.cur_votes.values() {
            total.extend(vb.votes.iter());
        }
        total
    }

    /// set_engine, refill vote pool's engine.
    pub fn set_engine(&mut self, engine: Arc<dyn PoSA>) {
        self.engine = Some(engine);
    }

    /// get_vote_by_block_hash, get target block votes from pool.
    pub fn get_vote_by_block_hash(&self, block_hash: H256) -> Option<Vec<&VoteEnvelope>> {
        match self.cur_votes.get(&block_hash) {
            None => None,
            Some(vb) => Some(vb.votes.iter().collect()),
        }
    }

    /// push_vote, when you received a new vote, try push into pool.
    pub fn push_vote(
        &mut self,
        reader: &dyn HeaderReader,
        vote: VoteEnvelope,
    ) -> anyhow::Result<(), DuoError> {
        let header = self
            .latest_header
            .as_ref()
            .ok_or(ParliaVoteError::UnknownLatestHeader {
                msg: format!("push_vote got none latest header!"),
            })?;

        let latest_number = header.number.0;
        let target_number = vote.data.target_number.0;
        // only accept votes with range (latest_number-LOWER_LIMIT_VOTE_BLOCK_NUMBER)~(latest_number+UPPER_LIMIT_VOTE_BLOCK_NUMBER)
        if target_number + LOWER_LIMIT_VOTE_BLOCK_NUMBER - 1 < latest_number
            || target_number > latest_number + UPPER_LIMIT_VOTE_BLOCK_NUMBER
        {
            return Err(ParliaVoteError::ExceedAllowedVoteRange {
                target: target_number,
                latest: latest_number,
            }
            .into());
        }

        let target_hash = vote.data.target_hash;
        let target_block = reader.read_header(BlockNumber(target_number), target_hash)?;
        let is_future_vote: bool = target_block.is_none();

        let (vote_cache, max_cap) = if !is_future_vote {
            (&self.cur_votes, MAX_CUR_VOTE_AMOUNT_PER_BLOCK)
        } else {
            (&self.future_votes, MAX_FUTURE_VOTE_AMOUNT_PER_BLOCK)
        };
        self.basic_verify_vote(&vote, vote_cache, max_cap)?;

        let (vote_q, vote_cache) = if !is_future_vote {
            (&mut self.cur_votes_queue, &mut self.cur_votes)
        } else {
            (&mut self.future_votes_queue, &mut self.future_votes)
        };

        // verify vote in current votes
        if !is_future_vote {
            self.engine
                .as_ref()
                .ok_or(ParliaVoteError::UnknownPoSA)?
                .verify_vote(reader, &vote)?;
            // Send vote for handler usage of broadcasting to peers.
            tokio::spawn({
                let v = vote.clone();
                let node = Arc::clone(&self.node);
                async move {
                    node.send_new_vote(v).await;
                }
            });
        }

        match vote_cache.get_mut(&target_hash) {
            None => {
                vote_q.push(VoteBoxInfo(target_number, target_hash));
                let mut vb = VoteBox {
                    block_number: vote.data.target_number,
                    block_hash: target_hash,
                    votes: Vec::with_capacity(max_cap),
                };
                vb.votes.push(vote);
                vote_cache.insert(target_hash, vb);
            }
            Some(vb) => {
                vb.votes.push(vote);
            }
        }
        Ok(())
    }

    /// clean_by_new_header, when new header arrived, clean useless cur votes, and transfer future votes to cur.
    pub fn clean_by_new_header(
        &mut self,
        reader: &dyn HeaderReader,
        header: &BlockHeader,
    ) -> anyhow::Result<(), DuoError> {
        self.latest_header = Some(header.clone());
        self.prune_cur_votes(header.number.0);
        self.prepare_cur_votes(reader, header)?;

        Ok(())
    }

    /// prepare_cur_votes, redistribute future votes to current votes.
    fn prepare_cur_votes(
        &mut self,
        reader: &dyn HeaderReader,
        latest_block: &BlockHeader,
    ) -> anyhow::Result<(), DuoError> {
        // handle before (latest_block - UPPER_LIMIT_VOTE_BLOCK_NUMBER) votes
        while let Some(info) = self.future_votes_queue.peek() {
            let VoteBoxInfo(block_number, block_hash) = *info;
            if block_number + UPPER_LIMIT_VOTE_BLOCK_NUMBER >= latest_block.number.0 {
                break;
            }
            self.future_votes_queue.pop();

            if let Some(vb) = self.future_votes.remove(&block_hash) {
                self.push_vote_box_to_cur(reader, vb)?;
            }
        }

        // handle after (latest_block - UPPER_LIMIT_VOTE_BLOCK_NUMBER) votes, find valid vote
        let mut tmp_future = Vec::new();
        while let Some(info) = self.future_votes_queue.peek() {
            let VoteBoxInfo(block_number, block_hash) = *info;
            if block_number > latest_block.number.0 {
                break;
            }
            self.future_votes_queue.pop();
            // only transfer the the vote in the local fork.
            let vote_block = reader.read_header(BlockNumber(block_number), block_hash)?;
            if vote_block.is_none() {
                tmp_future.push(VoteBoxInfo(block_number, block_hash));
                continue;
            }

            if let Some(vb) = self.future_votes.remove(&block_hash) {
                self.push_vote_box_to_cur(reader, vb)?;
            }
        }

        for v in tmp_future.into_iter() {
            self.future_votes_queue.push(v);
        }

        Ok(())
    }

    // prune_cur, clean the useless cached current votes in pool.
    fn prune_cur_votes(&mut self, latest_number: u64) {
        let cur_queue = &mut self.cur_votes_queue;

        while let Some(info) = cur_queue.peek() {
            let VoteBoxInfo(block_number, block_hash) = *info;
            if block_number + LOWER_LIMIT_VOTE_BLOCK_NUMBER - 1 >= latest_number {
                break;
            }
            cur_queue.pop();

            // continue clean cur_votes and received_vote_set
            if let Some(vb) = self.cur_votes.remove(&block_hash) {
                for vote in vb.votes.iter() {
                    // clean votes received flags.
                    self.received_vote_set.remove(&vote.hash());
                }
            }
        }
    }

    fn push_vote_box_to_cur(
        &mut self,
        reader: &dyn HeaderReader,
        mut vote_box: VoteBox,
    ) -> anyhow::Result<(), DuoError> {
        let mut valid_votes = Vec::with_capacity(vote_box.votes.len());
        for ve in vote_box.votes {
            // if not valid vote, just skip
            if let Err(err) = self
                .engine
                .as_ref()
                .ok_or(ParliaVoteError::UnknownPoSA)?
                .verify_vote(reader, &ve)
            {
                debug!("vote pool verify_vote err: {:?}, vote: {:?}", err, ve);
                continue;
            }

            // Send vote for handler usage of broadcasting to peers.
            tokio::spawn({
                let v = ve.clone();
                let node = Arc::clone(&self.node);
                async move {
                    node.send_new_vote(v).await;
                }
            });
            valid_votes.push(ve);
        }
        vote_box.votes = valid_votes;

        let block_hash = vote_box.block_hash;
        match self.cur_votes.get_mut(&block_hash) {
            None => {
                self.cur_votes_queue
                    .push(VoteBoxInfo(vote_box.block_number.0, block_hash));
                self.cur_votes.insert(block_hash, vote_box);
            }
            Some(vb) => {
                vb.votes.extend(vote_box.votes.into_iter());
            }
        }

        Ok(())
    }

    /// basic_verify_vote
    /// 1.check if duplicated vote in cache
    /// 2.check vote's signature if valid
    /// 3.check cur_votes and future_votes cap prevent DOS attack
    fn basic_verify_vote(
        &self,
        vote: &VoteEnvelope,
        vote_cache: &HashMap<H256, VoteBox>,
        max_cap: usize,
    ) -> anyhow::Result<(), DuoError> {
        let target_hash = vote.data.target_hash;

        if self.received_vote_set.get(&target_hash).is_some() {
            return Err(ParliaVoteError::ReceivedDupVote {
                target: vote.data.target_number.0,
                hash: target_hash,
                validator: vote.vote_address,
            }
            .into());
        }

        if let Some(vb) = vote_cache.get(&target_hash) {
            if vb.votes.len() > max_cap {
                return Err(ParliaVoteError::ExceedVotesCap { cap: max_cap }.into());
            }
        }

        vote.verify()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vote_box_info_order() {
        let mut heap: BinaryHeap<VoteBoxInfo> = BinaryHeap::new();

        heap.push(VoteBoxInfo(1, H256::zero()));
        heap.push(VoteBoxInfo(2, H256::zero()));
        heap.push(VoteBoxInfo(10, H256::zero()));

        assert_eq!(VoteBoxInfo(1, H256::zero()), *heap.peek().unwrap());
        assert_eq!(VoteBoxInfo(1, H256::zero()), heap.pop().unwrap());
        assert_eq!(VoteBoxInfo(2, H256::zero()), heap.pop().unwrap());
        assert_eq!(VoteBoxInfo(10, H256::zero()), heap.pop().unwrap());
        assert_eq!(true, heap.peek().is_none());
    }
}
