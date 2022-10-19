use super::*;
use hashlink::LruCache;
use parking_lot::Mutex;
use std::sync::Arc;

const MAX_CACHE_RECENT_SIZE: usize = 512;

pub struct VoteJournal {
    buffer: Mutex<LruCache<u64, VoteEnvelope>>,
}

impl VoteJournal {
    /// new, initial VoteJournal and cache
    pub fn new() -> anyhow::Result<Self, DuoError> {
        Ok(VoteJournal {
            buffer: Mutex::new(LruCache::new(MAX_CACHE_RECENT_SIZE)),
        })
    }

    /// write_vote, write cache and TODO write WAL
    pub fn write_vote(&self, vote: &VoteEnvelope) -> anyhow::Result<(), DuoError> {
        let mut buffer = self.buffer.lock();
        buffer.insert(vote.data.target_number.0, vote.clone());

        Ok(())
    }

    /// get_vote, read from cache
    pub fn get_vote(&self, block_number: u64) -> Option<VoteEnvelope> {
        let mut buffer = self.buffer.lock();
        match buffer.get(&block_number) {
            None => None,
            Some(v) => Some(v.clone()),
        }
    }
}
