use super::helpers;
use crate::{
    execution::{
        analysis_cache::AnalysisCache, processor::execute_transaction, tracer::adhoc::AdhocTracer,
    },
    kv::{mdbx::*, tables, MdbxWithDirHandle},
    models::*,
    u256_to_h256, Buffer, HeaderReader, IntraBlockState, StateReader, StateWriter,
};
use anyhow::format_err;
use async_trait::async_trait;
use bytes::Bytes;
use ethereum_jsonrpc::{types, TraceApiServer};
use jsonrpsee::core::{Error as RpcError, RpcResult};
use std::{collections::HashSet, sync::Arc};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateUpdate {
    EraseStorage(Address),
    Storage {
        address: Address,
        location: U256,
        initial: U256,
        current: U256,
    },
    Account {
        address: Address,
        initial: Option<Account>,
        current: Option<Account>,
    },
    Code {
        code_hash: H256,
        code: Bytes,
    },
}

#[derive(Debug)]
struct LoggingBuffer<'buffer, 'db, 'tx, K, E>
where
    'db: 'tx,
    'db: 'buffer,
    'tx: 'buffer,
    K: TransactionKind,
    E: EnvironmentKind,
{
    inner: &'buffer mut Buffer<'db, 'tx, K, E>,
    updates: Vec<StateUpdate>,
}

impl<'buffer, 'db, 'tx, K, E> LoggingBuffer<'buffer, 'db, 'tx, K, E>
where
    'db: 'tx,
    'db: 'buffer,
    'tx: 'buffer,
    K: TransactionKind,
    E: EnvironmentKind,
{
    pub fn new(buffer: &'buffer mut Buffer<'db, 'tx, K, E>) -> Self {
        Self {
            inner: buffer,
            updates: Vec::new(),
        }
    }

    pub fn into_updates(self) -> Vec<StateUpdate> {
        self.updates
    }
}

impl<'buffer, 'db, 'tx, K, E> HeaderReader for LoggingBuffer<'buffer, 'db, 'tx, K, E>
where
    'db: 'tx,
    'db: 'buffer,
    'tx: 'buffer,
    K: TransactionKind,
    E: EnvironmentKind,
{
    fn read_header(
        &self,
        block_number: BlockNumber,
        block_hash: H256,
    ) -> anyhow::Result<Option<BlockHeader>> {
        self.inner.read_header(block_number, block_hash)
    }
}

impl<'buffer, 'db, 'tx, K, E> StateReader for LoggingBuffer<'buffer, 'db, 'tx, K, E>
where
    'db: 'tx,
    'db: 'buffer,
    'tx: 'buffer,
    K: TransactionKind,
    E: EnvironmentKind,
{
    fn read_account(&self, address: Address) -> anyhow::Result<Option<Account>> {
        self.inner.read_account(address)
    }

    fn read_code(&self, code_hash: H256) -> anyhow::Result<Bytes> {
        self.inner.read_code(code_hash)
    }

    fn read_storage(&self, address: Address, location: U256) -> anyhow::Result<U256> {
        self.inner.read_storage(address, location)
    }
}

impl<'buffer, 'db, 'tx, K, E> StateWriter for LoggingBuffer<'buffer, 'db, 'tx, K, E>
where
    'db: 'tx,
    'db: 'buffer,
    'tx: 'buffer,
    K: TransactionKind,
    E: EnvironmentKind,
{
    fn erase_storage(&mut self, address: Address) -> anyhow::Result<()> {
        self.updates.push(StateUpdate::EraseStorage(address));
        self.inner.erase_storage(address)
    }

    fn begin_block(&mut self, block_number: BlockNumber) {
        self.inner.begin_block(block_number)
    }

    fn update_account(
        &mut self,
        address: Address,
        initial: Option<Account>,
        current: Option<Account>,
    ) {
        self.updates.push(StateUpdate::Account {
            address,
            initial,
            current,
        });
        self.inner.update_account(address, initial, current)
    }

    fn update_code(&mut self, code_hash: H256, code: Bytes) -> anyhow::Result<()> {
        self.updates.push(StateUpdate::Code {
            code_hash,
            code: code.clone(),
        });
        self.inner.update_code(code_hash, code)
    }

    fn update_storage(
        &mut self,
        address: Address,
        location: U256,
        initial: U256,
        current: U256,
    ) -> anyhow::Result<()> {
        self.updates.push(StateUpdate::Storage {
            address,
            location,
            initial,
            current,
        });
        self.inner
            .update_storage(address, location, initial, current)
    }
}

pub struct TraceApiServerImpl<SE>
where
    SE: EnvironmentKind,
{
    pub db: Arc<MdbxWithDirHandle<SE>>,
    pub call_gas_limit: u64,
}

fn do_call_many<K, E>(
    txn: &MdbxTransaction<'_, K, E>,
    header: &PartialHeader,
    historical: bool,
    calls: Vec<(Address, Message, HashSet<types::TraceType>)>,
) -> anyhow::Result<Vec<types::BlockTrace>>
where
    K: TransactionKind,
    E: EnvironmentKind,
{
    let mut traces = Vec::with_capacity(calls.len());

    let block_number = header.number;

    let chain_spec = txn
        .get(tables::Config, ())?
        .ok_or_else(|| format_err!("chain spec not found"))?;

    let mut analysis_cache = AnalysisCache::default();
    let block_spec = chain_spec.collect_block_spec(block_number);

    // TODO: borrowck wtf
    let mut buffer = Buffer::new(txn, if historical { Some(block_number) } else { None });
    for (sender, message, trace_types) in calls {
        let (output, updates, trace) = {
            let mut buffer = LoggingBuffer::new(&mut buffer);
            let mut state = IntraBlockState::new(&mut buffer);

            let mut tracer = AdhocTracer::new(trace_types.contains(&types::TraceType::Trace));

            let mut gas_used = 0;
            let (output, _) = execute_transaction(
                &mut state,
                &block_spec,
                header,
                &mut tracer,
                &mut analysis_cache,
                &mut gas_used,
                &message,
                sender,
            )?;

            state.write_to_state_same_block()?;
            (output, buffer.into_updates(), tracer.into_trace())
        };

        let mut state_diff = if trace_types.contains(&types::TraceType::StateDiff) {
            Some(types::StateDiff(Default::default()))
        } else {
            None
        };

        if let Some(types::StateDiff(state_diff)) = state_diff.as_mut() {
            for update in updates {
                match &update {
                    StateUpdate::Storage {
                        address,
                        location,
                        initial,
                        current,
                    } => {
                        if initial != current {
                            state_diff.entry(*address).or_default().storage.insert(
                                u256_to_h256(*location),
                                if *initial > 0 {
                                    types::Delta::Altered(types::AlteredType {
                                        from: u256_to_h256(*initial),
                                        to: u256_to_h256(*current),
                                    })
                                } else {
                                    types::Delta::Added(u256_to_h256(*current))
                                },
                            );
                        }
                    }
                    StateUpdate::Account {
                        address,
                        initial,
                        current,
                    } => {
                        if *initial != *current {
                            match (initial, current) {
                                (None, Some(account)) => {
                                    let diff = state_diff.entry(*address).or_insert_with(|| {
                                        types::AccountDiff {
                                            balance: types::Delta::Unchanged,
                                            nonce: types::Delta::Unchanged,
                                            code: types::Delta::Unchanged,
                                            storage: Default::default(),
                                        }
                                    });
                                    diff.balance = types::Delta::Added(account.balance);
                                    diff.nonce = types::Delta::Added(account.nonce.as_u256());
                                    diff.code = types::Delta::Added(
                                        buffer.read_code(account.code_hash)?.into(),
                                    );
                                }
                                (Some(initial), None) => {
                                    let diff = state_diff.entry(*address).or_default();
                                    diff.balance = types::Delta::Removed(initial.balance);
                                    diff.nonce = types::Delta::Removed(initial.nonce.as_u256());
                                    diff.code = types::Delta::Removed(
                                        buffer.read_code(initial.code_hash)?.into(),
                                    );
                                }
                                (Some(initial), Some(current)) => {
                                    let diff = state_diff.entry(*address).or_default();

                                    fn make_delta<T: PartialEq>(from: T, to: T) -> types::Delta<T> {
                                        if from == to {
                                            types::Delta::Unchanged
                                        } else {
                                            types::Delta::Altered(types::AlteredType { from, to })
                                        }
                                    }
                                    diff.balance = make_delta(initial.balance, current.balance);
                                    diff.nonce = make_delta(
                                        initial.nonce.as_u256(),
                                        current.nonce.as_u256(),
                                    );
                                    diff.code = make_delta(
                                        buffer.read_code(initial.code_hash)?.into(),
                                        buffer.read_code(current.code_hash)?.into(),
                                    );
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        traces.push(types::BlockTrace {
            output: output.into(),
            trace,
            // todo
            vm_trace: None,
            state_diff,
            transaction_hash: None,
        })
    }

    Ok(traces)
}

#[async_trait]
impl<DB> TraceApiServer for TraceApiServerImpl<DB>
where
    DB: EnvironmentKind,
{
    async fn call(
        &self,
        call: types::MessageCall,
        trace_type: HashSet<types::TraceType>,
        block_number: Option<types::BlockNumber>,
    ) -> RpcResult<types::BlockTrace> {
        Ok(self
            .call_many(vec![(call, trace_type)], block_number)
            .await?
            .remove(0))
    }

    async fn call_many(
        &self,
        calls: Vec<(types::MessageCall, HashSet<types::TraceType>)>,
        b: Option<types::BlockNumber>,
    ) -> RpcResult<Vec<types::BlockTrace>> {
        let db = self.db.clone();
        let call_gas_limit = self.call_gas_limit;

        tokio::task::spawn_blocking(move || {
            let txn = db.begin()?;

            let (block_number, block_hash) =
                helpers::resolve_block_id(&txn, b.unwrap_or(types::BlockNumber::Latest))?
                    .ok_or_else(|| format_err!("failed to resolve block {b:?}"))?;
            let historical = matches!(
                b.unwrap_or(types::BlockNumber::Latest),
                types::BlockNumber::Latest
            );

            let chain_id = txn
                .get(tables::Config, ())?
                .ok_or_else(|| format_err!("chain spec not found"))?
                .params
                .chain_id;

            let header = crate::accessors::chain::header::read(&txn, block_hash, block_number)?
                .ok_or_else(|| format_err!("header not found"))?
                .into();

            let msgs = calls
                .into_iter()
                .map(|(call, trace_types)| {
                    let (sender, message) = helpers::convert_message_call(
                        &Buffer::new(&txn, if historical { Some(block_number) } else { None }),
                        chain_id,
                        call,
                        &header,
                        U256::ZERO,
                        Some(call_gas_limit),
                    )?;
                    Ok((sender, message, trace_types))
                })
                .collect::<anyhow::Result<_>>()?;

            Ok(do_call_many(&txn, &header, historical, msgs)?)
        })
        .await
        .unwrap_or_else(|e| Err(RpcError::Custom(format!("{e}"))))
    }

    async fn raw_transaction(
        &self,
        rlp: types::Bytes,
        trace_type: HashSet<types::TraceType>,
    ) -> RpcResult<types::BlockTrace> {
        let _ = rlp;
        let _ = trace_type;

        Err(RpcError::Custom("not implemented".to_string()))
    }

    async fn replay_block_transactions(
        &self,
        block_number: types::BlockNumber,
        trace_type: HashSet<types::TraceType>,
    ) -> RpcResult<Vec<types::BlockTrace>> {
        let _ = block_number;
        let _ = trace_type;

        Err(RpcError::Custom("not implemented".to_string()))
    }

    async fn replay_transaction(
        &self,
        hash: H256,
        trace_type: HashSet<types::TraceType>,
    ) -> RpcResult<types::BlockTrace> {
        let _ = hash;
        let _ = trace_type;

        Err(RpcError::Custom("not implemented".to_string()))
    }

    async fn block(&self, block_number: types::BlockNumber) -> RpcResult<Vec<types::BlockTrace>> {
        let _ = block_number;

        Err(RpcError::Custom("not implemented".to_string()))
    }

    async fn filter(
        &self,
        from_block: Option<types::BlockNumber>,
        to_block: Option<types::BlockNumber>,
        from_address: Option<HashSet<Address>>,
        to_address: Option<HashSet<Address>>,
    ) -> RpcResult<Vec<types::BlockTrace>> {
        let _ = from_block;
        let _ = to_block;
        let _ = from_address;
        let _ = to_address;

        Err(RpcError::Custom("not implemented".to_string()))
    }
}
