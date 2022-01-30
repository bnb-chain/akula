use crate::{
    commitment::generic::*,
    consensus::ValidationError,
    kv::{mdbx::*, tables},
    models::*,
    stagedsync::{
        stage::{ExecOutput, Stage, StageError, StageInput, UnwindInput, UnwindOutput},
        stages::*,
    },
    StageId,
};
use anyhow::format_err;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use tracing::*;

const COMMITMENT_CHUNK: usize = 90_000;

#[derive(Debug)]
pub enum Change {
    Account(Address),
    Storage(Address, H256),
}

pub fn increment_commitment<'db, 'tx, E>(
    tx: &'tx MdbxTransaction<'db, RW, E>,
    from: Option<(BlockNumber, H256)>,
) -> anyhow::Result<H256>
where
    'db: 'tx,
    E: EnvironmentKind,
{
    let mut updates = HashMap::<Address, HashSet<H256>>::new();

    let previous_state_root = if let Some((from, previous_state_root)) = from {
        for change in tx.cursor(tables::AccountChangeSet)?.walk(Some(from + 1)) {
            updates.entry(change?.1.address).or_default();
        }

        for change in tx.cursor(tables::StorageChangeSet)?.walk(Some(from + 1)) {
            let change = change?;
            updates
                .entry(change.0.address)
                .or_default()
                .insert(change.1.location);
        }
        previous_state_root
    } else {
        for e in tx.cursor(tables::Account)?.walk(None) {
            updates.entry(e?.0).or_default();
        }

        for e in tx.cursor(tables::Storage)?.walk(None) {
            let (address, (location, _)) = e?;
            updates.entry(address).or_default().insert(location);
        }
        EMPTY_ROOT
    };

    println!("Changes since {from:?}: {updates:?}");

    fn compute_storage_root<'db: 'tx, 'tx, E>(
        tx: &'tx MdbxTransaction<'db, RW, E>,
        address: Address,
        locations: impl IntoIterator<Item = H256>,
    ) -> anyhow::Result<H256>
    where
        E: EnvironmentKind,
    {
        struct TxStateForStorage<'tx, 'db, K, E>
        where
            K: TransactionKind,
            E: EnvironmentKind,
            'db: 'tx,
        {
            tx: &'tx MdbxTransaction<'db, K, E>,
            address: Address,
        }

        impl<'tx, 'db, K, E> crate::commitment::generic::State<H256, U256>
            for TxStateForStorage<'tx, 'db, K, E>
        where
            K: TransactionKind,
            E: EnvironmentKind,
            'db: 'tx,
        {
            fn get_branch(&mut self, prefix: &[u8]) -> anyhow::Result<Option<BranchData<H256>>> {
                self.tx.get(
                    tables::StorageCommitment,
                    tables::StorageCommitmentKey {
                        address: self.address,
                        prefix: prefix.to_vec(),
                    },
                )
            }
            fn get_payload(&mut self, location: &H256) -> anyhow::Result<Option<U256>> {
                Ok(self
                    .tx
                    .cursor(tables::Storage)?
                    .seek_both_range(self.address, *location)?
                    .filter(|&(l, _)| l == *location)
                    .map(|(_, v)| v))
            }
        }

        let mut tx_state = TxStateForStorage { tx, address };

        let previous_storage_root = tx.get(tables::StorageRoot, address)?.unwrap_or(EMPTY_ROOT);
        let (storage_root, branch_updates) =
            HexPatriciaHashed::new(&mut tx_state, previous_storage_root)
                .process_updates(locations)?;
        for (branch_key, mut branch_update) in branch_updates {
            let branch_key = tables::StorageCommitmentKey {
                address,
                prefix: branch_key,
            };
            if branch_update.after_map.parts() > 0 {
                if let Some(old) = tx.get(tables::StorageCommitment, branch_key.clone())? {
                    branch_update = merge_hex_branches(old, branch_update)?;
                }
                tx.set(tables::StorageCommitment, branch_key, branch_update)?;
            } else {
                // println!("deleting {branch_update:?}");
                tx.del(tables::StorageCommitment, branch_key, None)?;
            }
        }
        if storage_root == EMPTY_ROOT {
            tx.del(tables::StorageRoot, address, None)?;
        } else {
            tx.set(tables::StorageRoot, address, storage_root)?;
        }

        Ok(storage_root)
    }

    let mut storage_roots = HashMap::new();
    for (address, locations) in updates {
        let entry = storage_roots.entry(address).or_insert(EMPTY_ROOT);
        if tx.get(tables::Account, address)?.is_some() {
            *entry = compute_storage_root(tx, address, locations)?;
        } else {
            let mut cur = tx.cursor(tables::StorageCommitment)?;
            while let Some((k, _)) = cur.seek(address)? {
                if k.address == address {
                    cur.delete_current()?;
                } else {
                    break;
                }
            }
            tx.del(tables::StorageRoot, address, None)?;
        }
    }

    struct TxStateWithStorageRoots<'tx, 'db, E>
    where
        E: EnvironmentKind,
        'db: 'tx,
    {
        tx: &'tx MdbxTransaction<'db, RW, E>,
        storage_roots: HashMap<Address, H256>,
    }

    impl<'tx, 'db, E> crate::commitment::generic::State<Address, RlpAccount>
        for TxStateWithStorageRoots<'tx, 'db, E>
    where
        E: EnvironmentKind,
        'db: 'tx,
    {
        fn get_branch(&mut self, prefix: &[u8]) -> anyhow::Result<Option<BranchData<Address>>> {
            self.tx.get(tables::AccountCommitment, prefix.to_vec())
        }
        fn get_payload(&mut self, address: &Address) -> anyhow::Result<Option<RlpAccount>> {
            let rlp_acc = if let Some(acc) = self.tx.get(tables::Account, *address)? {
                let storage_root = if let Some(v) = self.storage_roots.get(address).copied() {
                    v
                } else {
                    compute_storage_root(self.tx, *address, [])?
                };

                Some(acc.to_rlp(storage_root))
            } else {
                None
            };
            trace!("Loaded account {:?}: {:?}", address, rlp_acc);

            Ok(rlp_acc)
        }
    }

    let addresses = storage_roots.keys().copied().collect::<Vec<_>>();

    let mut tx_state = TxStateWithStorageRoots { tx, storage_roots };

    let (state_root, branch_updates) =
        HexPatriciaHashed::new(&mut tx_state, previous_state_root).process_updates(addresses)?;

    for (branch_key, mut branch_update) in branch_updates {
        if branch_update.after_map.parts() > 0 {
            if let Some(old) = tx.get(tables::AccountCommitment, branch_key.clone())? {
                branch_update = merge_hex_branches(old, branch_update)?;
            }
            tx.set(tables::AccountCommitment, branch_key, branch_update)?;
        } else {
            // println!("deleting {branch_update:?}");
            tx.del(tables::AccountCommitment, branch_key, None)?;
        }
    }

    Ok(state_root)
}

#[derive(Debug)]
pub struct Commitment;

#[async_trait]
impl<'db, E> Stage<'db, E> for Commitment
where
    E: EnvironmentKind,
{
    fn id(&self) -> StageId {
        COMMITMENT
    }

    async fn execute<'tx>(
        &mut self,
        tx: &'tx mut MdbxTransaction<'db, RW, E>,
        input: StageInput,
    ) -> Result<ExecOutput, StageError>
    where
        'db: 'tx,
    {
        let genesis = BlockNumber(0);
        let max_block = input
            .previous_stage
            .map(|tuple| tuple.1)
            .ok_or_else(|| format_err!("Cannot be first stage"))?;
        let from = input.stage_progress.unwrap_or(genesis);
        let previous_state_root = crate::accessors::chain::header::read_canonical(tx, from)?
            .ok_or_else(|| format_err!("no header"))?
            .state_root;

        let state_root = increment_commitment(tx, Some((from, previous_state_root)))?;

        let expected_root = crate::accessors::chain::header::read_canonical(tx, max_block)?
            .ok_or_else(|| format_err!("Block #{} not found", max_block))?
            .state_root;
        if expected_root != state_root {
            return Err(StageError::Validation {
                block: max_block,
                error: ValidationError::WrongStateRoot {
                    expected: expected_root,
                    got: state_root,
                },
            });
        }
        info!("State root OK: {:?}", state_root);

        Ok(ExecOutput::Progress {
            stage_progress: max_block,
            done: true,
            reached_tip: true,
        })
    }

    async fn unwind<'tx>(
        &mut self,
        tx: &'tx mut MdbxTransaction<'db, RW, E>,
        input: UnwindInput,
    ) -> anyhow::Result<UnwindOutput>
    where
        'db: 'tx,
    {
        let _ = tx;
        let _ = input;
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{keccak256, trie_root},
        h256_to_u256,
        kv::{
            new_mem_database,
            tables::{AccountChange, StorageChange, StorageChangeKey},
        },
        u256_to_h256, zeroless_view,
    };
    use bytes::BytesMut;
    use fastrlp::Encodable;
    use maplit::btreemap;
    use proptest::prelude::*;
    use std::collections::BTreeMap;
    use tracing_subscriber::{prelude::*, EnvFilter};

    // strategies
    fn addresses() -> impl Strategy<Value = Address> {
        any::<[u8; 20]>().prop_map(Address::from)
    }

    fn h256s() -> impl Strategy<Value = H256> {
        any::<[u8; 32]>().prop_map(H256::from)
    }

    fn u256s() -> impl Strategy<Value = U256> {
        any::<[u8; 32]>().prop_map(|v| h256_to_u256(H256::from(v)))
    }

    fn nonzero_u256s() -> impl Strategy<Value = U256> {
        u256s().prop_filter("value must not be zero", |&x| x != 0)
    }

    prop_compose! {
        fn accounts()(
            nonce in any::<u64>(),
            balance in u256s(),
            code_hash in h256s(),
        ) -> Account {
            Account { nonce, balance, code_hash }
        }
    }

    type Storage = BTreeMap<H256, U256>;

    fn account_storages() -> impl Strategy<Value = Storage> {
        prop::collection::btree_map(h256s(), nonzero_u256s(), 0..20)
    }

    prop_compose! {
        fn accounts_with_storage()(
            account in accounts(),
            storage in account_storages(),
        ) -> (Account, Storage) {
            (account, storage)
        }
    }

    type ChangingAccount = BTreeMap<u32, Option<(Account, Storage)>>;

    #[derive(Debug)]
    struct ChangingAccountsFixture {
        accounts: BTreeMap<Address, ChangingAccount>,
        before_increment: u32,
        after_increment: u32,
    }

    fn changing_accounts(max_height: u32) -> impl Strategy<Value = ChangingAccount> {
        prop::collection::btree_map(
            0..max_height,
            prop::option::of(accounts_with_storage()),
            1..3,
        )
        .prop_filter("does not contain changes", |x| {
            for v in x.values() {
                if v.is_some() {
                    return true;
                }
            }
            false
        })
    }

    prop_compose! {
        fn test_datas()(
            after_increment in 2u32..,
        )(
            before_increment in 0..after_increment - 2,
            after_increment in Just(after_increment),
            accounts in prop::collection::btree_map(
                addresses(),
                changing_accounts(after_increment - 1),
                0..100
            ),
        ) -> ChangingAccountsFixture {
            ChangingAccountsFixture {
                accounts,
                before_increment,
                after_increment,
            }
        }
    }

    // helper functions
    fn expected_storage_root(storage: &Storage) -> H256 {
        if storage.is_empty() {
            EMPTY_ROOT
        } else {
            trie_root(storage.iter().map(|(k, v)| {
                let mut b = BytesMut::new();
                Encodable::encode(&zeroless_view(&u256_to_h256(*v)), &mut b);
                (keccak256(k.to_fixed_bytes()), b)
            }))
        }
    }

    fn expected_state_root(accounts_with_storage: &BTreeMap<Address, (Account, Storage)>) -> H256 {
        trie_root(
            accounts_with_storage
                .iter()
                .map(|(&address, (account, storage))| {
                    let account_rlp = account.to_rlp(expected_storage_root(storage));
                    (keccak256(address), fastrlp::encode_fixed_size(&account_rlp))
                }),
        )
    }

    fn accounts_at_height(
        changing_accounts: &ChangingAccountsFixture,
        height: u32,
    ) -> BTreeMap<Address, (Account, Storage)> {
        let mut result = BTreeMap::new();
        for (address, state) in &changing_accounts.accounts {
            if let Some(account_with_storage) = changing_account_at_height(state, height) {
                result.insert(*address, account_with_storage.clone());
            }
        }
        result
    }

    fn populate_state<'db, 'tx, E>(
        tx: &'tx MdbxTransaction<'db, RW, E>,
        accounts_with_storage: BTreeMap<Address, (Account, Storage)>,
    ) -> anyhow::Result<()>
    where
        E: EnvironmentKind,
        'db: 'tx,
    {
        tx.clear_table(tables::Account)?;
        tx.clear_table(tables::Storage)?;

        let mut account_cursor = tx.cursor(tables::Account)?;
        let mut storage_cursor = tx.cursor(tables::Storage)?;

        for (address, (account, storage)) in accounts_with_storage {
            account_cursor.upsert(address, account)?;
            for (location, value) in storage {
                storage_cursor.upsert(address, (location, value))?
            }
        }

        Ok(())
    }

    fn populate_change_sets<'db, 'tx, E>(
        tx: &'tx MdbxTransaction<'db, RW, E>,
        changing_accounts: &BTreeMap<Address, ChangingAccount>,
    ) -> anyhow::Result<()>
    where
        E: EnvironmentKind,
        'db: 'tx,
    {
        tx.clear_table(tables::AccountChangeSet)?;
        tx.clear_table(tables::StorageChangeSet)?;

        let mut account_cursor = tx.cursor(tables::AccountChangeSet)?;
        let mut storage_cursor = tx.cursor(tables::StorageChangeSet)?;

        for (address, states) in changing_accounts {
            let mut previous: Option<&(Account, Storage)> = None;
            for (height, current) in states {
                let block_number = BlockNumber(*height as u64);
                if current.as_ref() != previous {
                    let previous_account = previous.as_ref().map(|(a, _)| *a);
                    let current_account = current.as_ref().map(|(a, _)| *a);
                    if current_account != previous_account {
                        account_cursor.upsert(
                            block_number,
                            AccountChange {
                                address: *address,
                                account: previous_account,
                            },
                        )?;
                    }
                    let empty_storage = Storage::new();
                    let previous_storage =
                        previous.as_ref().map(|(_, s)| s).unwrap_or(&empty_storage);
                    let current_storage =
                        current.as_ref().map(|(_, s)| s).unwrap_or(&empty_storage);
                    for (location, value) in previous_storage {
                        if current_storage.get(location).unwrap_or(&U256::ZERO) != value {
                            storage_cursor.upsert(
                                StorageChangeKey {
                                    block_number,
                                    address: *address,
                                },
                                StorageChange {
                                    location: *location,
                                    value: *value,
                                },
                            )?;
                        }
                    }
                    for location in current_storage.keys() {
                        if !previous_storage.contains_key(location) {
                            storage_cursor.upsert(
                                StorageChangeKey {
                                    block_number,
                                    address: *address,
                                },
                                StorageChange {
                                    location: *location,
                                    value: U256::ZERO,
                                },
                            )?;
                        }
                    }
                }
                previous = current.as_ref();
            }
        }

        Ok(())
    }

    fn changing_account_at_height(
        account: &ChangingAccount,
        height: u32,
    ) -> Option<&(Account, Storage)> {
        for (changed_at, state) in account.iter().rev() {
            if changed_at <= &height {
                return state.as_ref();
            }
        }
        None
    }

    // test
    fn do_trie_root_matches(test_data: ChangingAccountsFixture) {
        // println!("Testing {:?}", test_data);
        let db = new_mem_database().unwrap();

        let tx = db.begin_mutable().unwrap();
        let state_before_increment = accounts_at_height(&test_data, test_data.before_increment);
        let expected = expected_state_root(&state_before_increment);
        populate_state(&tx, state_before_increment).unwrap();
        tx.commit().unwrap();

        let tx = db.begin_mutable().unwrap();
        let root = increment_commitment(&tx, None).unwrap();
        tx.commit().unwrap();

        assert_eq!(root, expected);

        let tx = db.begin_mutable().unwrap();
        let state_after_increment = accounts_at_height(&test_data, test_data.after_increment);
        println!("State after increment: {state_after_increment:?}");
        let expected = expected_state_root(&state_after_increment);
        populate_state(&tx, state_after_increment).unwrap();
        populate_change_sets(&tx, &test_data.accounts).unwrap();
        tx.commit().unwrap();

        let tx = db.begin_mutable().unwrap();
        let root = increment_commitment(
            &tx,
            Some((BlockNumber(test_data.before_increment as u64), root)),
        )
        .unwrap();

        assert_eq!(root, expected);
    }

    proptest! {
        #[test]
        fn trie_root_matches(test_data in test_datas()) {
            do_trie_root_matches(test_data);
        }
    }

    #[test]
    fn simple_test() {
        do_trie_root_matches(ChangingAccountsFixture {
            accounts: btreemap! {
                "0x0000000000000000000000000000000004e9902f".parse().unwrap() => btreemap! {
                    25401498 => Some((
                        Account { nonce: 12290984943171145516, balance: "4748720256671620091126362205084857101385661332044029635729026024857354404727".parse().unwrap(), code_hash: "0xbf52cd0811840c178743c96b10d53b5fd665dfeba58b267b3e73217bae4cf9a7".parse().unwrap() },
                        btreemap!{
                            "0x06e0152c63f9c2dd1e1528b79d670f97d96f0cc603a5998721814ddf64329d23".parse().unwrap() => "80631644435090452564074685811861825445415271524508159156249589530193827769507".parse().unwrap(),
                            "0x15a97bea50efc5a4417d5612db8a75dcc6d77fa44ce83923f904cc505e63030a".parse().unwrap() => "44049044385114753595427640471769743457765742490020361638239702018276052982670".parse().unwrap(),
                            "0x1bfb677c3558b70d657dc4718f25c50e09b5e5917a636dd1893b69bd64b76033".parse().unwrap() => "36243419449551298517030967613872577000096160083821577963202974981450911669111".parse().unwrap(),
                            "0x2d2f078dea33bc19c4b6f46e7ec10eaa50f15a3aae099b8567767f4d05646e8c".parse().unwrap() => "63480809502500712317532671578860036427195628783534105026717601656586505860601".parse().unwrap(),
                            "0x6cea278611cab554e89d120d1af3fe5ab9e0a23fbe030773a63ef93991208d01".parse().unwrap() => "96786030165151146952439948321324804407128198318321959693466739486476873608854".parse().unwrap(),
                            "0xe4dc78e46fc9616e82b84226ea352e9b244027af9830ff4e6027cae2de688027".parse().unwrap() => "104124842345976401507912928723003672725573184803060977968906628833003383234826".parse().unwrap()
                        }
                    ))
                }
            },
            before_increment: 25401497,
            after_increment: 1653339461,
        })
    }

    fn setup() {
        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_target(false))
            .with(EnvFilter::from_default_env())
            .try_init();
    }

    #[test]
    fn simple_test_2() {
        setup();

        do_trie_root_matches(ChangingAccountsFixture {
            accounts: btreemap! {
                "0x0000000000000000000000000000000004e9902f".parse().unwrap() => btreemap! {
                    0 => Some((
                        Account { nonce: 12290984943171145516, balance: "4748720256671620091126362205084857101385661332044029635729026024857354404727".parse().unwrap(), code_hash: "0xbf52cd0811840c178743c96b10d53b5fd665dfeba58b267b3e73217bae4cf9a7".parse().unwrap() },
                        btreemap!{
                            "0x06e0152c63f9c2dd1e1528b79d670f97d96f0cc603a5998721814ddf64329d23".parse().unwrap() => "80631644435090452564074685811861825445415271524508159156249589530193827769507".parse().unwrap(),
                            "0x15a97bea50efc5a4417d5612db8a75dcc6d77fa44ce83923f904cc505e63030a".parse().unwrap() => "44049044385114753595427640471769743457765742490020361638239702018276052982670".parse().unwrap(),
                            "0x1bfb677c3558b70d657dc4718f25c50e09b5e5917a636dd1893b69bd64b76033".parse().unwrap() => "36243419449551298517030967613872577000096160083821577963202974981450911669111".parse().unwrap(),
                            "0x2d2f078dea33bc19c4b6f46e7ec10eaa50f15a3aae099b8567767f4d05646e8c".parse().unwrap() => "63480809502500712317532671578860036427195628783534105026717601656586505860601".parse().unwrap(),
                            "0x6cea278611cab554e89d120d1af3fe5ab9e0a23fbe030773a63ef93991208d01".parse().unwrap() => "96786030165151146952439948321324804407128198318321959693466739486476873608854".parse().unwrap(),
                            "0xe4dc78e46fc9616e82b84226ea352e9b244027af9830ff4e6027cae2de688027".parse().unwrap() => "104124842345976401507912928723003672725573184803060977968906628833003383234826".parse().unwrap()
                        }
                    ))
                }
            },
            before_increment: 25401497,
            after_increment: 1653339461,
        })
    }

    #[test]
    fn simple_test_3() {
        setup();

        do_trie_root_matches(ChangingAccountsFixture {
            accounts: btreemap! {
                "0x0000000000000000000000000000000004e9902f".parse().unwrap() => btreemap! {
                    0 => Some((
                        Account { nonce: 12290984943171145516, balance: "4748720256671620091126362205084857101385661332044029635729026024857354404727".parse().unwrap(), code_hash: "0xbf52cd0811840c178743c96b10d53b5fd665dfeba58b267b3e73217bae4cf9a7".parse().unwrap() },
                        btreemap!{}
                    ))
                }
            },
            before_increment: 25401497,
            after_increment: 1653339461,
        })
    }

    #[test]
    fn simple_test_4() {
        setup();

        do_trie_root_matches(ChangingAccountsFixture {
            accounts: btreemap! {
                "0x0000000000000000000000000000000000000000".parse().unwrap() => btreemap! {
                    0 => Some((
                        Account {
                            nonce: 0,
                            balance: "42".parse().unwrap(),
                            code_hash: EMPTY_HASH
                        },
                        btreemap!{},
                    ))
                },
                "0x0000000000000000000000000000000000000001".parse().unwrap() => btreemap! {
                    78332232 => Some((
                        Account {
                            nonce: 0,
                            balance: "42".parse().unwrap(),
                            code_hash: EMPTY_HASH
                        },
                        btreemap! {
                            // "0x028f056e0c12883ea8c79ce96df8a5fe1b3fb7a6f2d84763f1da5714d7641652".parse().unwrap() => "31106956167458871518259740820951850741785080860957391947844023071475806179750".parse().unwrap(), "0x0f9a0d3f2481c0b2f50a3fdcf1e667a47c5e53e47481bd29bd4ba6f4a62945f4".parse().unwrap() => "105354393189730074343867361887780795213312447953523014431762519473802778420227".parse().unwrap(), "0x0ffd67da66084e7494f1a422182a9ba08578a616db3fcd46b7e964cd680e6553".parse().unwrap() => "70229646618745260699318759463684799715124691577359130575820516112267362631785".parse().unwrap(), "0x66488b4955ea69ec397db69ed1f55514e7c74114d6688f7e8313fef01b20bc13".parse().unwrap() => "5260728441387294176927004555155131668877320224365156843966798302808175699120".parse().unwrap(), "0x73b5141afbb6d17b17a174f8770610a77af16d54a5b4467bf62f7abddb7e808f".parse().unwrap() => "58701713524010163786682558569066831123871757307278031086490604723441600373720".parse().unwrap(), "0xd8c662128341603c6dcfd2456d118e22b6fa474379d500f8dc4a86593be0a500".parse().unwrap() => "79344913227127318719597743996889137058221752234090511014997520857830349324302".parse().unwrap(), "0xf5a12a17b1bbb5f034b0e1b9680798ce311c8479200ff97d857be66fcf9d688a".parse().unwrap() => "81089698139785272563395308224588585453140544712968268521580443196978929113214".parse().unwrap(), "0xffdd4ec1e4dfaa9c5b8ad0d26b426113ff4a46c459b5a5f3d811decbe0441c70".parse().unwrap() => "7493069887994518256658602831598540368141959778266966349574306832585649955052".parse().unwrap()
                        },
                    ))
                }
            },
            before_increment: 78332231,
            after_increment: 2737898589,
        })
    }
}
