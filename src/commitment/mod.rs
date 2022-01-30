pub mod generic;
pub mod rlputil;

use self::rlputil::*;
use crate::{crypto::keccak256, models::*, prefix_length, u256_to_h256, zeroless_view};
use anyhow::{bail, ensure, format_err, Context};
use arrayref::array_ref;
use arrayvec::ArrayVec;
use bytes::BufMut;
use sha3::{Digest, Keccak256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{Debug, Display},
};
use tracing::*;

fn uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut x = 0;
    let mut s = 0;
    for (i, b) in buf.iter().copied().enumerate() {
        if i == 10 {
            return None;
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return None;
            }
            return Some(((x | b << s).into(), i + 1));
        }
        x |= (b & 0x7f) << s as u64;
        s += 7;
    }
    Some((0, 0))
}

fn encode_uvarint(out: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        out.push(x as u8 | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
}

fn encode_slice(out: &mut Vec<u8>, s: &[u8]) {
    encode_uvarint(out, s.len() as u64);
    out.extend_from_slice(s);
}

#[derive(Clone, Debug)]
pub struct Cell {
    h: Option<H256>,              // Cell hash
    apk: Option<Address>,         // account plain key
    spk: Option<(Address, H256)>, // storage plain key
    down_hashed_key: ArrayVec<u8, 128>,
    extension: ArrayVec<u8, 64>,
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: H256, // hash of the bytecode
    pub storage: Option<U256>,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            h: None,
            apk: None,
            spk: None,
            down_hashed_key: Default::default(),
            extension: Default::default(),
            nonce: Default::default(),
            balance: Default::default(),
            code_hash: EMPTY_HASH,
            storage: Default::default(),
        }
    }
}

impl Cell {
    fn compute_hash_len(&self, depth: usize) -> usize {
        if self.spk.is_some() && depth >= 64 {
            let key_len = 128 - depth + 1; // Length of hex key with terminator character
            let compact_len = (key_len - 1) / 2 + 1;
            let (kp, kl) = if compact_len > 1 {
                (1, compact_len)
            } else {
                (0, 1)
            };
            let storage_val = self.storage.map(u256_to_h256).unwrap_or_default();
            let val = RlpSerializableBytes(zeroless_view(&storage_val));
            let total_len = kp + kl + val.double_rlp_len();
            let pt = generate_struct_len(total_len).len();
            if total_len + pt < KECCAK_LENGTH {
                return total_len + pt;
            }
        }
        KECCAK_LENGTH + 1
    }

    fn fill_from_account(&mut self, account: Option<&Account>) {
        self.nonce = 0;
        self.balance = U256::ZERO;
        self.code_hash = EMPTY_HASH;
        if let Some(account) = account {
            self.nonce = account.nonce;
            self.balance = account.balance;
            self.code_hash = account.code_hash;
        }
    }

    fn fill_from_storage(&mut self, storage: Option<U256>) {
        self.storage = storage;
    }

    fn fill_from_upper_cell(&mut self, up_cell: Cell, depth: usize, depth_increment: usize) {
        self.down_hashed_key.clear();
        if up_cell.down_hashed_key.len() > depth_increment {
            self.down_hashed_key
                .try_extend_from_slice(&up_cell.down_hashed_key[depth_increment..])
                .unwrap();
        }
        self.extension.clear();
        if up_cell.extension.len() > depth_increment {
            self.extension
                .try_extend_from_slice(&up_cell.extension[depth_increment..])
                .unwrap();
        }
        if depth <= 64 {
            self.apk = up_cell.apk;
            if up_cell.apk.is_some() {
                self.balance = up_cell.balance;
                self.nonce = up_cell.nonce;
                self.code_hash = up_cell.code_hash;
                self.extension = up_cell.extension;
            }
        } else {
            self.apk = None;
        }
        self.spk = up_cell.spk;
        if up_cell.spk.is_some() {
            self.storage = up_cell.storage;
        }
        self.h = up_cell.h;
    }

    fn fill_from_lower_cell(
        &mut self,
        low_cell: Cell,
        low_depth: usize,
        pre_extension: &[u8],
        nibble: usize,
    ) {
        if low_depth < 64 || low_cell.apk.is_some() {
            self.apk = low_cell.apk;
        }
        if low_cell.apk.is_some() {
            self.balance = low_cell.balance;
            self.nonce = low_cell.nonce;
            self.code_hash = low_cell.code_hash;
        }
        self.spk = low_cell.spk;
        if low_cell.spk.is_some() {
            self.storage = low_cell.storage;
        }
        if low_cell.h.is_some() {
            if (low_cell.apk.is_none() && low_depth < 64)
                || (low_cell.spk.is_none() && low_depth > 64)
            {
                // Extension is related to either accounts branch node, or storage branch node, we prepend it by preExtension | nibble
                self.extension.clear();
                self.extension.try_extend_from_slice(pre_extension).unwrap();
                self.extension.push(nibble as u8);
                self.extension
                    .try_extend_from_slice(&low_cell.extension)
                    .unwrap();
            } else {
                // Extension is related to a storage branch node, so we copy it upwards as is
                self.extension = low_cell.extension;
            }
        }
        self.h = low_cell.h;
    }
}

#[derive(Debug)]
struct CellGrid {
    root: Cell, // Root cell of the tree
    // Rows of the grid correspond to the level of depth in the patricia tree
    // Columns of the grid correspond to pointers to the nodes further from the root
    grid: Vec<Vec<Cell>>, // First 64 rows of this grid are for account trie, and next 64 rows are for storage trie
}

impl Default for CellGrid {
    fn default() -> Self {
        Self {
            root: Cell::default(),
            grid: vec![vec![Cell::default(); 16]; 128],
        }
    }
}

impl CellGrid {
    fn clear_row(&mut self, row: usize) {
        for col in 0..16 {
            let cell = self.grid_cell_mut(CellPosition { row, col });

            cell.apk = None;
            cell.spk = None;
            cell.down_hashed_key.clear();
            cell.extension.clear();
            cell.h = None;
            cell.nonce = 0;
            cell.balance = U256::ZERO;
            cell.code_hash = EMPTY_HASH;
            cell.storage = None;
        }
    }

    fn cell(&self, cell_position: Option<CellPosition>) -> &Cell {
        if let Some(position) = cell_position {
            self.grid_cell(position)
        } else {
            self.root()
        }
    }

    fn cell_mut(&mut self, cell_position: Option<CellPosition>) -> &mut Cell {
        if let Some(position) = cell_position {
            self.grid_cell_mut(position)
        } else {
            self.root_mut()
        }
    }

    #[instrument(skip(self))]
    fn grid_cell(&self, cell_position: CellPosition) -> &Cell {
        &self.grid[cell_position.row as usize][cell_position.col as usize]
    }

    #[instrument(skip(self))]
    fn grid_cell_mut(&mut self, cell_position: CellPosition) -> &mut Cell {
        &mut self.grid[cell_position.row as usize][cell_position.col as usize]
    }

    #[instrument(skip(self))]
    fn root(&self) -> &Cell {
        &self.root
    }

    #[instrument(skip(self))]
    fn root_mut(&mut self) -> &mut Cell {
        &mut self.root
    }
}

pub fn hash_key(plain_key: &[u8], hashed_key_offset: usize) -> ArrayVec<u8, 64> {
    let hash_buf = keccak256(plain_key).0;
    let mut hash_buf = &hash_buf[hashed_key_offset / 2..];
    let mut dest = ArrayVec::new();
    if hashed_key_offset % 2 == 1 {
        dest.push(hash_buf[0] & 0xf);
        hash_buf = &hash_buf[1..];
    }
    for c in hash_buf {
        dest.push((c >> 4) & 0xf);
        dest.push(c & 0xf);
    }

    dest
}

impl Cell {
    fn derive_hashed_keys(&mut self, depth: usize) -> anyhow::Result<()> {
        let mut extra_len = 0_usize;
        if self.apk.is_some() {
            extra_len = 64_usize
                .checked_sub(depth)
                .ok_or_else(|| format_err!("account_plain_key present at depth > 64"))?;
        }

        if self.spk.is_some() {
            if depth >= 64 {
                extra_len = 128 - depth;
            } else {
                extra_len += 64;
            }
        }

        if extra_len > 0 {
            let orig = self.down_hashed_key.clone();
            while self.down_hashed_key.len() < 128 {
                self.down_hashed_key.push(0);
            }
            if !self.down_hashed_key.is_empty() {
                let dst = &mut self.down_hashed_key[extra_len..];
                let len = std::cmp::min(dst.len(), orig.len());
                dst[..len].copy_from_slice(&orig[..len]);
            }
            self.down_hashed_key.truncate(orig.len() + extra_len);
            let mut hashed_key_offset = 0;
            let mut down_offset = 0;
            if let Some(apk) = self.apk {
                let k = hash_key(&apk[..], depth);
                self.down_hashed_key[..k.len()].copy_from_slice(&k[..]);
                down_offset = 64 - depth;
            }
            if let Some((_, location)) = self.spk {
                if depth >= 64 {
                    hashed_key_offset = depth - 64;
                }
                let dst = &mut self.down_hashed_key[down_offset..];
                let k = hash_key(&location[..], hashed_key_offset);
                dst[..k.len()].copy_from_slice(&k[..]);
            }
        }

        Ok(())
    }

    fn fill_from_fields(&mut self, data: CellPayload) {
        self.down_hashed_key.clear();
        self.extension.clear();
        if let Some(extension) = data.extension {
            self.down_hashed_key
                .try_extend_from_slice(&extension[..])
                .unwrap();
            self.extension = extension;
        }

        self.apk = data.apk;
        self.spk = data.spk;
        self.h = data.h;
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CellPayload {
    pub field_bits: PartFlags,
    pub extension: Option<ArrayVec<u8, 64>>,
    pub apk: Option<Address>,
    pub spk: Option<(Address, H256)>,
    pub h: Option<H256>,
}

impl Debug for CellPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellPayload")
            .field("field_bits", &self.field_bits)
            .field("extension", &self.extension.as_ref().map(hex::encode))
            .field("apk", &self.apk)
            .field("spk", &self.spk)
            .field("h", &self.h)
            .finish()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BranchData {
    pub touch_map: BranchBitmap,
    pub after_map: BranchBitmap,
    pub payload: Vec<CellPayload>,
}

impl BranchData {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 2);

        out.extend_from_slice(&self.touch_map.0.to_be_bytes());
        out.extend_from_slice(&self.after_map.0.to_be_bytes());

        for payload in &self.payload {
            out.push(payload.field_bits);
            if let Some(extension) = &payload.extension {
                encode_slice(&mut out, &extension[..]);
            }
            if let Some(apk) = &payload.apk {
                encode_slice(&mut out, &apk[..]);
            }
            if let Some((addr, location)) = &payload.spk {
                let mut spk = [0; H160::len_bytes() + H256::len_bytes()];
                spk[..H160::len_bytes()].copy_from_slice(&addr.0);
                spk[H160::len_bytes()..].copy_from_slice(&location.0);
                encode_slice(&mut out, &spk[..]);
            }
            if let Some(h) = &payload.h {
                encode_slice(&mut out, &h[..]);
            }
        }

        out
    }

    pub fn decode(buf: &[u8], mut pos: usize) -> anyhow::Result<(Self, usize)> {
        fn extract_length(data: &[u8], mut pos: usize) -> anyhow::Result<(usize, usize)> {
            let (l, n) =
                uvarint(&data[pos..]).ok_or_else(|| format_err!("value overflow for len"))?;
            if n == 0 {
                bail!("buffer too small for len");
            }

            pos += n;

            let l = l as usize;

            if data.len() < pos + l {
                bail!("buffer too small for value");
            }

            Ok((pos, l))
        }

        ensure!(buf.len() >= pos + 4);
        let touch_map = BranchBitmap(u16::from_be_bytes(*array_ref!(buf, pos, 2)));
        pos += 2;

        let after_map = BranchBitmap(u16::from_be_bytes(*array_ref!(buf, pos, 2)));
        pos += 2;

        let mut payload = vec![];
        while buf.len() != pos {
            let field_bits = buf[pos];
            pos += 1;

            let mut extension = None;
            if field_bits & HASHEDKEY_PART != 0 {
                let l;
                (pos, l) = extract_length(buf, pos)?;

                if l > 0 {
                    let mut v = ArrayVec::new();
                    v.try_extend_from_slice(&buf[pos..pos + l])?;
                    extension = Some(v);
                    pos += l;
                }
            }

            let mut apk = None;
            if field_bits & ACCOUNT_PLAIN_PART != 0 {
                let l;
                (pos, l) = extract_length(buf, pos)?;

                if l > 0 {
                    ensure!(l == ADDRESS_LENGTH);
                    apk = Some(Address::from_slice(&buf[pos..pos + l]));
                    pos += l;
                }
            }

            let mut spk = None;
            if field_bits & STORAGE_PLAIN_PART != 0 {
                let l;
                (pos, l) = extract_length(buf, pos)?;

                if l > 0 {
                    ensure!(l == ADDRESS_LENGTH + KECCAK_LENGTH);
                    spk = Some((
                        Address::from_slice(&buf[pos..pos + ADDRESS_LENGTH]),
                        H256::from_slice(
                            &buf[pos + ADDRESS_LENGTH..pos + ADDRESS_LENGTH + KECCAK_LENGTH],
                        ),
                    ));
                    pos += l;
                }
            }

            let mut h = None;
            if field_bits & HASH_PART != 0 {
                let l;
                (pos, l) = extract_length(buf, pos)?;

                if l > 0 {
                    ensure!(l == KECCAK_LENGTH);
                    h = Some(H256::from_slice(&buf[pos..pos + KECCAK_LENGTH]));
                    pos += l;
                }
            }

            payload.push(CellPayload {
                field_bits,
                extension,
                apk,
                spk,
                h,
            });
        }

        Ok((
            Self {
                touch_map,
                after_map,
                payload,
            },
            pos,
        ))
    }
}

pub trait State {
    fn get_branch(&mut self, prefix: &[u8]) -> anyhow::Result<Option<BranchData>>;
    fn get_account(&mut self, address: Address) -> anyhow::Result<Option<Account>>;
    fn get_storage(&mut self, address: Address, location: H256) -> anyhow::Result<Option<U256>>;
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct BranchBitmap(pub u16);

impl BranchBitmap {
    pub fn parts(self) -> usize {
        self.0.count_ones() as usize
    }

    pub fn has(self, nibble: u8) -> bool {
        self.0 & (1_u16 << nibble as u16) != 0
    }

    pub fn from_nibble(nibble: u8) -> Self {
        Self(1_u16 << nibble as u16)
    }

    pub fn add_nibble(&mut self, nibble: u8) {
        self.0 |= 1_u16 << nibble as u16;
    }

    pub fn remove_nibble(&mut self, nibble: u8) {
        self.0 &= !(1_u16 << nibble as u16)
    }

    pub fn iter(self) -> NibbleIterator {
        NibbleIterator(self.0)
    }

    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

impl Debug for BranchBitmap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016b}", self.0)
    }
}

impl Display for BranchBitmap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016b}", self.0)
    }
}

pub struct NibbleIterator(u16);

impl Iterator for NibbleIterator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0 != 0 {
            let bit = self.0 & 0_u16.overflowing_sub(self.0).0;
            let nibble = bit.trailing_zeros();

            self.0 ^= bit;

            Some(nibble.try_into().unwrap())
        } else {
            None
        }
    }
}

/// HexPatriciaHashed implements commitment based on patricia merkle tree with radix 16,
/// with keys pre-hashed by keccak256
#[derive(Debug)]
pub struct HexPatriciaHashed<'state, S: State> {
    state: &'state mut S,

    grid: CellGrid,
    // How many rows (starting from row 0) are currently active and have corresponding selected columns
    // Last active row does not have selected column
    active_rows: usize,
    // Length of the key that reflects current positioning of the grid. It maybe larger than number of active rows,
    // if a account leaf cell represents multiple nibbles in the key
    current_key: ArrayVec<u8, 128>, // For each row indicates which column is currently selected
    depths: [usize; 128],           // For each row, the depth of cells in that row
    root_checked: bool, // Set to false if it is not known whether the root is empty, set to true if it is checked
    root_touched: bool,
    root_present: bool,
    branch_before: [bool; 128], // For each row, whether there was a branch node in the database loaded in unfold
    touch_map: [BranchBitmap; 128], // For each row, bitmap of cells that were either present before modification, or modified or deleted
    after_map: [BranchBitmap; 128], // For each row, bitmap of cells that were present after modification
}

#[derive(Clone, Copy, PartialEq)]
struct CellPosition {
    row: usize,
    col: usize,
}

impl Debug for CellPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellPosition")
            .field("row", &self.row)
            .field("col", &format_args!("{:x}", self.col))
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcessUpdateArg {
    pub account_changed: bool,
    pub changed_storage: HashSet<H256>,
}

impl<'state, S: State> HexPatriciaHashed<'state, S> {
    pub fn new(state: &'state mut S) -> Self {
        Self {
            state,

            grid: Default::default(),
            active_rows: Default::default(),
            current_key: Default::default(),
            depths: [0; 128],
            root_checked: Default::default(),
            root_touched: Default::default(),
            root_present: Default::default(),
            branch_before: [false; 128],
            touch_map: [Default::default(); 128],
            after_map: [Default::default(); 128],
        }
    }

    pub fn process_updates(
        mut self,
        updates: HashMap<Address, ProcessUpdateArg>,
    ) -> anyhow::Result<(H256, HashMap<Vec<u8>, BranchData>)> {
        let mut branch_node_updates = HashMap::new();

        #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
        struct PlainKey {
            address: Address,
            storage: Option<H256>,
        }

        let mut changed_keys = BTreeMap::new();

        for (
            address,
            ProcessUpdateArg {
                account_changed,
                changed_storage,
            },
        ) in updates
        {
            let hashed_address = hash_key(&address[..], 0);

            if account_changed {
                let mut v = ArrayVec::new();
                v.try_extend_from_slice(&hashed_address[..]).unwrap();
                changed_keys.insert(v, (address, None));
            }

            for location in changed_storage {
                let hashed_location = hash_key(&location[..], 0);

                let mut v = ArrayVec::new();
                v.try_extend_from_slice(&hashed_address[..]).unwrap();
                v.try_extend_from_slice(&hashed_location[..]).unwrap();
                changed_keys.insert(v, (address, Some(location)));
            }
        }

        for (hashed_key, (address, storage)) in changed_keys {
            trace!(
                "address={:?} storage={:?} hashed_key={:?}, current_key={:?}",
                address,
                storage,
                hex::encode(&hashed_key),
                hex::encode(&self.current_key),
            );

            // Keep folding until the current_key is the prefix of the key we modify
            while self.need_folding(&hashed_key[..]) {
                if let (Some(branch_node_update), update_key) = self.fold() {
                    branch_node_updates.insert(update_key, branch_node_update);
                }
            }

            // Now unfold until we step on an empty cell
            loop {
                let unfolding = self.need_unfolding(&hashed_key[..]);
                if unfolding == 0 {
                    break;
                }

                self.unfold(&hashed_key[..], unfolding)?;
            }

            // Update the cell
            if let Some(location) = storage {
                if let Some(value) = self.state.get_storage(address, location)? {
                    self.update_storage(address, location, hashed_key, value);
                } else {
                    self.delete_cell(hashed_key);
                }
            } else if let Some(account) = self.state.get_account(address)? {
                self.update_account(address, hashed_key, account);
            } else {
                self.delete_cell(hashed_key);
            }
        }

        // Folding everything up to the root
        while self.active_rows > 0 {
            if let (Some(branch_data), update_key) = self.fold() {
                branch_node_updates.insert(update_key, branch_data);
            }
        }

        Ok((
            H256::from_slice(&self.compute_cell_hash(None, 0)[1..]),
            branch_node_updates,
        ))
    }

    #[instrument(skip(self))]
    fn compute_cell_hash(&mut self, pos: Option<CellPosition>, depth: usize) -> ArrayVec<u8, 33> {
        let cell = self.grid.cell_mut(pos);
        let mut storage_root = None;
        if let Some((_, location)) = cell.spk {
            let hashed_key_offset = depth.saturating_sub(64);
            let singleton = depth <= 64;
            cell.down_hashed_key.clear();
            cell.down_hashed_key
                .try_extend_from_slice(&hash_key(&location[..], hashed_key_offset))
                .unwrap();
            cell.down_hashed_key.push(16); // Add terminator
            if singleton {
                trace!(
                    "leafHashWithKeyVal(singleton) for [{}]=>[{:?}]",
                    hex::encode(&cell.down_hashed_key[..64 - hashed_key_offset + 1]),
                    cell.storage
                );
                let storage_bytes = cell.storage.unwrap().to_be_bytes();
                storage_root = Some(H256::from_slice(
                    &leaf_hash_with_key_val(
                        &cell.down_hashed_key[..64 - hashed_key_offset + 1],
                        RlpSerializableBytes(zeroless_view(&storage_bytes)),
                        true,
                    )[1..],
                ));
            } else {
                trace!(
                    "leafHashWithKeyVal for [{}]=>[{:?}]",
                    hex::encode(&cell.down_hashed_key[..64 - hashed_key_offset + 1]),
                    cell.storage
                );
                let storage_bytes = cell.storage.unwrap().to_be_bytes();
                return leaf_hash_with_key_val(
                    &cell.down_hashed_key[..64 - hashed_key_offset + 1],
                    RlpSerializableBytes(zeroless_view(&storage_bytes)),
                    false,
                );
            }
        }
        if let Some(apk) = cell.apk {
            cell.down_hashed_key.clear();
            cell.down_hashed_key
                .try_extend_from_slice(&hash_key(&apk.0, depth))
                .unwrap();
            cell.down_hashed_key.push(16); // Add terminator

            let storage_root = storage_root.unwrap_or_else(|| {
                if !cell.extension.is_empty() {
                    // Extension
                    let h = cell.h.expect("computeCellHash extension without hash");
                    trace!(
                        "extension_hash for [{}]=>[{:?}]",
                        hex::encode(&cell.extension),
                        h
                    );
                    extension_hash(&cell.extension, h)
                } else if let Some(h) = cell.h {
                    h
                } else {
                    EMPTY_ROOT
                }
            });
            let account_rlp = fastrlp::encode_fixed_size(&RlpAccount {
                storage_root,
                nonce: cell.nonce,
                balance: cell.balance,
                code_hash: cell.code_hash,
            });
            trace!(
                "accountLeafHashWithKey for [{}]=>[{}]",
                hex::encode(&cell.down_hashed_key[..65 - depth]),
                hex::encode(&account_rlp)
            );
            return account_leaf_hash_with_key(
                &cell.down_hashed_key[..65 - depth],
                RlpEncodableBytes(&account_rlp),
            );
        }

        let mut buf = ArrayVec::new();
        buf.push(0x80 + 32);
        if !cell.extension.is_empty() {
            // Extension
            let cell_hash = cell.h.expect("extension without hash");
            trace!(
                "extension hash for [{}]=>[{:?}]",
                hex::encode(&cell.extension),
                cell_hash
            );
            buf.try_extend_from_slice(&extension_hash(&cell.extension, cell_hash).0)
                .unwrap();
        } else if let Some(cell_hash) = cell.h {
            buf.try_extend_from_slice(&cell_hash[..]).unwrap();
        } else {
            buf.try_extend_from_slice(&EMPTY_ROOT[..]).unwrap();
        }

        trace!("computed cell hash {}", hex::encode(&buf));

        buf
    }

    #[instrument(skip_all, fields(root_checked = self.root_checked))]
    fn need_unfolding(&self, hashed_key: &[u8]) -> usize {
        let cell: &Cell;
        let mut depth = 0_usize;
        if self.active_rows == 0 {
            trace!("root");
            cell = self.grid.root();
            if cell.down_hashed_key.is_empty() && cell.h.is_none() && !self.root_checked {
                // Need to attempt to unfold the root
                return 1;
            }
        } else {
            let col = hashed_key[self.current_key.len()] as usize;
            cell = self.grid.grid_cell(CellPosition {
                row: self.active_rows - 1,
                col,
            });
            depth = self.depths[self.active_rows - 1];
            trace!(
                "cell ({}, {:x}), currentKey=[{}], depth={}, cell.h=[{:?}]",
                self.active_rows - 1,
                col,
                hex::encode(&self.current_key[..]),
                depth,
                cell.h
            );
        }
        if hashed_key.len() <= depth {
            return 0;
        }
        if cell.down_hashed_key.is_empty() {
            if cell.h.is_none() {
                // cell is empty, no need to unfold further
                return 0;
            } else {
                // unfold branch node
                return 1;
            }
        }
        let cpl = prefix_length(
            &hashed_key[depth..],
            &cell.down_hashed_key[..cell.down_hashed_key.len() - 1],
        );
        trace!(
            "cpl={}, cell.downHashedKey=[{}], depth={}, hashedKey[depth..]=[{}]",
            cpl,
            hex::encode(&cell.down_hashed_key[..]),
            depth,
            hex::encode(&hashed_key[depth..]),
        );
        let mut unfolding = cpl + 1;
        if depth < 64 && depth + unfolding > 64 {
            // This is to make sure that unfolding always breaks at the level where storage subtrees start
            unfolding = 64 - depth;
            trace!("adjusted unfolding={}", unfolding);
        }

        unfolding
    }

    #[instrument(skip(self))]
    fn unfold_branch_node(
        &mut self,
        row: usize,
        deleted: bool,
        depth: usize,
    ) -> anyhow::Result<()> {
        let branch_data = self
            .state
            .get_branch(&hex_to_compact(&self.current_key[..]))?;

        if !self.root_checked && self.current_key.is_empty() && branch_data.is_none() {
            // Special case - empty or deleted root
            self.root_checked = true;
            return Ok(());
        }

        let branch_data =
            branch_data.ok_or_else(|| format_err!("branch data unexpectedly absent"))?;
        self.branch_before[row] = true;
        let bitmap = branch_data.touch_map;
        if deleted {
            // All cells come as deleted (touched but not present after)
            self.after_map[row] = Default::default();
            self.touch_map[row] = bitmap;
        } else {
            self.after_map[row] = bitmap;
            self.touch_map[row] = Default::default();
        }
        if bitmap.parts() != branch_data.payload.len() {
            bail!(
                "len mismatch {} != {}",
                bitmap.parts(),
                branch_data.payload.len()
            );
        }

        for (nibble, cell_payload) in bitmap.iter().zip(branch_data.payload.into_iter()) {
            let cell = self.grid.grid_cell_mut(CellPosition {
                row,
                col: nibble as usize,
            });
            cell.fill_from_fields(cell_payload);
            trace!(
                "cell ({}, {:x}) depth={}, hash=[{:?}], a=[{:?}], s=[{:?}], ex=[{}]",
                row,
                nibble,
                depth,
                cell.h,
                cell.apk,
                cell.spk,
                hex::encode(&cell.extension)
            );
            if let Some(account) = cell.apk {
                cell.fill_from_account(self.state.get_account(account)?.as_ref());
                trace!(
                    "accountFn[{:?}] return balance={}, nonce={}",
                    account,
                    &cell.balance,
                    cell.nonce
                );
            }
            if let Some((account, location)) = cell.spk {
                cell.fill_from_storage(self.state.get_storage(account, location)?);
            }
            cell.derive_hashed_keys(depth)?;
        }

        Ok(())
    }

    #[instrument(skip(self, hashed_key), fields(hashed_key = &*hex::encode(hashed_key), active_rows=self.active_rows))]
    fn unfold(&mut self, hashed_key: &[u8], unfolding: usize) -> anyhow::Result<()> {
        let touched;
        let present;
        let mut up_depth = 0;
        let depth;
        let up_cell;
        if self.active_rows == 0 {
            let root = self.grid.root();
            if self.root_checked && root.h.is_none() && root.down_hashed_key.is_empty() {
                // No unfolding for empty root
                return Ok(());
            }
            up_cell = root.clone();
            touched = self.root_touched;
            present = self.root_present;
            trace!("root, touched={}, present={}", touched, present);
        } else {
            up_depth = self.depths[self.active_rows - 1];
            let col = hashed_key[up_depth - 1];
            up_cell = self
                .grid
                .grid_cell(CellPosition {
                    row: self.active_rows - 1,
                    col: col as usize,
                })
                .clone();
            touched = self.touch_map[self.active_rows - 1].has(col);
            present = self.after_map[self.active_rows - 1].has(col);
            trace!(
                "upCell ({}, {:x}), touched {}, present {}",
                self.active_rows - 1,
                col,
                touched,
                present
            );
            self.current_key.push(col);
        };
        let row = self.active_rows;
        self.grid.clear_row(row);
        self.touch_map[row].clear();
        self.after_map[row].clear();
        self.branch_before[row] = false;
        if up_cell.down_hashed_key.is_empty() {
            depth = up_depth + 1;
            self.unfold_branch_node(row, touched && !present, depth)?;
        } else if up_cell.down_hashed_key.len() >= unfolding {
            depth = up_depth + unfolding;
            let nibble = up_cell.down_hashed_key[unfolding - 1];
            if touched {
                self.touch_map[row] = BranchBitmap::from_nibble(nibble);
            }
            if present {
                self.after_map[row] = BranchBitmap::from_nibble(nibble);
            }
            let cell = self.grid.grid_cell_mut(CellPosition {
                row,
                col: nibble as usize,
            });
            cell.fill_from_upper_cell(up_cell.clone(), depth, unfolding);
            trace!("cell ({}, {:x}) depth={}", row, nibble, depth);
            if row >= 64 {
                cell.apk = None;
            }
            if unfolding > 1 {
                self.current_key
                    .try_extend_from_slice(&up_cell.down_hashed_key[..unfolding - 1])
                    .unwrap();
            }
        } else {
            // upCell.downHashedLen < unfolding
            depth = up_depth + up_cell.down_hashed_key.len();
            let nibble = *up_cell.down_hashed_key.last().unwrap();
            if touched {
                self.touch_map[row] = BranchBitmap::from_nibble(nibble);
            }
            if present {
                self.after_map[row] = BranchBitmap::from_nibble(nibble);
            }
            let cell = self.grid.grid_cell_mut(CellPosition {
                row,
                col: nibble as usize,
            });
            cell.fill_from_upper_cell(up_cell.clone(), depth, up_cell.down_hashed_key.len());
            trace!("cell ({}, {:x}) depth={}", row, nibble, depth);
            if row >= 64 {
                cell.apk = None;
            }
            if up_cell.down_hashed_key.len() > 1 {
                self.current_key
                    .try_extend_from_slice(
                        &up_cell.down_hashed_key[..up_cell.down_hashed_key.len() - 1],
                    )
                    .unwrap();
            }
        }
        self.depths[self.active_rows] = depth;
        self.active_rows += 1;

        Ok(())
    }

    fn need_folding(&self, hashed_key: &[u8]) -> bool {
        !hashed_key[..].starts_with(&self.current_key[..])
    }

    #[instrument(skip(self), fields(active_rows=self.active_rows, current_key=&*hex::encode(&self.current_key), touch_map=&*self.touch_map[self.active_rows - 1].to_string(), after_map=&*self.after_map[self.active_rows - 1].to_string()))]
    pub(crate) fn fold(&mut self) -> (Option<BranchData>, Vec<u8>) {
        assert_ne!(self.active_rows, 0, "cannot fold - no active rows");
        // Move information to the row above
        let row = self.active_rows - 1;
        let mut col = 0;
        let mut up_depth = 0;
        let up_cell = if self.active_rows == 1 {
            trace!("upcell is root");

            None
        } else {
            up_depth = self.depths[self.active_rows - 2];
            col = self.current_key[up_depth - 1];

            trace!("upcell is ({} x {}), upDepth={}", row - 1, col, up_depth);

            Some(CellPosition {
                row: row - 1,
                col: col as usize,
            })
        };
        let depth = self.depths[self.active_rows - 1];
        let mut branch_data = None;

        let update_key = hex_to_compact(&self.current_key);
        trace!(
            "touch_map[{}]={}, after_map[{}]={}",
            row,
            self.touch_map[row],
            row,
            self.after_map[row]
        );

        let parts_count = self.after_map[row].parts();
        match parts_count {
            0 => {
                // Everything deleted
                if self.touch_map[row].parts() > 0 {
                    if row == 0 {
                        // Root is deleted because the tree is empty
                        self.root_touched = true;
                        self.root_present = false;
                    } else if up_depth == 64 {
                        // Special case - all storage items of an account have been deleted, but it does not automatically delete the account, just makes it empty storage
                        // Therefore we are not propagating deletion upwards, but turn it into a modification
                        self.touch_map[row - 1].add_nibble(col);
                    } else {
                        // Deletion is propagated upwards
                        self.touch_map[row - 1].add_nibble(col);
                        self.after_map[row - 1].remove_nibble(col);
                    }
                }
                let up_cell = self.grid.cell_mut(up_cell);
                up_cell.h = None;
                up_cell.apk = None;
                up_cell.spk = None;
                up_cell.extension.clear();
                up_cell.down_hashed_key.clear();
                if self.branch_before[row] {
                    let branch_data = branch_data.get_or_insert_with(BranchData::default);
                    branch_data.touch_map = self.touch_map[row];
                    branch_data.after_map.clear();
                }
                self.active_rows -= 1;
                if up_depth > 0 {
                    self.current_key.truncate(up_depth - 1);
                } else {
                    self.current_key.clear();
                }
            }
            1 => {
                // Leaf or extension node
                if self.touch_map[row].parts() != 0 {
                    // any modifications
                    if row == 0 {
                        self.root_touched = true;
                    } else {
                        // Modification is propagated upwards
                        self.touch_map[row - 1].add_nibble(col);
                    }
                }
                let nibble = self.after_map[row].0.trailing_zeros().try_into().unwrap();
                let low_cell = self
                    .grid
                    .grid_cell(CellPosition { row, col: nibble })
                    .clone();
                let up_cell = self.grid.cell_mut(up_cell);
                up_cell.extension.clear();
                up_cell.fill_from_lower_cell(
                    low_cell,
                    depth,
                    &self.current_key[up_depth..],
                    nibble,
                );

                // Delete if it existed
                if self.branch_before[row] {
                    let branch_data = branch_data.get_or_insert_with(BranchData::default);
                    branch_data.touch_map = self.touch_map[row];
                    branch_data.after_map.clear();
                }
                self.active_rows -= 1;

                self.current_key.truncate(up_depth.saturating_sub(1));
            }
            _ => {
                // Branch node
                if self.touch_map[row].parts() != 0 {
                    // any modifications
                    if row == 0 {
                        self.root_touched = true
                    } else {
                        // Modification is propagated upwards
                        self.touch_map[row - 1].add_nibble(col);
                    }
                }
                let mut changed_and_present =
                    BranchBitmap(self.touch_map[row].0 & self.after_map[row].0);
                if !self.branch_before[row] {
                    // There was no branch node before, so we need to touch even the singular child that existed
                    self.touch_map[row].0 |= self.after_map[row].0;
                    changed_and_present.0 |= self.after_map[row].0;
                }
                // Calculate total length of all hashes
                let mut total_branch_len = 17 - parts_count as usize; // for every empty cell, one byte

                for nibble in self.after_map[row].iter() {
                    total_branch_len += self
                        .grid
                        .cell_mut(Some(CellPosition {
                            row,
                            col: nibble as usize,
                        }))
                        .compute_hash_len(depth);
                }

                let mut b = BranchData {
                    touch_map: self.touch_map[row],
                    after_map: self.after_map[row],

                    ..Default::default()
                };

                let mut hasher = Keccak256::new();
                hasher.update(&rlputil::generate_struct_len(total_branch_len));

                let mut last_nibble = 0;

                for nibble in self.after_map[row].iter() {
                    for i in last_nibble..nibble {
                        hasher.update(&[0x80]);
                        trace!("{:x}: empty({},{:x})", i, row, i);
                    }
                    last_nibble = nibble + 1;
                    let cell_pos = CellPosition {
                        row,
                        col: nibble as usize,
                    };
                    {
                        let cell_hash = self.compute_cell_hash(Some(cell_pos), depth);
                        hasher.update(cell_hash);
                    }

                    if changed_and_present.has(nibble) {
                        let mut field_bits = 0_u8;

                        let cell = self.grid.grid_cell_mut(cell_pos);
                        if !cell.extension.is_empty() && cell.spk.is_none() {
                            field_bits |= HASHEDKEY_PART;
                        }
                        if cell.apk.is_some() {
                            field_bits |= ACCOUNT_PLAIN_PART;
                        }
                        if cell.spk.is_some() {
                            field_bits |= STORAGE_PLAIN_PART;
                        }
                        if cell.h.is_some() {
                            field_bits |= HASH_PART;
                        }

                        b.payload.push(CellPayload {
                            field_bits,
                            extension: if !cell.extension.is_empty() && cell.spk.is_none() {
                                Some(cell.extension.clone())
                            } else {
                                None
                            },
                            apk: cell.apk,
                            spk: cell.spk,
                            h: cell.h,
                        });
                    }
                }

                branch_data = Some(b);

                {
                    let mut i = last_nibble;
                    while i < 17 {
                        hasher.update(&[0x80]);
                        trace!("{:x}: empty({},{:x})", i, row, i);

                        i += 1;
                    }
                }

                let up_cell = self.grid.cell_mut(up_cell);
                let ext_len = depth - up_depth - 1;
                up_cell.extension.truncate(depth - up_depth - 1);
                while up_cell.extension.len() < ext_len {
                    up_cell.extension.push(0);
                }
                if ext_len > 0 {
                    up_cell.extension[..].copy_from_slice(&self.current_key[up_depth..]);
                }
                if depth < 64 {
                    up_cell.apk = None;
                }
                up_cell.spk = None;

                {
                    let h = H256::from_slice(&hasher.finalize()[..]);
                    trace!("}} [{:?}]", h);
                    up_cell.h = Some(h);
                }

                self.active_rows -= 1;

                self.current_key.truncate(up_depth.saturating_sub(1));
            }
        }
        if let Some(branch_data) = branch_data.as_mut() {
            trace!(
                "update key: {}, branch_data: [{:?}]",
                hex::encode(compact_to_hex(&update_key)),
                branch_data
            );
        }
        (branch_data, update_key)
    }

    #[instrument(skip(self), fields(active_rows=self.active_rows))]
    fn delete_cell(&mut self, hashed_key: ArrayVec<u8, 128>) {
        trace!("called");
        let cell: &mut Cell;
        if self.active_rows == 0 {
            // Remove the root
            cell = self.grid.cell_mut(None);
            self.root_touched = true;
            self.root_present = false;
        } else {
            let row = self.active_rows - 1;
            if self.depths[row] < hashed_key[..].len() {
                trace!(
                    "Skipping spurious delete depth={}, hashed_key_len={}",
                    self.depths[row],
                    hashed_key[..].len()
                );
                return;
            }
            let col = hashed_key[self.current_key.len()];
            cell = self.grid.cell_mut(Some(CellPosition {
                row,
                col: col as usize,
            }));
            if self.after_map[row].has(col) {
                // Prevent "spurious deletions", i.e. deletion of absent items
                self.touch_map[row].add_nibble(col);
                self.after_map[row].remove_nibble(col);
                trace!("Setting ({}, {:x})", row, col);
            } else {
                trace!("Ignoring ({}, {:x})", row, col);
            }
        }
        cell.extension.clear();
        cell.balance = U256::ZERO;
        cell.code_hash = EMPTY_HASH;
        cell.nonce = 0;
    }

    #[instrument(skip(self, hashed_key), fields(hashed_key = &*hex::encode(&hashed_key), active_rows=self.active_rows))]
    fn update_cell(&mut self, hashed_key: ArrayVec<u8, 128>) -> &mut Cell {
        trace!("called");
        if self.active_rows == 0 {
            self.active_rows += 1;
        }
        let row = self.active_rows - 1;
        let depth = self.depths[row];
        let col = hashed_key[self.current_key.len()];
        let cell = self.grid.grid_cell_mut(CellPosition {
            row,
            col: col as usize,
        });
        self.touch_map[row].add_nibble(col);
        self.after_map[row].add_nibble(col);
        trace!(
            "Setting ({}, {:x}), touch_map[{}]={}, depth={}",
            row,
            col,
            row,
            self.touch_map[row],
            depth
        );
        if cell.down_hashed_key.is_empty() {
            cell.down_hashed_key
                .try_extend_from_slice(&hashed_key[depth..])
                .unwrap();
            trace!(
                "set down_hashed_key=[{}]",
                hex::encode(&cell.down_hashed_key[..])
            );
        } else {
            trace!(
                "left down_hashed_key=[{}]",
                hex::encode(&cell.down_hashed_key[..])
            );
        }

        cell
    }

    #[instrument(skip(self, hashed_key))]
    fn update_account(
        &mut self,
        address: Address,
        hashed_key: ArrayVec<u8, 128>,
        account: Account,
    ) {
        let cell = self.update_cell(hashed_key);

        cell.apk = Some(address);
        cell.nonce = account.nonce;
        cell.balance = account.balance;
        cell.code_hash = account.code_hash;
    }

    #[instrument(skip(self))]
    fn update_storage(
        &mut self,
        address: Address,
        location: H256,
        hashed_key: ArrayVec<u8, 128>,
        value: U256,
    ) {
        let cell = self.update_cell(hashed_key);

        cell.spk = Some((address, location));
        cell.storage = Some(value);
    }
}

type PartFlags = u8;

const HASHEDKEY_PART: PartFlags = 1;
const ACCOUNT_PLAIN_PART: PartFlags = 2;
const STORAGE_PLAIN_PART: PartFlags = 4;
const HASH_PART: PartFlags = 8;

fn make_compact_zero_byte(key: &[u8]) -> (u8, usize, usize) {
    let mut compact_zero_byte = 0_u8;
    let mut key_pos = 0_usize;
    let mut key_len = key.len();
    if has_term(key) {
        key_len -= 1;
        compact_zero_byte = 0x20;
    }
    let first_nibble = key.first().copied().unwrap_or(0);
    if key_len & 1 == 1 {
        compact_zero_byte |= 0x10 | first_nibble; // Odd: (1<<4) + first nibble
        key_pos += 1
    }

    (compact_zero_byte, key_pos, key_len)
}

fn has_term(s: &[u8]) -> bool {
    s.last().map(|&v| v == 16).unwrap_or(false)
}

/// Combines two `BranchData`, number 2 coming after (and potentially shadowing) number 1
fn merge_hex_branches(old: &BranchData, new: &BranchData) -> anyhow::Result<BranchData> {
    let mut merged = BranchData::default();

    let old_bitmap = old.touch_map.0 & old.after_map.0;
    let new_bitmap = new.touch_map.0 & new.after_map.0;

    merged.touch_map = BranchBitmap(old.touch_map.0 | new.touch_map.0);
    merged.after_map = new.after_map;

    {
        let mut bitset = old_bitmap | new_bitmap;
        let mut old_payload_iter = old.payload.iter();
        let mut new_payload_iter = new.payload.iter();
        while bitset != 0 {
            let bit = bitset & 0_u16.overflowing_sub(bitset).0;
            if new_bitmap & bit != 0 {
                // Add fields from new BranchData
                merged
                    .payload
                    .push(new_payload_iter.next().context("no payload2")?.clone());
            }
            if old_bitmap & bit != 0 {
                let next_old_payload = old_payload_iter.next().context("no payload1")?;
                // Add fields from old BranchData
                if (new.touch_map.0 & bit == 0) && (new.after_map.0 & bit != 0) {
                    merged.payload.push(next_old_payload.clone());
                }
            }
            bitset ^= bit;
        }
    }

    Ok(merged)
}

#[instrument(skip(key), fields(key=&*hex::encode(key)))]
fn hex_to_compact(key: &[u8]) -> Vec<u8> {
    let (zero_byte, key_pos, key_len) = make_compact_zero_byte(key);
    let buf_len = key_len / 2 + 1; // always > 0
    let mut buf = vec![0; buf_len];
    buf[0] = zero_byte;

    let key = &key[key_pos..];
    let mut key_len = key.len();
    if has_term(key) {
        key_len -= 1;
    }

    let mut key_index = 0;
    let mut buf_index = 1;
    while key_index < key_len {
        if key_index == key_len - 1 {
            buf[buf_index] &= 0x0f
        } else {
            buf[buf_index] = key[key_index + 1]
        }
        buf[buf_index] |= key[key_index] << 4;

        key_index += 2;
        buf_index += 1;
    }

    buf
}

fn account_leaf_hash_with_key(key: &[u8], val: impl RlpSerializable) -> ArrayVec<u8, 33> {
    // Write key
    let (compact_len, (compact0, ni)) = if has_term(key) {
        (
            (key.len() - 1) / 2 + 1,
            if key.len() & 1 == 0 {
                (
                    0x30 + key[0], // Odd (1<<4) + first nibble
                    1,
                )
            } else {
                (0x20, 0)
            },
        )
    } else {
        (
            key.len() / 2 + 1,
            if key.len() & 1 == 1 {
                (
                    0x10 + key[0], // Odd (1<<4) + first nibble
                    1,
                )
            } else {
                (0, 0)
            },
        )
    };
    // Compute the total length of binary representation
    let (kp, kl) = if compact_len > 1 {
        (Some(0x80 + compact_len as u8), compact_len)
    } else {
        (None, 1)
    };
    complete_leaf_hash(kp, kl, compact_len, key, compact0, ni, val, true)
}

fn extension_hash(key: &[u8], hash: H256) -> H256 {
    let terminating = has_term(key);
    // Compute the total length of binary representation
    // Write key
    let (compact_len, (compact0, mut ni)) = if terminating {
        (
            (key.len() - 1) / 2 + 1,
            if key.len() & 1 == 0 {
                (
                    0x20 + 0x10 + key[0], // Odd: (3<<4) + first nibble
                    1,
                )
            } else {
                (0x20, 0)
            },
        )
    } else {
        (
            key.len() / 2 + 1,
            if key.len() & 1 == 1 {
                (
                    0x10 + key[0], // Odd: (1<<4) + first nibble
                    1,
                )
            } else {
                (0, 0)
            },
        )
    };
    let (kp, kl) = if compact_len > 1 {
        (Some(0x80 + compact_len as u8), compact_len)
    } else {
        (None, 1)
    };
    let total_len = if kp.is_some() { 1 } else { 0 } + kl + 33;

    let mut hasher = Keccak256::new();
    hasher.update(&generate_struct_len(total_len));
    if let Some(kp) = kp {
        hasher.update(&[kp]);
    }
    hasher.update(&[compact0]);
    if compact_len > 1 {
        for _ in 1..compact_len {
            hasher.update(&[key[ni] * 16 + key[ni + 1]]);
            ni += 2
        }
    }
    hasher.update(&[0x80 + KECCAK_LENGTH as u8]);
    hasher.update(&hash[..]);
    // Replace previous hash with the new one
    H256::from_slice(&hasher.finalize())
}

fn complete_leaf_hash(
    kp: Option<u8>,
    kl: usize,
    compact_len: usize,
    key: &[u8],
    compact0: u8,
    mut ni: usize,
    val: impl rlputil::RlpSerializable,
    singleton: bool,
) -> ArrayVec<u8, 33> {
    let total_len = if kp.is_some() { 1 } else { 0 } + kl + val.double_rlp_len();
    let len_prefix = generate_struct_len(total_len);
    let embedded = !singleton && total_len + len_prefix.len() < KECCAK_LENGTH;

    let mut buf = ArrayVec::new();
    if embedded {
        buf.try_extend_from_slice(&len_prefix).unwrap();
        if let Some(kp) = kp {
            buf.push(kp);
        }
        buf.push(compact0);
        for _ in 1..compact_len {
            buf.push(key[ni] * 16 + key[ni + 1]);
            ni += 2
        }
        let mut b = buf.writer();
        val.to_double_rlp(&mut b);
    } else {
        let mut hasher = Keccak256::new();
        hasher.update(&len_prefix);
        if let Some(kp) = kp {
            hasher.update(&[kp]);
        }
        hasher.update(&[compact0]);
        for _ in 1..compact_len {
            hasher.update(&[key[ni] * 16 + key[ni + 1]]);
            ni += 2;
        }
        val.to_double_rlp(&mut hasher);
        buf.push(0x80 + KECCAK_LENGTH as u8);
        buf.try_extend_from_slice(&hasher.finalize()[..]).unwrap();
    }

    buf
}

fn leaf_hash_with_key_val(
    key: &[u8],
    val: rlputil::RlpSerializableBytes<'_>,
    singleton: bool,
) -> ArrayVec<u8, 33> {
    // Compute the total length of binary representation
    // Write key
    let compact_len = (key.len() - 1) / 2 + 1;
    let (compact0, ni) = if key.len() & 1 == 0 {
        (0x30 + key[0], 1) // Odd: (3<<4) + first nibble
    } else {
        (0x20, 0)
    };
    let (kp, kl) = if compact_len > 1 {
        (Some(0x80 + compact_len as u8), compact_len)
    } else {
        (None, 1)
    };
    complete_leaf_hash(kp, kl, compact_len, key, compact0, ni, val, singleton)
}

fn compact_to_hex(compact: &[u8]) -> Vec<u8> {
    if compact.is_empty() {
        return vec![];
    }
    let mut base = keybytes_to_hex(compact);
    // delete terminator flag
    if base[0] < 2 {
        base.pop();
    }
    // apply odd flag
    let chop = (2 - base[0] as usize) & 1;
    base[chop..].to_vec()
}

fn keybytes_to_hex(s: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(s.len() * 2 + 1);
    for b in s.iter().copied() {
        nibbles.push(b / 16);
        nibbles.push(b % 16);
    }
    nibbles.push(16);
    nibbles
}

#[cfg(test)]
mod tests {
    use crate::res::chainspec::{MAINNET, ROPSTEN, SEPOLIA};

    use super::*;
    use hex_literal::hex;
    use maplit::hashmap;
    use std::collections::hash_map::Entry;
    use tracing_subscriber::{prelude::*, EnvFilter};

    #[derive(Debug, Default)]
    struct AccountUpdate {
        account: Option<Account>,
        storage: HashMap<H256, Option<U256>>,
    }

    #[derive(Debug, Default)]
    struct MockState {
        accounts: HashMap<Address, Account>,
        storage: HashMap<(Address, H256), U256>,
        branches: HashMap<Vec<u8>, BranchData>,
    }

    impl State for MockState {
        #[instrument(skip(self))]
        fn get_branch(&mut self, prefix: &[u8]) -> anyhow::Result<Option<BranchData>> {
            Ok(self.branches.get(prefix).cloned())
        }

        #[instrument(skip(self))]
        fn get_account(&mut self, address: Address) -> anyhow::Result<Option<Account>> {
            Ok(self.accounts.get(&address).copied())
        }

        #[instrument(skip(self))]
        fn get_storage(
            &mut self,
            address: Address,
            location: H256,
        ) -> anyhow::Result<Option<U256>> {
            Ok(self.storage.get(&(address, location)).copied())
        }
    }

    fn setup() {
        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_target(false))
            .with(EnvFilter::from_default_env())
            .try_init();
    }

    #[test]
    fn empty() {
        setup();

        let mut state = MockState::default();

        assert_eq!(
            HexPatriciaHashed::new(&mut state)
                .process_updates(HashMap::new())
                .unwrap(),
            (EMPTY_ROOT, HashMap::new())
        );
    }

    #[test]
    fn bitmap_nibble_iterator() {
        assert_eq!(
            BranchBitmap(0b1000000110000000).iter().collect::<Vec<_>>(),
            &[0x7, 0x8, 0xf]
        );
    }

    #[test]
    fn branchdata_encoding() {
        for (buf, branch_data) in [
            (
                &hex!("818081800434c783e610b30e83ecff161effbb7cd591dfccb72200000000000000000000000000000000000000000000000000000000000000070434c783e610b30e83ecff161effbb7cd591dfccb722000000000000000000000000000000000000000000000000000000000000000e0434c783e610b30e83ecff161effbb7cd591dfccb7220000000000000000000000000000000000000000000000000000000000000004") as &[u8],
                BranchData {
                    // 7, 8, f
                    touch_map: BranchBitmap(0b1000000110000000),
                    after_map: BranchBitmap(0b1000000110000000),
                    payload: vec![
                        CellPayload {
                            field_bits: STORAGE_PLAIN_PART,
                            extension: None,
                            apk: None,
                            spk: Some((Address::from(hex!("c783e610b30e83ecff161effbb7cd591dfccb722")), H256(hex!("0000000000000000000000000000000000000000000000000000000000000007")))),
                            h: None,
                        },
                        CellPayload {
                            field_bits: STORAGE_PLAIN_PART,
                            extension: None,
                            apk: None,
                            spk: Some((Address::from(hex!("c783e610b30e83ecff161effbb7cd591dfccb722")), H256(hex!("000000000000000000000000000000000000000000000000000000000000000e")))),
                            h: None,
                        },
                        CellPayload {
                            field_bits: STORAGE_PLAIN_PART,
                            extension: None,
                            apk: None,
                            spk: Some((Address::from(hex!("c783e610b30e83ecff161effbb7cd591dfccb722")), H256(hex!("0000000000000000000000000000000000000000000000000000000000000004")))),
                            h: None,
                        },
                    ],
                },
            ),
            (
                &hex!("2f7f2f7f0434c783e610b30e83ecff161effbb7cd591dfccb72200000000000000000000000000000000000000000000000000000000000000050901092084b6ffa0dc93412dbc5675a4856167d494f018749d04036ca7cbdd2b4c21141c0434c783e610b30e83ecff161effbb7cd591dfccb72200000000000000000000000000000000000000000000000000000000000000060434c783e610b30e83ecff161effbb7cd591dfccb722000000000000000000000000000000000000000000000000000000000001000208209f4533f1b8b641fe63d28fd5c827deca05427b086575535adf8536b7c19571d40434c783e610b30e83ecff161effbb7cd591dfccb7220000000000000000000000000000000000000000000000000000000000010004082078e36b30cc9dace946d7e93f6f9fd2e1b1ca7aee38b5b483417f0fa95f05e6dc0434c783e610b30e83ecff161effbb7cd591dfccb72200000000000000000000000000000000000000000000000000000000000100050820e8a4584ec3838e5f013e695e14c7443acacd635a6bc90dd5165947dd712d9a6c0820c00d8050a3e3af1ec71d35ef3cc72ee99127680c96db1f439c7b04e9ea6badb90820356e9beaa88ef7b6fce769d2a711dae16df4b2916a66a2182d50be8e590fda3e0820151eba0a12fd97cbc70045e701fbe6b2c6d13141c147ae4f11f0e9259d816a45") as &[u8],
                BranchData {
                    touch_map: BranchBitmap(0b0010111101111111),
                    after_map: BranchBitmap(0b0010111101111111),
                    payload: vec![
                        CellPayload {
                            field_bits: STORAGE_PLAIN_PART,
                            extension: None,
                            apk: None,
                            spk: Some((hex!("c783e610b30e83ecff161effbb7cd591dfccb722").into(), hex!("0000000000000000000000000000000000000000000000000000000000000005").into())),
                            h: None,
                        },
                        CellPayload {
                            field_bits: HASHEDKEY_PART | HASH_PART,
                            extension: Some({
                                let mut out = ArrayVec::new();
                                out.push(0x09);
                                out
                            }),
                            apk: None,
                            spk: None,
                            h: Some(hex!("84b6ffa0dc93412dbc5675a4856167d494f018749d04036ca7cbdd2b4c21141c").into()),
                        },
                        CellPayload {
                            field_bits: STORAGE_PLAIN_PART,
                            extension: None,
                            apk: None,
                            spk: Some((hex!("c783e610b30e83ecff161effbb7cd591dfccb722").into(), hex!("0000000000000000000000000000000000000000000000000000000000000006").into())),
                            h: None,
                        },
                        CellPayload {
                            field_bits: STORAGE_PLAIN_PART,
                            extension: None,
                            apk: None,
                            spk: Some((hex!("c783e610b30e83ecff161effbb7cd591dfccb722").into(), hex!("0000000000000000000000000000000000000000000000000000000000010002").into())),
                            h: None,
                        },
                        CellPayload {
                            field_bits: HASH_PART,
                            extension: None,
                            apk: None,
                            spk: None,
                            h: Some(hex!("9f4533f1b8b641fe63d28fd5c827deca05427b086575535adf8536b7c19571d4").into()),
                        },
                        CellPayload {
                            field_bits: STORAGE_PLAIN_PART,
                            extension: None,
                            apk: None,
                            spk: Some((hex!("c783e610b30e83ecff161effbb7cd591dfccb722").into(), hex!("0000000000000000000000000000000000000000000000000000000000010004").into())),
                            h: None,
                        },
                        CellPayload {
                            field_bits: HASH_PART,
                            extension: None,
                            apk: None,
                            spk: None,
                            h: Some(hex!("78e36b30cc9dace946d7e93f6f9fd2e1b1ca7aee38b5b483417f0fa95f05e6dc").into()),
                        },
                        CellPayload {
                            field_bits: STORAGE_PLAIN_PART,
                            extension: None,
                            apk: None,
                            spk: Some((hex!("c783e610b30e83ecff161effbb7cd591dfccb722").into(), hex!("0000000000000000000000000000000000000000000000000000000000010005").into())),
                            h: None,
                        },
                        CellPayload {
                            field_bits: HASH_PART,
                            extension: None,
                            apk: None,
                            spk: None,
                            h: Some(hex!("e8a4584ec3838e5f013e695e14c7443acacd635a6bc90dd5165947dd712d9a6c").into()),
                        },
                        CellPayload {
                            field_bits: HASH_PART,
                            extension: None,
                            apk: None,
                            spk: None,
                            h: Some(hex!("c00d8050a3e3af1ec71d35ef3cc72ee99127680c96db1f439c7b04e9ea6badb9").into()),
                        },
                        CellPayload {
                            field_bits: HASH_PART,
                            extension: None,
                            apk: None,
                            spk: None,
                            h: Some(hex!("356e9beaa88ef7b6fce769d2a711dae16df4b2916a66a2182d50be8e590fda3e").into()),
                        },
                        CellPayload {
                            field_bits: HASH_PART,
                            extension: None,
                            apk: None,
                            spk: None,
                            h: Some(hex!("151eba0a12fd97cbc70045e701fbe6b2c6d13141c147ae4f11f0e9259d816a45").into()),
                        },
                    ]
                }
            )
        ] {
            let (decoded, pos) = BranchData::decode(buf, 0).unwrap();
            assert_eq!(pos, buf.len());
            assert_eq!(decoded, branch_data);

            assert_eq!(decoded.encode(), buf);
        }
    }

    fn test_genesis(
        input: impl IntoIterator<
            Item = (
                [u8; 32],
                impl IntoIterator<Item = (impl Into<Address>, impl AsU256)>,
            ),
        >,
    ) {
        setup();

        let mut state = MockState::default();

        for (expected_state_root, balances) in input {
            let mut updates = HashMap::new();
            for (address, balance) in balances {
                let address = address.into();
                state.accounts.entry(address).or_default().balance += balance.as_u256();

                updates.insert(
                    address,
                    ProcessUpdateArg {
                        account_changed: true,
                        changed_storage: HashSet::new(),
                    },
                );
            }
            // let mut uncovered_nibbles = BranchBitmap(1);
            // while uncovered_nibbles.parts() > 0 {
            //     let address: Address = rand::random();

            //     let hashed_address = hash_key(&address[..], 0);

            //     if uncovered_nibbles.has(hashed_address[0]) {
            //         uncovered_nibbles.remove_nibble(hashed_address[0]);
            //         updates.insert(
            //             address,
            //             ProcessUpdateArg {
            //                 account_changed: true,
            //                 changed_storage: HashSet::new(),
            //             },
            //         );
            //     }
            // }
            let (state_root, updates) = HexPatriciaHashed::new(&mut state)
                .process_updates(updates)
                .unwrap();
            for (k, branch) in updates {
                match state.branches.entry(k) {
                    Entry::Occupied(pre) => {
                        let (k, pre) = pre.remove_entry();
                        state
                            .branches
                            .insert(k, merge_hex_branches(&pre, &branch).unwrap());
                    }
                    Entry::Vacant(e) => {
                        e.insert(branch);
                    }
                }
            }

            assert_eq!(state_root, H256(expected_state_root));
        }
    }

    #[test]
    fn sepolia_genesis() {
        test_genesis([
            (
                hex!("5eb6e371a698b8d68f665192350ffcecbbbf322916f4b51bd79bb6887da3f494"),
                SEPOLIA.balances[&BlockNumber(0)].clone(),
            ),
            (
                hex!("c91d4ecd59dce3067d340b3aadfc0542974b4fb4db98af39f980a91ea00db9dc"),
                hashmap! { hex!("2f14582947e292a2ecd20c430b46f2d27cfe213c").into() => U256::from(2 * ETHER) },
            ),
            (
                hex!("1a6f6e131d93e4ba1cc27ddd8e764b303247959e9adcf744158377b923a38e5f"),
                hashmap! { hex!("2f14582947e292a2ecd20c430b46f2d27cfe213c").into() => U256::from(2 * ETHER) },
            ),
        ]);
    }

    #[test]
    fn ropsten_genesis() {
        test_genesis([
            (
                hex!("217b0bbcfb72e2d57e28f33cb361b9983513177755dc3f33ce3e7022ed62b77b"),
                ROPSTEN.balances[&BlockNumber(0)].clone(),
            ),
            (
                hex!("c7b01007a10da045eacb90385887dd0c38fcb5db7393006bdde24b93873c334b"),
                hashmap! { hex!("d1aeb42885a43b72b518182ef893125814811048").into() => U256::from(5 * ETHER) },
            ),
            (
                hex!("afaa970cf920e8d3bfd5dd42881cf5508a42d5f0009e4ed86d3e68814b9dacf7"),
                hashmap! { hex!("d1aeb42885a43b72b518182ef893125814811048").into() => U256::from(5 * ETHER) },
            ),
        ]);
    }

    #[test]
    fn mainnet_genesis() {
        test_genesis([
            (
                hex!("d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544"),
                MAINNET.balances[&BlockNumber(0)].clone(),
            ),
            (
                hex!("d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3"),
                hashmap! { hex!("05a56e2d52c817161883f50c441c3228cfe54d9f").into() => U256::from(5 * ETHER) },
            ),
        ]);
    }
}
