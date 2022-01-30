use super::*;
use crate::{crypto::keccak256, models::*, prefix_length};
use anyhow::{bail, ensure, format_err, Context};
use arrayvec::ArrayVec;
use bytes::{Bytes, BytesMut};
use fastrlp::{Encodable, RlpEncodable};
use sha3::{Digest, Keccak256};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
};
use tracing::*;

pub type AccountCellPayload = RlpAccount;
pub type StorageCellPayload = U256;

const RLP_EMPTY_STRING_CODE: u8 = 0x80;

#[derive(Clone, Debug)]
pub struct Cell<K, V>
where
    K: AsRef<[u8]>,
{
    hash: Option<H256>,
    down_hashed_key: ArrayVec<u8, 65>,
    extension: ArrayVec<u8, 64>,
    payload: Option<(K, Option<V>)>,
}

impl<K, V> Default for Cell<K, V>
where
    K: AsRef<[u8]>,
{
    fn default() -> Self {
        Self {
            hash: Default::default(),
            down_hashed_key: Default::default(),
            extension: Default::default(),
            payload: Default::default(),
        }
    }
}

impl<K, V> Cell<K, V>
where
    K: AsRef<[u8]>,
    V: fastrlp::Encodable,
{
    fn compute_hash_len(&self, depth: usize) -> usize {
        if let Some((_, Some(value))) = &self.payload {
            let key_len = 64 - depth + 1; // Length of hex key with terminator character
            let compact_len = (key_len - 1) / 2 + 1;
            let (kp, kl) = if compact_len > 1 {
                (1, compact_len)
            } else {
                (0, 1)
            };
            let mut out = BytesMut::new();
            value.encode(&mut out);
            let total_len = kp + kl + out.len();
            let pt = rlputil::generate_struct_len(total_len).len();
            if total_len + pt < KECCAK_LENGTH {
                return total_len + pt;
            }
        }

        KECCAK_LENGTH + 1
    }

    fn fill_from_upper_cell(&mut self, up_cell: Cell<K, V>, depth_increment: usize) {
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
        self.payload = up_cell.payload;

        self.hash = up_cell.hash;
    }

    fn fill_from_lower_cell(
        &mut self,
        low_cell: Cell<K, V>,
        low_depth: usize,
        pre_extension: &[u8],
        nibble: usize,
    ) {
        if low_depth < 64 || low_cell.payload.is_some() {
            self.payload = low_cell.payload;
        }

        self.hash = low_cell.hash;
        if self.hash.is_some() {
            if self.payload.is_none() && low_depth < 64 {
                // Extension is related to branch node, we prepend it by preExtension | nibble
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
    }

    fn derive_hashed_keys(&mut self, depth: usize) -> anyhow::Result<()> {
        let mut extra_len = 0_usize;
        if self.payload.is_some() {
            extra_len = 64_usize
                .checked_sub(depth)
                .ok_or_else(|| format_err!("plain_key present at depth > 64"))?;
        }

        if extra_len > 0 {
            let orig = self.down_hashed_key.clone();
            while self.down_hashed_key.remaining_capacity() > 0 {
                self.down_hashed_key.push(0);
            }
            if !self.down_hashed_key.is_empty() {
                let dst = &mut self.down_hashed_key[extra_len..];
                let len = std::cmp::min(dst.len(), orig.len());
                dst[..len].copy_from_slice(&orig[..len]);
            }
            self.down_hashed_key.truncate(orig.len() + extra_len);
            if let Some((plain_key, _)) = &self.payload {
                let k = hash_key(plain_key.as_ref(), depth);
                self.down_hashed_key[..k.len()].copy_from_slice(&k[..]);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct StoredCell<K> {
    pub field_bits: PartFlags,
    pub extension: Option<ArrayVec<u8, 64>>,
    pub plain_key: Option<K>,
    pub hash: Option<H256>,
}

impl<K> Debug for StoredCell<K>
where
    K: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellPayload")
            .field("field_bits", &self.field_bits)
            .field("extension", &self.extension.as_ref().map(hex::encode))
            .field("plain_key", &self.plain_key)
            .field("hash", &self.hash)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchData<K> {
    pub touch_map: BranchBitmap,
    pub after_map: BranchBitmap,
    pub payload: Vec<StoredCell<K>>,
}

impl<K> Default for BranchData<K> {
    fn default() -> Self {
        Self {
            touch_map: Default::default(),
            after_map: Default::default(),
            payload: Default::default(),
        }
    }
}

impl<K> BranchData<K>
where
    K: crate::kv::traits::TableDecode + Clone,
{
    pub fn decode_with_pos(buf: &[u8], mut pos: usize) -> anyhow::Result<(Self, usize)> {
        fn extract_length(data: &[u8], mut pos: usize) -> anyhow::Result<(usize, usize)> {
            let mut n = data[pos..].len();
            let (l, rem) = unsigned_varint::decode::usize(&data[pos..])?;
            n -= rem.len();

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

            let mut plain_key = None;
            if field_bits & PLAINKEY_PART != 0 {
                let l;
                (pos, l) = extract_length(buf, pos)?;

                if l > 0 {
                    plain_key = Some(crate::kv::traits::TableDecode::decode(
                        buf.get(pos..pos + l)
                            .ok_or_else(|| format_err!("too short"))?,
                    )?);
                    pos += l;
                }
            }

            let mut hash = None;
            if field_bits & HASH_PART != 0 {
                let l;
                (pos, l) = extract_length(buf, pos)?;

                if l > 0 {
                    ensure!(l == KECCAK_LENGTH);
                    hash = Some(H256::from_slice(&buf[pos..pos + KECCAK_LENGTH]));
                    pos += l;
                }
            }

            payload.push(StoredCell {
                field_bits,
                extension,
                plain_key,
                hash,
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

pub trait State<K, V> {
    fn get_branch(&mut self, prefix: &[u8]) -> anyhow::Result<Option<BranchData<K>>>;
    fn get_payload(&mut self, key: &K) -> anyhow::Result<Option<V>>;
}

#[derive(Debug)]
struct CellRow<K, V>
where
    K: AsRef<[u8]>,
{
    /// Cells in this row
    cells: [Cell<K, V>; 16],
    /// Depth of cells in this row
    depth: usize,
    /// Whether there was a branch node in the database loaded in unfold
    branch_before: bool,
    /// Bitmap of cells that were either present before modification, or modified or deleted
    touch_map: BranchBitmap,
    /// Bitmap of cells that were present after modification
    after_map: BranchBitmap,
}

impl<K, V> Default for CellRow<K, V>
where
    K: AsRef<[u8]>,
{
    fn default() -> Self {
        Self {
            cells: Default::default(),
            depth: Default::default(),
            branch_before: Default::default(),
            touch_map: Default::default(),
            after_map: Default::default(),
        }
    }
}

#[derive(Debug)]
struct CellGrid<K, V>
where
    K: AsRef<[u8]>,
{
    /// Root cell of the tree
    root: Cell<K, V>,
    /// Rows of the grid correspond to the level of depth in the patricia tree
    /// Columns of the grid correspond to pointers to the nodes further from the root
    rows: ArrayVec<CellRow<K, V>, 64>,
}

impl<K: AsRef<[u8]>, V> Default for CellGrid<K, V> {
    fn default() -> Self {
        Self {
            root: Default::default(),
            rows: Default::default(),
        }
    }
}

impl<K, V> CellGrid<K, V>
where
    K: AsRef<[u8]>,
{
    fn delete_row(&mut self, row: usize) {
        self.rows.truncate(row);
    }
    fn cell(&self, cell_position: Option<CellPosition>) -> &Cell<K, V> {
        if let Some(cell_position) = cell_position {
            &self.rows[cell_position.row as usize].cells[cell_position.col as usize]
        } else {
            &self.root
        }
    }

    fn cell_mut(&mut self, cell_position: Option<CellPosition>) -> &mut Cell<K, V> {
        if let Some(cell_position) = cell_position {
            &mut self.rows[cell_position.row as usize].cells[cell_position.col as usize]
        } else {
            &mut self.root
        }
    }
}

fn hash_key(plain_key: &[u8], hashed_key_offset: usize) -> ArrayVec<u8, 64> {
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

/// HexPatriciaHashed implements commitment based on patricia merkle tree with radix 16,
/// with keys pre-hashed by keccak256
#[derive(Debug)]
pub struct HexPatriciaHashed<'state, K, V, S>
where
    S: State<K, V>,
    K: AsRef<[u8]>,
{
    state: &'state mut S,

    grid: CellGrid<K, V>,
    /// Length of the key that reflects current positioning of the grid. It may be larger than number of active rows,
    /// if a account leaf cell represents multiple nibbles in the key
    /// For each row indicates which column is currently selected
    current_key: ArrayVec<u8, 64>,
    root_checked: bool, // Set to false if it is not known whether the root is empty, set to true if it is checked
    root_touched: bool,
    root_present: bool,
}

impl<'state, K, V, S> HexPatriciaHashed<'state, K, V, S>
where
    K: AsRef<[u8]> + Clone + Debug + crate::kv::traits::TableObject,
    V: fastrlp::Encodable + Clone + Debug,
    S: State<K, V>,
{
    pub fn new(state: &'state mut S, previous_root: H256) -> Self {
        let mut s = Self {
            state,

            grid: Default::default(),
            current_key: Default::default(),
            root_checked: Default::default(),
            root_touched: Default::default(),
            root_present: Default::default(),
        };
        s.grid.root.hash = Some(previous_root);
        s
    }

    pub fn process_updates(
        mut self,
        updates: impl IntoIterator<Item = K>,
    ) -> anyhow::Result<(H256, HashMap<Vec<u8>, BranchData<K>>)> {
        let mut branch_node_updates = HashMap::new();

        let mut changed_keys = BTreeMap::new();

        for plain_key in updates {
            changed_keys.insert(hash_key(plain_key.as_ref(), 0), plain_key);
        }

        for (hashed_key, plain_key) in changed_keys {
            trace!(
                "plain_key={:?} hashed_key={:?}, current_key={:?}",
                hex::encode(plain_key.as_ref()),
                hex::encode(&hashed_key),
                hex::encode(&self.current_key),
            );

            // Keep folding until the current_key is the prefix of the key we modify
            while self.need_folding(&hashed_key[..]) {
                if let (Some(branch_node_update), update_key) = self.fold()? {
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
            if let Some(payload) = self.state.get_payload(&plain_key)? {
                self.update_cell(plain_key, hashed_key, payload);
            } else {
                self.delete_cell(hashed_key);
            }
        }

        // Folding everything up to the root
        while !self.grid.rows.is_empty() {
            if let (Some(branch_data), update_key) = self.fold()? {
                branch_node_updates.insert(update_key, branch_data);
            }
        }

        Ok((
            self.compute_cell_hash(None, 0).unwrap_hash(),
            branch_node_updates,
        ))
    }

    #[instrument(skip(self))]
    fn compute_cell_hash(&mut self, pos: Option<CellPosition>, depth: usize) -> HashOrValue {
        let cell = self.grid.cell_mut(pos);
        let hash = if let Some((plain_key, Some(value))) = &cell.payload {
            cell.down_hashed_key.clear();
            cell.down_hashed_key
                .try_extend_from_slice(&*hash_key(plain_key.as_ref(), depth))
                .unwrap();
            cell.down_hashed_key.push(16); // Add terminator

            let mut value_rlp = BytesMut::new();
            value.encode(&mut value_rlp);
            trace!(
                "accountLeafHashWithKey for [{}]=>[{}]",
                hex::encode(&cell.down_hashed_key[..]),
                hex::encode(&value_rlp)
            );
            HashOrValue::from_rlp(&leaf_node_rlp(&cell.down_hashed_key[..], &value_rlp[..])[..])
        } else if !cell.extension.is_empty() {
            // Extension
            let cell_hash = cell.hash.expect("extension without hash");
            trace!(
                "extension hash for [{}]=>[{:?}]",
                hex::encode(&cell.extension),
                cell_hash
            );
            HashOrValue::from_rlp(&extension_node_rlp(
                &cell.extension,
                &fastrlp::encode_fixed_size(&cell_hash)[..],
            ))
        } else if let Some(cell_hash) = cell.hash {
            HashOrValue::Hash(cell_hash)
        } else {
            HashOrValue::Hash(EMPTY_ROOT)
        };

        trace!("computed cell hash {:?}", hash);

        hash
    }

    #[instrument(skip_all, fields(root_checked = self.root_checked))]
    fn need_unfolding(&self, hashed_key: &[u8]) -> usize {
        let cell: &Cell<K, V>;
        let mut depth = 0_usize;
        if self.grid.rows.is_empty() {
            trace!("root");
            cell = &self.grid.root;
            if cell.down_hashed_key.is_empty() && cell.hash.is_none() && !self.root_checked {
                // Need to attempt to unfold the root
                return 1;
            }
        } else {
            let col = hashed_key[self.current_key.len()] as usize;
            let row = &self.grid.rows[self.grid.rows.len() - 1];
            cell = &row.cells[col];
            depth = row.depth;
            trace!(
                "cell ({}, {:x}), currentKey=[{}], depth={}, cell.h=[{:?}]",
                self.grid.rows.len() - 1,
                col,
                hex::encode(&self.current_key[..]),
                depth,
                cell.hash
            );
        }
        if hashed_key.len() <= depth {
            return 0;
        }
        if cell.down_hashed_key.is_empty() {
            if cell.hash.is_none() {
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
        cpl + 1
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

        let cell_row = &mut self.grid.rows[row];
        let branch_data =
            branch_data.ok_or_else(|| format_err!("branch data unexpectedly absent"))?;
        cell_row.branch_before = true;
        let bitmap = branch_data.after_map;
        if deleted {
            // All cells come as deleted (touched but not present after)
            cell_row.after_map = Default::default();
            cell_row.touch_map = bitmap;
        } else {
            cell_row.after_map = bitmap;
            cell_row.touch_map = Default::default();
        }
        if bitmap.parts() != branch_data.payload.len() {
            bail!(
                "len mismatch {} != {}",
                bitmap.parts(),
                branch_data.payload.len()
            );
        }

        trace!(
            "unfold_branch_node [branch_data={}], after_map={}, touch_map={}",
            hex::encode(crate::kv::traits::TableEncode::encode(branch_data.clone())),
            cell_row.after_map,
            cell_row.touch_map,
        );
        for (nibble, cell_payload) in bitmap.iter().zip(branch_data.payload.into_iter()) {
            let cell = &mut self.grid.rows[row].cells[nibble as usize];
            cell.down_hashed_key.clear();
            cell.extension.clear();
            if let Some(extension) = cell_payload.extension {
                cell.down_hashed_key
                    .try_extend_from_slice(&extension[..])
                    .unwrap();
                cell.extension = extension;
            }

            cell.payload = None;
            if let Some(plain_key) = cell_payload.plain_key {
                let value = self.state.get_payload(&plain_key)?;

                cell.payload = Some((plain_key, value));
            }

            cell.hash = cell_payload.hash;
            trace!(
                "cell ({}, {:x}) depth={}, hash=[{:?}], payload=[{:?}], ex=[{}]",
                row,
                nibble,
                depth,
                cell.hash,
                cell.payload,
                hex::encode(&cell.extension)
            );
            cell.derive_hashed_keys(depth)?;
        }

        Ok(())
    }

    #[instrument(skip(self, hashed_key), fields(hashed_key = &*hex::encode(hashed_key), active_rows=self.grid.rows.len()))]
    fn unfold(&mut self, hashed_key: &[u8], unfolding: usize) -> anyhow::Result<()> {
        let touched;
        let present;
        let mut up_depth = 0;
        let depth;
        let up_cell;
        if self.grid.rows.is_empty() {
            let root = &self.grid.root;
            if self.root_checked && root.hash.is_none() && root.down_hashed_key.is_empty() {
                // No unfolding for empty root
                return Ok(());
            }
            up_cell = root.clone();
            touched = self.root_touched;
            present = self.root_present;
            trace!("root, touched={}, present={}", touched, present);
        } else {
            let row_idx = self.grid.rows.len() - 1;
            let row = &self.grid.rows[row_idx];
            up_depth = row.depth;
            let col = hashed_key[up_depth - 1];
            up_cell = row.cells[col as usize].clone();
            touched = row.touch_map.has(col);
            present = row.after_map.has(col);
            trace!(
                "upCell ({}, {:x}), touched {}, present {}",
                row_idx,
                col,
                touched,
                present
            );
            self.current_key.push(col);
        };
        let row = self.grid.rows.len();
        self.grid.rows.push(CellRow::default());
        if up_cell.down_hashed_key.is_empty() {
            depth = up_depth + 1;
            self.unfold_branch_node(row, touched && !present, depth)?;
        } else if up_cell.down_hashed_key.len() >= unfolding {
            depth = up_depth + unfolding;
            let nibble = up_cell.down_hashed_key[unfolding - 1];
            if touched {
                self.grid.rows[row].touch_map = BranchBitmap::from_nibble(nibble);
            }
            if present {
                self.grid.rows[row].after_map = BranchBitmap::from_nibble(nibble);
            }
            let cell = &mut self.grid.rows[row].cells[nibble as usize];
            cell.fill_from_upper_cell(up_cell.clone(), unfolding);
            trace!("cell ({}, {:x}) depth={}", row, nibble, depth);
            if row == 64 {
                cell.payload = None;
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
                self.grid.rows[row].touch_map = BranchBitmap::from_nibble(nibble);
            }
            if present {
                self.grid.rows[row].after_map = BranchBitmap::from_nibble(nibble);
            }
            let cell = &mut self.grid.rows[row].cells[nibble as usize];
            cell.fill_from_upper_cell(up_cell.clone(), up_cell.down_hashed_key.len());
            trace!("cell ({}, {:x}) depth={}", row, nibble, depth);
            if row == 64 {
                cell.payload = None;
            }
            if up_cell.down_hashed_key.len() > 1 {
                self.current_key
                    .try_extend_from_slice(
                        &up_cell.down_hashed_key[..up_cell.down_hashed_key.len() - 1],
                    )
                    .unwrap();
            }
        }
        self.grid.rows[row].depth = depth;

        Ok(())
    }

    fn need_folding(&self, hashed_key: &[u8]) -> bool {
        !hashed_key[..].starts_with(&self.current_key[..])
    }

    #[instrument(skip(self), fields(active_rows=self.grid.rows.len(), current_key=&*hex::encode(&self.current_key), touch_map=&*self.grid.rows.last().unwrap().touch_map.to_string(), after_map=&*self.grid.rows.last().unwrap().after_map.to_string()))]
    pub(crate) fn fold(&mut self) -> anyhow::Result<(Option<BranchData<K>>, Vec<u8>)> {
        ensure!(!self.grid.rows.is_empty(), "cannot fold - no active rows");
        // Move information to the row above
        let row = self.grid.rows.len() - 1;
        let mut col = 0;
        let mut up_depth = 0;
        let up_cell = if row == 0 {
            trace!("upcell is root");

            None
        } else {
            up_depth = self.grid.rows[row - 1].depth;
            col = self.current_key[up_depth - 1];

            trace!("upcell is ({} x {}), upDepth={}", row - 1, col, up_depth);

            Some(CellPosition {
                row: row - 1,
                col: col as usize,
            })
        };
        let depth = self.grid.rows[row].depth;
        let mut branch_data = None;

        let update_key = hex_to_compact(&self.current_key);
        trace!(
            "touch_map[{}]={}, after_map[{}]={}",
            row,
            self.grid.rows[row].touch_map,
            row,
            self.grid.rows[row].after_map,
        );

        let parts_count = self.grid.rows[row].after_map.parts();
        match parts_count {
            0 => {
                // Everything deleted
                if self.grid.rows[row].touch_map.parts() > 0 {
                    if row == 0 {
                        // Root is deleted because the tree is empty
                        self.root_touched = true;
                        self.root_present = false;
                    } else {
                        // Deletion is propagated upwards
                        self.grid.rows[row - 1].touch_map.add_nibble(col);
                        self.grid.rows[row - 1].after_map.remove_nibble(col);
                    }
                }
                let up_cell = self.grid.cell_mut(up_cell);
                up_cell.hash = None;
                up_cell.payload = None;
                up_cell.extension.clear();
                up_cell.down_hashed_key.clear();
                if self.grid.rows[row].branch_before {
                    branch_data = Some(BranchData {
                        touch_map: self.grid.rows[row].touch_map,
                        ..Default::default()
                    });
                }
                self.grid.rows.pop();
                if up_depth > 0 {
                    self.current_key.truncate(up_depth - 1);
                } else {
                    self.current_key.clear();
                }
            }
            1 => {
                // Leaf or extension node
                if self.grid.rows[row].touch_map.parts() != 0 {
                    // any modifications
                    if row == 0 {
                        self.root_touched = true;
                    } else {
                        // Modification is propagated upwards
                        self.grid.rows[row - 1].touch_map.add_nibble(col);
                    }
                }
                let nibble = self.grid.rows[row]
                    .after_map
                    .0
                    .trailing_zeros()
                    .try_into()
                    .unwrap();
                let cell = {
                    let cell: &Cell<K, V> = &self.grid.rows[row].cells[nibble];
                    cell.clone()
                };
                let up_cell = self.grid.cell_mut(up_cell);
                up_cell.extension.clear();
                up_cell.fill_from_lower_cell(cell, depth, &self.current_key[up_depth..], nibble);

                // Delete if it existed
                if self.grid.rows[row].branch_before {
                    branch_data = Some(BranchData {
                        touch_map: self.grid.rows[row].touch_map,
                        ..Default::default()
                    });
                }
                self.grid.rows.pop();

                self.current_key.truncate(up_depth.saturating_sub(1));
            }
            _ => {
                // Branch node
                if self.grid.rows[row].touch_map.parts() != 0 {
                    // any modifications
                    if row == 0 {
                        self.root_touched = true
                    } else {
                        // Modification is propagated upwards
                        self.grid.rows[row - 1].touch_map.add_nibble(col);
                    }
                }
                let mut changed_and_present =
                    BranchBitmap(self.grid.rows[row].touch_map.0 & self.grid.rows[row].after_map.0);
                if !self.grid.rows[row].branch_before {
                    // There was no branch node before, so we need to touch even the singular child that existed
                    self.grid.rows[row].touch_map.0 |= self.grid.rows[row].after_map.0;
                    changed_and_present.0 |= self.grid.rows[row].after_map.0;
                }
                // Calculate total length of all hashes
                let mut total_branch_len = 17 - parts_count as usize; // for every empty cell, one byte

                for nibble in self.grid.rows[row].after_map.iter() {
                    total_branch_len +=
                        self.grid.rows[row].cells[nibble as usize].compute_hash_len(depth);
                }

                let mut b = BranchData {
                    touch_map: self.grid.rows[row].touch_map,
                    after_map: self.grid.rows[row].after_map,

                    ..Default::default()
                };

                let mut hasher = Keccak256::new();
                hasher.update(&rlputil::generate_struct_len(total_branch_len));

                let mut last_nibble = 0;

                for nibble in self.grid.rows[row].after_map.iter() {
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
                        match self.compute_cell_hash(Some(cell_pos), depth) {
                            HashOrValue::Value(value) => {
                                hasher.update(value);
                            }
                            HashOrValue::Hash(hash) => {
                                hasher.update(&[fastrlp::EMPTY_STRING_CODE + KECCAK_LENGTH as u8]);
                                hasher.update(hash);
                            }
                        }
                    }

                    if changed_and_present.has(nibble) {
                        let mut field_bits = 0_u8;

                        let cell = self.grid.cell_mut(Some(cell_pos));
                        if !cell.extension.is_empty() {
                            field_bits |= HASHEDKEY_PART;
                        }
                        if cell.payload.is_some() {
                            field_bits |= PLAINKEY_PART;
                        }
                        if cell.hash.is_some() {
                            field_bits |= HASH_PART;
                        }

                        b.payload.push(StoredCell {
                            field_bits,
                            extension: if !cell.extension.is_empty() {
                                Some(cell.extension.clone())
                            } else {
                                None
                            },
                            plain_key: cell.payload.as_ref().map(|(k, _)| k.clone()),
                            hash: cell.hash,
                        });
                    }
                }

                branch_data = Some(b);

                for i in last_nibble..=16 {
                    hasher.update(&[0x80]);
                    trace!("{:x}: empty({},{:x})", i, row, i);
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
                up_cell.payload = None;

                {
                    let h = H256::from_slice(&hasher.finalize()[..]);
                    trace!("}} [{:?}]", h);
                    up_cell.hash = Some(h);
                }

                self.grid.rows.pop();

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
        Ok((branch_data, update_key))
    }

    #[instrument(skip(self), fields(active_rows = self.grid.rows.len()))]
    fn delete_cell(&mut self, hashed_key: ArrayVec<u8, 64>) {
        trace!("called");
        let cell = if let Some(row) = self.grid.rows.len().checked_sub(1) {
            if self.grid.rows[row].depth < hashed_key[..].len() {
                trace!(
                    "Skipping spurious delete depth={}, hashed_key_len={}",
                    self.grid.rows[row].depth,
                    hashed_key[..].len()
                );
                return;
            }
            let col = hashed_key[self.current_key.len()];
            if self.grid.rows[row].after_map.has(col) {
                // Prevent "spurious deletions", i.e. deletion of absent items
                self.grid.rows[row].touch_map.add_nibble(col);
                self.grid.rows[row].after_map.remove_nibble(col);
                trace!("Setting ({}, {:x})", row, col);
            } else {
                trace!("Ignoring ({}, {:x})", row, col);
            }

            &mut self.grid.rows[row].cells[col as usize]
        } else {
            self.root_touched = true;
            self.root_present = false;

            &mut self.grid.root
        };

        cell.extension.clear();
        cell.payload = None;
    }

    #[instrument(skip(self, hashed_key), fields(hashed_key = &*hex::encode(&hashed_key)))]
    fn update_cell(&mut self, plain_key: K, hashed_key: ArrayVec<u8, 64>, payload: V) {
        trace!("called");
        if self.grid.rows.is_empty() {
            self.grid.rows.push(CellRow::default());
        }
        let row = self.grid.rows.len() - 1;
        let col = hashed_key[self.current_key.len()];
        let cell_row = &mut self.grid.rows[row];
        let cell = &mut cell_row.cells[col as usize];
        cell_row.touch_map.add_nibble(col);
        cell_row.after_map.add_nibble(col);
        trace!(
            "Setting ({}, {:x}), touch_map[{}]={}, depth={}",
            row,
            col,
            row,
            cell_row.touch_map,
            cell_row.depth
        );
        if cell.down_hashed_key.is_empty() {
            cell.down_hashed_key
                .try_extend_from_slice(&hashed_key[cell_row.depth..])
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

        cell.payload = Some((plain_key, Some(payload)));
    }
}

type PartFlags = u8;

const HASHEDKEY_PART: PartFlags = 1;
const PLAINKEY_PART: PartFlags = 2;
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
pub fn merge_hex_branches<K>(
    old: BranchData<K>,
    new: BranchData<K>,
) -> anyhow::Result<BranchData<K>> {
    let mut merged = BranchData::default();

    let old_bitmap = old.touch_map.0 & old.after_map.0;
    let new_bitmap = new.touch_map.0 & new.after_map.0;

    merged.touch_map = BranchBitmap(old.touch_map.0 | new.touch_map.0);
    merged.after_map = new.after_map;

    {
        let mut bitset = old_bitmap | new_bitmap;
        let mut old_payload_iter = old.payload.into_iter();
        let mut new_payload_iter = new.payload.into_iter();
        while bitset != 0 {
            let bit = bitset & 0_u16.overflowing_sub(bitset).0;
            if new_bitmap & bit != 0 {
                // Add fields from new BranchData
                merged
                    .payload
                    .push(new_payload_iter.next().context("no payload2")?);
            }
            if old_bitmap & bit != 0 {
                let next_old_payload = old_payload_iter.next().context("no payload1")?;
                // Add fields from old BranchData
                if (new.touch_map.0 & bit == 0) && (new.after_map.0 & bit != 0) {
                    merged.payload.push(next_old_payload);
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

fn encode_path(nibbles: &[u8], terminating: bool) -> Vec<u8> {
    let mut res = vec![0u8; nibbles.len() / 2 + 1];
    let odd = nibbles.len() % 2 != 0;
    let mut i = 0usize;

    res[0] = if terminating { 0x20 } else { 0x00 };
    res[0] += if odd { 0x10 } else { 0x00 };

    if odd {
        res[0] |= nibbles[0];
        i = 1;
    }

    for byte in res.iter_mut().skip(1) {
        *byte = (nibbles[i] << 4) + nibbles[i + 1];
        i += 2;
    }

    res
}

#[derive(Clone, Debug, PartialEq)]
enum HashOrValue {
    Value(ArrayVec<u8, 31>),
    Hash(H256),
}

impl HashOrValue {
    fn from_rlp(rlp: &[u8]) -> Self {
        if rlp.len() < KECCAK_LENGTH {
            let mut v = ArrayVec::new();
            v.try_extend_from_slice(rlp).unwrap();
            Self::Value(v)
        } else {
            Self::Hash(keccak256(rlp))
        }
    }

    fn unwrap_hash(self) -> H256 {
        match self {
            HashOrValue::Value(_) => panic!("not a hash"),
            HashOrValue::Hash(hash) => hash,
        }
    }
}

fn leaf_node_rlp(path: &[u8], value: &[u8]) -> BytesMut {
    let terminating = has_term(path);
    let encoded_path = &encode_path(
        if terminating {
            &path[..path.len() - 1]
        } else {
            path
        },
        terminating,
    );

    #[derive(RlpEncodable)]
    struct S<'a> {
        encoded_path: &'a [u8],
        value: &'a [u8],
    }

    let mut out = BytesMut::new();
    S {
        encoded_path,
        value,
    }
    .encode(&mut out);
    out
}

fn extension_node_rlp(path: &[u8], child_ref: &[u8]) -> BytesMut {
    let encoded_path = Bytes::from(encode_path(path, false));

    let mut out = BytesMut::new();
    let h = fastrlp::Header {
        list: true,
        payload_length: fastrlp::Encodable::length(&encoded_path) + child_ref.len(),
    };
    h.encode(&mut out);
    encoded_path.encode(&mut out);
    out.extend_from_slice(child_ref);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kv::traits::{TableDecode, TableEncode},
        res::chainspec::{GOERLI, MAINNET, ROPSTEN, SEPOLIA},
    };
    use hex_literal::hex;
    use maplit::hashmap;
    use std::collections::hash_map::Entry;
    use tracing_subscriber::{prelude::*, EnvFilter};

    struct MockStorageState<'a> {
        storage: Option<&'a HashMap<H256, U256>>,
        branches: Option<&'a HashMap<Vec<u8>, BranchData<H256>>>,
    }

    impl<'a> State<H256, U256> for MockStorageState<'a> {
        fn get_branch(&mut self, prefix: &[u8]) -> anyhow::Result<Option<BranchData<H256>>> {
            Ok(self
                .branches
                .and_then(|branches| branches.get(prefix).cloned()))
        }

        fn get_payload(&mut self, key: &H256) -> anyhow::Result<Option<U256>> {
            Ok(self.storage.and_then(|storage| storage.get(key).copied()))
        }
    }

    trait StorageRootProducer {
        fn produce_root<'a>(&mut self, state: &mut MockStorageState<'a>) -> anyhow::Result<H256>;
    }

    #[derive(Debug, Default)]
    struct HexPatriciaHashedStorageRootProducer;

    impl StorageRootProducer for HexPatriciaHashedStorageRootProducer {
        fn produce_root<'a>(&mut self, state: &mut MockStorageState<'a>) -> anyhow::Result<H256> {
            let keys = state
                .storage
                .map(|storage| storage.keys().copied().collect::<Vec<_>>())
                .unwrap_or_default();
            let (storage_root, updates) =
                HexPatriciaHashed::new(state, EMPTY_ROOT).process_updates(keys)?;
            assert_eq!(updates, HashMap::new());
            Ok(storage_root)
        }
    }

    #[derive(Debug, Default)]
    struct MemoryState<P> {
        storage_root_producer: P,

        accounts: HashMap<Address, Account>,
        account_branches: HashMap<Vec<u8>, BranchData<Address>>,

        storage: HashMap<Address, HashMap<H256, U256>>,
        storage_branches: HashMap<Address, HashMap<Vec<u8>, BranchData<H256>>>,
    }

    impl<P> State<Address, RlpAccount> for MemoryState<P>
    where
        P: StorageRootProducer,
    {
        fn get_branch(&mut self, prefix: &[u8]) -> anyhow::Result<Option<BranchData<Address>>> {
            Ok(self.account_branches.get(prefix).cloned())
        }

        fn get_payload(&mut self, address: &Address) -> anyhow::Result<Option<RlpAccount>> {
            Ok(if let Some(acc) = self.accounts.get(address) {
                let storage = self.storage.get(address);
                let branches = self.storage_branches.get(address);

                Some(
                    acc.to_rlp(
                        self.storage_root_producer
                            .produce_root(&mut MockStorageState { storage, branches })?,
                    ),
                )
            } else {
                None
            })
        }
    }

    type MockState = MemoryState<HexPatriciaHashedStorageRootProducer>;

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
            HexPatriciaHashed::new(&mut state, EMPTY_ROOT)
                .process_updates([])
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
                &hex!("818081800234c783e610b30e83ecff161effbb7cd591dfccb72200000000000000000000000000000000000000000000000000000000000000070234c783e610b30e83ecff161effbb7cd591dfccb722000000000000000000000000000000000000000000000000000000000000000e0234c783e610b30e83ecff161effbb7cd591dfccb7220000000000000000000000000000000000000000000000000000000000000004") as &[u8],
                BranchData {
                    // 7, 8, f
                    touch_map: BranchBitmap(0b1000000110000000),
                    after_map: BranchBitmap(0b1000000110000000),
                    payload: vec![
                        StoredCell {
                            field_bits: PLAINKEY_PART,
                            extension: None,
                            plain_key: Some((Address::from(hex!("c783e610b30e83ecff161effbb7cd591dfccb722")), H256(hex!("0000000000000000000000000000000000000000000000000000000000000007")))),
                            hash: None,
                        },
                        StoredCell {
                            field_bits: PLAINKEY_PART,
                            extension: None,
                            plain_key: Some((Address::from(hex!("c783e610b30e83ecff161effbb7cd591dfccb722")), H256(hex!("000000000000000000000000000000000000000000000000000000000000000e")))),
                            hash: None,
                        },
                        StoredCell {
                            field_bits: PLAINKEY_PART,
                            extension: None,
                            plain_key: Some((Address::from(hex!("c783e610b30e83ecff161effbb7cd591dfccb722")), H256(hex!("0000000000000000000000000000000000000000000000000000000000000004")))),
                            hash: None,
                        },
                    ],
                },
            ),
            (
                &hex!("2f7f2f7f0234c783e610b30e83ecff161effbb7cd591dfccb72200000000000000000000000000000000000000000000000000000000000000050901092084b6ffa0dc93412dbc5675a4856167d494f018749d04036ca7cbdd2b4c21141c0234c783e610b30e83ecff161effbb7cd591dfccb72200000000000000000000000000000000000000000000000000000000000000060234c783e610b30e83ecff161effbb7cd591dfccb722000000000000000000000000000000000000000000000000000000000001000208209f4533f1b8b641fe63d28fd5c827deca05427b086575535adf8536b7c19571d40234c783e610b30e83ecff161effbb7cd591dfccb7220000000000000000000000000000000000000000000000000000000000010004082078e36b30cc9dace946d7e93f6f9fd2e1b1ca7aee38b5b483417f0fa95f05e6dc0234c783e610b30e83ecff161effbb7cd591dfccb72200000000000000000000000000000000000000000000000000000000000100050820e8a4584ec3838e5f013e695e14c7443acacd635a6bc90dd5165947dd712d9a6c0820c00d8050a3e3af1ec71d35ef3cc72ee99127680c96db1f439c7b04e9ea6badb90820356e9beaa88ef7b6fce769d2a711dae16df4b2916a66a2182d50be8e590fda3e0820151eba0a12fd97cbc70045e701fbe6b2c6d13141c147ae4f11f0e9259d816a45") as &[u8],
                BranchData {
                    touch_map: BranchBitmap(0b0010111101111111),
                    after_map: BranchBitmap(0b0010111101111111),
                    payload: vec![
                        StoredCell {
                            field_bits: PLAINKEY_PART,
                            extension: None,
                            plain_key: Some((hex!("c783e610b30e83ecff161effbb7cd591dfccb722").into(), hex!("0000000000000000000000000000000000000000000000000000000000000005").into())),
                            hash: None,
                        },
                        StoredCell {
                            field_bits: HASHEDKEY_PART | HASH_PART,
                            extension: Some({
                                let mut out = ArrayVec::new();
                                out.push(0x09);
                                out
                            }),
                            plain_key: None,
                            hash: Some(hex!("84b6ffa0dc93412dbc5675a4856167d494f018749d04036ca7cbdd2b4c21141c").into()),
                        },
                        StoredCell {
                            field_bits: PLAINKEY_PART,
                            extension: None,
                            plain_key: Some((hex!("c783e610b30e83ecff161effbb7cd591dfccb722").into(), hex!("0000000000000000000000000000000000000000000000000000000000000006").into())),
                            hash: None,
                        },
                        StoredCell {
                            field_bits: PLAINKEY_PART,
                            extension: None,
                            plain_key: Some((hex!("c783e610b30e83ecff161effbb7cd591dfccb722").into(), hex!("0000000000000000000000000000000000000000000000000000000000010002").into())),
                            hash: None,
                        },
                        StoredCell {
                            field_bits: HASH_PART,
                            extension: None,
                            plain_key: None,
                            hash: Some(hex!("9f4533f1b8b641fe63d28fd5c827deca05427b086575535adf8536b7c19571d4").into()),
                        },
                        StoredCell {
                            field_bits: PLAINKEY_PART,
                            extension: None,
                            plain_key: Some((hex!("c783e610b30e83ecff161effbb7cd591dfccb722").into(), hex!("0000000000000000000000000000000000000000000000000000000000010004").into())),
                            hash: None,
                        },
                        StoredCell {
                            field_bits: HASH_PART,
                            extension: None,
                            plain_key: None,
                            hash: Some(hex!("78e36b30cc9dace946d7e93f6f9fd2e1b1ca7aee38b5b483417f0fa95f05e6dc").into()),
                        },
                        StoredCell {
                            field_bits: PLAINKEY_PART,
                            extension: None,
                            plain_key: Some((hex!("c783e610b30e83ecff161effbb7cd591dfccb722").into(), hex!("0000000000000000000000000000000000000000000000000000000000010005").into())),
                            hash: None,
                        },
                        StoredCell {
                            field_bits: HASH_PART,
                            extension: None,
                            plain_key: None,
                            hash: Some(hex!("e8a4584ec3838e5f013e695e14c7443acacd635a6bc90dd5165947dd712d9a6c").into()),
                        },
                        StoredCell {
                            field_bits: HASH_PART,
                            extension: None,
                            plain_key: None,
                            hash: Some(hex!("c00d8050a3e3af1ec71d35ef3cc72ee99127680c96db1f439c7b04e9ea6badb9").into()),
                        },
                        StoredCell {
                            field_bits: HASH_PART,
                            extension: None,
                            plain_key: None,
                            hash: Some(hex!("356e9beaa88ef7b6fce769d2a711dae16df4b2916a66a2182d50be8e590fda3e").into()),
                        },
                        StoredCell {
                            field_bits: HASH_PART,
                            extension: None,
                            plain_key: None,
                            hash: Some(hex!("151eba0a12fd97cbc70045e701fbe6b2c6d13141c147ae4f11f0e9259d816a45").into()),
                        },
                    ]
                }
            )
        ] {
            assert_eq!(branch_data.clone().encode(), buf);

            let (decoded, pos) = BranchData::decode_with_pos(buf, 0).unwrap();
            assert_eq!(decoded, branch_data);
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn test_merge_hex_branches() {
        let old = BranchData::<Address>::decode(&hex!("9adf9adf0214f47cae1cf79ca6758bfc787dbd21e6bdbe7112b80214d7eddb78ed295b3c9629240e8924fb8d8874ddd80214799d329e5f583419167cd722962485926e338f4a0214e2e2659028143784d557bcec6ff3a0721048880a082078c1c89686c6a1107d6bc50d3813047b650611c56cfa497bb8c8c7172b5869b80214beef32ca5b9a198d27b4e02f4c70439fe60356cf082045f551ed12d01f47c22b7b1d389c361422fcc530c570ed3fd16e9ec6dc1acf1002148b7f0977bb4f0fbe7076fa22bc24aca043583f5e0214d9a5179f091d85051d3c982785efd1455cec86990820b2fb090bdd6c9cb01c6fe6f9f983cf3a41934d4461534773f0c62a450d4bbc2302140000006916a87b82333f4245046623b23794c65c") as &[u8]).unwrap();
        let new = BranchData::<Address>::decode(&hex!(
            "00409adf0820cb55c1a09bd9300859240fd0f3d68bde8c71edf9157d786630a16ec83fd25100"
        ))
        .unwrap();
        let expected = BranchData::<Address>::decode(&hex!("9adf9adf0214f47cae1cf79ca6758bfc787dbd21e6bdbe7112b80214d7eddb78ed295b3c9629240e8924fb8d8874ddd80214799d329e5f583419167cd722962485926e338f4a0214e2e2659028143784d557bcec6ff3a0721048880a082078c1c89686c6a1107d6bc50d3813047b650611c56cfa497bb8c8c7172b5869b80820cb55c1a09bd9300859240fd0f3d68bde8c71edf9157d786630a16ec83fd25100082045f551ed12d01f47c22b7b1d389c361422fcc530c570ed3fd16e9ec6dc1acf1002148b7f0977bb4f0fbe7076fa22bc24aca043583f5e0214d9a5179f091d85051d3c982785efd1455cec86990820b2fb090bdd6c9cb01c6fe6f9f983cf3a41934d4461534773f0c62a450d4bbc2302140000006916a87b82333f4245046623b23794c65c")).unwrap();

        assert_eq!(merge_hex_branches(old, new).unwrap(), expected);
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
        let mut state_root = EMPTY_ROOT;

        for (expected_state_root, balances) in input {
            let mut updates = HashSet::new();
            for (address, balance) in balances {
                let address = address.into();
                state
                    .accounts
                    .entry(address)
                    .or_insert(Account {
                        nonce: 0,
                        balance: U256::ZERO,
                        code_hash: EMPTY_HASH,
                    })
                    .balance += balance.as_u256();

                updates.insert(address);
            }
            let updated_branches;
            (state_root, updated_branches) = HexPatriciaHashed::new(&mut state, state_root)
                .process_updates(updates)
                .unwrap();
            for (k, branch) in updated_branches {
                match state.account_branches.entry(k) {
                    Entry::Occupied(pre) => {
                        let (k, pre) = pre.remove_entry();
                        let merged = merge_hex_branches(pre.clone(), branch.clone()).unwrap();
                        state.account_branches.insert(k, merged);
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
            (
                hex!("1a6f6e131d93e4ba1cc27ddd8e764b303247959e9adcf744158377b923a38e5f"),
                hashmap! {},
            ),
        ]);
    }

    #[test]
    fn ropsten_genesis() {
        test_genesis([(
            hex!("217b0bbcfb72e2d57e28f33cb361b9983513177755dc3f33ce3e7022ed62b77b"),
            ROPSTEN.balances[&BlockNumber(0)].clone(),
        )]);
    }

    #[test]
    fn goerli_genesis() {
        test_genesis([(
            hex!("5d6cded585e73c4e322c30c2f782a336316f17dd85a4863b9d838d2d4b8b3008"),
            GOERLI.balances[&BlockNumber(0)].clone(),
        )]);
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
