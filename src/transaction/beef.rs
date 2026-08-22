//! BEEF format (BRC-62/95/96) serialization and deserialization.
//!
//! Supports V1, V2, and Atomic BEEF variants for SPV proof packaging.
//!
//! The normative reference is the TypeScript `@bsv/sdk` `Beef` class; the
//! TS-generated corpus under `test-vectors/beef_*.json` pins its byte-exact
//! output, and `tests/conformance_beef_vectors.rs` holds this module to it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Cursor, Read, Write};

use crate::primitives::utils::{from_hex, to_hex};
use crate::transaction::beef_tx::BeefTx;
use crate::transaction::error::TransactionError;
use crate::transaction::merkle_path::MerklePath;
use crate::transaction::transaction::Transaction;
use crate::transaction::{read_u32_le, read_varint, write_u32_le, write_varint};

/// BEEF V1 version marker (0x0100BEEF in LE = 4022206465).
pub const BEEF_V1: u32 = 4022206465;
/// BEEF V2 version marker (0x0200BEEF in LE = 4022206466).
pub const BEEF_V2: u32 = 4022206466;
/// Atomic BEEF prefix (0x01010101).
pub const ATOMIC_BEEF: u32 = 0x01010101;

/// Outcome of [`Beef::sort_txs`]: the txids of each partition, in the order
/// TS `sortTxs` reports them.
///
/// `valid` lists every transaction that has a proof, is an input-less
/// txid-only entry, or whose inputs chain back to one of those — in the
/// order they were accepted (proven and txid-only entries in array order,
/// then topologically sorted dependents). The other four are disjoint
/// subsets of what could not be placed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BeefSortResult {
    /// Input txids referenced by some transaction but absent from the beef.
    pub missing_inputs: Vec<String>,
    /// Transactions whose inputs are all present but which could not be
    /// placed — they depend (transitively) on a transaction in
    /// `with_missing_inputs`, or form a cycle.
    pub not_valid: Vec<String>,
    /// Transactions with a proof, or whose inputs chain back to one.
    pub valid: Vec<String>,
    /// Transactions with at least one input absent from the beef.
    pub with_missing_inputs: Vec<String>,
    /// Input-less txid-only entries (BRC-96 "known" transactions).
    pub txid_only: Vec<String>,
}

/// Outcome of [`Beef::verify_valid`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BeefVerifyResult {
    /// True iff the beef is structurally valid.
    pub valid: bool,
    /// Merkle root computed for each block height, to be confirmed against
    /// a chain tracker. Populated as far as verification got, so a rejected
    /// beef may still report the roots accepted before the failing check.
    pub roots: BTreeMap<u32, String>,
}

/// A BEEF (Background Evaluation Extended Format) container.
///
/// Contains a set of BUMPs (Merkle paths) and transactions that together
/// form a validity proof chain for SPV verification.
///
/// `txs` is kept in insertion order. Serialization emits dependency order
/// (TS `toBinary` sorts before writing) unless the beef is exactly what
/// [`Beef::from_binary`] parsed — a parsed, untouched beef round-trips to
/// its input bytes, as TS's parse-time byte cache makes it do — and
/// [`Beef::sort_txs`] applies the dependency order in place.
#[derive(Debug, Clone)]
pub struct Beef {
    /// BEEF version (BEEF_V1 or BEEF_V2).
    pub version: u32,
    /// Merkle paths (BUMPs) proving transaction inclusion in blocks.
    pub bumps: Vec<MerklePath>,
    /// Transactions with BEEF metadata.
    pub txs: Vec<BeefTx>,
    /// The subject txid recorded by an Atomic BEEF (BRC-95) prefix at parse
    /// time. It is a parse-side fact, not a serialization instruction:
    /// [`Beef::to_binary`] never re-emits the prefix (TS `toBinary` does not
    /// either); use [`Beef::to_binary_atomic`] to produce Atomic BEEF.
    pub atomic_txid: Option<String>,
    /// Whether serialization must compute dependency order. Cleared by
    /// `from_binary` (emit the parsed order) and `sort_txs`; set by every
    /// method that changes `txs` or `bumps`. TS keeps the same flag
    /// (`needsSort`) next to its serialization cache.
    needs_sort: bool,
}

impl Beef {
    /// Create a new empty Beef with the given version.
    pub fn new(version: u32) -> Self {
        Beef {
            version,
            bumps: Vec::new(),
            txs: Vec::new(),
            atomic_txid: None,
            needs_sort: true,
        }
    }

    // ------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------

    /// Deserialize a Beef from binary format, reading exactly one BEEF and
    /// leaving any bytes after it unread.
    ///
    /// This is the lenient prefix parser (TS `Beef.fromBinary` /
    /// `fromString`): trailing data is neither consumed nor rejected. Use
    /// [`Beef::from_binary_strict`] to enforce exact framing.
    pub fn from_binary(reader: &mut impl Read) -> Result<Self, TransactionError> {
        let mut version = read_u32_le(reader)?;
        let mut atomic_txid = None;

        if version == ATOMIC_BEEF {
            // Read 32-byte txid (reversed/LE on wire -> BE display hex)
            let mut txid_bytes = [0u8; 32];
            reader.read_exact(&mut txid_bytes)?;
            txid_bytes.reverse();
            atomic_txid = Some(to_hex(&txid_bytes));
            // Read inner BEEF version
            version = read_u32_le(reader)?;
        }

        if version != BEEF_V1 && version != BEEF_V2 {
            return Err(TransactionError::BeefError(format!(
                "Serialized BEEF must start with {BEEF_V1} or {BEEF_V2} but starts with {version}"
            )));
        }

        let mut beef = Beef::new(version);

        // Read bumps
        let bump_count = read_varint(reader)? as usize;
        for _ in 0..bump_count {
            // TS parity: Beef.fromReader parses embedded bumps with
            // legalOffsetsOnly=false, so a non-canonical/untrimmed bump does not
            // fail the whole BEEF. SPV integrity is still enforced downstream by
            // compute_root / "Mismatched roots".
            let bump = MerklePath::from_binary_with(reader, false)?;
            beef.bumps.push(bump);
        }

        // Read transactions
        let tx_count = read_varint(reader)? as usize;
        for _ in 0..tx_count {
            let beef_tx = if version == BEEF_V2 {
                BeefTx::from_binary_v2(reader)?
            } else {
                BeefTx::from_binary_v1(reader)?
            };
            beef.txs.push(beef_tx);
        }

        beef.atomic_txid = atomic_txid;
        beef.needs_sort = false;

        Ok(beef)
    }

    /// Deserialize a Beef that must span `bytes` exactly.
    ///
    /// TS `Beef.fromBinaryView`: trailing data after the BEEF is an error.
    /// This is the verdict to apply at a wire boundary — a prefix parser
    /// silently accepts whatever follows a well-formed BEEF.
    pub fn from_binary_strict(bytes: &[u8]) -> Result<Self, TransactionError> {
        let mut cursor = Cursor::new(bytes);
        let beef = Self::from_binary(&mut cursor)?;
        if cursor.position() as usize != bytes.len() {
            return Err(TransactionError::BeefError(
                "Serialized BEEF contains trailing data".to_string(),
            ));
        }
        Ok(beef)
    }

    /// Deserialize a Beef from a hex string (lenient framing, like
    /// [`Beef::from_binary`]).
    pub fn from_hex(hex: &str) -> Result<Self, TransactionError> {
        let bytes = from_hex(hex).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
        let mut cursor = Cursor::new(bytes);
        Self::from_binary(&mut cursor)
    }

    // ------------------------------------------------------------------
    // Serialization
    // ------------------------------------------------------------------

    /// Serialize this Beef to binary format.
    ///
    /// Matches TS `toBinary`: transactions are written in `sort_txs()` order
    /// once anything has been merged or removed since parse (or the beef was
    /// built from scratch), while a beef parsed by [`Beef::from_binary`] and
    /// not touched since re-emits exactly its input bytes. The order is
    /// computed without mutating `self`; call [`Beef::sort_txs`] to reorder
    /// `txs` in place. An Atomic prefix is never written — a parsed
    /// `atomic_txid` does not make this an Atomic BEEF on the way back out.
    pub fn to_binary(&self, writer: &mut impl Write) -> Result<(), TransactionError> {
        if self.needs_sort {
            let (order, _) = self.compute_sort_order();
            self.write_in_order(writer, &order)
        } else {
            let order: Vec<usize> = (0..self.txs.len()).collect();
            self.write_in_order(writer, &order)
        }
    }

    fn write_in_order(
        &self,
        writer: &mut impl Write,
        order: &[usize],
    ) -> Result<(), TransactionError> {
        write_u32_le(writer, self.version)?;

        write_varint(writer, self.bumps.len() as u64)?;
        for bump in &self.bumps {
            bump.to_binary(writer)?;
        }

        write_varint(writer, self.txs.len() as u64)?;
        for &i in order {
            let tx = &self.txs[i];
            if self.version == BEEF_V2 {
                tx.to_binary_v2(writer)?;
            } else {
                tx.to_binary_v1(writer)?;
            }
        }

        Ok(())
    }

    /// Serialize this Beef to a hex string.
    pub fn to_hex(&self) -> Result<String, TransactionError> {
        let mut buf = Vec::new();
        self.to_binary(&mut buf)?;
        Ok(to_hex(&buf))
    }

    /// Serialize as Atomic BEEF (BRC-95) for `txid`, which must exist here.
    ///
    /// The output holds exactly the subject and its dependency closure over
    /// this beef: the walk follows `input_txids` from the subject and stops
    /// at any transaction proven by a bump (or known only by txid). Closure
    /// is derived from txids, not array position, so an unsorted beef gives
    /// the same bytes as a sorted one. Transactions outside the closure are
    /// dropped; bumps no bump-proven closure member references are dropped
    /// and the survivors re-indexed in first-use order; the inner BEEF is
    /// written in dependency order.
    ///
    /// Success is not a completeness guarantee: a subject whose parent is
    /// absent serializes as an Atomic BEEF of just the subject (TS does the
    /// same), and only [`Beef::verify_valid`] on the result reports the
    /// missing input.
    ///
    /// Output layout: `ATOMIC_BEEF(4 LE) + txid(32, reversed) + BEEF`.
    pub fn to_binary_atomic(&self, txid: &str) -> Result<Vec<u8>, TransactionError> {
        let atomic = self.beef_for_atomic(txid)?;
        let mut txid_bytes =
            from_hex(txid).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
        txid_bytes.reverse(); // BE display -> LE wire

        let mut buf = Vec::new();
        write_u32_le(&mut buf, ATOMIC_BEEF)?;
        buf.extend_from_slice(&txid_bytes);
        atomic.to_binary(&mut buf)?;
        Ok(buf)
    }

    /// The closure beef `to_binary_atomic` serializes (TS `getBeefForAtomic`).
    fn beef_for_atomic(&self, txid: &str) -> Result<Beef, TransactionError> {
        let txid_to_idx = self.txid_index();
        let subject = *txid_to_idx.get(txid).ok_or_else(|| {
            TransactionError::BeefError(format!("{txid} does not exist in this Beef"))
        })?;
        let included = self.collect_atomic_transactions(subject, &txid_to_idx);
        let mut beef = self.copy_selected_transactions(&included);
        beef.sort_txs();
        Ok(beef)
    }

    /// Indices of the subject's dependency closure (TS
    /// `collectAtomicTransactions`): a depth-first walk over `input_txids`
    /// that does not descend below a bump-proven or txid-only entry.
    fn collect_atomic_transactions(
        &self,
        subject: usize,
        txid_to_idx: &HashMap<&str, usize>,
    ) -> HashSet<usize> {
        let mut included = HashSet::new();
        let mut stack = vec![subject];
        while let Some(i) = stack.pop() {
            if !included.insert(i) {
                continue;
            }
            let tx = &self.txs[i];
            if self.has_matching_bump(tx) || tx.is_txid_only() {
                continue;
            }
            for input_txid in &tx.input_txids {
                if let Some(&input) = txid_to_idx.get(input_txid.as_str()) {
                    stack.push(input);
                }
            }
        }
        included
    }

    /// True iff `tx.bump_index` names a bump whose level-0 leaves include
    /// `tx.txid`. A bump index that points at the wrong bump (or out of
    /// range) is not a proof.
    fn has_matching_bump(&self, tx: &BeefTx) -> bool {
        match tx.bump_index {
            Some(bi) if bi < self.bumps.len() => self.bumps[bi]
                .path
                .first()
                .is_some_and(|level| level.iter().any(|l| l.hash.as_deref() == Some(&tx.txid))),
            _ => false,
        }
    }

    /// Copy the selected transactions into a fresh beef, carrying only the
    /// bumps they are proven by, re-indexed in first-use order over the
    /// current `txs` order (TS `copySelectedTransactions`).
    fn copy_selected_transactions(&self, included: &HashSet<usize>) -> Beef {
        let mut beef = Beef::new(self.version);
        let mut bump_index_map: HashMap<usize, usize> = HashMap::new();

        for (i, tx) in self.txs.iter().enumerate() {
            if !included.contains(&i) || !self.has_matching_bump(tx) {
                continue;
            }
            let Some(bi) = tx.bump_index else { continue };
            if let std::collections::hash_map::Entry::Vacant(slot) = bump_index_map.entry(bi) {
                slot.insert(beef.bumps.len());
                beef.bumps.push(self.bumps[bi].clone());
            }
        }

        for (i, tx) in self.txs.iter().enumerate() {
            if !included.contains(&i) {
                continue;
            }
            beef.txs.push(BeefTx {
                tx: tx.tx.clone(),
                txid: tx.txid.clone(),
                bump_index: tx
                    .bump_index
                    .and_then(|bi| bump_index_map.get(&bi).copied()),
                input_txids: tx.input_txids.clone(),
            });
        }

        beef
    }

    /// BRC-95 transaction-inclusion check, without header-root validation:
    /// the subject exists, no txid repeats, and every transaction here is
    /// in the subject's recursive dependency graph.
    ///
    /// `txid` defaults to `atomic_txid`; with neither, the answer is false.
    pub fn is_atomic(&self, txid: Option<&str>) -> bool {
        let Some(txid) = txid.or(self.atomic_txid.as_deref()) else {
            return false;
        };
        if txid.is_empty() {
            return false;
        }
        let txid_to_idx = self.txid_index();
        if txid_to_idx.len() != self.txs.len() {
            return false;
        }
        let Some(&subject) = txid_to_idx.get(txid) else {
            return false;
        };
        self.collect_atomic_transactions(subject, &txid_to_idx)
            .len()
            == self.txs.len()
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /// txid -> position; a repeated txid resolves to its last position, as
    /// the TS index map does.
    fn txid_index(&self) -> HashMap<&str, usize> {
        self.txs
            .iter()
            .enumerate()
            .map(|(i, btx)| (btx.txid.as_str(), i))
            .collect()
    }

    fn position_of(&self, txid: &str) -> Option<usize> {
        self.txs.iter().rposition(|btx| btx.txid == txid)
    }

    /// Find a `BeefTx` by txid.
    pub fn find_txid(&self, txid: &str) -> Option<&BeefTx> {
        self.position_of(txid).map(|i| &self.txs[i])
    }

    /// Find the bump whose level-0 leaves include `txid`.
    pub fn find_bump(&self, txid: &str) -> Option<&MerklePath> {
        self.find_bump_index_for_txid(txid).map(|i| &self.bumps[i])
    }

    /// Index of the bump proving `txid`. When several bumps carry the same
    /// leaf the last one wins, as the TS txid->bump index does.
    fn find_bump_index_for_txid(&self, txid: &str) -> Option<usize> {
        self.bumps.iter().rposition(|bump| {
            bump.path
                .first()
                .is_some_and(|level| level.iter().any(|leaf| leaf.hash.as_deref() == Some(txid)))
        })
    }

    /// True iff some txid appears more than once in `txs`. The merge API
    /// replaces by txid, so only a serialization can carry a duplicate;
    /// `verify_valid` rejects it.
    pub fn has_duplicate_txids(&self) -> bool {
        let mut seen = HashSet::new();
        self.txs.iter().any(|btx| !seen.insert(btx.txid.as_str()))
    }

    // ------------------------------------------------------------------
    // Merging
    // ------------------------------------------------------------------

    /// Merge a MerklePath (BUMP) that is assumed to be fully valid.
    ///
    /// A bump with the same block height and computed root as an existing
    /// one is combined into it; otherwise the bump is appended. Every
    /// unproven transaction the (possibly combined) bump proves is then
    /// marked: its `bump_index` is set and the bump's leaf is flagged as a
    /// txid leaf, which is what `verify_valid` reads.
    ///
    /// Returns the index of the merged bump.
    pub fn merge_bump(&mut self, bump: &MerklePath) -> Result<usize, TransactionError> {
        // A path with no levels proves nothing and has no root to match on;
        // refusing it here leaves the beef untouched (TS throws from the
        // level-0 scan after the push).
        if bump.path.is_empty() {
            return Err(TransactionError::InvalidFormat(
                "Empty merkle path: tree height must be at least 1".to_string(),
            ));
        }
        self.needs_sort = true;
        let bi = self.find_or_insert_bump(bump)?;

        let leaf_txids: Vec<String> = self.bumps[bi]
            .path
            .first()
            .into_iter()
            .flatten()
            .filter_map(|leaf| leaf.hash.clone())
            .collect();
        for txid in leaf_txids {
            if let Some(pos) = self.position_of(&txid) {
                if self.txs[pos].bump_index.is_none() {
                    self.mark_tx_proven_by_bump(pos, bi)?;
                }
            }
        }

        Ok(bi)
    }

    /// Find an existing compatible bump or insert a new one; return its index.
    fn find_or_insert_bump(&mut self, bump: &MerklePath) -> Result<usize, TransactionError> {
        let same_height: Vec<usize> = self
            .bumps
            .iter()
            .enumerate()
            .filter(|(_, b)| b.block_height == bump.block_height)
            .map(|(i, _)| i)
            .collect();
        if !same_height.is_empty() {
            let root = bump.compute_root(None)?;
            for i in same_height {
                if self.bumps[i].compute_root(None)? != root {
                    continue;
                }
                self.bumps[i].combine(bump)?;
                return Ok(i);
            }
        }
        self.bumps.push(bump.clone());
        Ok(self.bumps.len() - 1)
    }

    /// Record bump `bi` as the proof of `txs[pos]` if the bump's level 0
    /// carries its txid, flagging that leaf as a txid leaf.
    fn mark_tx_proven_by_bump(&mut self, pos: usize, bi: usize) -> Result<(), TransactionError> {
        let txid = self.txs[pos].txid.clone();
        if let Some(leaf) = self.bumps[bi]
            .path
            .first_mut()
            .into_iter()
            .flatten()
            .find(|leaf| leaf.hash.as_deref() == Some(&txid))
        {
            leaf.txid = true;
            self.txs[pos].set_bump_index(Some(bi))?;
        }
        Ok(())
    }

    /// Give `txs[pos]` a proof if some existing bump carries its txid.
    fn try_to_validate_bump_index(&mut self, pos: usize) -> Result<bool, TransactionError> {
        if self.txs[pos].bump_index.is_some() {
            return Ok(true);
        }
        let Some(bi) = self.find_bump_index_for_txid(&self.txs[pos].txid) else {
            return Ok(false);
        };
        self.mark_tx_proven_by_bump(pos, bi)?;
        Ok(true)
    }

    /// Replace the entry sharing `tx`'s txid in place, or append; returns
    /// the entry's position. Replacing in place keeps the relative order
    /// of everything else, which is what the sort's tie-breaks read.
    fn replace_or_append_tx(&mut self, tx: BeefTx) -> usize {
        self.needs_sort = true;
        match self.position_of(&tx.txid) {
            Some(pos) => {
                self.txs[pos] = tx;
                pos
            }
            None => {
                self.txs.push(tx);
                self.txs.len() - 1
            }
        }
    }

    /// Remove an existing transaction with the given txid, preserving the
    /// relative order of the rest.
    pub fn remove_existing_txid(&mut self, txid: &str) {
        if let Some(pos) = self.position_of(txid) {
            self.txs.remove(pos);
            self.needs_sort = true;
        }
    }

    /// Merge a raw serialized transaction into this BEEF.
    ///
    /// Replaces any existing transaction with the same txid. Without an
    /// explicit `bump_index`, an existing bump carrying the txid supplies
    /// the proof.
    pub fn merge_raw_tx(
        &mut self,
        raw_tx: &[u8],
        bump_index: Option<usize>,
    ) -> Result<BeefTx, TransactionError> {
        let mut cursor = Cursor::new(raw_tx);
        let tx = Transaction::from_binary(&mut cursor)?;
        let pos = self.replace_or_append_tx(BeefTx::from_tx(tx, bump_index)?);
        self.try_to_validate_bump_index(pos)?;
        Ok(self.txs[pos].clone())
    }

    /// Merge a `Transaction` together with its `merkle_path` and, recursively,
    /// every `source_transaction` reachable from an unproven input.
    ///
    /// Each transaction's bump is merged first (so a bump already here
    /// absorbs it and proves whatever it can), then the transaction replaces
    /// any entry sharing its txid. The walk stops below a transaction that
    /// ends up proven — its ancestors are not needed for validity. Inputs are
    /// visited in order. Returns the entry for `tx` itself.
    pub fn merge_transaction(&mut self, tx: &Transaction) -> Result<BeefTx, TransactionError> {
        let root_txid = tx.id()?;
        let mut visited: HashSet<String> = HashSet::new();
        let mut stack: Vec<&Transaction> = vec![tx];

        while let Some(current) = stack.pop() {
            let txid = current.id()?;
            if !visited.insert(txid) {
                continue;
            }
            let bump_index = match &current.merkle_path {
                Some(mp) => Some(self.merge_bump(mp)?),
                None => None,
            };
            let pos = self.replace_or_append_tx(BeefTx::from_tx(current.clone(), bump_index)?);
            self.try_to_validate_bump_index(pos)?;
            if self.txs[pos].bump_index.is_none() {
                // Pushed in reverse so inputs pop in forward order.
                for input in current.inputs.iter().rev() {
                    if let Some(source) = &input.source_transaction {
                        stack.push(source);
                    }
                }
            }
        }

        self.find_txid(&root_txid).cloned().ok_or_else(|| {
            TransactionError::BeefError("Failed to merge root transaction".to_string())
        })
    }

    /// Add `txid` as a txid-only entry unless some entry already has it.
    /// A new entry that an existing bump proves picks up that proof.
    /// Returns the entry (existing or new).
    pub fn merge_txid_only(&mut self, txid: &str) -> BeefTx {
        let pos = match self.position_of(txid) {
            Some(pos) => pos,
            None => {
                self.txs.push(BeefTx::from_txid(txid.to_string()));
                self.needs_sort = true;
                let pos = self.txs.len() - 1;
                // A txid-only entry has no inputs to re-derive, so marking
                // cannot fail.
                let _ = self.try_to_validate_bump_index(pos);
                pos
            }
        };
        self.txs[pos].clone()
    }

    /// Merge one `BeefTx`: full data upgrades a txid-only entry (or fills a
    /// gap); a txid-only entry never downgrades a full one; a full entry
    /// never replaces an existing full one. Returns the resulting entry.
    ///
    /// A full entry whose `Transaction` carries proof-tree data — a
    /// `merkle_path`, or a `source_transaction` on any input — is merged as
    /// a graph through [`Beef::merge_transaction`], so its bump and every
    /// ancestor it links to come along. Only an entry built from a
    /// `Transaction` object has such data (a parsed entry never does); this
    /// is the TS `_tx` / `_rawTx` split (`mergeBeefTxEntry` routes `_tx`
    /// entries to `mergeTransactionGraph`). It is what lets a beef whose
    /// ancestor entry was removed or reduced to txid-only be merged back
    /// whole: the graph still hangs off the dependent's `Transaction`.
    pub fn merge_beef_tx(&mut self, btx: &BeefTx) -> Result<BeefTx, TransactionError> {
        let existing = self.position_of(&btx.txid);
        let existing_is_txid_only = existing.is_some_and(|pos| self.txs[pos].is_txid_only());

        if btx.is_txid_only() && existing.is_none() {
            return Ok(self.merge_txid_only(&btx.txid));
        }
        if let Some(tx) = &btx.tx {
            if existing.is_none() || existing_is_txid_only {
                if Self::carries_proof_tree(tx) {
                    return self.merge_transaction(tx);
                }
                // The incoming entry's bump_index refers to ITS beef's bumps;
                // the proof is re-derived against ours.
                let pos = self.replace_or_append_tx(BeefTx::from_tx(tx.clone(), None)?);
                self.try_to_validate_bump_index(pos)?;
                return Ok(self.txs[pos].clone());
            }
        }
        existing.map(|pos| self.txs[pos].clone()).ok_or_else(|| {
            TransactionError::BeefError(format!("Failed to merge BeefTx for txid: {}", btx.txid))
        })
    }

    /// True iff `tx` holds data only an in-memory transaction graph has.
    fn carries_proof_tree(tx: &Transaction) -> bool {
        tx.merkle_path.is_some() || tx.inputs.iter().any(|i| i.source_transaction.is_some())
    }

    /// Merge another Beef into this one: bumps first (deduplicated by block
    /// height + root), then transactions via [`Beef::merge_beef_tx`].
    pub fn merge_beef(&mut self, other: &Beef) -> Result<(), TransactionError> {
        for bump in &other.bumps {
            self.merge_bump(bump)?;
        }
        for btx in &other.txs {
            self.merge_beef_tx(btx)?;
        }
        Ok(())
    }

    /// Merge a Beef from binary data into this one.
    pub fn merge_beef_from_binary(&mut self, data: &[u8]) -> Result<(), TransactionError> {
        let mut cursor = Cursor::new(data);
        let other = Beef::from_binary(&mut cursor)?;
        self.merge_beef(&other)
    }

    /// Replace the entry for `txid` with a txid-only entry; `None` if the
    /// txid is unknown. A bump that proves it keeps proving it.
    pub fn make_txid_only(&mut self, txid: &str) -> Option<BeefTx> {
        let pos = self.position_of(txid)?;
        if !self.txs[pos].is_txid_only() {
            self.txs[pos] = BeefTx::from_txid(txid.to_string());
            self.needs_sort = true;
            let _ = self.try_to_validate_bump_index(pos);
        }
        Some(self.txs[pos].clone())
    }

    /// Remove every txid-only entry whose txid is in `known_txids`, then
    /// drop bumps no remaining transaction references and re-index the rest.
    ///
    /// Full transactions are never removed — they are validity data the
    /// beef's other transactions depend on.
    pub fn trim_known_txids(&mut self, known_txids: &[String]) -> Result<(), TransactionError> {
        let known: HashSet<&str> = known_txids.iter().map(String::as_str).collect();
        let before = self.txs.len();
        self.txs
            .retain(|tx| !(tx.is_txid_only() && known.contains(tx.txid.as_str())));
        if self.txs.len() != before {
            self.needs_sort = true;
        }
        self.reindex_bumps()
    }

    /// Drop bumps no transaction references; remap the survivors' indices.
    fn reindex_bumps(&mut self) -> Result<(), TransactionError> {
        let referenced: HashSet<usize> = self.txs.iter().filter_map(|tx| tx.bump_index).collect();
        if referenced.len() >= self.bumps.len() {
            return Ok(());
        }
        self.needs_sort = true;
        let mut index_map: HashMap<usize, usize> = HashMap::new();
        let mut kept = Vec::with_capacity(referenced.len());
        for (i, bump) in std::mem::take(&mut self.bumps).into_iter().enumerate() {
            if referenced.contains(&i) {
                index_map.insert(i, kept.len());
                kept.push(bump);
            }
        }
        self.bumps = kept;
        for tx in &mut self.txs {
            if let Some(bi) = tx.bump_index {
                let mapped = *index_map.get(&bi).ok_or_else(|| {
                    TransactionError::BeefError(format!(
                        "Internal error: bumpIndex {bi} not found in indexMap"
                    ))
                })?;
                tx.bump_index = Some(mapped);
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Sorting
    // ------------------------------------------------------------------

    /// Sort `txs` into dependency order and report the partitions.
    ///
    /// Resulting order: transactions with a missing input, then those that
    /// depend on them (or cycle), then input-less txid-only entries, then
    /// the valid set — proven transactions in their existing order followed
    /// by their dependents, ancestors before dependents. The unsortable
    /// entries lead so that the valid tail is self-contained.
    ///
    /// Sorting a sorted beef leaves the order unchanged. The report's lists
    /// follow the array order at the time of the call, so `valid` can list
    /// the same set in a different order on a second call.
    pub fn sort_txs(&mut self) -> BeefSortResult {
        self.needs_sort = false;
        let (order, result) = self.compute_sort_order();
        let mut old: Vec<Option<BeefTx>> = std::mem::take(&mut self.txs)
            .into_iter()
            .map(Some)
            .collect();
        self.txs = order
            .into_iter()
            .map(|i| old[i].take().expect("sort order is a permutation"))
            .collect();
        result
    }

    /// Txids of every transaction that has a proof, is an input-less
    /// txid-only entry, or chains back to one (the `valid` partition).
    ///
    /// Does not reorder `txs`; TS `getValidTxids` sorts in place as a side
    /// effect.
    pub fn get_valid_txids(&self) -> Vec<String> {
        self.compute_sort_order().1.valid
    }

    /// The TS `sortTxs` algorithm, as a permutation of `txs` plus the sort
    /// result, without touching `self`. Keyed by txid throughout, so a
    /// repeated txid collapses exactly as it does in the reference maps.
    fn compute_sort_order(&self) -> (Vec<usize>, BeefSortResult) {
        // Insertion-ordered "valid" set (TS: Object.keys of a Record).
        fn mark_valid<'a>(set: &mut HashSet<&'a str>, list: &mut Vec<String>, txid: &'a str) {
            if set.insert(txid) {
                list.push(txid.to_string());
            }
        }
        let mut valid: Vec<String> = Vec::new();
        let mut valid_set: HashSet<&str> = HashSet::new();

        let present: HashSet<&str> = self.txs.iter().map(|t| t.txid.as_str()).collect();
        let mut result: Vec<usize> = Vec::new();
        let mut txid_only: Vec<usize> = Vec::new();
        let mut queue: Vec<usize> = Vec::new();

        // Partition: proven, input-less txid-only, everything else.
        for (i, tx) in self.txs.iter().enumerate() {
            if tx.has_proof() {
                mark_valid(&mut valid_set, &mut valid, &tx.txid);
                result.push(i);
            } else if tx.is_txid_only() && tx.input_txids.is_empty() {
                mark_valid(&mut valid_set, &mut valid, &tx.txid);
                txid_only.push(i);
            } else {
                queue.push(i);
            }
        }

        // Separate entries with an input absent from the beef.
        let mut missing_inputs: Vec<String> = Vec::new();
        let mut txs_missing_inputs: Vec<usize> = Vec::new();
        let mut remaining: Vec<usize> = Vec::new();
        for &i in &queue {
            let mut has_missing = false;
            for input_txid in &self.txs[i].input_txids {
                if !present.contains(input_txid.as_str()) {
                    if !missing_inputs.contains(input_txid) {
                        missing_inputs.push(input_txid.clone());
                    }
                    has_missing = true;
                }
            }
            if has_missing {
                txs_missing_inputs.push(i);
            } else {
                remaining.push(i);
            }
        }

        // Topological sort of the remainder. An input that is neither valid
        // nor a candidate (it has a missing input itself) never resolves, so
        // its dependents stay unprocessed and land in `not_valid`.
        let candidates: HashSet<&str> = remaining
            .iter()
            .map(|&i| self.txs[i].txid.as_str())
            .collect();
        let mut indegree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut original_index: HashMap<&str, usize> = HashMap::new();
        let mut round: HashMap<&str, usize> = HashMap::new();
        for (qpos, &i) in remaining.iter().enumerate() {
            original_index.insert(self.txs[i].txid.as_str(), qpos);
        }
        let valid_snapshot: HashSet<&str> = valid.iter().map(String::as_str).collect();
        for &i in &remaining {
            let tx = &self.txs[i];
            let mut degree = 0;
            for input_txid in &tx.input_txids {
                if valid_snapshot.contains(input_txid.as_str()) {
                    continue;
                }
                degree += 1;
                if candidates.contains(input_txid.as_str()) {
                    dependents.entry(input_txid.as_str()).or_default().push(i);
                }
            }
            indegree.insert(tx.txid.as_str(), degree);
            round.insert(tx.txid.as_str(), 0);
        }

        // Process the ready list as it grows. A dependency that sits after
        // its dependent in the original order pushes the dependent into the
        // next "round", reproducing the reference's repeated-scan ordering.
        let mut ready: Vec<usize> = remaining
            .iter()
            .copied()
            .filter(|&i| indegree.get(self.txs[i].txid.as_str()) == Some(&0))
            .collect();
        let mut processed: HashSet<&str> = HashSet::new();
        let mut k = 0;
        while k < ready.len() {
            let i = ready[k];
            k += 1;
            let txid = self.txs[i].txid.as_str();
            if !processed.insert(txid) {
                continue;
            }
            let deps = dependents.get(txid).cloned().unwrap_or_default();
            for dep in deps {
                let dep_txid = self.txs[dep].txid.as_str();
                let advance = usize::from(
                    original_index.get(txid).copied().unwrap_or(0)
                        > original_index.get(dep_txid).copied().unwrap_or(0),
                );
                let next_round = round.get(txid).copied().unwrap_or(0) + advance;
                let r = round.entry(dep_txid).or_insert(0);
                *r = (*r).max(next_round);
                let next = indegree
                    .get(dep_txid)
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(1);
                indegree.insert(dep_txid, next);
                if next == 0 {
                    ready.push(dep);
                }
            }
        }

        let mut by_round: Vec<Vec<usize>> = Vec::new();
        for &i in &remaining {
            let txid = self.txs[i].txid.as_str();
            if !processed.contains(txid) {
                continue;
            }
            let r = round.get(txid).copied().unwrap_or(0);
            if by_round.len() <= r {
                by_round.resize_with(r + 1, Vec::new);
            }
            by_round[r].push(i);
        }
        for bucket in &by_round {
            for &i in bucket {
                mark_valid(&mut valid_set, &mut valid, &self.txs[i].txid);
                result.push(i);
            }
        }

        let not_valid: Vec<usize> = remaining
            .iter()
            .copied()
            .filter(|&i| !processed.contains(self.txs[i].txid.as_str()))
            .collect();

        let txids = |ix: &[usize]| ix.iter().map(|&i| self.txs[i].txid.clone()).collect();
        let sort_result = BeefSortResult {
            missing_inputs,
            not_valid: txids(&not_valid),
            valid: valid.clone(),
            with_missing_inputs: txids(&txs_missing_inputs),
            txid_only: txids(&txid_only),
        };

        let mut order = txs_missing_inputs;
        order.extend(not_valid);
        order.extend(txid_only);
        order.extend(result);
        (order, sort_result)
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    /// Structural validity (no merkle-root confirmation), evaluated over the
    /// dependency order without reordering `txs`.
    ///
    /// Valid iff: an Atomic subject, if recorded, closes over every
    /// transaction; no txid repeats; every transaction has a proof or
    /// chains back to one (txid-only entries count only with
    /// `allow_txid_only`); every bump txid leaf's computed root agrees
    /// with the first root seen for its height; every `bump_index` names
    /// a bump carrying the transaction's txid; and, in dependency order,
    /// every input is an already-accepted txid.
    ///
    /// `roots` carries the per-height merkle roots for a chain tracker to
    /// confirm. Errors come only from malformed merkle paths whose root
    /// cannot be computed at all.
    ///
    /// This does not mutate the beef. TS `verifyValid` calls `sortTxs()` on
    /// the way in, so a TS caller's next `toBinary` emits sorted bytes; a
    /// parsed beef verified here still serializes in its parsed order
    /// until something is merged or [`Beef::sort_txs`] is called.
    pub fn verify_valid(
        &self,
        allow_txid_only: bool,
    ) -> Result<BeefVerifyResult, TransactionError> {
        let mut r = BeefVerifyResult::default();

        if self.atomic_txid.is_some() && !self.is_atomic(None) {
            return Ok(r);
        }
        let (order, sr) = self.compute_sort_order();
        if self.has_duplicate_txids() {
            return Ok(r);
        }
        if !sr.missing_inputs.is_empty()
            || !sr.not_valid.is_empty()
            || (!sr.txid_only.is_empty() && !allow_txid_only)
            || !sr.with_missing_inputs.is_empty()
        {
            return Ok(r);
        }

        // Accepted txids: txid-only (if allowed), bump leaves, then each
        // transaction once its inputs are all accepted.
        let mut txids: HashSet<&str> = HashSet::new();

        for tx in &self.txs {
            if !tx.is_txid_only() {
                continue;
            }
            if !allow_txid_only {
                return Ok(r);
            }
            txids.insert(tx.txid.as_str());
        }

        for bump in &self.bumps {
            // `path` is a public field: a bump with no levels can prove
            // nothing and has no root to report (TS throws here).
            let level0 = bump.path.first().ok_or_else(|| {
                TransactionError::InvalidFormat(
                    "Empty merkle path: tree height must be at least 1".to_string(),
                )
            })?;
            for leaf in level0 {
                let Some(hash) = leaf.hash.as_deref().filter(|h| !h.is_empty()) else {
                    continue;
                };
                if !leaf.txid {
                    continue;
                }
                txids.insert(hash);
                let root = bump.compute_root(Some(hash))?;
                let accepted = r
                    .roots
                    .entry(bump.block_height)
                    .or_insert_with(|| root.clone());
                if *accepted != root {
                    return Ok(r);
                }
            }
        }

        for tx in &self.txs {
            if let Some(bi) = tx.bump_index {
                if bi >= self.bumps.len() {
                    return Ok(r);
                }
                let proven = self.bumps[bi]
                    .path
                    .first()
                    .is_some_and(|level| level.iter().any(|l| l.hash.as_deref() == Some(&tx.txid)));
                if !proven {
                    return Ok(r);
                }
            }
        }

        for &i in &order {
            let tx = &self.txs[i];
            for input_txid in &tx.input_txids {
                if !txids.contains(input_txid.as_str()) {
                    return Ok(r);
                }
            }
            txids.insert(tx.txid.as_str());
        }

        r.valid = true;
        Ok(r)
    }

    /// [`Beef::verify_valid`] reduced to its verdict. Does not reorder `txs`
    /// (TS `isValid` does, through `sortTxs`).
    pub fn is_valid(&self, allow_txid_only: bool) -> Result<bool, TransactionError> {
        Ok(self.verify_valid(allow_txid_only)?.valid)
    }

    // ------------------------------------------------------------------
    // Transaction extraction
    // ------------------------------------------------------------------

    /// The proof tree rooted at `txid` (TS `findAtomicTransaction`): the
    /// transaction with its merkle path if a bump proves it, otherwise with
    /// every input's `source_transaction` linked from this beef, recursively,
    /// down to the proven ancestors. `None` if the txid is unknown or known
    /// only by txid.
    ///
    /// Parsing does not link sources (TS `fromReader` does not either); this
    /// is where a parsed beef becomes a verifiable `Transaction`. Ancestors
    /// are built first and cloned into their dependents, so the walk is
    /// iterative and a deep chain costs copies rather than stack.
    pub fn find_atomic_transaction(&self, txid: &str) -> Option<Transaction> {
        let txid_to_idx = self.txid_index();
        let subject = *txid_to_idx.get(txid)?;
        self.txs[subject].tx.as_ref()?;
        let included = self.collect_atomic_transactions(subject, &txid_to_idx);
        let (order, _) = self.compute_sort_order();
        let mut built: HashMap<&str, Transaction> = HashMap::new();
        for i in order {
            if !included.contains(&i) {
                continue;
            }
            let btx = &self.txs[i];
            let Some(tx) = &btx.tx else { continue };
            let mut tx = tx.clone();
            if let Some(bump) = self.find_bump(&btx.txid) {
                tx.merkle_path = Some(bump.clone());
            } else {
                for input in &mut tx.inputs {
                    if input.source_transaction.is_some() {
                        continue;
                    }
                    if let Some(source) = input.source_txid.as_deref().and_then(|s| built.get(s)) {
                        input.source_transaction = Some(Box::new(source.clone()));
                    }
                }
            }
            built.insert(btx.txid.as_str(), tx);
        }
        built.remove(txid)
    }

    /// Extract the subject transaction from this BEEF, consuming it.
    ///
    /// The subject is `atomic_txid` if set, else the last transaction. It is
    /// returned as its proof tree ([`Beef::find_atomic_transaction`]).
    pub fn into_transaction(self) -> Result<Transaction, TransactionError> {
        let subject_idx = if let Some(ref atomic_txid) = self.atomic_txid {
            self.txs
                .iter()
                .position(|btx| btx.txid == *atomic_txid)
                .ok_or_else(|| {
                    TransactionError::BeefError(format!(
                        "atomic txid {atomic_txid} not found in BEEF"
                    ))
                })?
        } else {
            if self.txs.is_empty() {
                return Err(TransactionError::BeefError(
                    "BEEF contains no transactions".into(),
                ));
            }
            self.txs.len() - 1
        };

        let subject = &self.txs[subject_idx];
        if subject.is_txid_only() {
            return Err(TransactionError::BeefError(
                "subject tx is txid-only".into(),
            ));
        }
        self.find_atomic_transaction(&subject.txid).ok_or_else(|| {
            TransactionError::BeefError(format!("subject tx {} not found", subject.txid))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct BeefVector {
        name: String,
        hex: String,
        version: u32,
        bump_count: usize,
        tx_count: usize,
        #[serde(default)]
        txid: Option<String>,
    }

    fn load_test_vectors() -> Vec<BeefVector> {
        let json = include_str!("../../test-vectors/beef_valid.json");
        serde_json::from_str(json).expect("failed to parse beef_valid.json")
    }

    #[test]
    fn test_beef_v1_round_trip() {
        let vectors = load_test_vectors();
        for v in vectors.iter().filter(|v| v.version == 1) {
            let beef = Beef::from_hex(&v.hex)
                .unwrap_or_else(|e| panic!("failed to parse '{}': {}", v.name, e));
            assert_eq!(
                beef.bumps.len(),
                v.bump_count,
                "bump count mismatch for '{}'",
                v.name
            );
            assert_eq!(
                beef.txs.len(),
                v.tx_count,
                "tx count mismatch for '{}'",
                v.name
            );

            let result_hex = beef
                .to_hex()
                .unwrap_or_else(|e| panic!("failed to serialize '{}': {}", v.name, e));
            assert_eq!(result_hex, v.hex, "round-trip failed for '{}'", v.name);
        }
    }

    #[test]
    fn test_beef_tx_count() {
        let vectors = load_test_vectors();
        for v in &vectors {
            let beef = Beef::from_hex(&v.hex)
                .unwrap_or_else(|e| panic!("failed to parse '{}': {}", v.name, e));
            assert_eq!(
                beef.bumps.len(),
                v.bump_count,
                "bump count mismatch for '{}'",
                v.name
            );
            assert_eq!(
                beef.txs.len(),
                v.tx_count,
                "tx count mismatch for '{}'",
                v.name
            );

            // Verify txid if provided
            if let Some(ref expected_txid) = v.txid {
                let last_tx = &beef.txs[beef.txs.len() - 1];
                assert_eq!(
                    &last_tx.txid, expected_txid,
                    "txid mismatch for '{}'",
                    v.name
                );
            }
        }
    }

    #[test]
    fn test_merge_beef_combines_bumps_and_txs() {
        let vectors = load_test_vectors();
        // Parse two separate BEEFs and merge them
        let beef_a = Beef::from_hex(&vectors[0].hex).expect("parse beef_a");
        let beef_b = Beef::from_hex(&vectors[1].hex).expect("parse beef_b");

        let mut merged = Beef::new(BEEF_V2);
        merged.merge_beef(&beef_a).expect("merge beef_a");
        merged.merge_beef(&beef_b).expect("merge beef_b");

        // Merged should contain txs from both
        assert!(
            merged.txs.len() >= beef_a.txs.len(),
            "merged should have at least as many txs as beef_a"
        );
        assert!(
            !merged.bumps.is_empty(),
            "merged should have at least one bump"
        );

        // All txids from both should be present
        for btx in &beef_a.txs {
            assert!(
                merged.find_txid(&btx.txid).is_some(),
                "merged should contain txid {} from beef_a",
                btx.txid
            );
        }
        for btx in &beef_b.txs {
            assert!(
                merged.find_txid(&btx.txid).is_some(),
                "merged should contain txid {} from beef_b",
                btx.txid
            );
        }
    }

    #[test]
    fn test_merge_beef_deduplicates_same_txid() {
        let vectors = load_test_vectors();
        let beef_a = Beef::from_hex(&vectors[0].hex).expect("parse beef");

        let mut merged = Beef::new(BEEF_V2);
        merged.merge_beef(&beef_a).expect("merge first");
        let count_after_first = merged.txs.len();

        // Merge the same beef again
        merged.merge_beef(&beef_a).expect("merge second");
        assert_eq!(
            merged.txs.len(),
            count_after_first,
            "merging same beef twice should not duplicate txs"
        );
    }

    #[test]
    fn test_merge_beef_from_binary() {
        let vectors = load_test_vectors();
        let beef_a = Beef::from_hex(&vectors[0].hex).expect("parse beef");
        let binary = crate::primitives::utils::from_hex(&vectors[0].hex).expect("hex decode");

        let mut merged = Beef::new(BEEF_V2);
        merged
            .merge_beef_from_binary(&binary)
            .expect("merge from binary");

        assert_eq!(merged.txs.len(), beef_a.txs.len());
        assert_eq!(merged.bumps.len(), beef_a.bumps.len());
    }

    #[test]
    fn test_merge_raw_tx() {
        let vectors = load_test_vectors();
        let beef = Beef::from_hex(&vectors[0].hex).expect("parse beef");

        // Extract the raw tx bytes from the first transaction
        if let Some(ref tx) = beef.txs[0].tx {
            let mut raw_tx_buf = Vec::new();
            tx.to_binary(&mut raw_tx_buf).expect("serialize tx");

            let mut new_beef = Beef::new(BEEF_V2);
            let result = new_beef
                .merge_raw_tx(&raw_tx_buf, None)
                .expect("merge raw tx");
            assert_eq!(result.txid, beef.txs[0].txid);
            assert_eq!(new_beef.txs.len(), 1);
        }
    }

    #[test]
    fn test_merge_raw_tx_replaces_existing() {
        let vectors = load_test_vectors();
        let beef = Beef::from_hex(&vectors[0].hex).expect("parse beef");

        if let Some(ref tx) = beef.txs[0].tx {
            let mut raw_tx_buf = Vec::new();
            tx.to_binary(&mut raw_tx_buf).expect("serialize tx");

            let mut new_beef = Beef::new(BEEF_V2);
            new_beef
                .merge_raw_tx(&raw_tx_buf, None)
                .expect("merge first");
            new_beef
                .merge_raw_tx(&raw_tx_buf, None)
                .expect("merge second");

            assert_eq!(
                new_beef.txs.len(),
                1,
                "merging same raw tx twice should replace, not duplicate"
            );
        }
    }

    #[test]
    fn test_to_binary_atomic() {
        let vectors = load_test_vectors();
        let beef = Beef::from_hex(&vectors[0].hex).expect("parse beef");

        if let Some(ref expected_txid) = vectors[0].txid {
            let atomic = beef
                .to_binary_atomic(expected_txid)
                .expect("to_binary_atomic");

            // Should start with ATOMIC_BEEF prefix
            assert!(atomic.len() > 36, "atomic output too short");
            let prefix = u32::from_le_bytes([atomic[0], atomic[1], atomic[2], atomic[3]]);
            assert_eq!(prefix, ATOMIC_BEEF, "should start with ATOMIC_BEEF prefix");

            // Should contain the txid (reversed) at bytes 4..36
            let mut txid_bytes =
                crate::primitives::utils::from_hex(expected_txid).expect("hex decode txid");
            txid_bytes.reverse(); // to LE wire format
            assert_eq!(
                &atomic[4..36],
                &txid_bytes[..],
                "atomic should contain txid in LE"
            );

            // Round-trip: parse the atomic BEEF back
            let mut cursor = Cursor::new(&atomic);
            let parsed = Beef::from_binary(&mut cursor).expect("parse atomic beef");
            assert_eq!(
                parsed.atomic_txid.as_deref(),
                Some(expected_txid.as_str()),
                "parsed atomic txid should match"
            );
            assert_eq!(
                parsed.txs.len(),
                beef.txs.len(),
                "parsed atomic should have same tx count"
            );
        }
    }

    #[test]
    fn test_to_binary_atomic_nonexistent_txid() {
        let vectors = load_test_vectors();
        let beef = Beef::from_hex(&vectors[0].hex).expect("parse beef");

        let result = beef
            .to_binary_atomic("0000000000000000000000000000000000000000000000000000000000000000");
        assert!(result.is_err(), "should error for nonexistent txid");
    }

    #[test]
    fn test_find_txid() {
        let vectors = load_test_vectors();
        let beef = Beef::from_hex(&vectors[0].hex).expect("parse beef");

        if let Some(ref expected_txid) = vectors[0].txid {
            assert!(
                beef.find_txid(expected_txid).is_some(),
                "should find existing txid"
            );
        }

        assert!(
            beef.find_txid("0000000000000000000000000000000000000000000000000000000000000000")
                .is_none(),
            "should not find nonexistent txid"
        );
    }

    #[test]
    fn test_into_transaction_returns_last_tx() {
        let vectors = load_test_vectors();
        let beef = Beef::from_hex(&vectors[0].hex).expect("parse beef");
        let expected_txid = beef.txs.last().unwrap().txid.clone();
        let tx = beef.into_transaction().expect("into_transaction");
        assert_eq!(
            tx.id().unwrap(),
            expected_txid,
            "should return last (subject) tx"
        );
    }

    #[test]
    fn test_from_beef_hex() {
        let vectors = load_test_vectors();
        let beef = Beef::from_hex(&vectors[0].hex).expect("parse beef");
        let expected_txid = beef.txs.last().unwrap().txid.clone();
        let tx = crate::transaction::transaction::Transaction::from_beef(&vectors[0].hex)
            .expect("from_beef");
        assert_eq!(
            tx.id().unwrap(),
            expected_txid,
            "from_beef should return subject tx"
        );
    }

    #[test]
    fn test_sort_txs_proven_before_unproven() {
        let vectors = load_test_vectors();
        let mut beef = Beef::from_hex(&vectors[0].hex).expect("parse beef");
        beef.sort_txs();
        // After sorting, proven txs (with bump_index) should come before unproven
        let mut seen_unproven = false;
        for btx in &beef.txs {
            if btx.bump_index.is_some() {
                assert!(!seen_unproven, "proven tx should not come after unproven");
            } else {
                seen_unproven = true;
            }
        }
    }

    #[test]
    fn test_sort_txs_idempotent() {
        let vectors = load_test_vectors();
        let mut beef = Beef::from_hex(&vectors[0].hex).expect("parse beef");
        beef.sort_txs();
        let first_order: Vec<String> = beef.txs.iter().map(|t| t.txid.clone()).collect();
        beef.sort_txs();
        let second_order: Vec<String> = beef.txs.iter().map(|t| t.txid.clone()).collect();
        assert_eq!(first_order, second_order, "sort_txs should be idempotent");
    }

    #[test]
    fn test_merge_bump() {
        let vectors = load_test_vectors();
        let beef = Beef::from_hex(&vectors[0].hex).expect("parse beef");

        let mut new_beef = Beef::new(BEEF_V2);
        // Merge the first bump
        let idx = new_beef.merge_bump(&beef.bumps[0]).expect("merge bump");
        assert_eq!(idx, 0, "first bump should be at index 0");
        assert_eq!(new_beef.bumps.len(), 1);

        // Merging same bump again should combine, not add
        let idx2 = new_beef
            .merge_bump(&beef.bumps[0])
            .expect("merge bump again");
        assert_eq!(idx2, 0, "same bump should merge to index 0");
        assert_eq!(
            new_beef.bumps.len(),
            1,
            "should still be 1 bump after re-merge"
        );
    }

    #[test]
    fn test_into_transaction_sets_merkle_path_from_bumps() {
        // Vector 1 has 2 txs: a proven source tx and an unproven subject tx.
        // into_transaction should set merkle_path on the linked source tx.
        let vectors = load_test_vectors();
        let beef = Beef::from_hex(&vectors[1].hex).expect("parse vector 1");
        assert_eq!(beef.txs.len(), 2, "vector 1 should have 2 txs");

        // Find which tx has a bump (the proven one)
        let proven_count = beef.txs.iter().filter(|t| t.bump_index.is_some()).count();
        assert!(proven_count >= 1, "at least one tx should have a bump");

        let tx = beef.into_transaction().expect("into_transaction");

        // The subject tx (last in BEEF) is the unproven one — check if it
        // has a merkle_path set when appropriate.
        // Check source transactions have merkle_path set from bumps.
        for input in &tx.inputs {
            if let Some(ref source_txid) = input.source_txid {
                if let Some(ref source_tx) = input.source_transaction {
                    // Source tx was in the BEEF with a bump — merkle_path should be set
                    assert!(
                        source_tx.merkle_path.is_some(),
                        "source tx {source_txid} should have merkle_path set from BEEF bump"
                    );
                }
            }
        }
    }

    #[test]
    fn test_into_transaction_sets_merkle_path_on_subject() {
        // Vector 0 has 1 tx with a bump. into_transaction should set
        // merkle_path on the subject tx itself.
        let vectors = load_test_vectors();
        let beef = Beef::from_hex(&vectors[0].hex).expect("parse vector 0");
        assert!(
            beef.txs[0].bump_index.is_some(),
            "vector 0 tx should have a bump"
        );

        let tx = beef.into_transaction().expect("into_transaction");
        assert!(
            tx.merkle_path.is_some(),
            "subject tx with bump should have merkle_path set"
        );
    }
}
