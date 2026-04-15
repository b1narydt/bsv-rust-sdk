//! BEEF format (BRC-62/95/96) serialization and deserialization.
//!
//! Supports V1, V2, and Atomic BEEF variants for SPV proof packaging.

use std::io::{Cursor, Read, Write};

use crate::primitives::utils::{from_hex, to_hex};
use crate::transaction::beef_tx::BeefTx;
use crate::transaction::error::TransactionError;
use crate::transaction::merkle_path::MerklePath;
use crate::transaction::{read_u32_le, read_varint, write_u32_le, write_varint};

/// BEEF V1 version marker (0x0100BEEF in LE = 4022206465).
pub const BEEF_V1: u32 = 4022206465;
/// BEEF V2 version marker (0x0200BEEF in LE = 4022206466).
pub const BEEF_V2: u32 = 4022206466;
/// Atomic BEEF prefix (0x01010101).
pub const ATOMIC_BEEF: u32 = 0x01010101;

/// A BEEF (Background Evaluation Extended Format) container.
///
/// Contains a set of BUMPs (Merkle paths) and transactions that together
/// form a validity proof chain for SPV verification.
#[derive(Debug, Clone)]
pub struct Beef {
    /// BEEF version (BEEF_V1 or BEEF_V2).
    pub version: u32,
    /// Merkle paths (BUMPs) proving transaction inclusion in blocks.
    pub bumps: Vec<MerklePath>,
    /// Transactions with BEEF metadata.
    pub txs: Vec<BeefTx>,
    /// For Atomic BEEF: the txid of the proven transaction.
    pub atomic_txid: Option<String>,
}

impl Beef {
    /// Create a new empty Beef with the given version.
    pub fn new(version: u32) -> Self {
        Beef {
            version,
            bumps: Vec::new(),
            txs: Vec::new(),
            atomic_txid: None,
        }
    }

    /// Deserialize a Beef from binary format.
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
                "Serialized BEEF must start with {} or {} but starts with {}",
                BEEF_V1, BEEF_V2, version
            )));
        }

        let mut beef = Beef::new(version);

        // Read bumps
        let bump_count = read_varint(reader)
            .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?
            as usize;
        for _ in 0..bump_count {
            let bump = MerklePath::from_binary(reader)?;
            beef.bumps.push(bump);
        }

        // Read transactions
        let tx_count = read_varint(reader)
            .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?
            as usize;
        for _ in 0..tx_count {
            let beef_tx = if version == BEEF_V2 {
                BeefTx::from_binary_v2(reader)?
            } else {
                BeefTx::from_binary_v1(reader)?
            };
            beef.txs.push(beef_tx);
        }

        beef.atomic_txid = atomic_txid;

        // Link source transactions: for each input of each tx, if the input's
        // source_txid matches another tx in the BEEF, set source_transaction.
        beef.link_source_transactions();

        Ok(beef)
    }

    /// Serialize this Beef to binary format.
    pub fn to_binary(&self, writer: &mut impl Write) -> Result<(), TransactionError> {
        // Write Atomic BEEF prefix if applicable
        if let Some(ref txid) = self.atomic_txid {
            write_u32_le(writer, ATOMIC_BEEF)?;
            let mut txid_bytes =
                from_hex(txid).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
            txid_bytes.reverse(); // BE display -> LE wire
            writer.write_all(&txid_bytes)?;
        }

        write_u32_le(writer, self.version)?;

        // Write bumps
        write_varint(writer, self.bumps.len() as u64)?;
        for bump in &self.bumps {
            bump.to_binary(writer)?;
        }

        // Write transactions
        write_varint(writer, self.txs.len() as u64)?;
        for tx in &self.txs {
            if self.version == BEEF_V2 {
                tx.to_binary_v2(writer)?;
            } else {
                tx.to_binary_v1(writer)?;
            }
        }

        Ok(())
    }

    /// Deserialize a Beef from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, TransactionError> {
        let bytes = from_hex(hex).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
        let mut cursor = Cursor::new(bytes);
        Self::from_binary(&mut cursor)
    }

    /// Serialize this Beef to a hex string.
    pub fn to_hex(&self) -> Result<String, TransactionError> {
        let mut buf = Vec::new();
        self.to_binary(&mut buf)?;
        Ok(to_hex(&buf))
    }

    /// Extract the subject transaction from this BEEF, consuming it.
    ///
    /// If `atomic_txid` is set, returns the transaction matching that txid.
    /// Otherwise, returns the last transaction (the subject).
    /// Before returning, links source transactions from the BEEF for each input.
    pub fn into_transaction(
        self,
    ) -> Result<crate::transaction::transaction::Transaction, TransactionError> {
        let subject_idx = if let Some(ref atomic_txid) = self.atomic_txid {
            self.txs
                .iter()
                .position(|btx| btx.txid == *atomic_txid)
                .ok_or_else(|| {
                    TransactionError::BeefError(format!(
                        "atomic txid {} not found in BEEF",
                        atomic_txid
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

        let mut tx = self.txs[subject_idx]
            .tx
            .clone()
            .ok_or_else(|| TransactionError::BeefError("subject tx is txid-only".into()))?;

        // Set merkle_path on subject tx from its bump_index.
        if let Some(bi) = self.txs[subject_idx].bump_index {
            if bi >= self.bumps.len() {
                return Err(TransactionError::BeefError(format!(
                    "bump_index {} out of bounds (only {} bumps)",
                    bi, self.bumps.len()
                )));
            }
            if tx.merkle_path.is_none() {
                tx.merkle_path = Some(self.bumps[bi].clone());
            }
        }

        // Link source transactions: for each input, find source tx in BEEF
        // and set merkle_path from bump_index.
        for input in &mut tx.inputs {
            if let Some(ref source_txid) = input.source_txid {
                if input.source_transaction.is_none() {
                    for btx in &self.txs {
                        if btx.txid == *source_txid {
                            if let Some(ref source_tx) = btx.tx {
                                let mut linked = source_tx.clone();
                                if let Some(bi) = btx.bump_index {
                                    if bi >= self.bumps.len() {
                                        return Err(TransactionError::BeefError(format!(
                                            "bump_index {} out of bounds (only {} bumps) for source tx {}",
                                            bi, self.bumps.len(), btx.txid
                                        )));
                                    }
                                    if linked.merkle_path.is_none() {
                                        linked.merkle_path = Some(self.bumps[bi].clone());
                                    }
                                }
                                input.source_transaction = Some(Box::new(linked));
                            }
                            break;
                        }
                    }
                }
            }
        }

        Ok(tx)
    }

    /// Topologically sort transactions by dependency order.
    ///
    /// Uses Kahn's algorithm. Proven transactions (with bump_index) and those
    /// with no in-BEEF dependencies come first; dependent transactions follow.
    pub fn sort_txs(&mut self) {
        use std::collections::{HashMap, VecDeque};

        let n = self.txs.len();
        if n <= 1 {
            return;
        }

        // Build txid -> index map
        let txid_to_idx: HashMap<&str, usize> = self
            .txs
            .iter()
            .enumerate()
            .map(|(i, btx)| (btx.txid.as_str(), i))
            .collect();

        // Compute in-degree for each tx (how many of its input txids are in this BEEF)
        let mut in_degree = vec![0usize; n];
        // adjacency: txid_idx -> list of dependent tx indices
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];

        for (i, btx) in self.txs.iter().enumerate() {
            for input_txid in &btx.input_txids {
                if let Some(&dep_idx) = txid_to_idx.get(input_txid.as_str()) {
                    if dep_idx != i {
                        in_degree[i] += 1;
                        dependents[dep_idx].push(i);
                    }
                }
            }
        }

        // Start with nodes having in-degree 0
        let mut queue: VecDeque<usize> = VecDeque::new();
        for (i, &deg) in in_degree.iter().enumerate() {
            if deg == 0 {
                queue.push_back(i);
            }
        }

        let mut sorted_indices: Vec<usize> = Vec::with_capacity(n);
        while let Some(idx) = queue.pop_front() {
            sorted_indices.push(idx);
            for &dep in &dependents[idx] {
                in_degree[dep] -= 1;
                if in_degree[dep] == 0 {
                    queue.push_back(dep);
                }
            }
        }

        // If there are remaining nodes (cycle), append them
        if sorted_indices.len() < n {
            for i in 0..n {
                if !sorted_indices.contains(&i) {
                    sorted_indices.push(i);
                }
            }
        }

        // Reorder self.txs according to sorted_indices
        let old_txs = std::mem::take(&mut self.txs);
        self.txs = sorted_indices
            .into_iter()
            .map(|i| old_txs[i].clone())
            .collect();
    }

    /// Find a `BeefTx` by txid.
    pub fn find_txid(&self, txid: &str) -> Option<&BeefTx> {
        self.txs.iter().find(|btx| btx.txid == txid)
    }

    /// Merge a MerklePath (BUMP) that is assumed to be fully valid.
    ///
    /// If an identical bump (same block height, same computed root) already exists,
    /// combines them. Otherwise appends a new bump.
    ///
    /// After merging, scans transactions to assign bump indices to any that match
    /// a leaf in the merged bump.
    ///
    /// Returns the index of the merged bump.
    pub fn merge_bump(&mut self, bump: &MerklePath) -> Result<usize, TransactionError> {
        let mut bump_index: Option<usize> = None;

        for (i, existing) in self.bumps.iter_mut().enumerate() {
            if existing.block_height == bump.block_height {
                let root_a = existing.compute_root(None)?;
                let root_b = bump.compute_root(None)?;
                if root_a == root_b {
                    existing.combine(bump)?;
                    bump_index = Some(i);
                    break;
                }
            }
        }

        if bump_index.is_none() {
            bump_index = Some(self.bumps.len());
            self.bumps.push(bump.clone());
        }

        let bi = bump_index.expect("bump_index was just set");

        // Check if any existing transactions are proven by this bump
        let bump_ref = &self.bumps[bi];
        let leaf_txids: Vec<String> = bump_ref.path[0]
            .iter()
            .filter_map(|leaf| leaf.hash.clone())
            .collect();

        for btx in &mut self.txs {
            if btx.bump_index.is_none() && leaf_txids.contains(&btx.txid) {
                btx.bump_index = Some(bi);
            }
        }

        Ok(bi)
    }

    /// Remove an existing transaction with the given txid.
    pub fn remove_existing_txid(&mut self, txid: &str) {
        if let Some(pos) = self.txs.iter().position(|btx| btx.txid == txid) {
            self.txs.remove(pos);
        }
    }

    /// Merge a raw serialized transaction into this BEEF.
    ///
    /// Replaces any existing transaction with the same txid.
    ///
    /// If `bump_index` is provided, it must be a valid index into `self.bumps`.
    pub fn merge_raw_tx(
        &mut self,
        raw_tx: &[u8],
        bump_index: Option<usize>,
    ) -> Result<BeefTx, TransactionError> {
        let mut cursor = std::io::Cursor::new(raw_tx);
        let tx = crate::transaction::transaction::Transaction::from_binary(&mut cursor)?;
        let new_tx = BeefTx::from_tx(tx, bump_index)?;
        self.remove_existing_txid(&new_tx.txid);
        let txid = new_tx.txid.clone();
        self.txs.push(new_tx);

        // Try to find a bump for this transaction if none provided
        if bump_index.is_none() {
            self.try_to_validate_bump_index(&txid);
        }

        Ok(self.txs.last().cloned().expect("just pushed"))
    }

    /// Merge another Beef into this one.
    ///
    /// All BUMPs from `other` are merged first (deduplicating by block height + root),
    /// then all transactions are merged (replacing any with matching txids).
    pub fn merge_beef(&mut self, other: &Beef) -> Result<(), TransactionError> {
        for bump in &other.bumps {
            self.merge_bump(bump)?;
        }

        for btx in &other.txs {
            if btx.is_txid_only() {
                // Merge txid-only if we don't already have this txid
                if self.find_txid(&btx.txid).is_none() {
                    self.txs.push(BeefTx::from_txid(btx.txid.clone()));
                }
            } else if let Some(ref tx) = btx.tx {
                // Re-derive the bump index in the context of our bumps
                let new_bump_index = self.find_bump_index_for_txid(&btx.txid);
                let new_btx = BeefTx::from_tx(tx.clone(), new_bump_index)?;
                self.remove_existing_txid(&btx.txid);
                let txid = new_btx.txid.clone();
                self.txs.push(new_btx);
                if new_bump_index.is_none() {
                    self.try_to_validate_bump_index(&txid);
                }
            }
        }

        Ok(())
    }

    /// Merge a Beef from binary data into this one.
    pub fn merge_beef_from_binary(&mut self, data: &[u8]) -> Result<(), TransactionError> {
        let mut cursor = std::io::Cursor::new(data);
        let other = Beef::from_binary(&mut cursor)?;
        self.merge_beef(&other)
    }

    /// Serialize this Beef as Atomic BEEF (BRC-95) for a specific transaction.
    ///
    /// The target `txid` must exist in this Beef. After sorting by dependency order,
    /// if the target transaction is not the last one, transactions after it are excluded.
    ///
    /// The output format is: `ATOMIC_BEEF(4 bytes) + txid(32 bytes LE) + BEEF binary`.
    pub fn to_binary_atomic(&self, txid: &str) -> Result<Vec<u8>, TransactionError> {
        // Verify the txid exists
        if self.find_txid(txid).is_none() {
            return Err(TransactionError::BeefError(format!(
                "{} does not exist in this Beef",
                txid
            )));
        }

        // Clone and set up atomic txid
        let mut atomic_beef = self.clone();
        atomic_beef.atomic_txid = Some(txid.to_string());

        // If the target tx is not the last one, remove transactions after it
        if let Some(pos) = atomic_beef.txs.iter().position(|btx| btx.txid == txid) {
            atomic_beef.txs.truncate(pos + 1);
        }

        let mut buf = Vec::new();
        atomic_beef.to_binary(&mut buf)?;
        Ok(buf)
    }

    /// Try to find a bump index for a txid by scanning all bumps.
    fn try_to_validate_bump_index(&mut self, txid: &str) {
        for (i, bump) in self.bumps.iter().enumerate() {
            let found = bump.path[0]
                .iter()
                .any(|leaf| leaf.hash.as_deref() == Some(txid));
            if found {
                if let Some(btx) = self.txs.iter_mut().find(|btx| btx.txid == txid) {
                    btx.bump_index = Some(i);
                }
                return;
            }
        }
    }

    /// Find the bump index for a txid, if any bump contains it.
    fn find_bump_index_for_txid(&self, txid: &str) -> Option<usize> {
        for (i, bump) in self.bumps.iter().enumerate() {
            let found = bump.path[0]
                .iter()
                .any(|leaf| leaf.hash.as_deref() == Some(txid));
            if found {
                return Some(i);
            }
        }
        None
    }

    /// Link source transactions within this BEEF.
    ///
    /// For each transaction input, if its source_txid matches another transaction
    /// in this BEEF, set source_transaction to point to it.
    fn link_source_transactions(&mut self) {
        // Collect txid -> index mapping
        let txid_map: Vec<(String, usize)> = self
            .txs
            .iter()
            .enumerate()
            .map(|(i, btx)| (btx.txid.clone(), i))
            .collect();

        // We need to clone transactions to set source_transaction references
        // because Rust ownership rules prevent borrowing self.txs mutably
        // while also reading from it. We clone the source txs.
        let tx_clones: Vec<Option<crate::transaction::transaction::Transaction>> =
            self.txs.iter().map(|btx| btx.tx.clone()).collect();

        for btx in &mut self.txs {
            if let Some(ref mut tx) = btx.tx {
                for input in &mut tx.inputs {
                    if let Some(ref source_txid) = input.source_txid {
                        if input.source_transaction.is_none() {
                            // Find matching tx in BEEF
                            if let Some((_, idx)) =
                                txid_map.iter().find(|(tid, _)| tid == source_txid)
                            {
                                if let Some(ref source_tx) = tx_clones[*idx] {
                                    input.source_transaction = Some(Box::new(source_tx.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }
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
            merged.bumps.len() >= 1,
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
                        "source tx {} should have merkle_path set from BEEF bump",
                        source_txid
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
