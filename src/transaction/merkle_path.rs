//! MerklePath implementation for BUMP format (BRC-74) SPV proofs.
//!
//! Provides compact Merkle proof verification for transaction inclusion in a block.
//! Used by BEEF format and the Wallet layer for SPV verification.

use std::collections::HashSet;
use std::io::{Cursor, Read, Write};

use super::error::TransactionError;
use super::{read_varint, write_varint};
use crate::primitives::hash::hash256;
use crate::primitives::utils::{from_hex, to_hex};

/// A single leaf/node in the Merkle path at a given tree level.
#[derive(Debug, Clone, PartialEq)]
pub struct MerklePathLeaf {
    /// The offset (index) of this node at its level in the tree.
    pub offset: u64,
    /// The hash of this node as a hex string (big-endian display format).
    /// None if this is a duplicate leaf.
    pub hash: Option<String>,
    /// True if this leaf represents a target transaction ID.
    pub txid: bool,
    /// True if the sibling hash is the same as the current node's hash.
    pub duplicate: bool,
}

/// Represents a Merkle Path (BUMP format, BRC-74) for SPV proof verification.
///
/// Contains the block height and a tree of leaves at each level needed
/// to compute the Merkle root from a target transaction ID.
#[derive(Debug, Clone, PartialEq)]
pub struct MerklePath {
    /// The block height in which the transaction is included.
    pub block_height: u32,
    /// Tree levels from bottom (level 0 = leaf level) to top.
    /// Each level contains the leaves/nodes needed for proof computation.
    pub path: Vec<Vec<MerklePathLeaf>>,
}

impl MerklePath {
    /// Create a new MerklePath, validating offsets and root consistency.
    pub fn new(
        block_height: u32,
        path: Vec<Vec<MerklePathLeaf>>,
    ) -> Result<Self, TransactionError> {
        Self::new_inner(block_height, path, true)
    }

    /// Internal constructor with optional legal-offsets-only validation.
    fn new_inner(
        block_height: u32,
        path: Vec<Vec<MerklePathLeaf>>,
        legal_offsets_only: bool,
    ) -> Result<Self, TransactionError> {
        // Validate: no empty level 0, no duplicate offsets at any level,
        // and legal offsets at levels > 0.
        let mut legal_offsets: Vec<HashSet<u64>> =
            (0..path.len()).map(|_| HashSet::new()).collect();

        for (height, leaves) in path.iter().enumerate() {
            if leaves.is_empty() && height == 0 {
                return Err(TransactionError::InvalidFormat(format!(
                    "Empty level at height: {height}"
                )));
            }
            let mut offsets_at_height = HashSet::new();
            for leaf in leaves {
                if offsets_at_height.contains(&leaf.offset) {
                    return Err(TransactionError::InvalidFormat(format!(
                        "Duplicate offset: {}, at height: {}",
                        leaf.offset, height
                    )));
                }
                offsets_at_height.insert(leaf.offset);

                if height == 0 {
                    if !leaf.duplicate {
                        for (h, legal_offset) in legal_offsets
                            .iter_mut()
                            .enumerate()
                            .take(path.len())
                            .skip(1)
                        {
                            legal_offset.insert((leaf.offset >> h) ^ 1);
                        }
                    }
                } else if legal_offsets_only && !legal_offsets[height].contains(&leaf.offset) {
                    let legal: Vec<String> = legal_offsets[height]
                        .iter()
                        .map(|o| o.to_string())
                        .collect();
                    return Err(TransactionError::InvalidFormat(format!(
                        "Invalid offset: {}, at height: {}, with legal offsets: {}",
                        leaf.offset,
                        height,
                        legal.join(", ")
                    )));
                }
            }
        }

        let mp = MerklePath { block_height, path };

        // Verify all leaves at level 0 compute to the same root.
        let mut root: Option<String> = None;
        for leaf in &mp.path[0] {
            let computed = mp.compute_root(leaf.hash.as_deref())?;
            if let Some(ref r) = root {
                if *r != computed {
                    return Err(TransactionError::InvalidFormat(
                        "Mismatched roots".to_string(),
                    ));
                }
            } else {
                root = Some(computed);
            }
        }

        Ok(mp)
    }

    /// Parse a MerklePath from BUMP binary format.
    pub fn from_binary(reader: &mut impl Read) -> Result<Self, TransactionError> {
        let block_height =
            read_varint(reader).map_err(|e| TransactionError::InvalidFormat(e.to_string()))? as u32;
        let mut tree_height_buf = [0u8; 1];
        reader
            .read_exact(&mut tree_height_buf)
            .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
        let tree_height = tree_height_buf[0] as usize;

        let mut path: Vec<Vec<MerklePathLeaf>> = Vec::with_capacity(tree_height);
        for _ in 0..tree_height {
            path.push(Vec::new());
        }

        for level_vec in path.iter_mut().take(tree_height) {
            let n_leaves =
                read_varint(reader).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
            for _ in 0..n_leaves {
                let offset = read_varint(reader)
                    .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
                let mut flags_buf = [0u8; 1];
                reader
                    .read_exact(&mut flags_buf)
                    .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
                let flags = flags_buf[0];

                let duplicate = (flags & 1) != 0;
                let is_txid = (flags & 2) != 0;

                let hash = if duplicate {
                    None
                } else {
                    let mut hash_bytes = [0u8; 32];
                    reader
                        .read_exact(&mut hash_bytes)
                        .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
                    // Store as hex in big-endian display format (reverse of LE wire order)
                    hash_bytes.reverse();
                    Some(to_hex(&hash_bytes))
                };

                level_vec.push(MerklePathLeaf {
                    offset,
                    hash,
                    txid: is_txid,
                    duplicate,
                });
            }
            // Sort by offset
            level_vec.sort_by_key(|l| l.offset);
        }

        MerklePath::new_inner(block_height, path, true)
    }

    /// Serialize the MerklePath to BUMP binary format.
    pub fn to_binary(&self, writer: &mut impl Write) -> Result<(), TransactionError> {
        write_varint(writer, self.block_height as u64)
            .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
        let tree_height = self.path.len() as u8;
        writer
            .write_all(&[tree_height])
            .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;

        for level in &self.path {
            write_varint(writer, level.len() as u64)
                .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
            for leaf in level {
                write_varint(writer, leaf.offset)
                    .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
                let mut flags: u8 = 0;
                if leaf.duplicate {
                    flags |= 1;
                }
                if leaf.txid {
                    flags |= 2;
                }
                writer
                    .write_all(&[flags])
                    .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
                if !leaf.duplicate {
                    if let Some(ref h) = leaf.hash {
                        let mut hash_bytes = from_hex(h)
                            .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
                        // Reverse from BE display format to LE wire format
                        hash_bytes.reverse();
                        writer
                            .write_all(&hash_bytes)
                            .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Parse a MerklePath from a hex-encoded BUMP string.
    pub fn from_hex(hex: &str) -> Result<Self, TransactionError> {
        let bytes = from_hex(hex).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
        let mut cursor = Cursor::new(bytes);
        Self::from_binary(&mut cursor)
    }

    /// Serialize the MerklePath to a hex-encoded BUMP string.
    pub fn to_hex(&self) -> Result<String, TransactionError> {
        let mut buf = Vec::new();
        self.to_binary(&mut buf)?;
        Ok(to_hex(&buf))
    }

    /// Hash two concatenated hex-encoded hashes using the Bitcoin double-reversal pattern.
    ///
    /// Converts hex to bytes, reverses to LE, hash256, reverses result back to BE, hex-encodes.
    fn merkle_hash(hex_data: &str) -> Result<String, TransactionError> {
        let bytes =
            from_hex(hex_data).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
        let mut le_bytes = bytes;
        le_bytes.reverse();
        let hash_result = hash256(&le_bytes);
        let mut be_result = hash_result.to_vec();
        be_result.reverse();
        Ok(to_hex(&be_result))
    }

    /// Find the leaf at a given level with the specified offset.
    fn find_leaf(&self, height: usize, offset: u64) -> Option<&MerklePathLeaf> {
        self.path
            .get(height)
            .and_then(|level| level.iter().find(|l| l.offset == offset))
    }

    /// Find leaf at given height/offset, or compute it from the level below recursively.
    fn find_or_compute_leaf(
        &self,
        height: usize,
        offset: u64,
    ) -> Result<Option<MerklePathLeaf>, TransactionError> {
        // Check if leaf exists at this level
        if let Some(leaf) = self.find_leaf(height, offset) {
            return Ok(Some(leaf.clone()));
        }

        // Cannot compute level 0 leaves
        if height == 0 {
            return Ok(None);
        }

        // Try to compute from the level below
        let h = height - 1;
        let l = offset << 1;

        let leaf0 = self.find_or_compute_leaf(h, l)?;
        let leaf0 = match leaf0 {
            Some(ref leaf) if matches!(leaf.hash.as_deref(), Some(h) if !h.is_empty()) => leaf,
            _ => return Ok(None),
        };

        let leaf1 = match self.find_or_compute_leaf(h, l + 1)? {
            Some(leaf) => leaf,
            None => return Ok(None),
        };

        // SAFETY: leaf0.hash confirmed to be Some with non-empty content by match above
        let leaf0_hash = leaf0.hash.as_deref().unwrap_or("");

        let working_hash = if leaf1.duplicate {
            let combined = format!("{leaf0_hash}{leaf0_hash}");
            Self::merkle_hash(&combined)?
        } else {
            let combined = format!("{}{}", leaf1.hash.as_deref().unwrap_or(""), leaf0_hash);
            Self::merkle_hash(&combined)?
        };

        Ok(Some(MerklePathLeaf {
            offset,
            hash: Some(working_hash),
            txid: false,
            duplicate: false,
        }))
    }

    /// Find the offset index of a txid at level 0.
    fn index_of(&self, txid: &str) -> Result<u64, TransactionError> {
        self.path[0]
            .iter()
            .find(|l| l.hash.as_deref() == Some(txid))
            .map(|l| l.offset)
            .ok_or_else(|| {
                TransactionError::InvalidFormat(format!(
                    "Transaction ID {txid} not found in the Merkle Path"
                ))
            })
    }

    /// Compute the Merkle root from a transaction ID.
    ///
    /// If txid is None, uses the first leaf with a hash at level 0.
    pub fn compute_root(&self, txid: Option<&str>) -> Result<String, TransactionError> {
        let txid = match txid {
            Some(t) => t.to_string(),
            None => {
                let found = self.path[0]
                    .iter()
                    .find(|l| l.hash.is_some())
                    .ok_or_else(|| {
                        TransactionError::InvalidFormat(
                            "No valid leaf found in the Merkle Path".to_string(),
                        )
                    })?;
                // SAFETY: find predicate ensures hash.is_some()
                found.hash.clone().unwrap_or_default()
            }
        };

        let index = self.index_of(&txid)?;

        // Special case: single-transaction block
        if self.path.len() == 1 && self.path[0].len() == 1 {
            return Ok(txid);
        }

        let mut working_hash = txid;

        for height in 0..self.path.len() {
            let offset = (index >> height) ^ 1;
            let leaf = self.find_or_compute_leaf(height, offset)?.ok_or_else(|| {
                TransactionError::InvalidFormat(format!(
                    "Missing hash for index {index} at height {height}"
                ))
            })?;

            if leaf.duplicate {
                let combined = format!("{working_hash}{working_hash}");
                working_hash = Self::merkle_hash(&combined)?;
            } else if offset % 2 != 0 {
                // Sibling is on the right (odd offset), so sibling hash goes first
                let combined = format!("{}{}", leaf.hash.as_deref().unwrap_or(""), working_hash);
                working_hash = Self::merkle_hash(&combined)?;
            } else {
                let combined = format!("{}{}", working_hash, leaf.hash.as_deref().unwrap_or(""));
                working_hash = Self::merkle_hash(&combined)?;
            }
        }

        Ok(working_hash)
    }

    /// Combine another MerklePath into this one (compound proof).
    ///
    /// Both paths must have the same block_height and compute to the same root.
    /// After combining, trim is called to remove unnecessary intermediate nodes.
    pub fn combine(&mut self, other: &MerklePath) -> Result<(), TransactionError> {
        if self.block_height != other.block_height {
            return Err(TransactionError::InvalidFormat(
                "You cannot combine paths which do not have the same block height.".to_string(),
            ));
        }
        let root1 = self.compute_root(None)?;
        let root2 = other.compute_root(None)?;
        if root1 != root2 {
            return Err(TransactionError::InvalidFormat(
                "You cannot combine paths which do not have the same root.".to_string(),
            ));
        }

        let mut combined_path: Vec<Vec<MerklePathLeaf>> = Vec::new();
        for h in 0..self.path.len() {
            let mut level: Vec<MerklePathLeaf> = Vec::new();
            // Add all from self
            for leaf in &self.path[h] {
                level.push(leaf.clone());
            }
            // Add from other if offset not already present
            for leaf in &other.path[h] {
                if let Some(existing) = level.iter_mut().find(|l| l.offset == leaf.offset) {
                    // Upgrade to txid if the other has it marked
                    if leaf.txid {
                        existing.txid = true;
                    }
                } else {
                    level.push(leaf.clone());
                }
            }
            combined_path.push(level);
        }

        self.path = combined_path;
        self.trim();
        Ok(())
    }

    /// Remove unnecessary intermediate nodes that can be recomputed.
    ///
    /// Keeps only the minimum set of nodes needed for root computation
    /// from all txid-marked leaves at level 0.
    pub fn trim(&mut self) {
        // Sort all levels by offset first
        for level in self.path.iter_mut() {
            level.sort_by_key(|l| l.offset);
        }

        // Determine which offsets at each higher level are computed from level 0 txid nodes
        let mut computed_offsets: Vec<u64> = Vec::new();
        let mut drop_offsets: Vec<u64> = Vec::new();

        // Process level 0
        for i in 0..self.path[0].len() {
            let n = &self.path[0][i];
            if n.txid {
                // Level 0 txid nodes enable computing level 1
                let co = n.offset >> 1;
                // SAFETY: unwrap guarded by is_empty() short-circuit
                if computed_offsets.is_empty() || *computed_offsets.last().unwrap() != co {
                    computed_offsets.push(co);
                }
            } else {
                let is_odd = n.offset % 2 == 1;
                let peer_idx = if is_odd { i.wrapping_sub(1) } else { i + 1 };
                if peer_idx < self.path[0].len() {
                    let peer = &self.path[0][peer_idx];
                    if !peer.txid {
                        // Drop non-txid level 0 nodes without a txid peer
                        // SAFETY: unwrap guarded by is_empty() short-circuit
                        if drop_offsets.is_empty() || *drop_offsets.last().unwrap() != peer.offset {
                            drop_offsets.push(peer.offset);
                        }
                    }
                }
            }
        }

        // Remove dropped offsets from level 0
        Self::drop_offsets_from_level(&mut self.path[0], &drop_offsets);

        // Process higher levels
        for h in 1..self.path.len() {
            drop_offsets = computed_offsets.clone();
            computed_offsets = drop_offsets.iter().fold(Vec::new(), |mut acc, &o| {
                let no = o >> 1;
                // SAFETY: unwrap guarded by is_empty() short-circuit
                if acc.is_empty() || *acc.last().unwrap() != no {
                    acc.push(no);
                }
                acc
            });
            Self::drop_offsets_from_level(&mut self.path[h], &drop_offsets);
        }
    }

    /// Remove leaves with offsets in the drop list from a level.
    fn drop_offsets_from_level(level: &mut Vec<MerklePathLeaf>, drop_offsets: &[u64]) {
        for &offset in drop_offsets.iter().rev() {
            if let Some(idx) = level.iter().position(|n| n.offset == offset) {
                level.remove(idx);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ValidVector {
        #[allow(dead_code)]
        name: String,
        hex: String,
        block_height: u32,
        #[serde(default)]
        expected_root: Option<String>,
        #[serde(default)]
        path_json: Option<serde_json::Value>,
    }

    #[derive(Deserialize)]
    struct InvalidVector {
        name: String,
        hex: String,
        expected_error: String,
    }

    fn load_valid_vectors() -> Vec<ValidVector> {
        let data = include_str!("../../test-vectors/bump_valid.json");
        serde_json::from_str(data).expect("Failed to parse bump_valid.json")
    }

    fn load_invalid_vectors() -> Vec<InvalidVector> {
        let data = include_str!("../../test-vectors/bump_invalid.json");
        serde_json::from_str(data).expect("Failed to parse bump_invalid.json")
    }

    #[test]
    fn test_from_binary_round_trip() {
        let vectors = load_valid_vectors();
        for v in &vectors {
            let mp = MerklePath::from_hex(&v.hex).unwrap_or_else(|e| {
                panic!("Failed to parse '{}': {}", v.name, e);
            });
            assert_eq!(
                mp.block_height, v.block_height,
                "block_height mismatch for '{}'",
                v.name
            );
            let re_hex = mp.to_hex().unwrap_or_else(|e| {
                panic!("Failed to serialize '{}': {}", v.name, e);
            });
            assert_eq!(re_hex, v.hex, "Round-trip hex mismatch for '{}'", v.name);
        }
    }

    #[test]
    fn test_compute_root() {
        let vectors = load_valid_vectors();
        for v in &vectors {
            if let Some(ref expected_root) = v.expected_root {
                let mp = MerklePath::from_hex(&v.hex).unwrap();
                // Get txids from path_json if available, otherwise use all txid leaves
                let txids: Vec<String> = if let Some(ref pj) = v.path_json {
                    if let Some(arr) = pj.get("txids").and_then(|t| t.as_array()) {
                        arr.iter()
                            .filter_map(|t| t.as_str().map(|s| s.to_string()))
                            .collect()
                    } else {
                        mp.path[0].iter().filter_map(|l| l.hash.clone()).collect()
                    }
                } else {
                    mp.path[0].iter().filter_map(|l| l.hash.clone()).collect()
                };

                for txid in &txids {
                    let root = mp.compute_root(Some(txid)).unwrap_or_else(|e| {
                        panic!("compute_root failed for '{}' txid {}: {}", v.name, txid, e);
                    });
                    assert_eq!(
                        root, *expected_root,
                        "Root mismatch for '{}' txid {}",
                        v.name, txid
                    );
                }
            }
        }
    }

    #[test]
    fn test_invalid_bumps() {
        let vectors = load_invalid_vectors();
        for v in &vectors {
            let result = MerklePath::from_hex(&v.hex);
            assert!(
                result.is_err(),
                "Expected error for '{}' but got Ok",
                v.name
            );
            // For vectors where the error is a validation error (not a truncation/parse error),
            // verify the specific error message. Parse errors from truncated data may differ.
            let err_msg = result.unwrap_err().to_string();
            if !err_msg.contains("failed to fill whole buffer") {
                assert!(
                    err_msg.contains(&v.expected_error),
                    "Error for '{}': expected '{}' but got '{}'",
                    v.name,
                    v.expected_error,
                    err_msg
                );
            }
        }
    }

    #[test]
    fn test_combine() {
        // Use the BRC-74 vector which has multiple txids.
        // Replicates the TS SDK test: split the full path into two partial paths
        // (one for txid2, one for txid3) and combine them.
        let hex = "fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b0102fdf405000671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81fdf50500262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a528201fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4";
        let expected_root = "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4";
        let txid2 = "d888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00";
        let txid3 = "98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e";

        let full = MerklePath::from_hex(hex).unwrap();

        // TS test logic:
        // path0A = first 2 elements of level 0 (offset 3048, 3049)
        // path0B = last 2 elements of level 0 (offset 3050, 3051)
        // path1A = level 1 without first element (only 1525)
        // path1B = level 1 without last element (only 1524)
        // Both share levels 2-11.

        let path_a_levels: Vec<Vec<MerklePathLeaf>> = {
            let mut levels = Vec::new();
            // Level 0: first 2 leaves
            levels.push(full.path[0][..2].to_vec());
            // Level 1: skip first, keep rest
            levels.push(full.path[1][1..].to_vec());
            // Levels 2-11: same
            for h in 2..full.path.len() {
                levels.push(full.path[h].clone());
            }
            levels
        };

        let path_b_levels: Vec<Vec<MerklePathLeaf>> = {
            let mut levels = Vec::new();
            // Level 0: last 2 leaves
            levels.push(full.path[0][2..].to_vec());
            // Level 1: keep all but last
            let l1_len = full.path[1].len();
            levels.push(full.path[1][..l1_len - 1].to_vec());
            // Levels 2-11: same
            for h in 2..full.path.len() {
                levels.push(full.path[h].clone());
            }
            levels
        };

        // Skip legal-offsets-only validation for partial paths
        let mut path_a = MerklePath::new_inner(full.block_height, path_a_levels, false).unwrap();
        let path_b = MerklePath::new_inner(full.block_height, path_b_levels, false).unwrap();

        // Verify partial paths work for their own txids
        assert_eq!(path_a.compute_root(Some(txid2)).unwrap(), expected_root);
        assert!(path_a.compute_root(Some(txid3)).is_err());
        assert!(path_b.compute_root(Some(txid2)).is_err());
        assert_eq!(path_b.compute_root(Some(txid3)).unwrap(), expected_root);

        // Combine
        path_a.combine(&path_b).unwrap();

        // After combine, both txids should compute correctly
        assert_eq!(path_a.compute_root(Some(txid2)).unwrap(), expected_root);
        assert_eq!(path_a.compute_root(Some(txid3)).unwrap(), expected_root);
    }

    #[test]
    fn test_single_tx_block() {
        let hex = "fdd2040101000202ef57aa9f29c8141ae17935c88434457b2117890f23efba0d0e0cba7a7a37d5";
        let txid = "d5377a7aba0c0e0dbaef230f8917217b453484c83579e11a14c8299faa57ef02";
        let mp = MerklePath::from_hex(hex).unwrap();
        let root = mp.compute_root(Some(txid)).unwrap();
        assert_eq!(root, txid, "Single-tx block: root should equal txid");
    }
}
