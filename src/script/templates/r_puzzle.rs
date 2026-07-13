//! RPuzzle script template for R-value puzzle scripts.
//!
//! RPuzzle creates scripts that extract the R-value from a DER-encoded
//! signature and compare it (optionally hashed) against an expected value.
//! This enables knowledge-of-k-value based script puzzles.
//! Translates the TS SDK RPuzzle.ts.

use crate::primitives::big_number::BigNumber;
use crate::primitives::ecdsa::ecdsa_sign_with_k;
use crate::primitives::hash::sha256;
use crate::primitives::private_key::PrivateKey;
use crate::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use crate::script::error::ScriptError;
use crate::script::locking_script::LockingScript;
use crate::script::op::Op;
use crate::script::script::Script;
use crate::script::script_chunk::ScriptChunk;
use crate::script::templates::{ScriptTemplateLock, ScriptTemplateUnlock};
use crate::script::unlocking_script::UnlockingScript;

/// The type of hash applied to the R-value before comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RPuzzleType {
    /// Compare R-value directly (no hashing).
    Raw,
    /// Apply SHA-1 before comparison.
    SHA1,
    /// Apply SHA-256 before comparison.
    SHA256,
    /// Apply double SHA-256 (Hash256) before comparison.
    Hash256,
    /// Apply RIPEMD-160 before comparison.
    RIPEMD160,
    /// Apply Hash160 (RIPEMD160(SHA256)) before comparison.
    Hash160,
}

/// RPuzzle script template for R-value puzzle scripts.
///
/// Creates a locking script that extracts the R-value from a DER signature
/// on the stack, optionally hashes it, and compares against an expected value.
/// Unlocking requires knowledge of the k-value used to produce a matching R.
#[derive(Clone, Debug)]
pub struct RPuzzle {
    /// The type of hash to apply to the extracted R-value.
    pub puzzle_type: RPuzzleType,
    /// The expected R-value or hash of R-value for locking.
    pub value: Vec<u8>,
    /// The known k-value for unlocking (allows computing matching R).
    pub k_value: Option<BigNumber>,
    /// Private key for signing with known k.
    pub private_key: Option<PrivateKey>,
    /// Sighash scope for signing.
    pub sighash_type: u32,
}

impl RPuzzle {
    /// Create an RPuzzle template configured for locking.
    ///
    /// The `value` is the expected R-value (or hash of R-value, depending on
    /// `puzzle_type`) that must be matched by the unlocking signature.
    pub fn from_value(puzzle_type: RPuzzleType, value: Vec<u8>) -> Self {
        RPuzzle {
            puzzle_type,
            value,
            k_value: None,
            private_key: None,
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
        }
    }

    /// Create an RPuzzle template configured for unlocking.
    ///
    /// The `k` value is the nonce that will produce the expected R-value.
    /// The `key` is the private key used for signing.
    pub fn from_k(puzzle_type: RPuzzleType, value: Vec<u8>, k: BigNumber, key: PrivateKey) -> Self {
        RPuzzle {
            puzzle_type,
            value,
            k_value: Some(k),
            private_key: Some(key),
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
        }
    }

    /// Create an unlocking script from a sighash preimage.
    ///
    /// Signs with the known k-value to produce a signature whose R-value
    /// matches the puzzle's expected value.
    pub fn unlock(&self, preimage: &[u8]) -> Result<UnlockingScript, ScriptError> {
        let key = self.private_key.as_ref().ok_or_else(|| {
            ScriptError::InvalidScript("RPuzzle: no private key for unlock".into())
        })?;
        let k = self
            .k_value
            .as_ref()
            .ok_or_else(|| ScriptError::InvalidScript("RPuzzle: no k-value for unlock".into()))?;

        let msg_hash = sha256(preimage);
        let sig = ecdsa_sign_with_k(&msg_hash, key.bn(), k, true).map_err(|e| {
            ScriptError::InvalidSignature(format!("ECDSA sign with k failed: {e}"))
        })?;

        let mut sig_bytes = sig.to_der();
        sig_bytes.push(self.sighash_type as u8);

        let chunks = vec![ScriptChunk::new_raw(sig_bytes.len() as u8, Some(sig_bytes))];

        Ok(UnlockingScript::from_script(Script::from_chunks(chunks)))
    }

    /// Estimate the byte length of the unlocking script.
    ///
    /// RPuzzle unlock is just a signature: approximately 74 bytes.
    pub fn estimate_unlock_length(&self) -> usize {
        74
    }

    /// Build the R-value extraction opcodes from a DER signature on the stack.
    ///
    /// DER sig format: 0x30 <total_len> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>
    /// The extraction opcodes split the signature to isolate the R bytes:
    ///   OP_DUP OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP
    fn r_extraction_chunks() -> Vec<ScriptChunk> {
        vec![
            ScriptChunk::new_opcode(Op::OpDup),   // dup the sig
            ScriptChunk::new_opcode(Op::Op3),     // push 3
            ScriptChunk::new_opcode(Op::OpSplit), // split at byte 3 -> [first3] [rest]
            ScriptChunk::new_opcode(Op::OpNip),   // remove first3 -> [rest] (r_len|r|02|s...)
            ScriptChunk::new_opcode(Op::Op1),     // push 1
            ScriptChunk::new_opcode(Op::OpSplit), // split at 1 -> [r_len_byte] [r|02|s...]
            ScriptChunk::new_opcode(Op::OpSwap),  // swap -> [r|02|s...] [r_len_byte]
            ScriptChunk::new_opcode(Op::OpSplit), // split at r_len -> [r_bytes] [02|s...]
            ScriptChunk::new_opcode(Op::OpDrop),  // drop the s part -> [r_bytes]
        ]
    }

    /// Get the hash opcode for the puzzle type (if any).
    fn hash_opcode(&self) -> Option<Op> {
        match self.puzzle_type {
            RPuzzleType::Raw => None,
            RPuzzleType::SHA1 => Some(Op::OpSha1),
            RPuzzleType::SHA256 => Some(Op::OpSha256),
            RPuzzleType::Hash256 => Some(Op::OpHash256),
            RPuzzleType::RIPEMD160 => Some(Op::OpRipemd160),
            RPuzzleType::Hash160 => Some(Op::OpHash160),
        }
    }
}

impl ScriptTemplateLock for RPuzzle {
    /// Create an RPuzzle locking script.
    ///
    /// Structure:
    ///   OP_DUP OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP
    ///   `[OP_hash]`  (only if not Raw)
    ///   <expected_value> OP_EQUALVERIFY OP_CHECKSIG
    fn lock(&self) -> Result<LockingScript, ScriptError> {
        if self.value.is_empty() {
            return Err(ScriptError::InvalidScript(
                "RPuzzle: value must not be empty".into(),
            ));
        }

        let mut chunks = Self::r_extraction_chunks();

        // Add hash opcode if needed
        if let Some(hash_op) = self.hash_opcode() {
            chunks.push(ScriptChunk::new_opcode(hash_op));
        }

        // Push expected value
        let val_len = self.value.len();
        if val_len < 0x4c {
            chunks.push(ScriptChunk::new_raw(
                val_len as u8,
                Some(self.value.clone()),
            ));
        } else {
            chunks.push(ScriptChunk::new_raw(
                Op::OpPushData1.to_byte(),
                Some(self.value.clone()),
            ));
        }

        chunks.push(ScriptChunk::new_opcode(Op::OpEqualVerify));
        chunks.push(ScriptChunk::new_opcode(Op::OpCheckSig));

        Ok(LockingScript::from_script(Script::from_chunks(chunks)))
    }
}

impl ScriptTemplateUnlock for RPuzzle {
    fn sign(&self, preimage: &[u8]) -> Result<UnlockingScript, ScriptError> {
        self.unlock(preimage)
    }

    fn estimate_length(&self) -> Result<usize, ScriptError> {
        Ok(self.estimate_unlock_length())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::base_point::BasePoint;
    use crate::primitives::big_number::Endian;
    use crate::primitives::hash::sha256;

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // -----------------------------------------------------------------------
    // RPuzzle lock: Raw type produces correct extraction opcodes
    // -----------------------------------------------------------------------

    #[test]
    fn test_rpuzzle_lock_raw() {
        let value = vec![0xaa; 32];
        let rp = RPuzzle::from_value(RPuzzleType::Raw, value.clone());

        let lock_script = rp.lock().unwrap();
        let chunks = lock_script.chunks();

        // 9 extraction opcodes + <value> + OP_EQUALVERIFY + OP_CHECKSIG = 12
        assert_eq!(chunks.len(), 12, "Raw RPuzzle should have 12 chunks");

        // Verify extraction opcodes
        assert_eq!(chunks[0].op, Op::OpDup);
        assert_eq!(chunks[1].op, Op::Op3);
        assert_eq!(chunks[2].op, Op::OpSplit);
        assert_eq!(chunks[3].op, Op::OpNip);
        assert_eq!(chunks[4].op, Op::Op1);
        assert_eq!(chunks[5].op, Op::OpSplit);
        assert_eq!(chunks[6].op, Op::OpSwap);
        assert_eq!(chunks[7].op, Op::OpSplit);
        assert_eq!(chunks[8].op, Op::OpDrop);

        // No hash opcode for Raw, directly the value
        assert_eq!(chunks[9].data.as_ref().unwrap(), &value);
        assert_eq!(chunks[10].op, Op::OpEqualVerify);
        assert_eq!(chunks[11].op, Op::OpCheckSig);
    }

    // -----------------------------------------------------------------------
    // RPuzzle lock: SHA256 type includes OP_SHA256 before comparison
    // -----------------------------------------------------------------------

    #[test]
    fn test_rpuzzle_lock_sha256() {
        let value = vec![0xbb; 32];
        let rp = RPuzzle::from_value(RPuzzleType::SHA256, value.clone());

        let lock_script = rp.lock().unwrap();
        let chunks = lock_script.chunks();

        // 9 extraction + OP_SHA256 + <value> + OP_EQUALVERIFY + OP_CHECKSIG = 13
        assert_eq!(chunks.len(), 13, "SHA256 RPuzzle should have 13 chunks");

        // Check OP_SHA256 is present after extraction
        assert_eq!(chunks[9].op, Op::OpSha256);
        // Then value
        assert_eq!(chunks[10].data.as_ref().unwrap(), &value);
    }

    // -----------------------------------------------------------------------
    // RPuzzle lock: other hash types
    // -----------------------------------------------------------------------

    #[test]
    fn test_rpuzzle_lock_hash_types() {
        let value = vec![0xcc; 20];

        let test_cases = vec![
            (RPuzzleType::SHA1, Op::OpSha1, 13),
            (RPuzzleType::Hash256, Op::OpHash256, 13),
            (RPuzzleType::RIPEMD160, Op::OpRipemd160, 13),
            (RPuzzleType::Hash160, Op::OpHash160, 13),
        ];

        for (ptype, expected_op, expected_chunks) in test_cases {
            let rp = RPuzzle::from_value(ptype, value.clone());
            let lock_script = rp.lock().unwrap();
            let chunks = lock_script.chunks();

            assert_eq!(
                chunks.len(),
                expected_chunks,
                "{ptype:?} should have {expected_chunks} chunks"
            );
            assert_eq!(
                chunks[9].op, expected_op,
                "{ptype:?} hash opcode mismatch"
            );
        }
    }

    // -----------------------------------------------------------------------
    // RPuzzle: sign with known k produces valid signature
    // -----------------------------------------------------------------------

    #[test]
    fn test_rpuzzle_unlock_with_k() {
        let key = PrivateKey::from_hex("1").unwrap();
        let k = BigNumber::from_number(42);

        // Compute the R-value that this k produces: R = k * G
        let base_point = BasePoint::instance();
        let r_point = base_point.mul(&k);
        let r_bytes = r_point.get_x().to_array(Endian::Big, Some(32));

        // Use raw R-value as the puzzle value
        let rp = RPuzzle::from_k(RPuzzleType::Raw, r_bytes, k, key);

        let unlock_script = rp.unlock(b"test preimage").unwrap();
        assert_eq!(unlock_script.chunks().len(), 1);

        let sig_data = unlock_script.chunks()[0].data.as_ref().unwrap();
        assert!(sig_data.len() >= 70 && sig_data.len() <= 74);
    }

    // -----------------------------------------------------------------------
    // RPuzzle: round-trip verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_rpuzzle_roundtrip_raw() {
        let key = PrivateKey::from_hex("ff").unwrap();
        let k = BigNumber::from_number(12345);

        // Compute R-value from k
        let base_point = BasePoint::instance();
        let r_point = base_point.mul(&k);
        let r_value = r_point.get_x().to_array(Endian::Big, Some(32));

        // Create puzzle with the raw R-value
        let rp = RPuzzle::from_k(RPuzzleType::Raw, r_value.clone(), k.clone(), key.clone());

        // Lock should contain the R-value
        let lock_script = rp.lock().unwrap();
        let lock_chunks = lock_script.chunks();

        // The value chunk (after extraction opcodes, index 9 for Raw)
        let embedded_value = lock_chunks[9].data.as_ref().unwrap();
        assert_eq!(
            embedded_value, &r_value,
            "embedded value should match R-value"
        );

        // Unlock should produce a valid signature
        let unlock_script = rp.unlock(b"test roundtrip").unwrap();
        assert_eq!(unlock_script.chunks().len(), 1);

        // Extract R from the produced signature's DER encoding
        let sig_with_sighash = unlock_script.chunks()[0].data.as_ref().unwrap();
        let sig_der = &sig_with_sighash[..sig_with_sighash.len() - 1]; // strip sighash byte

        // Parse DER to extract R
        // DER: 0x30 <len> 0x02 <r_len> <r_bytes> ...
        assert_eq!(sig_der[0], 0x30);
        assert_eq!(sig_der[2], 0x02);
        let r_len = sig_der[3] as usize;
        let r_bytes = &sig_der[4..4 + r_len];

        // Strip leading zero if present (DER positive encoding)
        let r_trimmed = if !r_bytes.is_empty() && r_bytes[0] == 0x00 {
            &r_bytes[1..]
        } else {
            r_bytes
        };

        // Pad to 32 bytes for comparison
        let mut r_padded = vec![0u8; 32];
        let start = 32 - r_trimmed.len();
        r_padded[start..].copy_from_slice(r_trimmed);

        assert_eq!(
            r_padded, r_value,
            "signature R-value should match the puzzle value"
        );
    }

    // -----------------------------------------------------------------------
    // RPuzzle: round-trip with SHA256 hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_rpuzzle_roundtrip_sha256() {
        let key = PrivateKey::from_hex("abcd").unwrap();
        let k = BigNumber::from_number(9999);

        // Compute R-value from k
        let base_point = BasePoint::instance();
        let r_point = base_point.mul(&k);
        let r_value = r_point.get_x().to_array(Endian::Big, Some(32));

        // Hash the R-value with SHA256
        let r_hash = sha256(&r_value);

        // Create puzzle with SHA256 hash of R-value
        let rp = RPuzzle::from_k(RPuzzleType::SHA256, r_hash.to_vec(), k, key);

        // Lock should contain the SHA256 hash
        let lock_script = rp.lock().unwrap();
        let lock_chunks = lock_script.chunks();

        // After extraction (9) + OP_SHA256 (1) = index 10
        let embedded_hash = lock_chunks[10].data.as_ref().unwrap();
        assert_eq!(embedded_hash, &r_hash.to_vec());

        // Unlock should work
        let unlock_script = rp.unlock(b"sha256 test").unwrap();
        assert_eq!(unlock_script.chunks().len(), 1);
    }

    // -----------------------------------------------------------------------
    // RPuzzle: error cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_rpuzzle_lock_empty_value() {
        let rp = RPuzzle::from_value(RPuzzleType::Raw, vec![]);
        assert!(rp.lock().is_err());
    }

    #[test]
    fn test_rpuzzle_unlock_no_key() {
        let rp = RPuzzle::from_value(RPuzzleType::Raw, vec![0xaa; 32]);
        assert!(rp.unlock(b"test").is_err());
    }

    #[test]
    fn test_rpuzzle_unlock_no_k() {
        let rp = RPuzzle {
            puzzle_type: RPuzzleType::Raw,
            value: vec![0xaa; 32],
            k_value: None,
            private_key: Some(PrivateKey::from_hex("1").unwrap()),
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
        };
        assert!(rp.unlock(b"test").is_err());
    }

    // -----------------------------------------------------------------------
    // RPuzzle: estimate length
    // -----------------------------------------------------------------------

    #[test]
    fn test_rpuzzle_estimate_length() {
        let rp = RPuzzle::from_value(RPuzzleType::Raw, vec![0xaa; 32]);
        assert_eq!(rp.estimate_unlock_length(), 74);
    }

    // -----------------------------------------------------------------------
    // RPuzzle: binary roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_rpuzzle_lock_binary_roundtrip() {
        let value = vec![0xde, 0xad, 0xbe, 0xef];
        let rp = RPuzzle::from_value(RPuzzleType::SHA256, value);

        let lock_script = rp.lock().unwrap();
        let binary = lock_script.to_binary();

        let reparsed = Script::from_binary(&binary);
        assert_eq!(
            reparsed.to_binary(),
            binary,
            "binary roundtrip should match"
        );
    }
}
