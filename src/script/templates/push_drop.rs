//! PushDrop script template for embedding data in Bitcoin scripts.
//!
//! PushDrop creates scripts that embed arbitrary data fields followed by
//! OP_DROP operations to clean the stack, then lock with OP_CHECKSIG.
//! This enables data storage on-chain while maintaining spending control.
//! Translates the TS SDK PushDrop.ts (simplified without WalletInterface).

use crate::primitives::ecdsa::ecdsa_sign;
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

/// PushDrop script template for embedding data with spending control.
///
/// Creates a locking script that pushes data fields onto the stack,
/// drops them with OP_DROP operations, then verifies a signature
/// against a public key (OP_CHECKSIG).
#[derive(Clone, Debug)]
pub struct PushDrop {
    /// Data fields to embed in the script.
    pub fields: Vec<Vec<u8>>,
    /// Private key for signing (used for both lock pubkey and unlock signature).
    pub private_key: Option<PrivateKey>,
    /// Sighash scope for signing (default: SIGHASH_ALL | SIGHASH_FORKID).
    pub sighash_type: u32,
}

impl PushDrop {
    /// Create a PushDrop template with data fields and a key for locking and unlocking.
    ///
    /// The private key's public key will be used in the locking script,
    /// and the private key will be used for signing in the unlocking script.
    pub fn new(fields: Vec<Vec<u8>>, key: PrivateKey) -> Self {
        PushDrop {
            fields,
            private_key: Some(key),
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
        }
    }

    /// Create a PushDrop template for locking only (no signing capability).
    ///
    /// Requires knowing the public key bytes to embed in the script.
    /// Use `new()` instead if you also need unlock capability.
    pub fn lock_only(fields: Vec<Vec<u8>>) -> Self {
        PushDrop {
            fields,
            private_key: None,
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
        }
    }

    /// Create an unlocking script from a sighash preimage.
    ///
    /// Produces: `<signature_DER + sighash_byte>`
    pub fn unlock(&self, preimage: &[u8]) -> Result<UnlockingScript, ScriptError> {
        let key = self.private_key.as_ref().ok_or_else(|| {
            ScriptError::InvalidScript("PushDrop: no private key for unlock".into())
        })?;

        let msg_hash = sha256(preimage);
        let sig = ecdsa_sign(&msg_hash, key.bn(), true)
            .map_err(|e| ScriptError::InvalidSignature(format!("ECDSA sign failed: {}", e)))?;

        let mut sig_bytes = sig.to_der();
        sig_bytes.push(self.sighash_type as u8);

        let chunks = vec![ScriptChunk::new_raw(sig_bytes.len() as u8, Some(sig_bytes))];

        Ok(UnlockingScript::from_script(Script::from_chunks(chunks)))
    }

    /// Estimate the byte length of the unlocking script.
    ///
    /// PushDrop unlock is just a signature: approximately 74 bytes
    /// (1 push opcode + up to 72 DER sig bytes + 1 sighash byte).
    pub fn estimate_unlock_length(&self) -> usize {
        74
    }

    /// Decode a PushDrop locking script, recovering the embedded data fields.
    ///
    /// Parses the script pattern:
    /// `<field_1> <field_2> ... <field_N> OP_DROP|OP_2DROP... <pubkey> OP_CHECKSIG`
    ///
    /// Returns a PushDrop with the extracted fields, no private key, and default sighash.
    pub fn decode(script: &LockingScript) -> Result<PushDrop, ScriptError> {
        let chunks = script.chunks();
        if chunks.len() < 3 {
            return Err(ScriptError::InvalidScript(
                "PushDrop::decode: script too short".into(),
            ));
        }

        // Last chunk must be OP_CHECKSIG
        let last = &chunks[chunks.len() - 1];
        if last.op != Op::OpCheckSig {
            return Err(ScriptError::InvalidScript(
                "PushDrop::decode: last opcode must be OP_CHECKSIG".into(),
            ));
        }

        // Second-to-last must be a pubkey data push
        let pubkey_chunk = &chunks[chunks.len() - 2];
        if pubkey_chunk.data.is_none() {
            return Err(ScriptError::InvalidScript(
                "PushDrop::decode: expected pubkey data push before OP_CHECKSIG".into(),
            ));
        }

        // Walk backwards from before the pubkey to count OP_DROP and OP_2DROP
        let mut drop_field_count = 0usize;
        let mut pos = chunks.len() - 3; // start just before pubkey
        loop {
            let chunk = &chunks[pos];
            if chunk.op == Op::Op2Drop {
                drop_field_count += 2;
            } else if chunk.op == Op::OpDrop {
                drop_field_count += 1;
            } else {
                break;
            }
            if pos == 0 {
                break;
            }
            pos -= 1;
        }

        if drop_field_count == 0 {
            return Err(ScriptError::InvalidScript(
                "PushDrop::decode: no OP_DROP/OP_2DROP found".into(),
            ));
        }

        // The leading chunks (0..drop_field_count) should be data pushes
        if drop_field_count > pos + 1 {
            return Err(ScriptError::InvalidScript(
                "PushDrop::decode: not enough data pushes for drop count".into(),
            ));
        }

        // Data fields are the first `drop_field_count` chunks
        // pos currently points to the last non-drop chunk before drops, which should be
        // the last data field. But we need to calculate: data fields end at the chunk
        // just before the first drop opcode.
        let data_end = pos + 1; // exclusive end of data field range
        if data_end != drop_field_count {
            return Err(ScriptError::InvalidScript(format!(
                "PushDrop::decode: field count mismatch: {} data chunks but {} drops",
                data_end, drop_field_count
            )));
        }

        let mut fields = Vec::with_capacity(drop_field_count);
        for chunk in &chunks[0..drop_field_count] {
            let data = chunk.data.as_ref().ok_or_else(|| {
                ScriptError::InvalidScript("PushDrop::decode: expected data push for field".into())
            })?;
            fields.push(data.clone());
        }

        Ok(PushDrop {
            fields,
            private_key: None,
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
        })
    }

    /// Create a data push chunk with appropriate opcode for the data length.
    fn make_data_push(data: &[u8]) -> ScriptChunk {
        let len = data.len();
        if len < 0x4c {
            // Direct push: opcode IS the length
            ScriptChunk::new_raw(len as u8, Some(data.to_vec()))
        } else if len < 256 {
            ScriptChunk::new_raw(Op::OpPushData1.to_byte(), Some(data.to_vec()))
        } else if len < 65536 {
            ScriptChunk::new_raw(Op::OpPushData2.to_byte(), Some(data.to_vec()))
        } else {
            ScriptChunk::new_raw(Op::OpPushData4.to_byte(), Some(data.to_vec()))
        }
    }
}

impl ScriptTemplateLock for PushDrop {
    /// Create a PushDrop locking script.
    ///
    /// Structure: `<field_1> <field_2> ... <field_N> OP_DROP|OP_2DROP... <pubkey> OP_CHECKSIG`
    ///
    /// Each field is pushed as data, then removed with OP_DROP (or OP_2DROP
    /// for pairs). The final element on stack will be verified against the
    /// embedded public key via OP_CHECKSIG.
    fn lock(&self) -> Result<LockingScript, ScriptError> {
        let key = self.private_key.as_ref().ok_or_else(|| {
            ScriptError::InvalidScript(
                "PushDrop: need private key to derive pubkey for lock".into(),
            )
        })?;

        if self.fields.is_empty() {
            return Err(ScriptError::InvalidScript(
                "PushDrop: at least one data field required".into(),
            ));
        }

        let mut chunks = Vec::new();

        // Push each data field
        for field in &self.fields {
            chunks.push(Self::make_data_push(field));
        }

        // Add OP_DROP for each field to clean the stack
        // Use OP_2DROP where possible for efficiency
        let num_fields = self.fields.len();
        let num_2drops = num_fields / 2;
        let num_drops = num_fields % 2;

        for _ in 0..num_2drops {
            chunks.push(ScriptChunk::new_opcode(Op::Op2Drop));
        }
        for _ in 0..num_drops {
            chunks.push(ScriptChunk::new_opcode(Op::OpDrop));
        }

        // Add <pubkey> OP_CHECKSIG
        let pubkey = key.to_public_key();
        let pubkey_bytes = pubkey.to_der();
        chunks.push(ScriptChunk::new_raw(
            pubkey_bytes.len() as u8,
            Some(pubkey_bytes),
        ));
        chunks.push(ScriptChunk::new_opcode(Op::OpCheckSig));

        Ok(LockingScript::from_script(Script::from_chunks(chunks)))
    }
}

impl ScriptTemplateUnlock for PushDrop {
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

    // -----------------------------------------------------------------------
    // PushDrop::decode tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pushdrop_decode_roundtrip_one_field() {
        let key = PrivateKey::from_hex("1").unwrap();
        let fields = vec![vec![0xca, 0xfe, 0xba, 0xbe]];
        let pd = PushDrop::new(fields.clone(), key);
        let lock_script = pd.lock().unwrap();

        let decoded = PushDrop::decode(&lock_script).unwrap();
        assert_eq!(decoded.fields, fields, "decode should recover 1 field");
    }

    #[test]
    fn test_pushdrop_decode_roundtrip_two_fields() {
        let key = PrivateKey::from_hex("1").unwrap();
        let fields = vec![vec![0x01, 0x02], vec![0x03, 0x04]];
        let pd = PushDrop::new(fields.clone(), key);
        let lock_script = pd.lock().unwrap();

        let decoded = PushDrop::decode(&lock_script).unwrap();
        assert_eq!(
            decoded.fields, fields,
            "decode should recover 2 fields (OP_2DROP)"
        );
    }

    #[test]
    fn test_pushdrop_decode_roundtrip_three_fields() {
        let key = PrivateKey::from_hex("1").unwrap();
        let fields = vec![vec![0x01], vec![0x02], vec![0x03]];
        let pd = PushDrop::new(fields.clone(), key);
        let lock_script = pd.lock().unwrap();

        let decoded = PushDrop::decode(&lock_script).unwrap();
        assert_eq!(
            decoded.fields, fields,
            "decode should recover 3 fields (OP_2DROP + OP_DROP)"
        );
    }

    #[test]
    fn test_pushdrop_decode_non_pushdrop_script_errors() {
        // A simple P2PKH script should not decode as PushDrop
        let script = LockingScript::from_binary(&[0x76, 0xa9, 0x14]);
        assert!(PushDrop::decode(&script).is_err());
    }

    // -----------------------------------------------------------------------
    // PushDrop lock: 1 field produces script with data and OP_DROP
    // -----------------------------------------------------------------------

    #[test]
    fn test_pushdrop_lock_one_field() {
        let key = PrivateKey::from_hex("1").unwrap();
        let data = vec![0xca, 0xfe, 0xba, 0xbe];
        let pd = PushDrop::new(vec![data.clone()], key);

        let lock_script = pd.lock().unwrap();
        let chunks = lock_script.chunks();

        // Should have: <data> OP_DROP <pubkey> OP_CHECKSIG = 4 chunks
        assert_eq!(chunks.len(), 4, "1-field PushDrop should have 4 chunks");

        // First chunk: data push
        assert_eq!(chunks[0].data.as_ref().unwrap(), &data);
        // Second: OP_DROP
        assert_eq!(chunks[1].op, Op::OpDrop);
        // Third: pubkey (33 bytes)
        assert_eq!(chunks[2].data.as_ref().unwrap().len(), 33);
        // Fourth: OP_CHECKSIG
        assert_eq!(chunks[3].op, Op::OpCheckSig);
    }

    // -----------------------------------------------------------------------
    // PushDrop lock: multiple fields includes all data
    // -----------------------------------------------------------------------

    #[test]
    fn test_pushdrop_lock_multiple_fields() {
        let key = PrivateKey::from_hex("1").unwrap();
        let fields = vec![vec![0x01, 0x02], vec![0x03, 0x04], vec![0x05, 0x06]];
        let pd = PushDrop::new(fields.clone(), key);

        let lock_script = pd.lock().unwrap();
        let chunks = lock_script.chunks();

        // 3 data pushes + 1 OP_2DROP + 1 OP_DROP + 1 pubkey + 1 OP_CHECKSIG = 7
        assert_eq!(chunks.len(), 7, "3-field PushDrop should have 7 chunks");

        // Verify data fields are present
        assert_eq!(chunks[0].data.as_ref().unwrap(), &fields[0]);
        assert_eq!(chunks[1].data.as_ref().unwrap(), &fields[1]);
        assert_eq!(chunks[2].data.as_ref().unwrap(), &fields[2]);

        // OP_2DROP for first pair, OP_DROP for odd one
        assert_eq!(chunks[3].op, Op::Op2Drop);
        assert_eq!(chunks[4].op, Op::OpDrop);

        // Pubkey + checksig
        assert_eq!(chunks[6].op, Op::OpCheckSig);
    }

    // -----------------------------------------------------------------------
    // PushDrop lock: even number of fields uses OP_2DROP efficiently
    // -----------------------------------------------------------------------

    #[test]
    fn test_pushdrop_lock_even_fields() {
        let key = PrivateKey::from_hex("1").unwrap();
        let fields = vec![vec![0x01], vec![0x02]];
        let pd = PushDrop::new(fields, key);

        let lock_script = pd.lock().unwrap();
        let chunks = lock_script.chunks();

        // 2 data pushes + 1 OP_2DROP + 1 pubkey + 1 OP_CHECKSIG = 5 chunks
        assert_eq!(chunks.len(), 5);
        assert_eq!(chunks[2].op, Op::Op2Drop);
    }

    // -----------------------------------------------------------------------
    // PushDrop unlock: produces valid signature
    // -----------------------------------------------------------------------

    #[test]
    fn test_pushdrop_unlock_produces_signature() {
        let key = PrivateKey::from_hex("1").unwrap();
        let pd = PushDrop::new(vec![vec![0xaa]], key);

        let unlock_script = pd.unlock(b"test preimage").unwrap();
        assert_eq!(
            unlock_script.chunks().len(),
            1,
            "PushDrop unlock should be 1 chunk (just sig)"
        );

        let sig_data = unlock_script.chunks()[0].data.as_ref().unwrap();
        // DER signature is typically 70-73 bytes + 1 sighash byte
        assert!(sig_data.len() >= 70 && sig_data.len() <= 74);
        // Last byte is sighash
        assert_eq!(
            *sig_data.last().unwrap(),
            (SIGHASH_ALL | SIGHASH_FORKID) as u8
        );
    }

    // -----------------------------------------------------------------------
    // PushDrop: estimate length
    // -----------------------------------------------------------------------

    #[test]
    fn test_pushdrop_estimate_length() {
        let key = PrivateKey::from_hex("1").unwrap();
        let pd = PushDrop::new(vec![vec![0x01]], key);
        assert_eq!(pd.estimate_unlock_length(), 74);
    }

    // -----------------------------------------------------------------------
    // PushDrop: error cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_pushdrop_lock_no_key() {
        let pd = PushDrop::lock_only(vec![vec![0x01]]);
        assert!(pd.lock().is_err());
    }

    #[test]
    fn test_pushdrop_lock_no_fields() {
        let key = PrivateKey::from_hex("1").unwrap();
        let pd = PushDrop::new(vec![], key);
        assert!(pd.lock().is_err());
    }

    #[test]
    fn test_pushdrop_unlock_no_key() {
        let pd = PushDrop::lock_only(vec![vec![0x01]]);
        assert!(pd.unlock(b"test").is_err());
    }

    // -----------------------------------------------------------------------
    // PushDrop: trait implementations
    // -----------------------------------------------------------------------

    #[test]
    fn test_pushdrop_trait_sign() {
        let key = PrivateKey::from_hex("ff").unwrap();
        let pd = PushDrop::new(vec![vec![0x01, 0x02, 0x03]], key);
        let unlock_script = pd.sign(b"sighash data").unwrap();
        assert_eq!(unlock_script.chunks().len(), 1);
    }

    // -----------------------------------------------------------------------
    // PushDrop: binary roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_pushdrop_lock_binary_roundtrip() {
        let key = PrivateKey::from_hex("1").unwrap();
        let pd = PushDrop::new(vec![vec![0xde, 0xad]], key);

        let lock_script = pd.lock().unwrap();
        let binary = lock_script.to_binary();

        // Re-parse and verify
        let reparsed = Script::from_binary(&binary);
        assert_eq!(
            reparsed.to_binary(),
            binary,
            "binary roundtrip should match"
        );
    }
}
