//! PushDrop script template for embedding data in Bitcoin scripts.
//!
//! PushDrop creates scripts that embed arbitrary data fields followed by
//! OP_DROP operations to clean the stack, then lock with OP_CHECKSIG.
//! This enables data storage on-chain while maintaining spending control.
//!
//! Supports two lock positions matching the TS SDK:
//! - **Before** (default): `<pubkey> OP_CHECKSIG <fields...> OP_2DROP... OP_DROP`
//! - **After**: `<fields...> OP_2DROP... OP_DROP <pubkey> OP_CHECKSIG`

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

/// Lock position for the public key in the PushDrop script.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum LockPosition {
    /// `<pubkey> OP_CHECKSIG <fields...> OP_2DROP...` (TS default)
    #[default]
    Before,
    /// `<fields...> OP_2DROP... <pubkey> OP_CHECKSIG`
    After,
}

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
    /// Where the locking pubkey is placed in the script.
    pub lock_position: LockPosition,
}

impl PushDrop {
    /// Create a PushDrop template with data fields and a key for locking and unlocking.
    pub fn new(fields: Vec<Vec<u8>>, key: PrivateKey) -> Self {
        PushDrop {
            fields,
            private_key: Some(key),
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
            lock_position: LockPosition::default(),
        }
    }

    /// Create a PushDrop template for locking only (no signing capability).
    pub fn lock_only(fields: Vec<Vec<u8>>) -> Self {
        PushDrop {
            fields,
            private_key: None,
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
            lock_position: LockPosition::default(),
        }
    }

    /// Set the lock position (builder pattern).
    pub fn with_lock_position(mut self, position: LockPosition) -> Self {
        self.lock_position = position;
        self
    }

    /// Create an unlocking script from a sighash preimage.
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
    pub fn estimate_unlock_length(&self) -> usize {
        74
    }

    /// Decode a PushDrop locking script, recovering the embedded data fields.
    ///
    /// Supports both lock positions:
    /// - **Before**: `<pubkey> OP_CHECKSIG <fields...> [<sig>] OP_2DROP...`
    /// - **After**: `<fields...> OP_2DROP... <pubkey> OP_CHECKSIG`
    ///
    /// Defaults to `Before` (matching TS SDK default).
    pub fn decode(script: &LockingScript) -> Result<PushDrop, ScriptError> {
        Self::decode_with_position(script, LockPosition::Before)
    }

    /// Decode with explicit lock position.
    pub fn decode_with_position(
        script: &LockingScript,
        position: LockPosition,
    ) -> Result<PushDrop, ScriptError> {
        let chunks = script.chunks();
        if chunks.len() < 3 {
            return Err(ScriptError::InvalidScript(
                "PushDrop::decode: script too short".into(),
            ));
        }

        let fields = match position {
            LockPosition::Before => Self::decode_before(chunks)?,
            LockPosition::After => Self::decode_after(chunks)?,
        };

        Ok(PushDrop {
            fields,
            private_key: None,
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
            lock_position: position,
        })
    }

    /// Decode "before" layout: `<pubkey> OP_CHECKSIG <fields...> OP_2DROP...`
    ///
    /// Matches TS SDK `PushDrop.decode(script, 'before')`:
    /// - Skip chunks[0] (pubkey) and chunks[1] (OP_CHECKSIG)
    /// - Read data pushes from index 2 until next chunk is OP_DROP/OP_2DROP
    fn decode_before(chunks: &[ScriptChunk]) -> Result<Vec<Vec<u8>>, ScriptError> {
        if chunks.len() < 2 || chunks[0].data.is_none() || chunks[1].op != Op::OpCheckSig {
            return Err(ScriptError::InvalidScript(
                "PushDrop::decode(before): expected <pubkey> OP_CHECKSIG at start".into(),
            ));
        }

        let mut fields = Vec::new();
        for i in 2..chunks.len() {
            // Check if next chunk is a DROP — if so, this is the last field
            let next_is_drop = chunks
                .get(i + 1)
                .is_some_and(|next| next.op == Op::OpDrop || next.op == Op::Op2Drop);

            // Stop if THIS chunk is a DROP
            if chunks[i].op == Op::OpDrop || chunks[i].op == Op::Op2Drop {
                break;
            }

            if let Some(ref data) = chunks[i].data {
                fields.push(data.clone());
            }

            if next_is_drop {
                break;
            }
        }

        Ok(fields)
    }

    /// Decode "after" layout: `<fields...> OP_2DROP... <pubkey> OP_CHECKSIG`
    fn decode_after(chunks: &[ScriptChunk]) -> Result<Vec<Vec<u8>>, ScriptError> {
        let last = &chunks[chunks.len() - 1];
        if last.op != Op::OpCheckSig {
            return Err(ScriptError::InvalidScript(
                "PushDrop::decode(after): last opcode must be OP_CHECKSIG".into(),
            ));
        }

        if chunks[chunks.len() - 2].data.is_none() {
            return Err(ScriptError::InvalidScript(
                "PushDrop::decode(after): expected pubkey before OP_CHECKSIG".into(),
            ));
        }

        // Walk backwards from before the pubkey to count DROP opcodes
        let mut drop_field_count = 0usize;
        let mut pos = chunks.len() - 3;
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
                "PushDrop::decode(after): no OP_DROP/OP_2DROP found".into(),
            ));
        }

        let mut fields = Vec::with_capacity(drop_field_count);
        for chunk in &chunks[0..drop_field_count] {
            let data = chunk.data.as_ref().ok_or_else(|| {
                ScriptError::InvalidScript(
                    "PushDrop::decode(after): expected data push for field".into(),
                )
            })?;
            fields.push(data.clone());
        }

        Ok(fields)
    }

    /// Create a data push chunk with appropriate opcode for the data length.
    fn make_data_push(data: &[u8]) -> ScriptChunk {
        let len = data.len();
        if len < 0x4c {
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
    /// Create a PushDrop locking script using the configured lock position.
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

        let pubkey = key.to_public_key();
        let pubkey_bytes = pubkey.to_der();

        let mut lock_chunks = vec![
            ScriptChunk::new_raw(pubkey_bytes.len() as u8, Some(pubkey_bytes)),
            ScriptChunk::new_opcode(Op::OpCheckSig),
        ];

        let mut field_chunks = Vec::new();
        for field in &self.fields {
            field_chunks.push(Self::make_data_push(field));
        }

        let num_fields = self.fields.len();
        for _ in 0..num_fields / 2 {
            field_chunks.push(ScriptChunk::new_opcode(Op::Op2Drop));
        }
        for _ in 0..num_fields % 2 {
            field_chunks.push(ScriptChunk::new_opcode(Op::OpDrop));
        }

        let chunks = match self.lock_position {
            LockPosition::Before => {
                lock_chunks.extend(field_chunks);
                lock_chunks
            }
            LockPosition::After => {
                field_chunks.extend(lock_chunks);
                field_chunks
            }
        };

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
    // Lock position: Before (default, matches TS SDK)
    // -----------------------------------------------------------------------

    #[test]
    fn test_before_lock_one_field() {
        let key = PrivateKey::from_hex("1").unwrap();
        let data = vec![0xca, 0xfe, 0xba, 0xbe];
        let pd = PushDrop::new(vec![data.clone()], key);
        let lock_script = pd.lock().unwrap();
        let chunks = lock_script.chunks();

        // <pubkey> OP_CHECKSIG <data> OP_DROP = 4 chunks
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].data.as_ref().unwrap().len(), 33); // pubkey
        assert_eq!(chunks[1].op, Op::OpCheckSig);
        assert_eq!(chunks[2].data.as_ref().unwrap(), &data);
        assert_eq!(chunks[3].op, Op::OpDrop);
    }

    #[test]
    fn test_before_lock_three_fields() {
        let key = PrivateKey::from_hex("1").unwrap();
        let fields = vec![vec![0x01], vec![0x02], vec![0x03]];
        let pd = PushDrop::new(fields.clone(), key);
        let lock_script = pd.lock().unwrap();
        let chunks = lock_script.chunks();

        // <pubkey> OP_CHECKSIG <f0> <f1> <f2> OP_2DROP OP_DROP = 7
        assert_eq!(chunks.len(), 7);
        assert_eq!(chunks[0].data.as_ref().unwrap().len(), 33);
        assert_eq!(chunks[1].op, Op::OpCheckSig);
        assert_eq!(chunks[2].data.as_ref().unwrap(), &fields[0]);
        assert_eq!(chunks[3].data.as_ref().unwrap(), &fields[1]);
        assert_eq!(chunks[4].data.as_ref().unwrap(), &fields[2]);
        assert_eq!(chunks[5].op, Op::Op2Drop);
        assert_eq!(chunks[6].op, Op::OpDrop);
    }

    #[test]
    fn test_before_decode_roundtrip() {
        let key = PrivateKey::from_hex("1").unwrap();
        let fields = vec![
            b"SLAP".to_vec(),
            vec![0x02, 0x79],
            b"https://example.com".to_vec(),
            b"ls_ship".to_vec(),
        ];
        let pd = PushDrop::new(fields.clone(), key);
        let lock_script = pd.lock().unwrap();

        let decoded = PushDrop::decode(&lock_script).unwrap();
        assert_eq!(decoded.fields, fields);
        assert_eq!(decoded.lock_position, LockPosition::Before);
    }

    // -----------------------------------------------------------------------
    // Lock position: After (legacy)
    // -----------------------------------------------------------------------

    #[test]
    fn test_after_lock_one_field() {
        let key = PrivateKey::from_hex("1").unwrap();
        let data = vec![0xca, 0xfe];
        let pd = PushDrop::new(vec![data.clone()], key).with_lock_position(LockPosition::After);
        let lock_script = pd.lock().unwrap();
        let chunks = lock_script.chunks();

        // <data> OP_DROP <pubkey> OP_CHECKSIG = 4
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].data.as_ref().unwrap(), &data);
        assert_eq!(chunks[1].op, Op::OpDrop);
        assert_eq!(chunks[2].data.as_ref().unwrap().len(), 33);
        assert_eq!(chunks[3].op, Op::OpCheckSig);
    }

    #[test]
    fn test_after_decode_roundtrip() {
        let key = PrivateKey::from_hex("1").unwrap();
        let fields = vec![vec![0x01, 0x02], vec![0x03, 0x04]];
        let pd = PushDrop::new(fields.clone(), key).with_lock_position(LockPosition::After);
        let lock_script = pd.lock().unwrap();

        let decoded = PushDrop::decode_with_position(&lock_script, LockPosition::After).unwrap();
        assert_eq!(decoded.fields, fields);
    }

    // -----------------------------------------------------------------------
    // Unlock + error cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_unlock_produces_signature() {
        let key = PrivateKey::from_hex("1").unwrap();
        let pd = PushDrop::new(vec![vec![0xaa]], key);
        let unlock_script = pd.unlock(b"test preimage").unwrap();
        assert_eq!(unlock_script.chunks().len(), 1);
        let sig_data = unlock_script.chunks()[0].data.as_ref().unwrap();
        assert!(sig_data.len() >= 70 && sig_data.len() <= 74);
    }

    #[test]
    fn test_lock_no_key_errors() {
        let pd = PushDrop::lock_only(vec![vec![0x01]]);
        assert!(pd.lock().is_err());
    }

    #[test]
    fn test_lock_no_fields_errors() {
        let key = PrivateKey::from_hex("1").unwrap();
        let pd = PushDrop::new(vec![], key);
        assert!(pd.lock().is_err());
    }

    #[test]
    fn test_decode_non_pushdrop_errors() {
        let script = LockingScript::from_binary(&[0x76, 0xa9, 0x14]);
        assert!(PushDrop::decode(&script).is_err());
    }
}
