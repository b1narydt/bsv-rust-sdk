//! Script type: chunk-based Bitcoin script with binary serialization.
//!
//! Translates the TS SDK Script.ts. Supports parsing from binary, hex,
//! and ASM formats with identical OP_RETURN conditional-block semantics.

use crate::script::error::ScriptError;
use crate::script::op::Op;
use crate::script::script_chunk::ScriptChunk;

/// A Bitcoin script represented as a sequence of parsed chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    chunks: Vec<ScriptChunk>,
}

impl Script {
    /// Create an empty script.
    pub fn new() -> Self {
        Script { chunks: Vec::new() }
    }

    /// Parse a script from raw binary bytes.
    pub fn from_binary(bytes: &[u8]) -> Self {
        Script {
            chunks: Self::parse_chunks(bytes),
        }
    }

    /// Parse a script from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, ScriptError> {
        if hex.is_empty() {
            return Ok(Script::new());
        }
        if !hex.len().is_multiple_of(2) {
            return Err(ScriptError::InvalidFormat(
                "hex string has odd length".to_string(),
            ));
        }
        let bytes = hex_to_bytes(hex).map_err(ScriptError::InvalidFormat)?;
        Ok(Script::from_binary(&bytes))
    }

    /// Parse a script from a space-separated ASM string.
    ///
    /// Handles opcodes like "OP_DUP", data pushes as hex strings,
    /// "0" as OP_0, and "-1" as OP_1NEGATE.
    /// `OP_PUSHDATA1/2/4` in ASM format: `"OP_PUSHDATA1 <len> <hex>"`
    pub fn from_asm(asm: &str) -> Self {
        if asm.is_empty() {
            return Script::new();
        }

        let mut chunks = Vec::new();
        let tokens: Vec<&str> = asm.split(' ').collect();
        let mut i = 0;

        while i < tokens.len() {
            let token = tokens[i];

            // Special cases for "0" and "-1"
            if token == "0" {
                chunks.push(ScriptChunk::new_opcode(Op::Op0));
                i += 1;
                continue;
            }
            if token == "-1" {
                chunks.push(ScriptChunk::new_opcode(Op::Op1Negate));
                i += 1;
                continue;
            }

            // Try to parse as opcode name
            if let Some(op) = Op::from_name(token) {
                // Check for PUSHDATA ops that have data following
                if op == Op::OpPushData1 || op == Op::OpPushData2 || op == Op::OpPushData4 {
                    // Format: OP_PUSHDATA1 <len> <hex_data>
                    if i + 2 < tokens.len() {
                        let hex_data = tokens[i + 2];
                        let data = hex_to_bytes(hex_data).unwrap_or_default();
                        chunks.push(ScriptChunk::new_raw(op.to_byte(), Some(data)));
                        i += 3;
                    } else {
                        chunks.push(ScriptChunk::new_opcode(op));
                        i += 1;
                    }
                } else {
                    chunks.push(ScriptChunk::new_opcode(op));
                    i += 1;
                }
                continue;
            }

            // Not an opcode -- treat as hex data
            let mut hex = token.to_string();
            if !hex.len().is_multiple_of(2) {
                hex = format!("0{hex}");
            }
            if let Ok(data) = hex_to_bytes(&hex) {
                let len = data.len();
                let op_byte = if len < 0x4c {
                    len as u8
                } else if len < 256 {
                    Op::OpPushData1.to_byte()
                } else if len < 65536 {
                    Op::OpPushData2.to_byte()
                } else {
                    Op::OpPushData4.to_byte()
                };
                chunks.push(ScriptChunk::new_raw(op_byte, Some(data)));
            }
            i += 1;
        }

        Script { chunks }
    }

    /// Create a script from pre-built chunks.
    pub fn from_chunks(chunks: Vec<ScriptChunk>) -> Self {
        Script { chunks }
    }

    /// Serialize the script to binary bytes.
    pub fn to_binary(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, chunk) in self.chunks.iter().enumerate() {
            let serialized = chunk.serialize();
            out.extend_from_slice(&serialized);
            // If this is an OP_RETURN data chunk (with data, not inside conditional),
            // it's the last chunk the serializer should emit, since parse_chunks
            // would have consumed the rest as data.
            if chunk.op == Op::OpReturn && chunk.data.is_some() {
                // Check if this is the last chunk or there are trailing chunks
                // (There shouldn't be, but be defensive)
                let _ = i; // just consume, all remaining chunks are already in self.chunks
            }
        }
        out
    }

    /// Serialize then hex-encode.
    pub fn to_hex(&self) -> String {
        let bytes = self.to_binary();
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// ASM string representation.
    pub fn to_asm(&self) -> String {
        self.chunks
            .iter()
            .map(|c| c.to_asm())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Access the parsed chunks.
    pub fn chunks(&self) -> &[ScriptChunk] {
        &self.chunks
    }

    /// Number of chunks.
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether the script has no chunks.
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Remove all occurrences of `target` from this script (borrowing).
    ///
    /// Matching is done by comparing the serialized bytes of each chunk
    /// against the full serialized target, following the TS SDK's
    /// `findAndDelete` algorithm.
    pub fn find_and_delete(&self, target: &Script) -> Script {
        let target_bytes = target.to_binary();
        let target_len = target_bytes.len();
        if target_len == 0 {
            return self.clone();
        }

        let target_op = target_bytes[0];

        // Fast early-exit: if no chunk has a matching op_byte, skip allocation
        if !self.chunks.iter().any(|c| c.op_byte == target_op) {
            return self.clone();
        }

        // Clone chunks once and use retain for in-place removal (avoids per-chunk clone)
        let mut result_chunks = self.chunks.clone();
        Self::retain_non_matching(&mut result_chunks, target_op, target_len, &target_bytes);
        Script {
            chunks: result_chunks,
        }
    }

    /// Remove all occurrences of `target` from this script (consuming self to avoid clone).
    ///
    /// Same semantics as `find_and_delete` but takes ownership, avoiding the
    /// internal `Vec<ScriptChunk>` clone when the caller no longer needs the original.
    pub fn find_and_delete_owned(mut self, target: &Script) -> Script {
        let target_bytes = target.to_binary();
        let target_len = target_bytes.len();
        if target_len == 0 {
            return self;
        }

        let target_op = target_bytes[0];

        // Fast early-exit: if no chunk has a matching op_byte, return self unchanged
        if !self.chunks.iter().any(|c| c.op_byte == target_op) {
            return self;
        }

        Self::retain_non_matching(&mut self.chunks, target_op, target_len, &target_bytes);
        self
    }

    /// Core retain logic shared by find_and_delete and find_and_delete_owned.
    fn retain_non_matching(
        chunks: &mut Vec<ScriptChunk>,
        target_op: u8,
        target_len: usize,
        target_bytes: &[u8],
    ) {
        chunks.retain(|chunk| {
            // Cheap u8 comparison first
            if chunk.op_byte != target_op {
                return true;
            }
            let data = chunk.data.as_deref().unwrap_or(&[]);
            let data_len = data.len();

            if data_len == 0 && chunk.data.is_none() {
                return target_len != 1;
            }

            // OP_RETURN data chunk or direct push (0x01..=0x4b)
            if chunk.op == Op::OpReturn || chunk.op_byte < Op::OpPushData1.to_byte() {
                if target_len != 1 + data_len {
                    return true;
                }
                return target_bytes[1..] != *data;
            }

            if chunk.op == Op::OpPushData1 {
                if target_len != 2 + data_len {
                    return true;
                }
                if target_bytes[1] != (data_len & 0xff) as u8 {
                    return true;
                }
                return target_bytes[2..] != *data;
            }

            if chunk.op == Op::OpPushData2 {
                if target_len != 3 + data_len {
                    return true;
                }
                if target_bytes[1] != (data_len & 0xff) as u8 {
                    return true;
                }
                if target_bytes[2] != ((data_len >> 8) & 0xff) as u8 {
                    return true;
                }
                return target_bytes[3..] != *data;
            }

            if chunk.op == Op::OpPushData4 {
                if target_len != 5 + data_len {
                    return true;
                }
                let size = data_len as u32;
                if target_bytes[1] != (size & 0xff) as u8 {
                    return true;
                }
                if target_bytes[2] != ((size >> 8) & 0xff) as u8 {
                    return true;
                }
                if target_bytes[3] != ((size >> 16) & 0xff) as u8 {
                    return true;
                }
                if target_bytes[4] != ((size >> 24) & 0xff) as u8 {
                    return true;
                }
                return target_bytes[5..] != *data;
            }

            true
        });
    }

    /// Check if the script contains only push-data operations.
    ///
    /// Push-only means all opcodes are <= OP_16 (0x60).
    pub fn is_push_only(&self) -> bool {
        for chunk in &self.chunks {
            if chunk.op_byte > Op::Op16.to_byte() {
                return false;
            }
        }
        true
    }

    // -- Internal parsing -----------------------------------------------------

    /// Parse raw bytes into script chunks, handling OP_RETURN conditional
    /// block semantics and push-data opcodes.
    fn parse_chunks(bytes: &[u8]) -> Vec<ScriptChunk> {
        let mut chunks = Vec::new();
        let length = bytes.len();
        let mut pos = 0;
        let mut in_conditional_block: i32 = 0;

        while pos < length {
            let op_byte = bytes[pos];
            pos += 1;

            // OP_RETURN outside conditionals: remaining bytes become single data chunk
            if op_byte == Op::OpReturn.to_byte() && in_conditional_block == 0 {
                let remaining = bytes[pos..].to_vec();
                chunks.push(ScriptChunk::new_raw(
                    op_byte,
                    if remaining.is_empty() {
                        None
                    } else {
                        Some(remaining)
                    },
                ));
                break;
            }

            // Track conditional depth
            if op_byte == Op::OpIf.to_byte()
                || op_byte == Op::OpNotIf.to_byte()
                || op_byte == Op::OpVerIf.to_byte()
                || op_byte == Op::OpVerNotIf.to_byte()
            {
                in_conditional_block += 1;
            } else if op_byte == Op::OpEndIf.to_byte() {
                in_conditional_block -= 1;
            }

            // Direct push: opcode 0x01..=0x4b means push that many bytes
            if op_byte > 0 && op_byte < Op::OpPushData1.to_byte() {
                let push_len = op_byte as usize;
                let end = (pos + push_len).min(length);
                let data = bytes[pos..end].to_vec();
                chunks.push(ScriptChunk::new_raw(op_byte, Some(data)));
                pos = end;
            } else if op_byte == Op::OpPushData1.to_byte() {
                let push_len = if pos < length { bytes[pos] as usize } else { 0 };
                pos += 1;
                let end = (pos + push_len).min(length);
                let data = bytes[pos..end].to_vec();
                chunks.push(ScriptChunk::new_raw(op_byte, Some(data)));
                pos = end;
            } else if op_byte == Op::OpPushData2.to_byte() {
                let b0 = if pos < length { bytes[pos] as usize } else { 0 };
                let b1 = if pos + 1 < length {
                    bytes[pos + 1] as usize
                } else {
                    0
                };
                let push_len = b0 | (b1 << 8);
                pos = (pos + 2).min(length);
                let end = (pos + push_len).min(length);
                let data = bytes[pos..end].to_vec();
                chunks.push(ScriptChunk::new_raw(op_byte, Some(data)));
                pos = end;
            } else if op_byte == Op::OpPushData4.to_byte() {
                let b0 = if pos < length { bytes[pos] as usize } else { 0 };
                let b1 = if pos + 1 < length {
                    bytes[pos + 1] as usize
                } else {
                    0
                };
                let b2 = if pos + 2 < length {
                    bytes[pos + 2] as usize
                } else {
                    0
                };
                let b3 = if pos + 3 < length {
                    bytes[pos + 3] as usize
                } else {
                    0
                };
                let push_len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
                pos = (pos + 4).min(length);
                let end = (pos + push_len).min(length);
                let data = bytes[pos..end].to_vec();
                chunks.push(ScriptChunk::new_raw(op_byte, Some(data)));
                pos = end;
            } else {
                // Regular opcode with no data
                chunks.push(ScriptChunk::new_raw(op_byte, None));
            }
        }

        chunks
    }
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

// -- Hex utility --------------------------------------------------------------

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd hex length".to_string());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|_| format!("invalid hex at position {i}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_binary_roundtrip_empty() {
        let script = Script::from_binary(&[]);
        assert!(script.is_empty());
        assert_eq!(script.to_binary(), Vec::<u8>::new());
    }

    #[test]
    fn test_binary_roundtrip_p2pkh() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let pubkey_hash = [0xab; 20];
        let mut script_bytes = vec![0x76, 0xa9, 0x14]; // OP_DUP, OP_HASH160, push 20
        script_bytes.extend_from_slice(&pubkey_hash);
        script_bytes.push(0x88); // OP_EQUALVERIFY
        script_bytes.push(0xac); // OP_CHECKSIG

        let script = Script::from_binary(&script_bytes);
        let rt = script.to_binary();
        assert_eq!(rt, script_bytes, "binary round-trip failed for P2PKH");

        // Verify chunk count: DUP, HASH160, <data>, EQUALVERIFY, CHECKSIG = 5
        assert_eq!(script.len(), 5);
    }

    #[test]
    fn test_binary_roundtrip_pushdata1() {
        // OP_PUSHDATA1 with 100 bytes of data
        let mut script_bytes = vec![0x4c, 100]; // OP_PUSHDATA1, length=100
        script_bytes.extend_from_slice(&[0xcc; 100]);
        let script = Script::from_binary(&script_bytes);
        assert_eq!(script.to_binary(), script_bytes);
    }

    #[test]
    fn test_binary_roundtrip_pushdata2() {
        // OP_PUSHDATA2 with 300 bytes of data
        let mut script_bytes = vec![0x4d, 0x2c, 0x01]; // OP_PUSHDATA2, length=300 LE
        script_bytes.extend_from_slice(&[0xdd; 300]);
        let script = Script::from_binary(&script_bytes);
        assert_eq!(script.to_binary(), script_bytes);
    }

    #[test]
    fn test_hex_roundtrip() {
        let hex = "76a914abababababababababababababababababababab88ac";
        let script = Script::from_hex(hex).unwrap();
        assert_eq!(script.to_hex(), hex);
    }

    #[test]
    fn test_from_hex_empty() {
        let script = Script::from_hex("").unwrap();
        assert!(script.is_empty());
    }

    #[test]
    fn test_from_hex_odd_length() {
        let result = Script::from_hex("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_asm_roundtrip_p2pkh() {
        let asm =
            "OP_DUP OP_HASH160 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa OP_EQUALVERIFY OP_CHECKSIG";
        let script = Script::from_asm(asm);
        let result_asm = script.to_asm();
        assert_eq!(result_asm, asm);
    }

    #[test]
    fn test_asm_zero_and_negative_one() {
        let asm = "0 -1 OP_ADD";
        let script = Script::from_asm(asm);
        // OP_0 renders as "0", OP_1NEGATE as "-1"
        assert_eq!(script.to_asm(), "0 -1 OP_ADD");
    }

    #[test]
    fn test_op_return_outside_conditional() {
        // OP_RETURN followed by arbitrary data outside a conditional block
        // The parser should treat everything after OP_RETURN as a single data chunk
        let mut script_bytes = vec![0x6a]; // OP_RETURN
        script_bytes.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let script = Script::from_binary(&script_bytes);
        assert_eq!(script.len(), 1, "OP_RETURN + data should be one chunk");
        assert_eq!(
            script.chunks()[0].data.as_ref().unwrap(),
            &[0x01, 0x02, 0x03, 0x04]
        );

        // Round-trip
        assert_eq!(script.to_binary(), script_bytes);
    }

    #[test]
    fn test_op_return_inside_conditional() {
        // OP_IF OP_RETURN OP_ENDIF -- OP_RETURN inside conditional should NOT
        // consume remaining bytes
        let script_bytes = vec![
            0x63, // OP_IF
            0x6a, // OP_RETURN
            0x68, // OP_ENDIF
        ];

        let script = Script::from_binary(&script_bytes);
        assert_eq!(
            script.len(),
            3,
            "OP_RETURN inside conditional should be a standalone opcode"
        );
        assert!(
            script.chunks()[1].data.is_none(),
            "OP_RETURN inside conditional should have no data"
        );

        assert_eq!(script.to_binary(), script_bytes);
    }

    #[test]
    fn test_op_return_no_data() {
        // Just OP_RETURN with nothing after it
        let script_bytes = vec![0x6a];
        let script = Script::from_binary(&script_bytes);
        assert_eq!(script.len(), 1);
        assert!(script.chunks()[0].data.is_none());
        assert_eq!(script.to_binary(), script_bytes);
    }

    #[test]
    fn test_find_and_delete_simple() {
        // Create a script: OP_1 OP_2 OP_3 OP_2
        let script = Script::from_binary(&[0x51, 0x52, 0x53, 0x52]);
        // Delete OP_2
        let target = Script::from_binary(&[0x52]);
        let result = script.find_and_delete(&target);
        assert_eq!(result.to_binary(), vec![0x51, 0x53]);
    }

    #[test]
    fn test_find_and_delete_data_push() {
        // Create a script with a data push: <03 aabbcc> OP_DUP
        let script_bytes = vec![0x03, 0xaa, 0xbb, 0xcc, 0x76];
        let script = Script::from_binary(&script_bytes);

        // Target: the data push <03 aabbcc>
        let target = Script::from_binary(&[0x03, 0xaa, 0xbb, 0xcc]);
        let result = script.find_and_delete(&target);
        assert_eq!(result.to_binary(), vec![0x76]); // only OP_DUP remains
    }

    #[test]
    fn test_find_and_delete_empty_target() {
        let script = Script::from_binary(&[0x76, 0x76]);
        let target = Script::new();
        let result = script.find_and_delete(&target);
        assert_eq!(result.to_binary(), vec![0x76, 0x76]);
    }

    #[test]
    fn test_is_push_only() {
        // OP_1 (0x51), push data, OP_16 (0x60) -- all push-only
        let push_script = Script::from_binary(&[0x51, 0x03, 0xaa, 0xbb, 0xcc, 0x60]);
        assert!(push_script.is_push_only());

        // OP_DUP (0x76) -- not push-only
        let non_push = Script::from_binary(&[0x76]);
        assert!(!non_push.is_push_only());
    }

    #[test]
    fn test_from_chunks() {
        let chunks = vec![
            ScriptChunk::new_opcode(Op::OpDup),
            ScriptChunk::new_opcode(Op::OpCheckSig),
        ];
        let script = Script::from_chunks(chunks);
        assert_eq!(script.len(), 2);
        assert_eq!(script.to_binary(), vec![0x76, 0xac]);
    }

    #[test]
    fn test_complex_script_roundtrip() {
        // A more complex script with mixed opcodes and pushes
        let hex = "5121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe52ae";
        let script = Script::from_hex(hex).unwrap();
        assert_eq!(script.to_hex(), hex);
    }

    #[test]
    fn test_nested_conditional_op_return() {
        // OP_IF OP_IF OP_RETURN OP_ENDIF OP_ENDIF -- double nested
        // OP_RETURN at depth 2 should NOT consume remaining bytes
        let script_bytes = vec![
            0x63, // OP_IF
            0x63, // OP_IF
            0x6a, // OP_RETURN
            0x68, // OP_ENDIF
            0x68, // OP_ENDIF
        ];
        let script = Script::from_binary(&script_bytes);
        assert_eq!(script.len(), 5);
        assert!(script.chunks()[2].data.is_none());
        assert_eq!(script.to_binary(), script_bytes);
    }
}
