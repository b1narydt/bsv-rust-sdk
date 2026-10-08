//! ScriptChunk: a parsed element of a Bitcoin script.
//!
//! Each chunk is either a bare opcode or a data push (opcode + data bytes).

use crate::script::op::Op;

/// A single parsed element of a script.
#[derive(Debug, Clone)]
pub struct ScriptChunk {
    /// The opcode. For direct pushes (0x01..=0x4b) this is the raw byte
    /// cast via `Op::from`, which gives `OpInvalidOpcode`. The parser
    /// stores the raw byte value as `op_byte` instead.
    pub op: Op,
    /// For push operations this carries the raw opcode byte (which may
    /// be a direct-push length 0x01..=0x4b that has no named Op variant).
    pub op_byte: u8,
    /// The pushed data, if any.
    pub data: Option<Vec<u8>>,
    /// For a push read by the parser, the length its opcode declared (`usize::MAX` when the length bytes
    /// themselves were missing); a shorter `data` means the script ended inside the push. `None` for chunks
    /// built in code. Not part of equality.
    pub declared_len: Option<usize>,
}

impl PartialEq for ScriptChunk {
    fn eq(&self, other: &Self) -> bool {
        self.op == other.op && self.op_byte == other.op_byte && self.data == other.data
    }
}

impl Eq for ScriptChunk {}

impl ScriptChunk {
    /// Create a new chunk with just an opcode (no data).
    pub fn new_opcode(op: Op) -> Self {
        ScriptChunk {
            op,
            op_byte: op.to_byte(),
            data: None,
            declared_len: None,
        }
    }

    /// Create a new chunk from a raw opcode byte and optional data.
    pub fn new_raw(op_byte: u8, data: Option<Vec<u8>>) -> Self {
        ScriptChunk {
            op: Op::from(op_byte),
            op_byte,
            data,
            declared_len: None,
        }
    }

    /// A push chunk as the parser read it, with the length its opcode declared.
    pub fn new_parsed_push(op_byte: u8, data: Vec<u8>, declared_len: usize) -> Self {
        ScriptChunk {
            op: Op::from(op_byte),
            op_byte,
            data: Some(data),
            declared_len: Some(declared_len),
        }
    }

    /// Serialized byte length of this chunk.
    pub fn len(&self) -> usize {
        let data_len = self.data.as_ref().map_or(0, |d| d.len());
        if data_len == 0 && self.data.is_none() {
            // Pure opcode, no data
            return 1;
        }

        // OP_RETURN with data: opcode + raw data (no length prefix)
        if self.op == Op::OpReturn && self.data.is_some() {
            return 1 + data_len;
        }

        // Direct push (opcode IS the length: 0x01..=0x4b)
        if self.op_byte >= 0x01 && self.op_byte <= 0x4b {
            return 1 + data_len;
        }

        match self.op {
            Op::OpPushData1 => 1 + 1 + data_len,
            Op::OpPushData2 => 1 + 2 + data_len,
            Op::OpPushData4 => 1 + 4 + data_len,
            _ => 1 + data_len,
        }
    }

    /// Whether the chunk has a non-zero serialized length (always true).
    pub fn is_empty(&self) -> bool {
        false
    }

    /// ASM string representation.
    ///
    /// Data pushes render as lowercase hex. Opcodes render as their name.
    pub fn to_asm(&self) -> String {
        match &self.data {
            Some(data) => {
                let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
                hex
            }
            None => self.op.to_name().to_string(),
        }
    }

    /// Serialize this chunk to binary bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.push(self.op_byte);

        if let Some(data) = &self.data {
            if self.op == Op::OpReturn {
                // OP_RETURN data chunk: opcode + raw data
                out.extend_from_slice(data);
                return out;
            }

            // Direct push (0x01..=0x4b): opcode is the length
            if self.op_byte >= 0x01 && self.op_byte <= 0x4b {
                out.extend_from_slice(data);
                return out;
            }

            match self.op {
                Op::OpPushData1 => {
                    out.push(data.len() as u8);
                    out.extend_from_slice(data);
                }
                Op::OpPushData2 => {
                    let len = data.len() as u16;
                    out.push((len & 0xff) as u8);
                    out.push(((len >> 8) & 0xff) as u8);
                    out.extend_from_slice(data);
                }
                Op::OpPushData4 => {
                    let len = data.len() as u32;
                    out.push((len & 0xff) as u8);
                    out.push(((len >> 8) & 0xff) as u8);
                    out.push(((len >> 16) & 0xff) as u8);
                    out.push(((len >> 24) & 0xff) as u8);
                    out.extend_from_slice(data);
                }
                _ => {
                    out.extend_from_slice(data);
                }
            }
        }

        out
    }
}
