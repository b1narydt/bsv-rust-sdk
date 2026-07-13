//! Inscription and OP_RETURN data embedding helpers.
//!
//! Provides structured inscription creation (content type + data)
//! and simple OP_RETURN data scripts.
//! Translates the Go SDK inscriptions.go.

use crate::script::error::ScriptError;
use crate::script::locking_script::LockingScript;
use crate::script::op::Op;
use crate::script::script::Script;
use crate::script::script_chunk::ScriptChunk;

/// An inscription with a content type and data payload.
///
/// Encoded as an OP_FALSE OP_RETURN script with two data pushes:
/// the content type string and the raw data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inscription {
    pub content_type: String,
    pub data: Vec<u8>,
}

impl Inscription {
    /// Create a new inscription with the given content type and data.
    pub fn new(content_type: &str, data: Vec<u8>) -> Self {
        Inscription {
            content_type: content_type.to_string(),
            data,
        }
    }

    /// Convert this inscription to a locking script.
    ///
    /// Format: OP_FALSE OP_RETURN <content_type_bytes> <data_bytes>
    pub fn to_script(&self) -> LockingScript {
        let ct_bytes = self.content_type.as_bytes().to_vec();
        let chunks = vec![
            ScriptChunk::new_opcode(Op::Op0), // OP_FALSE = OP_0
            ScriptChunk::new_opcode(Op::OpReturn),
            Self::make_data_chunk(&ct_bytes),
            Self::make_data_chunk(&self.data),
        ];
        LockingScript::from_script(Script::from_chunks(chunks))
    }

    /// Parse an inscription from a script.
    ///
    /// Expected format: OP_FALSE/OP_0 OP_RETURN <content_type_data> <payload_data>
    pub fn from_script(script: &Script) -> Result<Self, ScriptError> {
        let chunks = script.chunks();

        if chunks.len() < 4 {
            return Err(ScriptError::InvalidScript(
                "inscription script must have at least 4 chunks".to_string(),
            ));
        }

        // First chunk: OP_FALSE (OP_0)
        if chunks[0].op != Op::Op0 {
            return Err(ScriptError::InvalidScript(
                "inscription must start with OP_FALSE/OP_0".to_string(),
            ));
        }

        // Second chunk: OP_RETURN
        if chunks[1].op != Op::OpReturn {
            return Err(ScriptError::InvalidScript(
                "inscription second opcode must be OP_RETURN".to_string(),
            ));
        }

        // Third chunk: content type data
        let ct_data = chunks[2].data.as_ref().ok_or_else(|| {
            ScriptError::InvalidScript("inscription content type chunk has no data".to_string())
        })?;
        let content_type = String::from_utf8(ct_data.clone()).map_err(|e| {
            ScriptError::InvalidScript(format!("inscription content type is not valid UTF-8: {e}"))
        })?;

        // Fourth chunk: payload data
        let data = chunks[3].data.as_ref().ok_or_else(|| {
            ScriptError::InvalidScript("inscription data chunk has no data".to_string())
        })?;

        Ok(Inscription {
            content_type,
            data: data.clone(),
        })
    }

    /// Create an appropriate data push chunk for the given bytes.
    fn make_data_chunk(data: &[u8]) -> ScriptChunk {
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
        ScriptChunk::new_raw(op_byte, Some(data.to_vec()))
    }
}

/// Create a simple OP_FALSE OP_RETURN data script (no content type).
///
/// Format: `OP_FALSE OP_RETURN <data>`
pub fn op_return_data(data: &[u8]) -> LockingScript {
    let chunks = vec![
        ScriptChunk::new_opcode(Op::Op0), // OP_FALSE
        ScriptChunk::new_opcode(Op::OpReturn),
        Inscription::make_data_chunk(data),
    ];
    LockingScript::from_script(Script::from_chunks(chunks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inscription_to_script_format() {
        let insc = Inscription::new("text/plain", b"hello world".to_vec());
        let script = insc.to_script();
        let binary = script.to_binary();

        // First byte: OP_FALSE (0x00)
        assert_eq!(binary[0], 0x00, "should start with OP_FALSE");
        // Second byte: OP_RETURN (0x6a)
        assert_eq!(binary[1], 0x6a, "second byte should be OP_RETURN");
    }

    #[test]
    fn test_inscription_roundtrip() {
        let insc = Inscription::new("text/plain", b"hello world".to_vec());
        let script = insc.to_script();

        // The script uses from_chunks, which does NOT trigger OP_RETURN
        // conditional-block semantics from parse_chunks. We need to parse
        // the chunks directly.
        let decoded = Inscription::from_script(&script).unwrap();
        assert_eq!(decoded.content_type, "text/plain");
        assert_eq!(decoded.data, b"hello world");
    }

    #[test]
    fn test_inscription_from_script_invalid() {
        // Too few chunks
        let script = Script::from_chunks(vec![ScriptChunk::new_opcode(Op::Op0)]);
        assert!(Inscription::from_script(&script).is_err());

        // Wrong first opcode
        let script = Script::from_chunks(vec![
            ScriptChunk::new_opcode(Op::Op1),
            ScriptChunk::new_opcode(Op::OpReturn),
            ScriptChunk::new_raw(4, Some(b"test".to_vec())),
            ScriptChunk::new_raw(4, Some(b"data".to_vec())),
        ]);
        assert!(Inscription::from_script(&script).is_err());
    }

    #[test]
    fn test_op_return_data_format() {
        let script = op_return_data(b"test data");
        let binary = script.to_binary();

        assert_eq!(binary[0], 0x00, "OP_FALSE");
        assert_eq!(binary[1], 0x6a, "OP_RETURN");
        // Third byte is push length (9 bytes of "test data")
        assert_eq!(binary[2], 9);
        assert_eq!(&binary[3..12], b"test data");
    }

    #[test]
    fn test_op_return_data_empty() {
        let script = op_return_data(&[]);
        let binary = script.to_binary();

        assert_eq!(binary[0], 0x00, "OP_FALSE");
        assert_eq!(binary[1], 0x6a, "OP_RETURN");
        assert_eq!(binary[2], 0x00, "push 0 bytes");
    }

    #[test]
    fn test_inscription_various_content_types() {
        let test_cases = vec![
            ("application/json", b"{\"key\":\"value\"}".to_vec()),
            ("image/png", vec![0x89, 0x50, 0x4e, 0x47]),
            ("text/html", b"<html></html>".to_vec()),
        ];

        for (ct, data) in test_cases {
            let insc = Inscription::new(ct, data.clone());
            let script = insc.to_script();
            let decoded = Inscription::from_script(&script).unwrap();
            assert_eq!(decoded.content_type, ct);
            assert_eq!(decoded.data, data);
        }
    }
}
