//! Action data (var2) encoding/decoding per STAS-3 spec v0.2 §6.
//!
//! var2's first byte is the action selector:
//! - 0x00 / empty push  → Passive
//! - 0x01               → Swap descriptor (61+ bytes, recursive `next`)
//! - 0x02               → Frozen marker (must stand alone if standalone byte)
//! - other              → Custom (treated as opaque user data)
//!
//! Encoding rule: the *push* form depends on action selection — Passive can
//! be `OP_0` (empty push); Frozen as a standalone byte 0x02 is encoded as
//! the opcode `OP_2` (single byte 0x52) but as a *prefix* on existing data
//! is encoded by prepending 0x02 to that data and then using normal
//! pushdata encoding (§6.2). Swap and Custom always use pushdata encoding
//! of their full bytes (including the action byte).

use super::error::Stas3Error;

/// High-level var2 content. The encoder converts to wire bytes; the decoder
/// parses wire bytes to recover this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionData {
    /// No active state; optional owner notes.
    /// `Passive(vec![])` encodes as `OP_0` (empty push).
    /// `Passive(b)` encodes as `0x00` + b (pushdata).
    Passive(Vec<u8>),

    /// Frozen marker. Standalone form encodes as `OP_2` (single byte 0x52).
    /// Wraps an underlying var2 payload (possibly empty).
    /// Encoded as 0x02 followed by underlying bytes (pushdata if non-empty).
    Frozen(Vec<u8>),

    /// Swap descriptor, action byte 0x01.
    Swap(SwapDescriptor),

    /// Application-defined; first byte is some other value than 0x00/0x01/0x02.
    /// Encoded as a direct pushdata of the bytes.
    Custom(Vec<u8>),
}

/// Swap descriptor per spec v0.2 §6.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapDescriptor {
    /// SHA-256 of the counterparty's full locking script.
    pub requested_script_hash: [u8; 32],
    /// HASH160 of where the counter-asset is delivered.
    pub receive_addr: [u8; 20],
    /// Exchange rate numerator. If 0, engine skips rate verification.
    pub rate_numerator: u32,
    /// Exchange rate denominator.
    pub rate_denominator: u32,
    /// Optional recursive `next`. None = terminal (no `next` field present).
    pub next: Option<Box<NextVar2>>,
}

/// Optional recursive `next` field of a swap descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextVar2 {
    /// Leading 0x00 + arbitrary bytes (or empty).
    Passive(Vec<u8>),
    /// Single byte 0x02 — frozen marker, no trailing bytes allowed.
    Frozen,
    /// Recursive swap (encoded WITHOUT leading 0x01 — the action byte is implied).
    Swap(SwapDescriptor),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SwapDescriptorError {
    #[error("missing action byte 0x01 at start of swap descriptor")]
    MissingActionByte,
    #[error("descriptor truncated at offset {0} (need at least {1} more bytes)")]
    Truncated(usize, usize),
    #[error("unknown next-form leading byte 0x{0:02x} at offset {1}")]
    UnknownNextForm(u8, usize),
    #[error("trailing bytes after frozen marker (0x02)")]
    TrailingAfterFrozen,
}

impl SwapDescriptor {
    /// Encode as a complete var2 payload INCLUDING the leading 0x01 action byte.
    pub fn to_var2_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(61);
        out.push(0x01);
        self.append_body(&mut out);
        out
    }

    /// Append BODY (no leading 0x01), then any `next` payload.
    fn append_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.requested_script_hash);
        out.extend_from_slice(&self.receive_addr);
        out.extend_from_slice(&self.rate_numerator.to_le_bytes());
        out.extend_from_slice(&self.rate_denominator.to_le_bytes());
        if let Some(next) = &self.next {
            next.append(out);
        }
    }

    /// Parse a complete var2 payload starting with 0x01.
    pub fn parse(bytes: &[u8]) -> Result<Self, SwapDescriptorError> {
        if bytes.is_empty() || bytes[0] != 0x01 {
            return Err(SwapDescriptorError::MissingActionByte);
        }
        let (desc, rest) = Self::parse_body(&bytes[1..])?;
        if !rest.is_empty() {
            // A well-formed top-level descriptor consumes every byte after
            // the leading 0x01 — recursive `next` swallows any tail. If we
            // arrive here with bytes remaining, the input is malformed.
            return Err(SwapDescriptorError::UnknownNextForm(
                rest[0],
                bytes.len() - rest.len(),
            ));
        }
        Ok(desc)
    }

    /// Parse the body (after the leading 0x01 has been stripped).
    /// Returns (descriptor, remaining_bytes).
    fn parse_body(bytes: &[u8]) -> Result<(Self, &[u8]), SwapDescriptorError> {
        const MIN_BODY: usize = 32 + 20 + 4 + 4;
        if bytes.len() < MIN_BODY {
            return Err(SwapDescriptorError::Truncated(0, MIN_BODY - bytes.len()));
        }
        let mut requested_script_hash = [0u8; 32];
        requested_script_hash.copy_from_slice(&bytes[0..32]);
        let mut receive_addr = [0u8; 20];
        receive_addr.copy_from_slice(&bytes[32..52]);
        let rate_numerator = u32::from_le_bytes(bytes[52..56].try_into().unwrap());
        let rate_denominator = u32::from_le_bytes(bytes[56..60].try_into().unwrap());
        let rest = &bytes[60..];
        let (next, rest) = if rest.is_empty() {
            (None, rest)
        } else {
            let (n, r) = NextVar2::parse(rest)?;
            (Some(Box::new(n)), r)
        };
        Ok((
            SwapDescriptor {
                requested_script_hash,
                receive_addr,
                rate_numerator,
                rate_denominator,
                next,
            },
            rest,
        ))
    }
}

impl NextVar2 {
    fn append(&self, out: &mut Vec<u8>) {
        match self {
            NextVar2::Passive(rest) => {
                out.push(0x00);
                out.extend_from_slice(rest);
            }
            NextVar2::Frozen => {
                out.push(0x02);
            }
            NextVar2::Swap(inner) => {
                // Recursive: encoded WITHOUT leading 0x01 (action byte implied)
                inner.append_body(out);
            }
        }
    }

    fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), SwapDescriptorError> {
        if bytes.is_empty() {
            return Err(SwapDescriptorError::Truncated(0, 1));
        }
        match bytes[0] {
            0x00 => {
                // Passive: 0x00 followed by arbitrary owner data through end of input
                Ok((NextVar2::Passive(bytes[1..].to_vec()), &[]))
            }
            0x02 => {
                // Frozen: must be exactly one byte
                if bytes.len() > 1 {
                    return Err(SwapDescriptorError::TrailingAfterFrozen);
                }
                Ok((NextVar2::Frozen, &[]))
            }
            _ => {
                // Anything else: recursive Swap descriptor with implied action byte
                let (inner, rest) = SwapDescriptor::parse_body(bytes)?;
                Ok((NextVar2::Swap(inner), rest))
            }
        }
    }
}

impl ActionData {
    /// Decode the *contents* of a var2 push into `ActionData`.
    ///
    /// This takes the unwrapped bytes (NOT including the script's push opcode header).
    /// `&[]` represents an empty push (OP_0) — decoded as `Passive(vec![])`.
    ///
    /// The standalone OP_2 case (frozen marker as opcode 0x52) is handled by
    /// the script *parser* (which sees the opcode and synthesizes a single-byte
    /// `[0x02]` payload to pass here). This function sees `[0x02]` and decodes
    /// it as `Frozen(vec![])`. The script-level OP_2 mapping happens in the
    /// Phase 3 lock builder, not here.
    pub fn parse(bytes: &[u8]) -> Result<Self, Stas3Error> {
        if bytes.is_empty() {
            return Ok(ActionData::Passive(vec![]));
        }
        match bytes[0] {
            0x00 => Ok(ActionData::Passive(bytes[1..].to_vec())),
            0x01 => {
                let desc = SwapDescriptor::parse(bytes)
                    .map_err(|e| Stas3Error::InvalidScript(format!("swap descriptor: {e}")))?;
                Ok(ActionData::Swap(desc))
            }
            0x02 => Ok(ActionData::Frozen(bytes[1..].to_vec())),
            _ => Ok(ActionData::Custom(bytes.to_vec())),
        }
    }

    /// Encode as the *contents* of a var2 push (NOT including push opcode header).
    /// Caller wraps with the appropriate push opcode (see Phase 3 lock builder).
    ///
    /// `Passive(vec![])` → `vec![]` (caller will emit OP_0).
    /// `Frozen(vec![])` → `vec![0x02]` (caller will emit as single-byte push or use OP_2).
    pub fn to_var2_bytes(&self) -> Vec<u8> {
        match self {
            ActionData::Passive(rest) if rest.is_empty() => vec![],
            ActionData::Passive(rest) => {
                let mut out = Vec::with_capacity(1 + rest.len());
                out.push(0x00);
                out.extend_from_slice(rest);
                out
            }
            ActionData::Frozen(rest) => {
                let mut out = Vec::with_capacity(1 + rest.len());
                out.push(0x02);
                out.extend_from_slice(rest);
                out
            }
            ActionData::Swap(desc) => desc.to_var2_bytes(),
            ActionData::Custom(b) => b.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- ActionData encoding/decoding ---------------------------------------

    #[test]
    fn test_passive_empty_round_trip() {
        let ad = ActionData::Passive(vec![]);
        let bytes = ad.to_var2_bytes();
        assert_eq!(bytes, Vec::<u8>::new());
        let parsed = ActionData::parse(&bytes).unwrap();
        assert_eq!(parsed, ad);
    }

    #[test]
    fn test_passive_with_bytes_round_trip() {
        let ad = ActionData::Passive(vec![0xab, 0xcd]);
        let bytes = ad.to_var2_bytes();
        assert_eq!(bytes, vec![0x00, 0xab, 0xcd]);
        let parsed = ActionData::parse(&bytes).unwrap();
        assert_eq!(parsed, ad);
    }

    #[test]
    fn test_frozen_empty_round_trip() {
        let ad = ActionData::Frozen(vec![]);
        let bytes = ad.to_var2_bytes();
        assert_eq!(bytes, vec![0x02]);
        let parsed = ActionData::parse(&bytes).unwrap();
        assert_eq!(parsed, ad);
    }

    #[test]
    fn test_frozen_with_payload_round_trip() {
        let ad = ActionData::Frozen(vec![0xff]);
        let bytes = ad.to_var2_bytes();
        assert_eq!(bytes, vec![0x02, 0xff]);
        let parsed = ActionData::parse(&bytes).unwrap();
        assert_eq!(parsed, ad);
    }

    #[test]
    fn test_custom_round_trip() {
        // Leading byte must NOT be 0x00/0x01/0x02 to be Custom.
        let ad = ActionData::Custom(vec![0xde, 0xad]);
        let bytes = ad.to_var2_bytes();
        assert_eq!(bytes, vec![0xde, 0xad]);
        let parsed = ActionData::parse(&bytes).unwrap();
        assert_eq!(parsed, ad);
    }

    // -- SwapDescriptor encoder/decoder -------------------------------------

    fn base_descriptor() -> SwapDescriptor {
        SwapDescriptor {
            requested_script_hash: [0u8; 32],
            receive_addr: [0u8; 20],
            rate_numerator: 1,
            rate_denominator: 2,
            next: None,
        }
    }

    #[test]
    fn test_swap_descriptor_61_byte_minimum_round_trip() {
        let d = base_descriptor();
        let bytes = d.to_var2_bytes();
        assert_eq!(bytes.len(), 61);
        assert_eq!(bytes[0], 0x01);
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn test_swap_descriptor_rate_skip_mode_round_trip() {
        // rate_numerator = 0 puts the engine in rate-skip mode; encoding
        // must still round-trip cleanly.
        let mut d = base_descriptor();
        d.rate_numerator = 0;
        d.rate_denominator = 1;
        let bytes = d.to_var2_bytes();
        assert_eq!(bytes.len(), 61);
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn test_swap_descriptor_with_passive_next() {
        let mut d = base_descriptor();
        d.next = Some(Box::new(NextVar2::Passive(vec![0xaa])));
        let bytes = d.to_var2_bytes();
        // 61 (descriptor incl 0x01) + 1 (0x00 marker) + 1 (payload byte) = 63
        assert_eq!(bytes.len(), 63);
        assert_eq!(bytes[61], 0x00);
        assert_eq!(bytes[62], 0xaa);
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn test_swap_descriptor_with_frozen_next() {
        let mut d = base_descriptor();
        d.next = Some(Box::new(NextVar2::Frozen));
        let bytes = d.to_var2_bytes();
        // 61 + 1 (0x02) = 62
        assert_eq!(bytes.len(), 62);
        assert_eq!(bytes[61], 0x02);
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn test_swap_descriptor_with_recursive_swap_next() {
        let inner = SwapDescriptor {
            requested_script_hash: [0x22; 32],
            receive_addr: [0x42; 20],
            rate_numerator: 20,
            rate_denominator: 21,
            next: None,
        };
        let mut d = base_descriptor();
        d.next = Some(Box::new(NextVar2::Swap(inner)));
        let bytes = d.to_var2_bytes();
        // 61 (top, includes 0x01) + 60 (inner body, no leading 0x01) = 121
        assert_eq!(bytes.len(), 121);
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn test_swap_descriptor_parse_rejects_non_action_leading_byte() {
        let res = SwapDescriptor::parse(&[0x02]);
        assert_eq!(res, Err(SwapDescriptorError::MissingActionByte));
    }

    #[test]
    fn test_swap_descriptor_parse_rejects_truncated_body() {
        let res = SwapDescriptor::parse(&[0x01, 0xff]);
        assert!(matches!(res, Err(SwapDescriptorError::Truncated(..))));
    }

    #[test]
    fn test_next_var2_frozen_with_trailing_bytes_is_rejected() {
        let res = NextVar2::parse(&[0x02, 0x00]);
        assert_eq!(res, Err(SwapDescriptorError::TrailingAfterFrozen));
    }

    #[test]
    fn test_recursive_swap_parse_via_swap_descriptor_parse() {
        // Two-hop chain: top → Swap(inner) → no further next.
        let inner = SwapDescriptor {
            requested_script_hash: [0xaa; 32],
            receive_addr: [0xbb; 20],
            rate_numerator: 7,
            rate_denominator: 9,
            next: None,
        };
        let top = SwapDescriptor {
            requested_script_hash: [0x11; 32],
            receive_addr: [0x22; 20],
            rate_numerator: 3,
            rate_denominator: 5,
            next: Some(Box::new(NextVar2::Swap(inner))),
        };
        let bytes = top.to_var2_bytes();
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, top);
    }

    // -- ActionData::Swap variant via parse ---------------------------------

    #[test]
    fn test_action_data_swap_round_trip() {
        let d = SwapDescriptor {
            requested_script_hash: [0xab; 32],
            receive_addr: [0xcd; 20],
            rate_numerator: 5,
            rate_denominator: 7,
            next: Some(Box::new(NextVar2::Frozen)),
        };
        let ad = ActionData::Swap(d.clone());
        let bytes = ad.to_var2_bytes();
        let parsed = ActionData::parse(&bytes).unwrap();
        assert_eq!(parsed, ActionData::Swap(d));
    }

    #[test]
    fn test_action_data_swap_invalid_returns_invalid_script_error() {
        // 0x01 followed by truncated body — ActionData::parse must surface
        // the error wrapped as Stas3Error::InvalidScript.
        let err = ActionData::parse(&[0x01, 0x02, 0x03]).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("swap descriptor"), "unexpected msg: {msg}");
            }
            other => panic!("expected InvalidScript, got {other:?}"),
        }
    }
}
