//! STAS-3 locking script construction (spec v0.2 §5.1, §6).
//!
//! Builds the canonical on-chain layout:
//!
//! ```text
//! [0x14] [owner:20]               # bare PUSH20 of owner PKH/MPKH
//! [var2 push]                     # action data (Passive / Frozen / Swap / Custom)
//! [engine:2899]                   # STAS3_ENGINE_BYTES verbatim
//! [0x14 protoID:20]               # PUSH20 of redemption PKH (= protocol ID)
//! [flags push]                    # 1-byte data push of flags byte
//! [svc fields...]                 # one push per set flag bit (low-to-high)
//! [optional data...]              # 0+ application pushes
//! ```
//!
//! Round-trips byte-for-byte through `decode::decode_locking_script`.

use crate::script::locking_script::LockingScript;

use super::action_data::ActionData;
use super::constants::STAS3_ENGINE_BYTES;
use super::error::Stas3Error;

/// Inputs to build a STAS-3 locking script. Owner and protoID PKHs MUST be
/// derived via Type-42 (per spec §1A) — this function does not enforce
/// derivation; downstream tests verify policy compliance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockParams {
    pub owner_pkh: [u8; 20],
    pub action_data: ActionData,
    pub redemption_pkh: [u8; 20],
    pub flags: u8,
    /// One entry per set flag bit, in left-to-right order of increasing bit
    /// (bit 0 = FREEZABLE → first; bit 1 = CONFISCATABLE → second). See
    /// spec §5.2.3.
    pub service_fields: Vec<Vec<u8>>,
    pub optional_data: Vec<Vec<u8>>,
}

/// Build the canonical STAS-3 locking script.
pub fn build_locking_script(params: &LockParams) -> Result<LockingScript, Stas3Error> {
    let mut bytes = Vec::with_capacity(
        21                          // owner push
        + 80                        // var2 (worst-case swap descriptor 61+ bytes + push header)
        + STAS3_ENGINE_BYTES.len()  // 2899
        + 21                        // redemption push
        + 2                         // flags push (header + 1 byte)
        + params.service_fields.iter().map(|s| s.len() + 3).sum::<usize>()
        + params.optional_data.iter().map(|s| s.len() + 3).sum::<usize>(),
    );

    // 1. Owner — bare PUSH20 + 20 bytes
    bytes.push(0x14);
    bytes.extend_from_slice(&params.owner_pkh);

    // 2. var2 — encode ActionData with the appropriate push opcode
    push_var2(&mut bytes, &params.action_data);

    // 3. Engine bytes verbatim
    bytes.extend_from_slice(STAS3_ENGINE_BYTES);

    // 4. protoID — bare PUSH20 + 20 bytes
    bytes.push(0x14);
    bytes.extend_from_slice(&params.redemption_pkh);

    // 5. Flags — always pushed as a 1-byte data push (PUSH1 + flags byte),
    //    NEVER as OP_N opcode. Per spec §5.2.2; decoder enforces 1-byte.
    bytes.push(0x01);
    bytes.push(params.flags);

    // 6. Service fields
    for f in &params.service_fields {
        push_data_minimal(&mut bytes, f);
    }

    // 7. Optional data
    for d in &params.optional_data {
        push_data_minimal(&mut bytes, d);
    }

    Ok(LockingScript::from_binary(&bytes))
}

/// Encode the var2 push using minimal Bitcoin script encoding.
///
/// Special cases per spec §6:
/// - `Passive(empty)` → emit single byte `0x00` (OP_0)
/// - `Frozen(empty)`  → emit single byte `0x52` (OP_2 — frozen marker)
/// - All other forms → standard data push of the var2 bytes
fn push_var2(bytes: &mut Vec<u8>, ad: &ActionData) {
    match ad {
        ActionData::Passive(rest) if rest.is_empty() => {
            bytes.push(0x00); // OP_0
        }
        ActionData::Frozen(rest) if rest.is_empty() => {
            bytes.push(0x52); // OP_2 — frozen marker (spec §6.2)
        }
        _ => {
            let body = ad.to_var2_bytes();
            push_data_minimal(bytes, &body);
        }
    }
}

/// Minimal Bitcoin Script data-push encoding.
///
/// - Empty → OP_0 (0x00)
/// - 1..=75 bytes → bare push (length byte + data)
/// - 76..=255 bytes → OP_PUSHDATA1
/// - 256..=65535 bytes → OP_PUSHDATA2
/// - >65535 bytes → OP_PUSHDATA4
///
/// Note: this does NOT collapse single bytes 0x01..=0x10 to OP_N. STAS-3
/// data fields (service, optional, swap descriptors) are always emitted as
/// length-prefixed data pushes for parser stability.
pub(crate) fn push_data_minimal(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        out.push(0x00);
    } else if len <= 75 {
        out.push(len as u8);
        out.extend_from_slice(data);
    } else if len <= 255 {
        out.push(0x4c);
        out.push(len as u8);
        out.extend_from_slice(data);
    } else if len <= 65535 {
        out.push(0x4d);
        out.push((len & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.extend_from_slice(data);
    } else {
        out.push(0x4e);
        out.push((len & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 24) & 0xff) as u8);
        out.extend_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::templates::stas3::action_data::{NextVar2, SwapDescriptor};
    use crate::script::templates::stas3::flags::{CONFISCATABLE, FREEZABLE};

    fn minimal_passive_params() -> LockParams {
        LockParams {
            owner_pkh: [0xaa; 20],
            action_data: ActionData::Passive(vec![]),
            redemption_pkh: [0xbb; 20],
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        }
    }

    #[test]
    fn test_build_minimal_passive() {
        let params = minimal_passive_params();
        let script = build_locking_script(&params).unwrap();
        let bytes = script.to_binary();

        // Total length: owner(21) + var2(1, OP_0) + engine(2899) + protoID(21)
        //             + flags push(2) = 2944
        assert_eq!(bytes.len(), 21 + 1 + STAS3_ENGINE_BYTES.len() + 21 + 2);
        assert_eq!(bytes.len(), 2944);

        // Byte-level layout
        assert_eq!(bytes[0], 0x14, "owner push opcode");
        assert_eq!(&bytes[1..21], &[0xaa; 20], "owner pkh");
        assert_eq!(bytes[21], 0x00, "var2 OP_0 for empty Passive");
        assert_eq!(
            &bytes[22..22 + STAS3_ENGINE_BYTES.len()],
            STAS3_ENGINE_BYTES,
            "engine bytes verbatim"
        );
        let proto_pos = 22 + STAS3_ENGINE_BYTES.len();
        assert_eq!(bytes[proto_pos], 0x14, "protoID push opcode");
        assert_eq!(&bytes[proto_pos + 1..proto_pos + 21], &[0xbb; 20], "protoID pkh");
        let flags_pos = proto_pos + 21;
        assert_eq!(bytes[flags_pos], 0x01, "flags push header (PUSH1)");
        assert_eq!(bytes[flags_pos + 1], 0x00, "flags byte (=0)");

        // Spot-check the constants the spec calls out.
        assert_eq!(bytes[2921], 0x14);
        assert_eq!(bytes[2942], 0x01);
        assert_eq!(bytes[2943], 0x00);
    }

    #[test]
    fn test_build_frozen_empty_emits_op_2() {
        let mut p = minimal_passive_params();
        p.action_data = ActionData::Frozen(vec![]);
        let bytes = build_locking_script(&p).unwrap().to_binary();
        assert_eq!(bytes[21], 0x52, "frozen empty must emit OP_2");
    }

    #[test]
    fn test_build_passive_with_data() {
        let mut p = minimal_passive_params();
        p.action_data = ActionData::Passive(vec![0xab, 0xcd]);
        let bytes = build_locking_script(&p).unwrap().to_binary();
        // var2 body is [0x00, 0xab, 0xcd] (3 bytes), pushed as PUSH3 + body.
        assert_eq!(bytes[21], 0x03, "PUSH3 length header");
        assert_eq!(&bytes[22..25], &[0x00, 0xab, 0xcd]);
    }

    #[test]
    fn test_build_swap_descriptor() {
        let desc = SwapDescriptor {
            requested_script_hash: [0u8; 32],
            receive_addr: [0u8; 20],
            rate_numerator: 0,
            rate_denominator: 0,
            next: None,
        };
        let mut p = minimal_passive_params();
        p.action_data = ActionData::Swap(desc);
        let bytes = build_locking_script(&p).unwrap().to_binary();
        // var2 body: 0x01 + 32 + 20 + 4 + 4 = 61 bytes; push header is 0x3d.
        assert_eq!(bytes[21], 0x3d, "PUSH61 length header");
        assert_eq!(bytes[22], 0x01, "swap action byte");
        // Remaining 60 bytes should all be zero.
        assert!(bytes[23..23 + 60].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_build_with_freezable_flag() {
        let mut p = minimal_passive_params();
        p.flags = FREEZABLE;
        p.service_fields = vec![vec![0x11; 20]];
        let bytes = build_locking_script(&p).unwrap().to_binary();
        let flags_pos = 22 + STAS3_ENGINE_BYTES.len() + 21;
        assert_eq!(bytes[flags_pos], 0x01, "flags push header");
        assert_eq!(bytes[flags_pos + 1], FREEZABLE);
        // First service field: PUSH20 + 20 bytes of 0x11
        assert_eq!(bytes[flags_pos + 2], 0x14);
        assert_eq!(&bytes[flags_pos + 3..flags_pos + 23], &[0x11; 20]);
    }

    #[test]
    fn test_build_with_both_flags_and_two_authorities() {
        let mut p = minimal_passive_params();
        p.flags = FREEZABLE | CONFISCATABLE;
        p.service_fields = vec![vec![0x11; 20], vec![0x22; 20]];
        let bytes = build_locking_script(&p).unwrap().to_binary();
        let flags_pos = 22 + STAS3_ENGINE_BYTES.len() + 21;
        assert_eq!(bytes[flags_pos + 1], 0x03);
        // Freezable auth (first)
        assert_eq!(bytes[flags_pos + 2], 0x14);
        assert_eq!(&bytes[flags_pos + 3..flags_pos + 23], &[0x11; 20]);
        // Confiscation auth (second)
        assert_eq!(bytes[flags_pos + 23], 0x14);
        assert_eq!(&bytes[flags_pos + 24..flags_pos + 44], &[0x22; 20]);
    }

    #[test]
    fn test_build_with_optional_data_only() {
        let mut p = minimal_passive_params();
        p.optional_data = vec![vec![0x55; 32]];
        let bytes = build_locking_script(&p).unwrap().to_binary();
        let flags_pos = 22 + STAS3_ENGINE_BYTES.len() + 21;
        // After flags push (2 bytes), no svc fields → optional starts immediately.
        let opt_pos = flags_pos + 2;
        assert_eq!(bytes[opt_pos], 0x20, "PUSH32 length header");
        assert_eq!(&bytes[opt_pos + 1..opt_pos + 33], &[0x55; 32]);
        assert_eq!(bytes.len(), opt_pos + 33);
    }

    #[test]
    fn test_build_with_recursive_swap_next() {
        // Round-trip a 3-hop chain through the var2 push.
        let inner = SwapDescriptor {
            requested_script_hash: [0xaa; 32],
            receive_addr: [0xbb; 20],
            rate_numerator: 7,
            rate_denominator: 9,
            next: Some(Box::new(NextVar2::Frozen)),
        };
        let top = SwapDescriptor {
            requested_script_hash: [0x11; 32],
            receive_addr: [0x22; 20],
            rate_numerator: 3,
            rate_denominator: 5,
            next: Some(Box::new(NextVar2::Swap(inner))),
        };
        let mut p = minimal_passive_params();
        p.action_data = ActionData::Swap(top);
        let bytes = build_locking_script(&p).unwrap().to_binary();
        // var2 push: 61 (top) + 60 (inner body) + 1 (frozen marker) = 122 bytes
        // → PUSHDATA1 (0x4c) + 122 + body
        assert_eq!(bytes[21], 0x4c);
        assert_eq!(bytes[22], 122);
        assert_eq!(bytes[23], 0x01, "outer action byte");
    }

    // ---- push_data_minimal boundary tests ---------------------------------

    #[test]
    fn test_push_data_minimal_empty_is_op_0() {
        let mut buf = Vec::new();
        push_data_minimal(&mut buf, &[]);
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn test_push_data_minimal_boundary_75() {
        let mut buf = Vec::new();
        let data = vec![0xab; 75];
        push_data_minimal(&mut buf, &data);
        assert_eq!(buf.len(), 76);
        assert_eq!(buf[0], 75);
        assert_eq!(&buf[1..], &data[..]);
    }

    #[test]
    fn test_push_data_minimal_boundary_76() {
        let mut buf = Vec::new();
        let data = vec![0xcd; 76];
        push_data_minimal(&mut buf, &data);
        assert_eq!(buf.len(), 78);
        assert_eq!(buf[0], 0x4c, "PUSHDATA1 opcode");
        assert_eq!(buf[1], 76);
        assert_eq!(&buf[2..], &data[..]);
    }

    #[test]
    fn test_push_data_minimal_boundary_255() {
        let mut buf = Vec::new();
        let data = vec![0x77; 255];
        push_data_minimal(&mut buf, &data);
        assert_eq!(buf.len(), 257);
        assert_eq!(buf[0], 0x4c);
        assert_eq!(buf[1], 0xff);
        assert_eq!(&buf[2..], &data[..]);
    }

    #[test]
    fn test_push_data_minimal_boundary_256() {
        let mut buf = Vec::new();
        let data = vec![0x33; 256];
        push_data_minimal(&mut buf, &data);
        assert_eq!(buf.len(), 259);
        assert_eq!(buf[0], 0x4d, "PUSHDATA2 opcode");
        // Length is little-endian u16 = 0x0100
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x01);
        assert_eq!(&buf[3..], &data[..]);
    }
}
