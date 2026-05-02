//! STAS-3 locking script decoder — inverse of `lock::build_locking_script`.
//!
//! Reads a `LockingScript` and recovers `DecodedLock`. Round-trips
//! byte-for-byte with the builder for any well-formed input the builder
//! could produce.

use crate::script::locking_script::LockingScript;

use super::action_data::ActionData;
use super::constants::STAS3_ENGINE_BYTES;
use super::error::Stas3Error;
use super::flags;

/// Decoded fields from a STAS-3 locking script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedLock {
    pub owner_pkh: [u8; 20],
    pub action_data: ActionData,
    pub redemption_pkh: [u8; 20],
    pub flags: u8,
    /// Service fields in left-to-right order (one per set flag bit, lowest first).
    pub service_fields: Vec<Vec<u8>>,
    pub optional_data: Vec<Vec<u8>>,
}

/// Parse a STAS-3 locking script.
pub fn decode_locking_script(script: &LockingScript) -> Result<DecodedLock, Stas3Error> {
    let bytes = script.to_binary();
    let mut p = 0usize;

    // 1. Owner: 0x14 + 20 bytes
    if bytes.get(p).copied() != Some(0x14) {
        return Err(Stas3Error::InvalidScript(format!(
            "expected 0x14 owner push at byte {p}, got {:?}",
            bytes.get(p)
        )));
    }
    p += 1;
    if bytes.len() < p + 20 {
        return Err(Stas3Error::InvalidScript("truncated at owner pkh".into()));
    }
    let mut owner_pkh = [0u8; 20];
    owner_pkh.copy_from_slice(&bytes[p..p + 20]);
    p += 20;

    // 2. var2 push — read one push, recover bytes, decode into ActionData.
    let (var2_bytes, np) = read_push(&bytes, p, "var2")?;
    p = np;
    let action_data = decode_var2(&var2_bytes)?;

    // 3. Engine bytes — must match canonically
    if bytes.len() < p + STAS3_ENGINE_BYTES.len() {
        return Err(Stas3Error::InvalidScript("truncated at engine".into()));
    }
    let engine_slice = &bytes[p..p + STAS3_ENGINE_BYTES.len()];
    if engine_slice != STAS3_ENGINE_BYTES {
        return Err(Stas3Error::InvalidScript(format!(
            "engine bytes mismatch starting at byte {p}"
        )));
    }
    p += STAS3_ENGINE_BYTES.len();

    // 4. protoID: 0x14 + 20 bytes
    if bytes.get(p).copied() != Some(0x14) {
        return Err(Stas3Error::InvalidScript(format!(
            "expected 0x14 protoID push at byte {p}, got {:?}",
            bytes.get(p)
        )));
    }
    p += 1;
    if bytes.len() < p + 20 {
        return Err(Stas3Error::InvalidScript("truncated at protoID".into()));
    }
    let mut redemption_pkh = [0u8; 20];
    redemption_pkh.copy_from_slice(&bytes[p..p + 20]);
    p += 20;

    // 5. Flags — must be a length-1 data push (PUSH1 + 1 byte).
    let (flags_bytes, np) = read_push(&bytes, p, "flags")?;
    p = np;
    if flags_bytes.len() != 1 {
        return Err(Stas3Error::InvalidScript(format!(
            "flags push must be 1 byte, got {}",
            flags_bytes.len()
        )));
    }
    let flags_byte = flags_bytes[0];

    // 6. Service fields — one push per set flag bit, in left-to-right order
    //    (bit 0 = FREEZABLE → first push if set; bit 1 = CONFISCATABLE → next).
    let svc_count = (flags::is_freezable(flags_byte) as usize)
        + (flags::is_confiscatable(flags_byte) as usize);
    let mut service_fields = Vec::with_capacity(svc_count);
    for i in 0..svc_count {
        let (data, np) = read_push(&bytes, p, &format!("service_field[{i}]"))?;
        p = np;
        service_fields.push(data);
    }

    // 7. Remaining pushes are optional_data
    let mut optional_data = Vec::new();
    while p < bytes.len() {
        let (data, np) = read_push(&bytes, p, "optional_data")?;
        p = np;
        optional_data.push(data);
    }

    Ok(DecodedLock {
        owner_pkh,
        action_data,
        redemption_pkh,
        flags: flags_byte,
        service_fields,
        optional_data,
    })
}

/// Read a single push opcode at `pos` and return (data, next_position).
///
/// Handles: OP_0, OP_1..OP_16, OP_1NEGATE, bare push (0x01..0x4b),
/// OP_PUSHDATA1/2/4. Returns Err for any non-push opcode at this position.
fn read_push(bytes: &[u8], pos: usize, label: &str) -> Result<(Vec<u8>, usize), Stas3Error> {
    let op = *bytes.get(pos).ok_or_else(|| {
        Stas3Error::InvalidScript(format!("truncated reading {label} at byte {pos}"))
    })?;
    match op {
        0x00 => Ok((Vec::new(), pos + 1)),
        // OP_1NEGATE → pushes byte 0x81 onto the stack
        0x4f => Ok((vec![0x81], pos + 1)),
        // OP_1..OP_16
        0x51..=0x60 => Ok((vec![op - 0x50], pos + 1)),
        // Bare push (length encoded in opcode byte)
        0x01..=0x4b => {
            let n = op as usize;
            let start = pos + 1;
            let end = start + n;
            if bytes.len() < end {
                return Err(Stas3Error::InvalidScript(format!(
                    "truncated bare push of {n} bytes at {pos} reading {label}"
                )));
            }
            Ok((bytes[start..end].to_vec(), end))
        }
        // OP_PUSHDATA1
        0x4c => {
            let len_pos = pos + 1;
            let n = *bytes.get(len_pos).ok_or_else(|| {
                Stas3Error::InvalidScript(format!("truncated PUSHDATA1 length at {len_pos}"))
            })? as usize;
            let start = pos + 2;
            let end = start + n;
            if bytes.len() < end {
                return Err(Stas3Error::InvalidScript(format!(
                    "truncated PUSHDATA1 body of {n} bytes"
                )));
            }
            Ok((bytes[start..end].to_vec(), end))
        }
        // OP_PUSHDATA2
        0x4d => {
            if bytes.len() < pos + 3 {
                return Err(Stas3Error::InvalidScript(
                    "truncated PUSHDATA2 header".into(),
                ));
            }
            let n = u16::from_le_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
            let start = pos + 3;
            let end = start + n;
            if bytes.len() < end {
                return Err(Stas3Error::InvalidScript(format!(
                    "truncated PUSHDATA2 body of {n} bytes"
                )));
            }
            Ok((bytes[start..end].to_vec(), end))
        }
        // OP_PUSHDATA4
        0x4e => {
            if bytes.len() < pos + 5 {
                return Err(Stas3Error::InvalidScript(
                    "truncated PUSHDATA4 header".into(),
                ));
            }
            let n = u32::from_le_bytes([
                bytes[pos + 1],
                bytes[pos + 2],
                bytes[pos + 3],
                bytes[pos + 4],
            ]) as usize;
            let start = pos + 5;
            let end = start + n;
            if bytes.len() < end {
                return Err(Stas3Error::InvalidScript(format!(
                    "truncated PUSHDATA4 body of {n} bytes"
                )));
            }
            Ok((bytes[start..end].to_vec(), end))
        }
        _ => Err(Stas3Error::InvalidScript(format!(
            "expected push opcode at byte {pos} reading {label}, got 0x{op:02x}"
        ))),
    }
}

/// Decode the var2 push payload back to ActionData.
///
/// Inverse of `lock::push_var2`:
/// - empty bytes (came from OP_0) → ActionData::Passive(vec![])
/// - single byte [0x02] (came from OP_2 OR pushdata of [0x02])
///   → ActionData::Frozen(vec![])
/// - other → ActionData::parse(bytes)
fn decode_var2(bytes: &[u8]) -> Result<ActionData, Stas3Error> {
    ActionData::parse(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::templates::stas3::action_data::{NextVar2, SwapDescriptor};
    use crate::script::templates::stas3::flags::{CONFISCATABLE, FREEZABLE};
    use crate::script::templates::stas3::lock::{build_locking_script, LockParams};

    fn round_trip(params: LockParams) -> DecodedLock {
        let script1 = build_locking_script(&params).unwrap();
        let bytes1 = script1.to_binary();
        let decoded = decode_locking_script(&script1).unwrap();
        // Decoded fields must equal originals
        assert_eq!(decoded.owner_pkh, params.owner_pkh);
        assert_eq!(decoded.action_data, params.action_data);
        assert_eq!(decoded.redemption_pkh, params.redemption_pkh);
        assert_eq!(decoded.flags, params.flags);
        assert_eq!(decoded.service_fields, params.service_fields);
        assert_eq!(decoded.optional_data, params.optional_data);

        // STRICT byte-equality round-trip: rebuild from decoded → identical bytes.
        let rebuilt = LockParams {
            owner_pkh: decoded.owner_pkh,
            action_data: decoded.action_data.clone(),
            redemption_pkh: decoded.redemption_pkh,
            flags: decoded.flags,
            service_fields: decoded.service_fields.clone(),
            optional_data: decoded.optional_data.clone(),
        };
        let bytes2 = build_locking_script(&rebuilt).unwrap().to_binary();
        assert_eq!(
            bytes1, bytes2,
            "round-trip byte equality failure"
        );
        decoded
    }

    fn base_params() -> LockParams {
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
    fn test_round_trip_minimal_passive() {
        round_trip(base_params());
    }

    #[test]
    fn test_round_trip_frozen_empty() {
        let mut p = base_params();
        p.action_data = ActionData::Frozen(vec![]);
        round_trip(p);
    }

    #[test]
    fn test_round_trip_frozen_with_payload() {
        let mut p = base_params();
        p.action_data = ActionData::Frozen(vec![0xab, 0xcd]);
        round_trip(p);
    }

    #[test]
    fn test_round_trip_passive_with_payload() {
        let mut p = base_params();
        p.action_data = ActionData::Passive(vec![0x99]);
        round_trip(p);
    }

    #[test]
    fn test_round_trip_swap_descriptor_with_passive_next() {
        let desc = SwapDescriptor {
            requested_script_hash: [0x55; 32],
            receive_addr: [0x66; 20],
            rate_numerator: 13,
            rate_denominator: 17,
            next: Some(Box::new(NextVar2::Passive(vec![0xde, 0xad, 0xbe, 0xef]))),
        };
        let mut p = base_params();
        p.action_data = ActionData::Swap(desc);
        round_trip(p);
    }

    #[test]
    fn test_round_trip_recursive_swap_chain_3_hops() {
        let leaf = SwapDescriptor {
            requested_script_hash: [0x33; 32],
            receive_addr: [0x44; 20],
            rate_numerator: 1,
            rate_denominator: 1,
            next: Some(Box::new(NextVar2::Frozen)),
        };
        let middle = SwapDescriptor {
            requested_script_hash: [0x22; 32],
            receive_addr: [0x33; 20],
            rate_numerator: 2,
            rate_denominator: 3,
            next: Some(Box::new(NextVar2::Swap(leaf))),
        };
        let top = SwapDescriptor {
            requested_script_hash: [0x11; 32],
            receive_addr: [0x22; 20],
            rate_numerator: 5,
            rate_denominator: 7,
            next: Some(Box::new(NextVar2::Swap(middle))),
        };
        let mut p = base_params();
        p.action_data = ActionData::Swap(top);
        round_trip(p);
    }

    #[test]
    fn test_round_trip_flags_freezable_only() {
        let mut p = base_params();
        p.flags = FREEZABLE;
        p.service_fields = vec![vec![0x77; 20]];
        round_trip(p);
    }

    #[test]
    fn test_round_trip_flags_freezable_and_confiscatable() {
        let mut p = base_params();
        p.flags = FREEZABLE | CONFISCATABLE;
        p.service_fields = vec![vec![0x77; 20], vec![0x88; 20]];
        round_trip(p);
    }

    #[test]
    fn test_round_trip_with_three_optional_data_fields() {
        // Exercises bare push (32), PUSHDATA1 (100), PUSHDATA2 (300).
        let mut p = base_params();
        p.optional_data = vec![vec![1; 32], vec![2; 100], vec![3; 300]];
        round_trip(p);
    }

    #[test]
    fn test_round_trip_flags_with_optional_data() {
        let mut p = base_params();
        p.flags = FREEZABLE;
        p.service_fields = vec![vec![0xee; 20]];
        p.optional_data = vec![vec![0xaa; 8], vec![0xbb; 80]];
        round_trip(p);
    }

    // ---- Negative cases ----------------------------------------------------

    #[test]
    fn test_decode_rejects_non_0x14_owner() {
        // Manually craft bytes starting with OP_0 instead of PUSH20.
        let bytes = vec![0x00, 0xaa, 0xbb];
        let script = LockingScript::from_binary(&bytes);
        let err = decode_locking_script(&script).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => assert!(
                msg.contains("expected 0x14 owner push"),
                "unexpected msg: {msg}"
            ),
            other => panic!("expected InvalidScript, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_rejects_engine_mismatch() {
        let mut bytes = build_locking_script(&base_params()).unwrap().to_binary();
        // Flip a byte in the middle of the engine region.
        let pos = 22 + STAS3_ENGINE_BYTES.len() / 2;
        bytes[pos] ^= 0xff;
        let script = LockingScript::from_binary(&bytes);
        let err = decode_locking_script(&script).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => assert!(
                msg.contains("engine bytes mismatch"),
                "unexpected msg: {msg}"
            ),
            other => panic!("expected InvalidScript, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_rejects_truncated_at_proto_id() {
        // Build a valid script then truncate inside the protoID push.
        let bytes = build_locking_script(&base_params()).unwrap().to_binary();
        // protoID push opcode lives at index 22 + engine_len; truncate to
        // include the opcode but NOT the full 20 bytes that follow.
        let proto_op_pos = 22 + STAS3_ENGINE_BYTES.len();
        let truncated = bytes[..proto_op_pos + 10].to_vec();
        let script = LockingScript::from_binary(&truncated);
        let err = decode_locking_script(&script).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => assert!(
                msg.contains("truncated at protoID"),
                "unexpected msg: {msg}"
            ),
            other => panic!("expected InvalidScript, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_rejects_multi_byte_flag_push() {
        // Build by hand: owner + var2(OP_0) + engine + protoID + 2-byte flags push.
        let mut bytes = Vec::new();
        bytes.push(0x14);
        bytes.extend_from_slice(&[0xaa; 20]);
        bytes.push(0x00); // var2 OP_0
        bytes.extend_from_slice(STAS3_ENGINE_BYTES);
        bytes.push(0x14);
        bytes.extend_from_slice(&[0xbb; 20]);
        // 2-byte flags push (PUSH2 + 2 bytes) — illegal per our spec discipline.
        bytes.push(0x02);
        bytes.push(0x01);
        bytes.push(0x02);
        let script = LockingScript::from_binary(&bytes);
        let err = decode_locking_script(&script).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => assert!(
                msg.contains("flags push must be 1 byte"),
                "unexpected msg: {msg}"
            ),
            other => panic!("expected InvalidScript, got {other:?}"),
        }
    }
}
