//! STAS-3 trailing piece-array construction (spec v0.2 §8.1, §9.5).
//!
//! For merge / atomic-swap variants, the unlocking script's "merge section"
//! contains the OTHER input's source-tx bytes, split at every occurrence of
//! the OTHER input's *counterparty script* (everything past the two
//! variable parameters at the very start of the STAS script — i.e. past
//! `[OP_DATA_20 + 20B owner][var2 push]`).
//!
//! This matches the **canonical 2,899-byte engine** and the stas3-sdk
//! TypeScript reference (`Stas3Merge.ts::extractCounterpartyScript` +
//! `splitByCounterpartyScript`). The engine reconstructs the OTHER input's
//! source-tx bytes by interleaving the segments with the locking-script
//! bytes the engine already has from the outpoint, then HASH256s the
//! result and cross-checks it against the BIP-143 preimage's outpoint
//! commitment.
//!
//! ## Wire ordering
//!
//! `split_by_counterparty_script` returns segments in **forward order**
//! (head, gaps, tail). The unlock-script emitter (`unlock.rs`) reverses
//! them on the wire per spec §9.5 — so callers pass forward-order slices
//! to `TrailingParams::{Merge,AtomicSwap}::pieces`.

use crate::script::locking_script::LockingScript;

use super::super::error::Stas3Error;

/// Extract the counterparty-script bytes from a STAS-3 locking script.
///
/// The counterparty script is everything AFTER the two leading variable
/// pushes:
/// 1. `[OP_DATA_20 + 20B owner_pkh]` (always 21 bytes)
/// 2. `[var2 push]` — the action_data (Passive / Frozen / Swap …) — its
///    length is determined by the push opcode.
///
/// Everything past those two pushes — covenant body + OP_RETURN data
/// section — is constant across all STAS tokens of the same type and
/// serves as the "needle" for splitting source-tx bytes.
pub fn counterparty_script_from_lock(lock: &LockingScript) -> Result<Vec<u8>, Stas3Error> {
    let bytes = lock.to_binary();
    let var2_offset = 21usize; // 0x14 + 20 bytes
    if bytes.len() < var2_offset + 1 || bytes[0] != 0x14 {
        return Err(Stas3Error::InvalidScript(
            "counterparty_script_from_lock: not a STAS-shaped script (missing \
             OP_DATA_20 owner)"
                .into(),
        ));
    }
    let after_var2 = skip_push_offset(&bytes, var2_offset).ok_or_else(|| {
        Stas3Error::InvalidScript(
            "counterparty_script_from_lock: var2 push is malformed".into(),
        )
    })?;
    Ok(bytes[after_var2..].to_vec())
}

/// Split a raw transaction's bytes at every occurrence of `counterparty_script`,
/// returning segments in forward (source-order) order.
///
/// For an N-occurrence source tx, this returns `N + 1` segments: the bytes
/// before the first occurrence, between each consecutive pair, and after
/// the last. Reassembling `seg_0 || cs || seg_1 || cs || ... || cs || seg_N`
/// reproduces the original `raw_tx`.
///
/// The unlock-script emitter pushes them tail-first per spec §9.5.
///
/// # Errors
/// * [`Stas3Error::InvalidScript`] when `counterparty_script` is empty.
pub fn split_by_counterparty_script(
    raw_tx: &[u8],
    counterparty_script: &[u8],
) -> Result<Vec<Vec<u8>>, Stas3Error> {
    if counterparty_script.is_empty() {
        return Err(Stas3Error::InvalidScript(
            "split_by_counterparty_script: counterparty_script must be non-empty".into(),
        ));
    }
    let mut segments: Vec<Vec<u8>> = Vec::new();
    let mut cursor = 0usize;
    loop {
        match find_subsequence(raw_tx, counterparty_script, cursor) {
            Some(match_at) => {
                segments.push(raw_tx[cursor..match_at].to_vec());
                cursor = match_at + counterparty_script.len();
            }
            None => {
                segments.push(raw_tx[cursor..].to_vec());
                break;
            }
        }
    }
    Ok(segments)
}

/// Linear-scan search for `needle` in `haystack` starting at `from`.
fn find_subsequence(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < from + needle.len() {
        return None;
    }
    let last_start = haystack.len() - needle.len();
    let mut i = from;
    while i <= last_start {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Given `script` and the offset of a push opcode, return the offset PAST
/// the entire push (header + body).
fn skip_push_offset(script: &[u8], offset: usize) -> Option<usize> {
    if offset >= script.len() {
        return None;
    }
    let opcode = script[offset];
    match opcode {
        0x00 => Some(offset + 1),
        0x4f | 0x51..=0x60 => Some(offset + 1),
        0x01..=0x4b => {
            let end = offset + 1 + opcode as usize;
            if end > script.len() {
                None
            } else {
                Some(end)
            }
        }
        0x4c => {
            if offset + 1 >= script.len() {
                return None;
            }
            let end = offset + 2 + script[offset + 1] as usize;
            if end > script.len() {
                None
            } else {
                Some(end)
            }
        }
        0x4d => {
            if offset + 2 >= script.len() {
                return None;
            }
            let len =
                u16::from_le_bytes([script[offset + 1], script[offset + 2]]) as usize;
            let end = offset + 3 + len;
            if end > script.len() {
                None
            } else {
                Some(end)
            }
        }
        0x4e => {
            if offset + 4 >= script.len() {
                return None;
            }
            let len = u32::from_le_bytes([
                script[offset + 1],
                script[offset + 2],
                script[offset + 3],
                script[offset + 4],
            ]) as usize;
            let end = offset + 5 + len;
            if end > script.len() {
                None
            } else {
                Some(end)
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::locking_script::LockingScript;

    fn fake_stas_script(owner: u8, var2: u8, engine_payload: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(22 + 2 + engine_payload.len());
        s.push(0x14);
        s.extend(std::iter::repeat(owner).take(20));
        s.push(0x01);
        s.push(var2);
        s.extend_from_slice(engine_payload);
        s
    }

    #[test]
    fn counterparty_script_extracts_post_var2() {
        let script = fake_stas_script(0x77, 0x55, &[0xE1, 0xE2, 0xE3]);
        let lock = LockingScript::from_binary(&script);
        let cs = counterparty_script_from_lock(&lock).unwrap();
        assert_eq!(cs, vec![0xE1, 0xE2, 0xE3]);
    }

    #[test]
    fn counterparty_script_rejects_non_stas() {
        let lock = LockingScript::from_binary(&[0x76, 0xa9, 0x14, 0x00, 0x88, 0xac]);
        assert!(counterparty_script_from_lock(&lock).is_err());
    }

    #[test]
    fn split_round_trip_single_occurrence() {
        let raw = b"PREFIX-CSCRIPT-SUFFIX".to_vec();
        let cs = b"CSCRIPT".to_vec();
        let segs = split_by_counterparty_script(&raw, &cs).unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0], b"PREFIX-".to_vec());
        assert_eq!(segs[1], b"-SUFFIX".to_vec());
    }

    #[test]
    fn split_round_trip_two_occurrences() {
        let raw = b"AAA-CS-BBB-CS-CCC".to_vec();
        let cs = b"CS".to_vec();
        let segs = split_by_counterparty_script(&raw, &cs).unwrap();
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0], b"AAA-".to_vec());
        assert_eq!(segs[1], b"-BBB-".to_vec());
        assert_eq!(segs[2], b"-CCC".to_vec());

        // Reassembly check.
        let mut reassembled = Vec::new();
        for (i, seg) in segs.iter().enumerate() {
            reassembled.extend_from_slice(seg);
            if i + 1 < segs.len() {
                reassembled.extend_from_slice(&cs);
            }
        }
        assert_eq!(reassembled, raw);
    }

    #[test]
    fn split_no_occurrence_returns_whole_input() {
        let raw = b"XXXXXXXX".to_vec();
        let cs = b"CS".to_vec();
        let segs = split_by_counterparty_script(&raw, &cs).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0], raw);
    }

    #[test]
    fn split_empty_cs_errors() {
        let raw = b"abc".to_vec();
        assert!(split_by_counterparty_script(&raw, &[]).is_err());
    }

    #[test]
    fn split_at_boundaries() {
        // CS at the very start
        let raw = b"CS-rest".to_vec();
        let cs = b"CS".to_vec();
        let segs = split_by_counterparty_script(&raw, &cs).unwrap();
        assert_eq!(segs.len(), 2);
        assert!(segs[0].is_empty());
        assert_eq!(segs[1], b"-rest".to_vec());

        // CS at the very end
        let raw = b"prefix-CS".to_vec();
        let segs = split_by_counterparty_script(&raw, &cs).unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0], b"prefix-".to_vec());
        assert!(segs[1].is_empty());
    }
}
