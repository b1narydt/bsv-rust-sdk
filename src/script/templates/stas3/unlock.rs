//! STAS-3 unlocking script construction (spec v0.2 §7).
//!
//! This module hosts both the **general** unlocking script builder
//! (`build_unlocking_script`) and the **transfer-shape** thin wrapper
//! (`build_transfer_unlocking`) retained for backward compatibility.
//!
//! Witness layout per spec §4:
//!
//! ```text
//! Slots 1-12   : 0..=4 STAS output triplets (satoshis, ownerPKH, var2)
//! Slots 13-14  : change pair (satoshis, ownerPKH) — OP_FALSE OP_FALSE if absent
//! Slot  15     : noteData — OP_FALSE if absent
//! Slots 16-17  : funding pointer (vout, txidLE) — OP_FALSE OP_FALSE if absent
//! Slot  18     : txType  (always PUSH1 + value)
//! Slot  19     : sighashPreimage
//! Slot  20     : spendType (always PUSH1 + value)
//! Slots 21+    : authz (P2PKH / P2MPKH / Suppressed) and trailing op params
//! ```
//!
//! Encoding rules: amounts (slots 1, 4, 7, 10, 13, 16) use script-num
//! encoding (collapsed to OP_N for 1..=16, OP_0 for 0); all data fields
//! (PKH, txid, preimage, sig, pubkey, var2, pieces, scripts) use minimal
//! data pushes via length prefix.

use super::error::Stas3Error;
use super::lock::push_data_minimal;
use super::spend_type::{SpendType, TxType};

/// One STAS-3 output for the unlocking script's output section.
#[derive(Clone, Debug)]
pub struct StasOutputWitness {
    pub satoshis: u64,
    pub owner_pkh: [u8; 20],
    /// Bytes of var2 contents (NOT including push opcode) — produced by
    /// `ActionData::to_var2_bytes()`. Empty Vec means "OP_0 / passive empty".
    pub var2_bytes: Vec<u8>,
}

/// Inline P2PKH change pair. None means "no change output".
#[derive(Clone, Debug)]
pub struct ChangeWitness {
    pub satoshis: u64,
    pub owner_pkh: [u8; 20],
}

/// Funding input reference (slots 16-17). None means "no funding pointer".
#[derive(Clone, Debug)]
pub struct FundingPointer {
    pub vout: u32,
    /// Little-endian — txid bytes as they appear in the tx serialization.
    pub txid_le: [u8; 32],
}

/// Authorization witness (slots 21+). One of three forms per spec §10:
/// - `P2pkh`: standard `<sig> <pubkey>` pair.
/// - `P2mpkh`: `OP_0 <sig_1> ... <sig_m> <multisig_redeem_script>` (the
///   leading `OP_0` is the standard CHECKMULTISIG dummy).
/// - `Suppressed`: when owner = `EMPTY_HASH160`, the engine accepts a
///   single OP_FALSE in lieu of a real signature (spec §10.3).
#[derive(Clone, Debug)]
pub enum AuthzWitness {
    /// Standard P2PKH: `<sig> <pubkey>`.
    P2pkh { sig: Vec<u8>, pubkey: Vec<u8> },
    /// P2MPKH: `OP_0 <sig_1> ... <sig_m> <multisig_redeem_script>`.
    P2mpkh {
        sigs: Vec<Vec<u8>>,
        redeem_script: Vec<u8>,
    },
    /// Owner = `EMPTY_HASH160`: emit single OP_FALSE.
    Suppressed,
}

/// Trailing parameters per spec §8.1 / §9.5 — depend on tx-type.
///
/// **Wire format** (matches the canonical 2,899-byte engine and the
/// stas3-sdk TypeScript reference, NOT the earlier blob design):
///
/// The "merge section" is the single witness slot that replaces what used to
/// be the `txType` slot. The engine reads this slot via `OP_2DROP OP_SIZE
/// OP_IFDUP OP_IF...`:
/// - size 0 → no-merge fast path (Regular spends).
/// - size 33 → pubkey path (the engine sees the pubkey on top of stack via a
///   different slot — handled by `AuthzWitness` below).
/// - other size → piece-array dispatch (merge / atomic-swap variants).
///
/// For the **Regular** variant we push a single `OP_FALSE`. For **Merge**
/// and **AtomicSwap** we push the merge section as a multi-chunk sequence:
/// `mergeVout(scriptNum), seg_n, seg_{n-1}, ..., seg_0, segCount(scriptNum)`,
/// optionally followed by `counterpartyScript, swapIndicator(1)` for atomic
/// swap. Each segment is its **own** minimal-data push (NOT a single padded
/// blob — that was the Phase 5c-1 design, deprecated).
///
/// Pieces are produced in **forward (head-first)** order by
/// [`crate::script::templates::stas3::factory::pieces::split_by_counterparty_script`].
/// The unlock emitter reverses them on the wire per spec §9.5.
#[derive(Clone, Debug)]
pub enum TrailingParams {
    /// `txType = 0` (Regular): no merge section. Emits a single `OP_FALSE`.
    None,
    /// `txType = 1` (AtomicSwap): the OTHER input's source-tx vout, the
    /// pieces of the OTHER input's source tx (split by the OTHER input's
    /// counterparty script), the segment count, then the OTHER input's
    /// FULL locking script + swap indicator (1).
    AtomicSwap {
        /// `sourceOutputIndex` of the OTHER STAS input.
        merge_vout: u32,
        /// Pieces in forward order (head, gaps, tail). The emitter reverses
        /// at wire-emit time per spec §9.5.
        pieces: Vec<Vec<u8>>,
        /// Full locking-script bytes of the OTHER STAS input (NOT just the
        /// counterparty portion — the whole script).
        counterparty_script: Vec<u8>,
    },
    /// `txType in 2..=7` (Merge): the OTHER input's source-tx vout, the
    /// pieces of the OTHER input's source tx (split by the shared
    /// counterparty script), and the segment count.
    ///
    /// For 2-input merge: `merge_vout` is the OTHER input's source vout
    /// and `pieces` are extracted from the OTHER input's source tx. For
    /// merges with more than 2 inputs the spec is silent on the
    /// multi-input case in this per-input slot encoding; only 2-input
    /// merge is implemented.
    Merge {
        /// `sourceOutputIndex` of the OTHER STAS input.
        merge_vout: u32,
        /// Pieces in forward order (head, gaps, tail).
        pieces: Vec<Vec<u8>>,
    },
}

/// General witness inputs to `build_unlocking_script`.
///
/// `stas_outputs` length must be 0..=4 per spec §7. The builder emits
/// exactly one triplet per element (omitting absent ones entirely — slots
/// 4-12 simply do not appear when there are fewer than 4 STAS outputs).
#[derive(Clone, Debug)]
pub struct UnlockParams {
    pub stas_outputs: Vec<StasOutputWitness>,
    pub change: Option<ChangeWitness>,
    pub note: Option<Vec<u8>>,
    pub funding: Option<FundingPointer>,
    pub tx_type: TxType,
    pub spend_type: SpendType,
    pub preimage: Vec<u8>,
    pub authz: AuthzWitness,
    pub trailing: TrailingParams,
}

/// Build the unlocking script bytes for any STAS-3 spend shape.
///
/// Returns `Stas3Error::InvalidScript` if `stas_outputs.len() > 4`.
pub fn build_unlocking_script(p: &UnlockParams) -> Result<Vec<u8>, Stas3Error> {
    if p.stas_outputs.len() > 4 {
        return Err(Stas3Error::InvalidScript(format!(
            "max 4 STAS outputs per spend (per spec §7), got {}",
            p.stas_outputs.len()
        )));
    }

    let mut out = Vec::with_capacity(256 + p.preimage.len());

    // Slots 1-12: 0..=4 STAS output triplets (omit absent ones entirely).
    for s in &p.stas_outputs {
        push_script_num(&mut out, s.satoshis as i64);
        push_data_minimal(&mut out, &s.owner_pkh);
        push_data_minimal(&mut out, &s.var2_bytes);
    }

    // Slots 13-14: change pair (or OP_FALSE OP_FALSE if absent).
    if let Some(c) = &p.change {
        push_script_num(&mut out, c.satoshis as i64);
        push_data_minimal(&mut out, &c.owner_pkh);
    } else {
        out.push(0x00);
        out.push(0x00);
    }

    // Slot 15: note (or OP_FALSE).
    match &p.note {
        Some(payload) => push_data_minimal(&mut out, payload),
        None => out.push(0x00),
    }

    // Slots 16-17: funding pointer (or OP_FALSE OP_FALSE).
    if let Some(f) = &p.funding {
        push_script_num(&mut out, f.vout as i64);
        push_data_minimal(&mut out, &f.txid_le);
    } else {
        out.push(0x00);
        out.push(0x00);
    }

    // Slot 18: "merge section" — replaces what used to be a single `txType`
    // byte with the TS-reference / canonical-engine layout per spec §9.5.
    //
    // For txType==Regular: single OP_FALSE (engine takes the size==0
    // fast path on top-of-stack pubkey-presence inspection — actually the
    // engine sees `pubkey` on top from the authz tail, takes size==33 path,
    // and the merge section sits unread deeper in the stack).
    //
    // For Merge / AtomicSwap: a multi-chunk sequence:
    //
    //   `mergeVout(scriptNum), seg_n, seg_{n-1}, ..., seg_0, segCount(scriptNum)`
    //
    // optionally followed by `counterpartyScript, swap_indicator(1)` for
    // atomic swap. Each segment is its OWN minimal-data push (NOT a single
    // length-prefixed blob).
    //
    // Note: the `tx_type` field on `UnlockParams` is RETAINED for caller
    // ergonomics + downstream introspection; the wire format infers the
    // dispatch from the merge section's stack shape, so the explicit
    // `txType` byte we used to push at this slot is gone.
    match &p.trailing {
        TrailingParams::None => {
            out.push(0x00); // OP_FALSE — no merge section
        }
        TrailingParams::Merge { merge_vout, pieces } => {
            push_script_num(&mut out, *merge_vout as i64);
            // Pieces are passed in forward (head-first) order; engine
            // consumes them tail-first (per spec §9.5), so reverse on emit.
            for piece in pieces.iter().rev() {
                push_data_minimal(&mut out, piece);
            }
            push_script_num(&mut out, pieces.len() as i64);
        }
        TrailingParams::AtomicSwap {
            merge_vout,
            pieces,
            counterparty_script,
        } => {
            push_script_num(&mut out, *merge_vout as i64);
            for piece in pieces.iter().rev() {
                push_data_minimal(&mut out, piece);
            }
            push_script_num(&mut out, pieces.len() as i64);
            push_data_minimal(&mut out, counterparty_script);
            push_script_num(&mut out, 1); // swap indicator
        }
    }

    // Slot 19: preimage.
    push_data_minimal(&mut out, &p.preimage);

    // Slot 20: spendType (script-num).
    push_script_num(&mut out, p.spend_type.to_u8() as i64);

    // Slots 21+: authz.
    match &p.authz {
        AuthzWitness::P2pkh { sig, pubkey } => {
            push_data_minimal(&mut out, sig);
            push_data_minimal(&mut out, pubkey);
        }
        AuthzWitness::P2mpkh {
            sigs,
            redeem_script,
        } => {
            // OP_0 dummy for CHECKMULTISIG bug compatibility.
            out.push(0x00);
            for s in sigs {
                push_data_minimal(&mut out, s);
            }
            push_data_minimal(&mut out, redeem_script);
        }
        AuthzWitness::Suppressed => {
            // Single OP_FALSE in lieu of a real authz tail.
            out.push(0x00);
        }
    }

    Ok(out)
}

/// Inputs to the transfer-shape unlock builder. Retained for
/// backward compatibility with Phase 4 — delegates to
/// `build_unlocking_script` via `build_transfer_unlocking`.
#[derive(Clone, Debug)]
pub struct TransferUnlockParams {
    /// Exactly 1 STAS output in transfer shape.
    pub stas_output: StasOutputWitness,
    pub change: Option<ChangeWitness>,
    pub funding: Option<FundingPointer>,
    /// BIP-143 preimage bytes (slot 19).
    pub preimage: Vec<u8>,
    /// DER signature WITH sighash byte appended (P2PKH format).
    pub signature: Vec<u8>,
    /// 33-byte compressed pubkey.
    pub pubkey: Vec<u8>,
}

/// Build a transfer-shape STAS-3 unlocking script.
///
/// Thin wrapper over `build_unlocking_script` with:
/// - exactly 1 STAS output
/// - txType = Regular (0)
/// - spendType = Transfer (1)
/// - P2PKH authz
/// - no trailing params, no note
pub fn build_transfer_unlocking(p: &TransferUnlockParams) -> Result<Vec<u8>, Stas3Error> {
    build_unlocking_script(&UnlockParams {
        stas_outputs: vec![p.stas_output.clone()],
        change: p.change.clone(),
        note: None,
        funding: p.funding.clone(),
        tx_type: TxType::Regular,
        spend_type: SpendType::Transfer,
        preimage: p.preimage.clone(),
        authz: AuthzWitness::P2pkh {
            sig: p.signature.clone(),
            pubkey: p.pubkey.clone(),
        },
        trailing: TrailingParams::None,
    })
}

/// Push an i64 as a Bitcoin script number with minimal canonical encoding:
/// - 0          → OP_0   (single byte 0x00)
/// - 1..=16     → OP_N   (single opcode 0x51..=0x60)
/// - -1         → OP_1NEGATE (0x4f)
/// - other      → minimal-LE data push (sign-magnitude with optional 0x00
///   sentinel byte when MSB has bit 0x80 set, per `to_script_num`).
fn push_script_num(out: &mut Vec<u8>, n: i64) {
    if n == 0 {
        out.push(0x00); // OP_0
        return;
    }
    if (1..=16).contains(&n) {
        out.push(0x50 + n as u8);
        return;
    }
    if n == -1 {
        out.push(0x4f); // OP_1NEGATE
        return;
    }
    push_data_minimal(out, &to_script_num(n));
}

/// Encode an i64 as Bitcoin script-num bytes (sign-magnitude little-endian).
///
/// Empty Vec for 0; otherwise minimal-LE bytes with high bit of MSB used as
/// the sign indicator. A 0x00 (or 0x80 for negatives) sentinel byte is
/// appended when the magnitude's MSB has bit 0x80 set, so the value isn't
/// misread as a different sign.
fn to_script_num(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let neg = n < 0;
    let mut abs = n.unsigned_abs();
    let mut bytes = Vec::with_capacity(9);
    while abs > 0 {
        bytes.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if bytes.last().copied().unwrap_or(0) & 0x80 != 0 {
        bytes.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        let last = bytes.len() - 1;
        bytes[last] |= 0x80;
    }
    bytes
}


#[cfg(test)]
mod tests {
    use super::*;

    fn collect_num(n: i64) -> Vec<u8> {
        let mut buf = Vec::new();
        push_script_num(&mut buf, n);
        buf
    }

    #[test]
    fn test_push_script_num_zero() {
        assert_eq!(collect_num(0), vec![0x00]);
    }

    #[test]
    fn test_push_script_num_one_is_op_1() {
        assert_eq!(collect_num(1), vec![0x51]);
    }

    #[test]
    fn test_push_script_num_16_is_op_16() {
        assert_eq!(collect_num(16), vec![0x60]);
    }

    #[test]
    fn test_push_script_num_17_is_pushdata() {
        assert_eq!(collect_num(17), vec![0x01, 0x11]);
    }

    #[test]
    fn test_push_script_num_127() {
        assert_eq!(collect_num(127), vec![0x01, 0x7f]);
    }

    #[test]
    fn test_push_script_num_128_sentinel() {
        // 128 = 0x80; MSB has bit 0x80 → append 0x00 sentinel; PUSH2 + body.
        assert_eq!(collect_num(128), vec![0x02, 0x80, 0x00]);
    }

    #[test]
    fn test_push_script_num_256() {
        // 256 = 0x0100 LE = [0x00, 0x01].
        assert_eq!(collect_num(256), vec![0x02, 0x00, 0x01]);
    }

    #[test]
    fn test_push_script_num_neg_one() {
        assert_eq!(collect_num(-1), vec![0x4f]);
    }

    #[test]
    fn test_build_transfer_unlocking_basic() {
        // Use mock data with small values that collapse to OP_N opcodes.
        let params = TransferUnlockParams {
            stas_output: StasOutputWitness {
                satoshis: 1,
                owner_pkh: [0xaa; 20],
                var2_bytes: vec![],
            },
            change: Some(ChangeWitness {
                satoshis: 1,
                owner_pkh: [0xbb; 20],
            }),
            funding: Some(FundingPointer {
                vout: 1,
                txid_le: [0xcc; 32],
            }),
            preimage: vec![0xde; 50],
            signature: vec![0xee; 71],
            pubkey: vec![0x02; 33],
        };
        let bytes = build_transfer_unlocking(&params).unwrap();

        let mut p = 0usize;
        // Slot 1: OP_1 (satoshis=1)
        assert_eq!(bytes[p], 0x51);
        p += 1;
        // Slot 2: PUSH20 + 0xaa
        assert_eq!(bytes[p], 0x14);
        p += 21;
        // Slot 3: OP_0 (empty var2)
        assert_eq!(bytes[p], 0x00);
        p += 1;
        // Slot 13: OP_1 (change satoshis=1)
        assert_eq!(bytes[p], 0x51);
        p += 1;
        // Slot 14: PUSH20 + 0xbb
        assert_eq!(bytes[p], 0x14);
        p += 21;
        // Slot 15: OP_0 noteData
        assert_eq!(bytes[p], 0x00);
        p += 1;
        // Slot 16: OP_1 funding vout=1
        assert_eq!(bytes[p], 0x51);
        p += 1;
        // Slot 17: PUSH32 funding txid
        assert_eq!(bytes[p], 0x20);
        p += 33;
        // Slot 18: OP_0 txType=0
        assert_eq!(bytes[p], 0x00);
        p += 1;
        // Slot 19: PUSH50 preimage
        assert_eq!(bytes[p], 50);
        p += 51;
        // Slot 20: OP_1 spendType=1
        assert_eq!(bytes[p], 0x51);
        p += 1;
        // Slot 21: PUSH71 sig
        assert_eq!(bytes[p], 71);
        p += 72;
        // Slot 22: PUSH33 pubkey
        assert_eq!(bytes[p], 33);
        p += 34;

        assert_eq!(bytes.len(), p);
    }

    #[test]
    fn test_build_transfer_unlocking_no_change_no_funding() {
        let params = TransferUnlockParams {
            stas_output: StasOutputWitness {
                satoshis: 100,
                owner_pkh: [0x11; 20],
                var2_bytes: vec![],
            },
            change: None,
            funding: None,
            preimage: vec![0xab; 10],
            signature: vec![0xcd; 71],
            pubkey: vec![0x03; 33],
        };
        let bytes = build_transfer_unlocking(&params).unwrap();
        // STAS: PUSH1+0x64 (100), PUSH20+pkh, OP_0
        assert_eq!(&bytes[0..2], &[0x01, 0x64]);
        assert_eq!(bytes[2], 0x14);
        assert_eq!(bytes[23], 0x00);
        // change OP_FALSE OP_FALSE
        assert_eq!(&bytes[24..26], &[0x00, 0x00]);
        // noteData OP_FALSE
        assert_eq!(bytes[26], 0x00);
        // funding OP_FALSE OP_FALSE
        assert_eq!(&bytes[27..29], &[0x00, 0x00]);
        // txType OP_0 (script-num for 0)
        assert_eq!(bytes[29], 0x00);
        // preimage push
        assert_eq!(bytes[30], 10);
    }

    // -------- generalization tests --------

    fn small_authz_p2pkh() -> AuthzWitness {
        AuthzWitness::P2pkh {
            sig: vec![0xee; 71],
            pubkey: vec![0x02; 33],
        }
    }

    fn small_preimage() -> Vec<u8> {
        vec![0xde; 50]
    }

    #[test]
    fn test_max_stas_outputs_rejected() {
        // 5 STAS outputs must be rejected per spec §7 (max 4).
        let mk_out = || StasOutputWitness {
            satoshis: 1,
            owner_pkh: [0xaa; 20],
            var2_bytes: vec![],
        };
        let res = build_unlocking_script(&UnlockParams {
            stas_outputs: vec![mk_out(), mk_out(), mk_out(), mk_out(), mk_out()],
            change: None,
            note: None,
            funding: None,
            tx_type: TxType::Regular,
            spend_type: SpendType::Transfer,
            preimage: small_preimage(),
            authz: small_authz_p2pkh(),
            trailing: TrailingParams::None,
        });
        assert!(matches!(res, Err(Stas3Error::InvalidScript(_))));
    }

    #[test]
    fn test_build_2_stas_outputs_uses_two_triplets() {
        // Two STAS outputs → two triplets (slots 1-3 and 4-6) appear back-to-back.
        let bytes = build_unlocking_script(&UnlockParams {
            stas_outputs: vec![
                StasOutputWitness {
                    satoshis: 1,
                    owner_pkh: [0xaa; 20],
                    var2_bytes: vec![],
                },
                StasOutputWitness {
                    satoshis: 2,
                    owner_pkh: [0xbb; 20],
                    var2_bytes: vec![],
                },
            ],
            change: None,
            note: None,
            funding: None,
            tx_type: TxType::Regular,
            spend_type: SpendType::Transfer,
            preimage: small_preimage(),
            authz: small_authz_p2pkh(),
            trailing: TrailingParams::None,
        })
        .unwrap();

        // Slot 1: OP_1
        assert_eq!(bytes[0], 0x51);
        // Slot 2: PUSH20 + 0xaa..
        assert_eq!(bytes[1], 0x14);
        assert_eq!(&bytes[2..22], &[0xaa; 20]);
        // Slot 3: OP_0 (empty var2)
        assert_eq!(bytes[22], 0x00);
        // Slot 4: OP_2 (satoshis=2)
        assert_eq!(bytes[23], 0x52);
        // Slot 5: PUSH20 + 0xbb..
        assert_eq!(bytes[24], 0x14);
        assert_eq!(&bytes[25..45], &[0xbb; 20]);
        // Slot 6: OP_0 (empty var2)
        assert_eq!(bytes[45], 0x00);

        // Two triplets: 1 + 21 + 1  +  1 + 21 + 1 = 46 bytes consumed.
        // Then change OP_FALSE OP_FALSE at [46..48].
        assert_eq!(&bytes[46..48], &[0x00, 0x00]);
    }

    #[test]
    fn test_authz_suppressed_emits_single_op_false() {
        let bytes = build_unlocking_script(&UnlockParams {
            stas_outputs: vec![StasOutputWitness {
                satoshis: 1,
                owner_pkh: [0xaa; 20],
                var2_bytes: vec![],
            }],
            change: None,
            note: None,
            funding: None,
            tx_type: TxType::Regular,
            spend_type: SpendType::Transfer,
            preimage: small_preimage(),
            authz: AuthzWitness::Suppressed,
            trailing: TrailingParams::None,
        })
        .unwrap();

        // Layout up to spendType:
        //   STAS triplet (1 + 21 + 1 = 23)
        //   change OP_FALSE OP_FALSE (2)            → 25
        //   note OP_FALSE (1)                       → 26
        //   funding OP_FALSE OP_FALSE (2)           → 28
        //   txType OP_0 (1)                         → 29
        //   preimage PUSH50 + 50 (51)               → 80
        //   spendType OP_1 (1)                      → 81
        // Then suppressed authz: single 0x00 at [81], length 82.
        assert_eq!(bytes[81], 0x00);
        assert_eq!(bytes.len(), 82);
    }

    #[test]
    fn test_trailing_merge_2_pieces() {
        // New wire format per spec §9.5 + canonical engine: the merge
        // section sits in the slot that used to hold `txType`. Layout for
        // a 2-piece merge is:
        //   mergeVout(scriptNum), seg_1, seg_0, segCount(scriptNum)
        // (segments reversed from forward order on emit).
        let p0 = vec![0x11; 30]; // forward-order piece 0 (head)
        let p1 = vec![0x22; 40]; // forward-order piece 1 (tail)
        let bytes = build_unlocking_script(&UnlockParams {
            stas_outputs: vec![StasOutputWitness {
                satoshis: 1,
                owner_pkh: [0xaa; 20],
                var2_bytes: vec![],
            }],
            change: None,
            note: None,
            funding: None,
            tx_type: TxType::Merge2,
            spend_type: SpendType::Transfer,
            preimage: small_preimage(),
            authz: small_authz_p2pkh(),
            trailing: TrailingParams::Merge {
                merge_vout: 0,
                pieces: vec![p0.clone(), p1.clone()],
            },
        })
        .unwrap();

        // Slot layout (offset, content):
        //   STAS triplet (23 bytes) + change OP_FALSE OP_FALSE (2) +
        //   note OP_FALSE (1) + funding OP_FALSE OP_FALSE (2) = 28
        //
        // Now the merge section starts at offset 28:
        //   mergeVout=0  → OP_FALSE (1 byte)                     → offset 29
        //   seg_1 (PUSH40 + 40 bytes = 41 bytes)                 → offset 70
        //   seg_0 (PUSH30 + 30 bytes = 31 bytes)                 → offset 101
        //   segCount=2 → OP_2 (1 byte)                           → offset 102
        //   preimage PUSH50 + 50 = 51                            → offset 153
        //   spendType OP_1 = 1                                   → offset 154
        //   authz P2PKH: PUSH71 + 71 + PUSH33 + 33 = 106         → offset 260

        assert_eq!(bytes[28], 0x00); // mergeVout=0
        assert_eq!(bytes[29], 40); // PUSH40 for seg_1
        assert_eq!(&bytes[30..70], &p1[..]);
        assert_eq!(bytes[70], 30); // PUSH30 for seg_0
        assert_eq!(&bytes[71..101], &p0[..]);
        assert_eq!(bytes[101], 0x52); // OP_2 segCount
        // preimage starts at offset 102
        assert_eq!(bytes[102], 50); // PUSH50
        assert_eq!(bytes.len(), 260);
    }

    #[test]
    fn test_trailing_atomic_swap_with_counterparty_script() {
        // AtomicSwap merge section: mergeVout, seg(s) reversed, segCount,
        // counterpartyScript, swap_indicator(1).
        let cs = vec![0xcc; 25];
        let p0 = vec![0x11; 30]; // forward-order single piece (head=tail for trivial)
        let bytes = build_unlocking_script(&UnlockParams {
            stas_outputs: vec![StasOutputWitness {
                satoshis: 1,
                owner_pkh: [0xaa; 20],
                var2_bytes: vec![],
            }],
            change: None,
            note: None,
            funding: None,
            tx_type: TxType::AtomicSwap,
            spend_type: SpendType::Transfer,
            preimage: small_preimage(),
            authz: small_authz_p2pkh(),
            trailing: TrailingParams::AtomicSwap {
                merge_vout: 0,
                pieces: vec![p0.clone()],
                counterparty_script: cs.clone(),
            },
        })
        .unwrap();

        // Layout offsets:
        //   STAS(23) + change(2) + note(1) + funding(2) = 28
        //   mergeVout OP_0 (1)                               → 29
        //   seg_0 PUSH30 + 30 (31)                           → 60
        //   segCount OP_1 (1)                                → 61
        //   counterpartyScript PUSH25 + 25 (26)              → 87
        //   swap_indicator OP_1 (1)                          → 88
        //   preimage PUSH50 + 50 (51)                        → 139
        //   spendType OP_1 (1)                               → 140
        //   authz P2PKH = 106                                → 246
        assert_eq!(bytes[28], 0x00); // mergeVout
        assert_eq!(bytes[29], 30); // PUSH30 for seg_0
        assert_eq!(&bytes[30..60], &p0[..]);
        assert_eq!(bytes[60], 0x51); // OP_1 segCount
        assert_eq!(bytes[61], 25); // PUSH25 for cs
        assert_eq!(&bytes[62..87], &cs[..]);
        assert_eq!(bytes[87], 0x51); // swap indicator
        assert_eq!(bytes[88], 50); // PUSH50 preimage
        assert_eq!(bytes.len(), 246);
    }
}
