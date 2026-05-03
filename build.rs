//! Build-time check: compile the official STAS-3 ASM template and verify
//! it matches the bundled `stas3_body.bin` byte-for-byte.
//!
//! Inputs:
//! - `src/script/templates/stas3/stas3_template_official.txt` — vendored
//!   copy of the official STAS-3 template (contains placeholders for
//!   `<owner address>`, `<2nd variable field>`, `<"redemption address"...>`,
//!   etc.). This file is the **canonical source-of-truth** for the
//!   STAS-3 body bytes within this SDK; `.ref/` is no longer required for
//!   builds. Any drift between this file and the upstream template must
//!   be a deliberate, reviewed change (the byte-equality check below
//!   guards against accidental drift).
//! - `src/script/templates/stas3/stas3_body.bin` — canonical 2,899-byte body.
//!
//! Process:
//! 1. Read the vendored template; strip the two leading placeholders and
//!    everything from `<"redemption address"` to end. The result is the
//!    body ASM that ends with `OP_RETURN`.
//! 2. Tokenize the body ASM (whitespace-separated). For each token:
//!    - If it starts with `OP_`, look up its byte via the hardcoded opcode
//!      map and emit one byte.
//!    - Else it's a hex literal — decode and emit a minimal Bitcoin push
//!      (bare push for length ≤ 75, OP_PUSHDATA1 for ≤ 255, OP_PUSHDATA2
//!      for ≤ 65535).
//! 3. Read the bundled `stas3_body.bin`. Assert it is exactly 2,899 bytes,
//!    starts with `0x6d` (OP_2DROP), and ends with `0x6a` (OP_RETURN).
//! 4. Assert the compiled bytes byte-equal the bundled bytes. On mismatch,
//!    panic with both lengths and the first divergent byte offset.
//!
//! The byte-equality check is **fail-closed**: the vendored template is a
//! tracked file in this repository, so the build hard-fails if it goes
//! missing or cannot be read. There is no silent fallback.
//!
//! `cargo:rerun-if-changed` is set for the vendored template, the bundled
//! `.bin`, and the recorded `.asm` so cargo recompiles when any of them
//! change.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const OFFICIAL_TEMPLATE_PATH: &str = "src/script/templates/stas3/stas3_template_official.txt";
const BODY_BIN_PATH: &str = "src/script/templates/stas3/stas3_body.bin";
const BODY_ASM_PATH: &str = "src/script/templates/stas3/stas3_body.asm";

const EXPECTED_BODY_LEN: usize = 2899;
const OP_2DROP: u8 = 0x6d;
const OP_RETURN: u8 = 0x6a;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;

fn main() {
    println!("cargo:rerun-if-changed={OFFICIAL_TEMPLATE_PATH}");
    println!("cargo:rerun-if-changed={BODY_BIN_PATH}");
    println!("cargo:rerun-if-changed={BODY_ASM_PATH}");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let template_path = manifest_dir.join(OFFICIAL_TEMPLATE_PATH);
    let bin_path = manifest_dir.join(BODY_BIN_PATH);

    // 1. Sanity-check the bundled bin first (independent of ASM compile).
    let bundled = fs::read(&bin_path).unwrap_or_else(|e| {
        panic!("failed to read {}: {}", bin_path.display(), e);
    });
    assert_eq!(
        bundled.len(),
        EXPECTED_BODY_LEN,
        "bundled stas3_body.bin is {} bytes, expected {}",
        bundled.len(),
        EXPECTED_BODY_LEN
    );
    assert_eq!(
        bundled[0], OP_2DROP,
        "bundled stas3_body.bin must start with OP_2DROP (0x6d), found {:#04x}",
        bundled[0]
    );
    assert_eq!(
        bundled[EXPECTED_BODY_LEN - 1],
        OP_RETURN,
        "bundled stas3_body.bin must end with OP_RETURN (0x6a), found {:#04x}",
        bundled[EXPECTED_BODY_LEN - 1]
    );

    // 2. Compile the vendored official template and compare byte-for-byte.
    //    The vendored template is a tracked file in this repository, so a
    //    missing/unreadable file is a real defect — fail the build hard.
    let template_text = fs::read_to_string(&template_path).unwrap_or_else(|e| {
        panic!(
            "failed to read vendored STAS-3 template at {}: {} \
             (this file is the canonical source-of-truth for STAS-3 body \
             bytes — restore it from git history or upstream)",
            template_path.display(),
            e
        );
    });

    let body_asm = strip_template_placeholders(&template_text);
    let compiled = compile_asm(&body_asm);

    if compiled != bundled {
        let mismatch_offset = compiled
            .iter()
            .zip(bundled.iter())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| compiled.len().min(bundled.len()));
        panic!(
            "STAS-3 ASM compile mismatch: compiled {} bytes vs bundled {} bytes; first divergent byte at offset {} (compiled={:#04x?}, bundled={:#04x?})",
            compiled.len(),
            bundled.len(),
            mismatch_offset,
            compiled.get(mismatch_offset),
            bundled.get(mismatch_offset),
        );
    }
}

/// Strip the leading `<owner address/MPKH - 20 bytes>` and `<2nd variable
/// field>` placeholders, and the trailing `<"redemption address".../>`
/// section onward. Returns the body ASM (which ends with `OP_RETURN`).
fn strip_template_placeholders(text: &str) -> String {
    // The two leading placeholders both start with `<` and end with `>`.
    // Drop the first two `<...>` runs from the head.
    let mut remaining = text;
    for _ in 0..2 {
        let lt = remaining.find('<').unwrap_or_else(|| {
            panic!("STAS-3 template: expected leading placeholder `<...>` not found");
        });
        let rest = &remaining[lt..];
        let gt = rest.find('>').unwrap_or_else(|| {
            panic!("STAS-3 template: unterminated leading placeholder `<...`");
        });
        remaining = &rest[gt + 1..];
    }

    // Now strip from the next `<` (the `<"redemption address"...>`) to end.
    let suffix_start = remaining.find('<').unwrap_or_else(|| {
        panic!("STAS-3 template: expected trailing `<\"redemption address\"...>` placeholder not found");
    });
    remaining[..suffix_start].trim().to_string()
}

/// Compile space/whitespace-separated ASM tokens to script bytes.
///
/// - Tokens starting with `OP_` are looked up in the hardcoded opcode map
///   and emitted as a single byte.
/// - All other non-empty tokens are interpreted as hex literals (no `0x`
///   prefix; hex digits only) and pushed using minimal Bitcoin push encoding.
fn compile_asm(asm: &str) -> Vec<u8> {
    let opcodes = build_opcode_map();
    let mut out = Vec::with_capacity(EXPECTED_BODY_LEN);

    for token in asm.split_whitespace() {
        if token.is_empty() {
            continue;
        }
        if let Some(stripped) = token.strip_prefix("OP_") {
            // OP_* opcode lookup. The map's keys include the `OP_` prefix
            // so re-attach for lookup; using stripped only for early bail.
            let _ = stripped;
            let byte = opcodes
                .get(token)
                .copied()
                .unwrap_or_else(|| panic!("STAS-3 ASM: unknown opcode `{token}`"));
            out.push(byte);
        } else if is_hex_literal(token) {
            let bytes = decode_hex(token)
                .unwrap_or_else(|| panic!("STAS-3 ASM: invalid hex literal `{token}`"));
            push_minimal(&bytes, &mut out);
        } else {
            panic!("STAS-3 ASM: unrecognized token `{token}` (not OP_* or hex)");
        }
    }

    out
}

fn is_hex_literal(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + c - b'a'),
        b'A'..=b'F' => Some(10 + c - b'A'),
        _ => None,
    }
}

/// Emit a minimal Bitcoin script push of `data` into `out`.
fn push_minimal(data: &[u8], out: &mut Vec<u8>) {
    let n = data.len();
    if n <= 75 {
        out.push(n as u8);
    } else if n <= 0xff {
        out.push(OP_PUSHDATA1);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(OP_PUSHDATA2);
        out.push((n & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
    } else {
        panic!("STAS-3 ASM: push of {n} bytes exceeds OP_PUSHDATA2 range");
    }
    out.extend_from_slice(data);
}

/// Hardcoded opcode-name → byte map covering every opcode used in the
/// official STAS-3 template (verified by listing unique `OP_*` tokens).
/// Mirrors `bsv::script::op::Op::from_name`. Keep in sync with op.rs if
/// new opcodes are added to the template.
fn build_opcode_map() -> HashMap<&'static str, u8> {
    let entries: &[(&str, u8)] = &[
        // push value
        ("OP_0", 0x00),
        ("OP_FALSE", 0x00),
        ("OP_PUSHDATA1", 0x4c),
        ("OP_PUSHDATA2", 0x4d),
        ("OP_PUSHDATA4", 0x4e),
        ("OP_1NEGATE", 0x4f),
        ("OP_1", 0x51),
        ("OP_TRUE", 0x51),
        ("OP_2", 0x52),
        ("OP_3", 0x53),
        ("OP_4", 0x54),
        ("OP_5", 0x55),
        ("OP_6", 0x56),
        ("OP_7", 0x57),
        ("OP_8", 0x58),
        ("OP_9", 0x59),
        ("OP_10", 0x5a),
        ("OP_11", 0x5b),
        ("OP_12", 0x5c),
        ("OP_13", 0x5d),
        ("OP_14", 0x5e),
        ("OP_15", 0x5f),
        ("OP_16", 0x60),
        // control / flow
        ("OP_NOP", 0x61),
        ("OP_IF", 0x63),
        ("OP_NOTIF", 0x64),
        ("OP_ELSE", 0x67),
        ("OP_ENDIF", 0x68),
        ("OP_VERIFY", 0x69),
        ("OP_RETURN", 0x6a),
        // stack
        ("OP_TOALTSTACK", 0x6b),
        ("OP_FROMALTSTACK", 0x6c),
        ("OP_2DROP", 0x6d),
        ("OP_2DUP", 0x6e),
        ("OP_3DUP", 0x6f),
        ("OP_2OVER", 0x70),
        ("OP_2ROT", 0x71),
        ("OP_2SWAP", 0x72),
        ("OP_IFDUP", 0x73),
        ("OP_DEPTH", 0x74),
        ("OP_DROP", 0x75),
        ("OP_DUP", 0x76),
        ("OP_NIP", 0x77),
        ("OP_OVER", 0x78),
        ("OP_PICK", 0x79),
        ("OP_ROLL", 0x7a),
        ("OP_ROT", 0x7b),
        ("OP_SWAP", 0x7c),
        ("OP_TUCK", 0x7d),
        // data manipulation
        ("OP_CAT", 0x7e),
        ("OP_SPLIT", 0x7f),
        ("OP_NUM2BIN", 0x80),
        ("OP_BIN2NUM", 0x81),
        ("OP_SIZE", 0x82),
        // bit logic
        ("OP_INVERT", 0x83),
        ("OP_AND", 0x84),
        ("OP_OR", 0x85),
        ("OP_XOR", 0x86),
        ("OP_EQUAL", 0x87),
        ("OP_EQUALVERIFY", 0x88),
        // numeric
        ("OP_1ADD", 0x8b),
        ("OP_1SUB", 0x8c),
        ("OP_NEGATE", 0x8f),
        ("OP_ABS", 0x90),
        ("OP_NOT", 0x91),
        ("OP_0NOTEQUAL", 0x92),
        ("OP_ADD", 0x93),
        ("OP_SUB", 0x94),
        ("OP_MUL", 0x95),
        ("OP_DIV", 0x96),
        ("OP_MOD", 0x97),
        ("OP_LSHIFT", 0x98),
        ("OP_RSHIFT", 0x99),
        ("OP_BOOLAND", 0x9a),
        ("OP_BOOLOR", 0x9b),
        ("OP_NUMEQUAL", 0x9c),
        ("OP_NUMEQUALVERIFY", 0x9d),
        ("OP_NUMNOTEQUAL", 0x9e),
        ("OP_LESSTHAN", 0x9f),
        ("OP_GREATERTHAN", 0xa0),
        ("OP_LESSTHANOREQUAL", 0xa1),
        ("OP_GREATERTHANOREQUAL", 0xa2),
        ("OP_MIN", 0xa3),
        ("OP_MAX", 0xa4),
        ("OP_WITHIN", 0xa5),
        // crypto
        ("OP_RIPEMD160", 0xa6),
        ("OP_SHA1", 0xa7),
        ("OP_SHA256", 0xa8),
        ("OP_HASH160", 0xa9),
        ("OP_HASH256", 0xaa),
        ("OP_CODESEPARATOR", 0xab),
        ("OP_CHECKSIG", 0xac),
        ("OP_CHECKSIGVERIFY", 0xad),
        ("OP_CHECKMULTISIG", 0xae),
        ("OP_CHECKMULTISIGVERIFY", 0xaf),
    ];
    entries.iter().copied().collect()
}
