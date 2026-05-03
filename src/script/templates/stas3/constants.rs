//! STAS-3 protocol constants per spec v0.2 §12.

/// The canonical 2,899-byte STAS-3 engine body.
/// Compiled from official ASM at stastech.org's `stassso/STAS-3-script-templates`.
/// Verified byte-equal to the ASM compile by build.rs.
pub const STAS3_ENGINE_BYTES: &[u8] = include_bytes!("stas3_body.bin");

/// Length of the canonical engine body.
pub const STAS3_ENGINE_LEN: usize = 2899;

/// Length of an STAS-3 P2MPKH locking script.
pub const P2MPKH_LOCKING_LEN: usize = 70;

/// HASH160("") — sentinel signaling signature suppression in owner / receive_addr slots.
/// See spec v0.2 §10.3.
pub const EMPTY_HASH160: [u8; 20] = [
    0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1, 0x37, 0x06,
    0xa4, 0x13, 0x2c, 0xcf, 0xb1, 0x6f, 0x7c, 0x3b, 0x9f, 0xcb,
];

/// ECDSA-trick constant: half of secp256k1 group order n. (Spec §12)
pub const HALF_N: [u8; 17] = [
    0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0,
    0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba, 0xfe,
];

/// ECDSA-trick fixed DER prefix for synthesized signature (r = G_x). (Spec §12)
pub const SIG_PREFIX_DER: [u8; 38] = [
    0x30, 0x44, 0x02, 0x20, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
    0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x02, 0x20,
];

/// ECDSA-trick verification key A. (Spec §12)
pub const PUBKEY_A: [u8; 33] = [
    0x03, 0x8f, 0xf8, 0x3d, 0x8c, 0xf1, 0x21, 0x21, 0x49, 0x16, 0x09, 0xc4, 0x93, 0x9d,
    0xc1, 0x1c, 0x4a, 0xa3, 0x55, 0x03, 0x50, 0x8f, 0xe4, 0x32, 0xdc, 0x5a, 0x5c, 0x19,
    0x05, 0x60, 0x8b, 0x92, 0x18,
];

/// ECDSA-trick verification key B. (Spec §12)
pub const PUBKEY_B: [u8; 33] = [
    0x02, 0x36, 0x35, 0x95, 0x47, 0x89, 0xa0, 0x2e, 0x39, 0xfb, 0x7e, 0x54, 0x44, 0x0b,
    0x6f, 0x52, 0x8d, 0x53, 0xef, 0xd6, 0x56, 0x35, 0xdd, 0xad, 0x7f, 0x3c, 0x40, 0x85,
    0xf9, 0x7f, 0xdb, 0xdc, 0x48,
];

/// Maximum payload size for the trailing OP_RETURN note (spec §11).
pub const MAX_NOTE_BYTES: usize = 65_533;

/// MetaWatt protocolID namespace (spec §14.6 — locked decisions).
pub const PROTOCOL_OWNER: &str = "stas3owner";
pub const PROTOCOL_MINT: &str = "stas3mint";
pub const PROTOCOL_FREEZE: &str = "stas3freeze";
pub const PROTOCOL_CONFISCATE: &str = "stas3confiscate";
pub const PROTOCOL_SWAP: &str = "stas3swap";
pub const PROTOCOL_FUEL: &str = "stas3fuel";

/// Default basket names.
pub const BASKET_TOKENS: &str = "stas3tokens";
pub const BASKET_FUEL: &str = "stas3fuel";

/// Standard STAS-3 transaction version (entry to `Spend` "relaxed" mode).
/// Spec v0.2 implies post-genesis flags; using version 2 enables the
/// non-clean-stack and non-push-only acceptance paths needed for the
/// covenant-style execution.
pub const STAS3_TX_VERSION: u32 = 2;

/// Default sighash scope for STAS-3 owner spending: SIGHASH_ALL | SIGHASH_FORKID.
pub const SIGHASH_DEFAULT: u32 = 0x41; // SIGHASH_ALL=0x01 | SIGHASH_FORKID=0x40

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hash::hash160;

    #[test]
    fn test_engine_body_length() {
        assert_eq!(STAS3_ENGINE_BYTES.len(), STAS3_ENGINE_LEN);
        assert_eq!(STAS3_ENGINE_LEN, 2899);
    }

    #[test]
    fn test_engine_starts_with_op_2drop() {
        assert_eq!(STAS3_ENGINE_BYTES[0], 0x6d);
    }

    #[test]
    fn test_engine_ends_with_op_return() {
        assert_eq!(STAS3_ENGINE_BYTES[2898], 0x6a);
    }

    #[test]
    fn test_empty_hash160_is_correct_value() {
        assert_eq!(hash160(&[]), EMPTY_HASH160);
    }
}
