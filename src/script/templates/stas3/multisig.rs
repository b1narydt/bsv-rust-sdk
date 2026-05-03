//! Pay-to-Multiple-Public-Key-Hash (P2MPKH) multisig redeem script
//! container — STAS-3 spec §10.2.
//!
//! Implements the wire format for the m-of-n multisig redeem script that
//! lives behind a 20-byte `MPKH` digest in P2MPKH and STAS-3 ownership
//! slots. The redeem script itself is only revealed at spend time.
//!
//! # Module purpose
//!
//! - Build the canonical STAS-3 redeem script for a given threshold and
//!   key set.
//! - Compute the `MPKH = HASH160(redeem_script)` digest stored in
//!   STAS / P2MPKH locking scripts.
//! - Build the fixed 70-byte P2MPKH locking script that brackets a STAS
//!   token's lifecycle (issuance / redemption UTXOs) — exposed via
//!   [`p2mpkh_locking_script_bytes`] for use by `factory/common.rs`.
//!
//! # Wire format (spec §10.2)
//!
//! ```text
//! redeem_script = [m: 1B raw 0x01..0x05]
//!                 [0x21][pk1 33B compressed SEC1]
//!                 …
//!                 [0x21][pkN 33B compressed SEC1]
//!                 [n: 1B raw 0x01..0x05]
//! ```
//!
//! Length = `2 + 34 * N` bytes.  `m` and `n` are RAW length bytes (NOT
//! `OP_m` / `OP_n` opcodes) and there is **no** trailing
//! `OP_CHECKMULTISIG` byte — the engine inlines the `OP_CHECKMULTISIG`
//! step.
//!
//! Constraints: `1 <= m <= n <= 5`.
//!
//! # Locking script (70 bytes)
//!
//! Used at issuance and redemption UTXOs only (in-life STAS UTXOs inline
//! the same logic):
//!
//! ```text
//! 76 a9 14 <MPKH:20> 88 82 01 21 87 63 ac 67
//! 51 7f 51 7f 73 63 7c 7f 68
//! 51 7f 73 63 7c 7f 68 51 7f 73 63 7c 7f 68
//! 51 7f 73 63 7c 7f 68 51 7f 73 63 7c 7f 68
//! ae 68
//! ```
//!
//! Total 70 bytes (3-byte prefix + 20-byte `MPKH` + 47-byte suffix).
//!
//! # Unlocking script
//!
//! Per spec §10.2, the unlocking script for a P2MPKH input is:
//!
//! ```text
//! OP_0 <sig_1> <sig_2> … <sig_m> <redeem_script>
//! ```
//!
//! The leading `OP_0` is the dummy stack element required by
//! `OP_CHECKMULTISIG`. This module only models the `MultisigScript`
//! container and lock-script wire formats; signature emission is
//! handled by [`super::unlock::AuthzWitness::P2mpkh`].

use super::constants::P2MPKH_LOCKING_LEN;
use super::error::Stas3Error;
use crate::primitives::hash::hash160;
use crate::primitives::public_key::PublicKey;

/// Maximum number of public keys allowed in a STAS-3 P2MPKH redeem
/// script.
///
/// The STAS-3 specification (§10.2) constrains both the threshold `m`
/// and the key count `n` to the inclusive range `1..=5`, encoded as a
/// single raw length byte.
pub const MAX_MULTISIG_KEYS: usize = 5;

/// Minimum number of public keys in a multisig script.
pub const MIN_MULTISIG_KEYS: usize = 1;

/// The 47-byte tail of the P2MPKH locking script that follows the
/// 20-byte `MPKH`. Spec §10.2 reference assembly:
///
/// `OP_EQUALVERIFY OP_SIZE 0x21 OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE
///  OP_1 OP_SPLIT (OP_1 OP_SPLIT OP_IFDUP OP_IF OP_SWAP OP_SPLIT OP_ENDIF)×5
///  OP_CHECKMULTISIG OP_ENDIF`
const P2MPKH_LOCKING_SUFFIX: [u8; 47] = [
    0x88, 0x82, 0x01, 0x21, 0x87, 0x63, 0xac, 0x67,
    0x51, 0x7f, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
    0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
    0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
    0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
    0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
    0xae, 0x68,
];

/// The 3-byte prefix of the P2MPKH locking script:
/// `OP_DUP OP_HASH160 OP_DATA_20`.
const P2MPKH_LOCKING_PREFIX: [u8; 3] = [0x76, 0xa9, 0x14];

/// `OP_DATA_33` push-prefix used in front of every compressed pubkey
/// inside the redeem buffer.
const OP_DATA_33: u8 = 0x21;

/// A canonical STAS-3 multisig redeem-script container.
///
/// Holds an `m`-of-`n` threshold and the ordered list of `n` compressed
/// public keys. Order matters — at spend time signatures are matched to
/// keys sequentially by `OP_CHECKMULTISIG`.
#[derive(Clone, Debug)]
pub struct MultisigScript {
    /// Threshold — minimum number of signatures required to spend.
    threshold: u8,
    /// The set of public keys (compressed, 33 bytes each).
    public_keys: Vec<PublicKey>,
}

impl MultisigScript {
    /// Create a new multisig script with the given threshold and public
    /// keys.
    ///
    /// # Arguments
    /// * `threshold` — the `m` in `m`-of-`n` (minimum signatures
    ///   required). Must satisfy `1 <= m <= n`.
    /// * `public_keys` — the `n` public keys, in canonical order. Must
    ///   be non-empty and contain at most [`MAX_MULTISIG_KEYS`] entries.
    ///
    /// # Errors
    /// Returns [`Stas3Error::InvalidScript`] when the constraints above
    /// are violated.
    pub fn new(threshold: u8, public_keys: Vec<PublicKey>) -> Result<Self, Stas3Error> {
        let n = public_keys.len();

        if n < MIN_MULTISIG_KEYS {
            return Err(Stas3Error::InvalidScript(
                "multisig requires at least 1 public key".to_string(),
            ));
        }
        if n > MAX_MULTISIG_KEYS {
            return Err(Stas3Error::InvalidScript(format!(
                "multisig supports at most {MAX_MULTISIG_KEYS} public keys, got {n}"
            )));
        }
        if threshold == 0 {
            return Err(Stas3Error::InvalidScript(
                "multisig threshold must be at least 1".to_string(),
            ));
        }
        if threshold as usize > n {
            return Err(Stas3Error::InvalidScript(format!(
                "threshold {threshold} exceeds number of keys {n}"
            )));
        }

        Ok(MultisigScript {
            threshold,
            public_keys,
        })
    }

    /// The threshold (`m`) — minimum signatures required.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// The total number of keys (`n`).
    pub fn n(&self) -> usize {
        self.public_keys.len()
    }

    /// The public keys in this multisig script.
    pub fn public_keys(&self) -> &[PublicKey] {
        &self.public_keys
    }

    /// Serialize to the canonical STAS-3 redeem-script byte buffer.
    ///
    /// Produces:
    /// `[m_raw] [0x21 pk1] [0x21 pk2] … [0x21 pkN] [n_raw]`
    ///
    /// Length = `2 + 34 * N` bytes.
    ///
    /// `m_raw` and `n_raw` are RAW length bytes in the range
    /// `0x01..=0x05`, **not** `OP_m` / `OP_n` opcodes. No trailing
    /// `OP_CHECKMULTISIG` byte is emitted — the engine inlines that
    /// step. This is the exact buffer hashed to derive the `MPKH` and
    /// pushed onto the stack at spend time.
    pub fn to_serialized_bytes(&self) -> Vec<u8> {
        let n = self.public_keys.len();
        let mut bytes = Vec::with_capacity(2 + n * 34);

        // m: raw length byte (0x01..=0x05).
        bytes.push(self.threshold);

        // Each public key: 0x21 push-prefix + 33 bytes compressed SEC1.
        for pk in &self.public_keys {
            let compressed = pk.to_der(); // 33-byte compressed SEC1 form
            debug_assert_eq!(
                compressed.len(),
                33,
                "PublicKey::to_der must return 33-byte compressed form"
            );
            bytes.push(OP_DATA_33);
            bytes.extend_from_slice(&compressed);
        }

        // n: raw length byte (0x01..=0x05).
        bytes.push(n as u8);

        bytes
    }

    /// Compute the `MPKH` — the 20-byte HASH160 of the canonical redeem
    /// script (see [`Self::to_serialized_bytes`]).
    ///
    /// This is the value embedded in P2MPKH and STAS-3 locking scripts
    /// in place of a single `PKH`.
    pub fn mpkh(&self) -> [u8; 20] {
        hash160(&self.to_serialized_bytes())
    }

    /// Build the fixed 70-byte P2MPKH locking script for this multisig.
    ///
    /// Equivalent to `p2mpkh_locking_script_bytes(self.mpkh())`.
    pub fn p2mpkh_locking_script(&self) -> [u8; P2MPKH_LOCKING_LEN] {
        p2mpkh_locking_script_bytes(self.mpkh())
    }

    /// Parse a `MultisigScript` from the canonical STAS-3 wire format.
    ///
    /// Expects exactly:
    /// `[m_raw] [0x21 pk1] … [0x21 pkN] [n_raw]`
    ///
    /// # Errors
    /// Returns an error if the buffer length is wrong, the leading or
    /// trailing length bytes are out of range, any push-prefix is not
    /// `0x21`, or any embedded public key fails to decode.
    pub fn from_serialized_bytes(bytes: &[u8]) -> Result<Self, Stas3Error> {
        // Minimum length: m + (0x21 + 33) + n = 2 + 34 = 36 (1-of-1).
        if bytes.len() < 2 + 34 {
            return Err(Stas3Error::InvalidScript(format!(
                "redeem script too short: {} bytes",
                bytes.len()
            )));
        }

        let m = bytes[0];
        let n = *bytes.last().unwrap();

        if !(MIN_MULTISIG_KEYS as u8..=MAX_MULTISIG_KEYS as u8).contains(&m) {
            return Err(Stas3Error::InvalidScript(format!(
                "invalid threshold byte: 0x{m:02x}"
            )));
        }
        if !(MIN_MULTISIG_KEYS as u8..=MAX_MULTISIG_KEYS as u8).contains(&n) {
            return Err(Stas3Error::InvalidScript(format!(
                "invalid key-count byte: 0x{n:02x}"
            )));
        }
        if m > n {
            return Err(Stas3Error::InvalidScript(format!(
                "threshold {m} exceeds key count {n}"
            )));
        }

        let expected_len = 2 + (n as usize) * 34;
        if bytes.len() != expected_len {
            return Err(Stas3Error::InvalidScript(format!(
                "expected {} bytes for {}-of-{} redeem script, got {}",
                expected_len,
                m,
                n,
                bytes.len()
            )));
        }

        // Parse public keys: each is OP_DATA_33 (0x21) followed by 33 bytes.
        let key_section = &bytes[1..bytes.len() - 1];
        let mut public_keys = Vec::with_capacity(n as usize);
        for i in 0..n as usize {
            let offset = i * 34;
            if key_section[offset] != OP_DATA_33 {
                return Err(Stas3Error::InvalidScript(format!(
                    "expected 0x21 push-prefix at key {}, got 0x{:02x}",
                    i, key_section[offset]
                )));
            }
            let pk_bytes = &key_section[offset + 1..offset + 34];
            let pk = PublicKey::from_der_bytes(pk_bytes).map_err(|e| {
                Stas3Error::InvalidScript(format!(
                    "invalid public key at index {i}: {e}"
                ))
            })?;
            public_keys.push(pk);
        }

        MultisigScript::new(m, public_keys)
    }
}

/// Build the fixed 70-byte STAS-3 P2MPKH locking-script body for the
/// given `mpkh`.
///
/// Layout (spec §10.2):
///
/// ```text
/// 76 a9 14 <MPKH:20> 88 82 01 21 87 63 ac 67
/// (51 7f 51 7f 73 63 7c 7f 68)
/// (51 7f 73 63 7c 7f 68) × 4
/// ae 68
/// ```
///
/// Total 70 bytes. Used at issuance and redemption UTXOs — the non-STAS
/// outputs that bracket a STAS token's lifecycle. In-life STAS UTXOs
/// embed the same logic inside the STAS-3 base template.
///
/// # Arguments
/// * `mpkh` — the 20-byte `HASH160` of a STAS-3 redeem script.
///
/// # Returns
/// A 70-byte array containing the locking-script body.
pub fn p2mpkh_locking_script_bytes(mpkh: [u8; 20]) -> [u8; P2MPKH_LOCKING_LEN] {
    let mut out = [0u8; P2MPKH_LOCKING_LEN];
    out[..3].copy_from_slice(&P2MPKH_LOCKING_PREFIX);
    out[3..23].copy_from_slice(&mpkh);
    out[23..].copy_from_slice(&P2MPKH_LOCKING_SUFFIX);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::private_key::PrivateKey;
    use crate::primitives::utils::to_hex;

    /// Deterministic 33-byte compressed public key for vector tests.
    /// Builds a valid SEC1 point by deriving from a known private-key
    /// seed (scalar `seed`).
    fn det_pubkey(seed: u8) -> PublicKey {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = seed;
        let sk = PrivateKey::from_bytes(&sk_bytes).expect("valid scalar");
        sk.to_public_key()
    }

    /// Helper: derive `n` deterministic public keys from scalar seeds
    /// `1..=n`.
    fn det_pubkeys(n: usize) -> Vec<PublicKey> {
        (1u8..=n as u8).map(det_pubkey).collect()
    }

    #[test]
    fn multisig_script_1_of_1_length_is_36() {
        let pubs = det_pubkeys(1);
        let ms = MultisigScript::new(1, pubs).unwrap();

        // 1 (m) + 34 (0x21 + 33 bytes pk) + 1 (n) = 36 bytes.
        let bytes = ms.to_serialized_bytes();
        assert_eq!(bytes.len(), 36);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x21);
        assert_eq!(bytes[35], 0x01);
    }

    #[test]
    fn multisig_script_2_of_3_roundtrip() {
        let pubs = det_pubkeys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();

        assert_eq!(ms.threshold(), 2);
        assert_eq!(ms.n(), 3);

        // Serialize and parse back.
        let bytes = ms.to_serialized_bytes();
        // Length = 2 + 34 * 3 = 104
        assert_eq!(bytes.len(), 2 + 34 * 3);
        // First byte = m (raw 0x02), last byte = n (raw 0x03).
        assert_eq!(bytes[0], 0x02);
        assert_eq!(*bytes.last().unwrap(), 0x03);

        let ms2 = MultisigScript::from_serialized_bytes(&bytes).unwrap();
        assert_eq!(ms2.threshold(), 2);
        assert_eq!(ms2.n(), 3);

        // MPKH should be deterministic and round-trip.
        assert_eq!(ms.mpkh(), ms2.mpkh());
    }

    #[test]
    fn deterministic_3_of_5_redeem_vector() {
        // Deterministic 3-of-5 with public keys derived from secp256k1
        // scalar seeds 1, 2, 3, 4, 5 (i.e. compressed encodings of
        // `i * G`).
        let pubs = det_pubkeys(5);
        let ms = MultisigScript::new(3, pubs.clone()).unwrap();
        let bytes = ms.to_serialized_bytes();

        // Spec mandates length = 2 + 34 * 5 = 172.
        assert_eq!(bytes.len(), 172);
        // m = 0x03, n = 0x05 raw bytes.
        assert_eq!(bytes[0], 0x03);
        assert_eq!(*bytes.last().unwrap(), 0x05);

        // Each key slot is 0x21 followed by 33 bytes; verify offsets.
        for i in 0..5 {
            let off = 1 + i * 34;
            assert_eq!(bytes[off], 0x21, "key {} push prefix should be 0x21", i);
            assert_eq!(
                &bytes[off + 1..off + 34],
                &pubs[i].to_der()[..],
                "key {} body must match seed-derived public key",
                i
            );
        }

        // Exact 172-byte hex of the canonical 3-of-5 redeem buffer for
        // the public keys `i * G` (i = 1..=5). Cross-validates against
        // independent implementations (Bittoku, Elixir reference).
        let expected_hex = concat!(
            "03",
            // pk1 = 1 * G
            "21", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            // pk2 = 2 * G
            "21", "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            // pk3 = 3 * G
            "21", "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            // pk4 = 4 * G
            "21", "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            // pk5 = 5 * G
            "21", "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
            "05",
        );
        assert_eq!(to_hex(&bytes), expected_hex);

        // MPKH = HASH160(redeem_buffer); pinned for cross-SDK parity
        // check (Bittoku, Elixir).
        assert_eq!(
            to_hex(&ms.mpkh()),
            "deb7bfb8b45c2bfe4579af5126b46c4d95e4e3a6"
        );
    }

    #[test]
    fn p2mpkh_locking_script_bytes_pattern_mpkh() {
        // For a structured MPKH (0x11..0x04 wrap) build the 70-byte
        // locking script and check prefix / mpkh slot / suffix tail.
        let mpkh: [u8; 20] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let body = p2mpkh_locking_script_bytes(mpkh);

        assert_eq!(body.len(), P2MPKH_LOCKING_LEN);
        // Prefix = 76 a9 14 (OP_DUP OP_HASH160 PUSH20)
        assert_eq!(&body[..3], &[0x76, 0xa9, 0x14]);
        // MPKH at offset 3..23
        assert_eq!(&body[3..23], &mpkh);
        // Last two bytes = 0xae 0x68 (OP_CHECKMULTISIG OP_ENDIF)
        assert_eq!(&body[68..70], &[0xae, 0x68]);
        // Full canonical-suffix slice
        assert_eq!(&body[23..70], &P2MPKH_LOCKING_SUFFIX);
    }

    #[test]
    fn multisig_script_rejects_zero_threshold() {
        let pubs = det_pubkeys(3);
        let err = MultisigScript::new(0, pubs).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("threshold must be at least 1"), "got: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn multisig_script_rejects_threshold_exceeding_keys() {
        let pubs = det_pubkeys(2);
        let err = MultisigScript::new(3, pubs).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("threshold 3 exceeds"), "got: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn multisig_script_rejects_too_many_keys() {
        let pubs = det_pubkeys(MAX_MULTISIG_KEYS + 1);
        let err = MultisigScript::new(1, pubs).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("at most"), "got: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn multisig_script_rejects_empty_keys() {
        let err = MultisigScript::new(1, vec![]).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("at least 1"), "got: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn from_serialized_bytes_rejects_short() {
        let err = MultisigScript::from_serialized_bytes(&[0x01, 0x02, 0x03]).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("too short"), "got: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn from_serialized_bytes_rejects_bad_threshold() {
        // m = 0x06 is out of 1..=5 range.
        let mut bytes = vec![0x06];
        bytes.push(0x21);
        bytes.extend_from_slice(&[0u8; 33]);
        bytes.push(0x06);
        let err = MultisigScript::from_serialized_bytes(&bytes).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("invalid threshold byte"), "got: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn from_serialized_bytes_rejects_bad_push_prefix() {
        // Length matches a 1-of-1 redeem script (36 bytes) but the
        // push-prefix byte is wrong.
        let mut bytes = vec![0x01];
        bytes.push(0x4c); // wrong push prefix
        bytes.extend_from_slice(&[0u8; 33]);
        bytes.push(0x01);
        let err = MultisigScript::from_serialized_bytes(&bytes).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("push-prefix"), "got: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn mpkh_is_20_bytes() {
        let pubs = det_pubkeys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        assert_eq!(ms.mpkh().len(), 20);
    }

    #[test]
    fn mpkh_round_trip() {
        let pubs = det_pubkeys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        let bytes = ms.to_serialized_bytes();
        let parsed = MultisigScript::from_serialized_bytes(&bytes).unwrap();
        assert_eq!(parsed.mpkh(), ms.mpkh());
    }

    #[test]
    fn p2mpkh_locking_script_method_matches_free_fn() {
        let pubs = det_pubkeys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        let lock_via_method = ms.p2mpkh_locking_script();
        let lock_via_fn = p2mpkh_locking_script_bytes(ms.mpkh());
        assert_eq!(lock_via_method, lock_via_fn);
        assert_eq!(lock_via_method.len(), P2MPKH_LOCKING_LEN);
    }
}
