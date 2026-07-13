//! Private key type for secp256k1 ECDSA operations.
//!
//! PrivateKey wraps a BigNumber scalar in [1, n-1] and provides
//! key generation, import/export (hex, WIF), signing, and public
//! key derivation. Mirrors the TS SDK PrivateKey.ts API.

use crate::primitives::base_point::BasePoint;
use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::curve::Curve;
use crate::primitives::ecdsa::ecdsa_sign;
use crate::primitives::error::PrimitivesError;
use crate::primitives::hash::{sha256, sha256_hmac};
use crate::primitives::point::Point;
use crate::primitives::public_key::PublicKey;
use crate::primitives::random::random_bytes;
use crate::primitives::signature::Signature;
use crate::primitives::utils::{base58_check_decode, base58_check_encode};

/// A secp256k1 private key (256-bit scalar in [1, n-1]).
///
/// Uses composition (not inheritance) with BigNumber as the internal
/// representation, following Rust conventions.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    inner: BigNumber,
}

impl PrivateKey {
    /// Generate a random private key using OS entropy.
    ///
    /// Generates 32 random bytes and reduces mod n, ensuring the
    /// result is in [1, n-1].
    pub fn from_random() -> Result<Self, PrimitivesError> {
        let curve = Curve::secp256k1();
        loop {
            let bytes = random_bytes(32);
            let bn = BigNumber::from_bytes(&bytes, Endian::Big);
            let key = bn
                .umod(&curve.n)
                .map_err(|e| PrimitivesError::InvalidPrivateKey(format!("mod n: {e}")))?;
            if !key.is_zero() {
                return Ok(PrivateKey { inner: key });
            }
            // Extremely unlikely (probability 2^-256), but loop to be safe
        }
    }

    /// Create a private key from raw bytes (big-endian).
    ///
    /// Must be a valid 32-byte scalar in [1, n-1].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitivesError> {
        let bn = BigNumber::from_bytes(bytes, Endian::Big);
        Self::validate_range(&bn)?;
        Ok(PrivateKey { inner: bn })
    }

    /// Create a private key from a hexadecimal string.
    ///
    /// The hex string is parsed as a big-endian 256-bit integer.
    /// Must be in [1, n-1].
    pub fn from_hex(hex: &str) -> Result<Self, PrimitivesError> {
        let bn = BigNumber::from_hex(hex)?;
        Self::validate_range(&bn)?;
        Ok(PrivateKey { inner: bn })
    }

    /// Create a private key from a string (alias for from_hex).
    pub fn from_string(s: &str) -> Result<Self, PrimitivesError> {
        Self::from_hex(s)
    }

    /// Create a private key from a WIF (Wallet Import Format) string.
    ///
    /// WIF format: Base58Check(prefix(1) || key(32) || compression_flag(1))
    /// The compression flag must be 0x01 (we only support compressed keys).
    pub fn from_wif(wif: &str) -> Result<Self, PrimitivesError> {
        let (prefix, payload) = base58_check_decode(wif, 1)?;

        if payload.len() != 33 {
            return Err(PrimitivesError::InvalidWif(format!(
                "invalid WIF data length: expected 33, got {}",
                payload.len()
            )));
        }

        if payload[32] != 0x01 {
            return Err(PrimitivesError::InvalidWif(
                "invalid WIF compression flag (expected 0x01)".to_string(),
            ));
        }

        let _ = prefix; // prefix validated by Base58Check decode
        let bn = BigNumber::from_bytes(&payload[..32], Endian::Big);
        Self::validate_range(&bn)?;
        Ok(PrivateKey { inner: bn })
    }

    /// Export the private key as a 64-character zero-padded hex string.
    pub fn to_hex(&self) -> String {
        let hex = self.inner.to_hex();
        format!("{hex:0>64}")
    }

    /// Export the private key in WIF (Wallet Import Format).
    ///
    /// WIF format: Base58Check(prefix || key(32) || 0x01)
    /// Default prefix is `[0x80]` for mainnet.
    pub fn to_wif(&self, prefix: &[u8]) -> String {
        let mut key_data = self.inner.to_array(Endian::Big, Some(32));
        key_data.push(0x01); // compression flag
        base58_check_encode(&key_data, prefix)
    }

    /// Derive the corresponding public key.
    ///
    /// Computes pubkey = inner * G using the precomputed base point.
    pub fn to_public_key(&self) -> PublicKey {
        let base_point = BasePoint::instance();
        let point = base_point.mul(&self.inner);
        PublicKey::from_point(point)
    }

    /// Sign a message (raw bytes) using ECDSA.
    ///
    /// The message is first hashed with SHA-256, then signed
    /// using RFC 6979 deterministic nonce generation.
    pub fn sign(&self, message: &[u8], force_low_s: bool) -> Result<Signature, PrimitivesError> {
        let msg_hash = sha256(message);
        ecdsa_sign(&msg_hash, &self.inner, force_low_s)
    }

    /// Get the private key as 32 big-endian bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_array(Endian::Big, Some(32))
    }

    /// Access the underlying BigNumber.
    pub fn bn(&self) -> &BigNumber {
        &self.inner
    }

    /// Compute ECDH shared secret: self.bn * public_key.point.
    ///
    /// Returns the resulting point on the curve. The public key must be
    /// a valid point on secp256k1.
    pub fn derive_shared_secret(&self, public_key: &PublicKey) -> Result<Point, PrimitivesError> {
        if !public_key.point().validate() {
            return Err(PrimitivesError::InvalidPublicKey(
                "public key is not on the curve".to_string(),
            ));
        }
        let result = public_key.point().mul(&self.inner);
        Ok(result)
    }

    /// Derive a child private key using Type-42 key derivation (BRC-42).
    ///
    /// Computes: child = (self + HMAC-SHA256(shared_secret_compressed, invoice_number)) mod n
    /// where shared_secret = self * counterparty.
    pub fn derive_child(
        &self,
        counterparty: &PublicKey,
        invoice_number: &str,
    ) -> Result<PrivateKey, PrimitivesError> {
        let shared_secret = self.derive_shared_secret(counterparty)?;
        self.derive_child_with_secret(&shared_secret, invoice_number)
    }

    /// Derive a child private key from a *precomputed* ECDH shared secret.
    ///
    /// This is the per-message cheap half of [`derive_child`]: the expensive
    /// ECDH point-multiply (`self * counterparty`) is the caller's
    /// responsibility, and its result is passed in as `shared_secret`. The
    /// shared secret depends ONLY on `(self, counterparty)` — NOT on
    /// `invoice_number` — so it can be cached per counterparty and reused
    /// across every message. The `invoice_number` (which embeds the per-message
    /// nonce) only flows through the HMAC and the scalar add below, both of
    /// which are recomputed every call. Output is bit-identical to
    /// [`derive_child`] for the same `shared_secret`/`invoice_number`.
    pub fn derive_child_with_secret(
        &self,
        shared_secret: &Point,
        invoice_number: &str,
    ) -> Result<PrivateKey, PrimitivesError> {
        let curve = Curve::secp256k1();
        let shared_secret_bytes = shared_secret.to_der(true); // 33-byte compressed
        let hmac_result = sha256_hmac(&shared_secret_bytes, invoice_number.as_bytes());
        let hmac_bn = BigNumber::from_bytes(&hmac_result, Endian::Big);
        let child =
            self.inner.add(&hmac_bn).umod(&curve.n).map_err(|e| {
                PrimitivesError::ArithmeticError(format!("derive_child mod n: {e}"))
            })?;
        let child_bytes = child.to_array(Endian::Big, Some(32));
        PrivateKey::from_bytes(&child_bytes)
    }

    /// Validate that a BigNumber is in the valid range [1, n-1].
    fn validate_range(bn: &BigNumber) -> Result<(), PrimitivesError> {
        let curve = Curve::secp256k1();
        if bn.is_zero() {
            return Err(PrimitivesError::InvalidPrivateKey(
                "private key must not be zero".to_string(),
            ));
        }
        if bn.cmp(&curve.n) >= 0 {
            return Err(PrimitivesError::InvalidPrivateKey(
                "private key must be less than curve order n".to_string(),
            ));
        }
        if bn.is_negative() {
            return Err(PrimitivesError::InvalidPrivateKey(
                "private key must not be negative".to_string(),
            ));
        }
        Ok(())
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.cmp(&other.inner) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::ecdsa::ecdsa_verify;

    // -----------------------------------------------------------------------
    // PrivateKey: generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_from_random() {
        let key = PrivateKey::from_random().unwrap();
        let curve = Curve::secp256k1();

        // Key should be in [1, n-1]
        assert!(!key.bn().is_zero(), "Random key should not be zero");
        assert!(
            key.bn().cmp(&curve.n) < 0,
            "Random key should be less than n"
        );
    }

    #[test]
    fn test_private_key_from_random_unique() {
        let k1 = PrivateKey::from_random().unwrap();
        let k2 = PrivateKey::from_random().unwrap();
        assert_ne!(k1, k2, "Two random keys should differ");
    }

    // -----------------------------------------------------------------------
    // PrivateKey: from_hex / to_hex
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_from_hex() {
        let key = PrivateKey::from_hex("1").unwrap();
        assert_eq!(
            key.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn test_private_key_hex_roundtrip() {
        let hex = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
        let key = PrivateKey::from_hex(hex).unwrap();
        assert_eq!(key.to_hex(), hex);
    }

    #[test]
    fn test_private_key_from_hex_zero_rejected() {
        let result = PrivateKey::from_hex("0");
        assert!(result.is_err(), "Zero should be rejected");
    }

    #[test]
    fn test_private_key_from_hex_too_large() {
        // n = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        // n itself should be rejected
        let result = PrivateKey::from_hex(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        );
        assert!(result.is_err(), "n should be rejected");
    }

    // -----------------------------------------------------------------------
    // PrivateKey: from_string
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_from_string() {
        let key = PrivateKey::from_string("1").unwrap();
        assert_eq!(
            key.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    // -----------------------------------------------------------------------
    // PrivateKey: WIF import/export
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_wif_roundtrip() {
        let key = PrivateKey::from_hex("1").unwrap();
        let wif = key.to_wif(&[0x80]);
        let recovered = PrivateKey::from_wif(&wif).unwrap();
        assert_eq!(key, recovered, "WIF round-trip should recover same key");
    }

    #[test]
    fn test_private_key_wif_known_vector() {
        // Key = 1, mainnet WIF
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let key = PrivateKey::from_wif(wif).unwrap();
        assert_eq!(
            key.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn test_private_key_to_wif_known_vector() {
        let key = PrivateKey::from_hex("1").unwrap();
        let wif = key.to_wif(&[0x80]);
        assert_eq!(wif, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
    }

    #[test]
    fn test_private_key_wif_test_vectors() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct WifVector {
            private_key_hex: String,
            wif_mainnet: String,
            wif_prefix: String,
            #[allow(dead_code)]
            description: String,
        }

        let data = include_str!("../../test-vectors/private_key_wif.json");
        let vectors: Vec<WifVector> = serde_json::from_str(data).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let key = PrivateKey::from_hex(&v.private_key_hex).unwrap();
            let prefix_bytes = crate::primitives::utils::from_hex(&v.wif_prefix).unwrap();
            let wif = key.to_wif(&prefix_bytes);
            assert_eq!(wif, v.wif_mainnet, "Vector {i}: WIF mismatch");

            // Round-trip
            let recovered = PrivateKey::from_wif(&wif).unwrap();
            assert_eq!(key, recovered, "Vector {i}: WIF round-trip failed");
        }
    }

    // -----------------------------------------------------------------------
    // PrivateKey: to_public_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_to_public_key() {
        // Key = 1, pubkey = G
        let key = PrivateKey::from_hex("1").unwrap();
        let pubkey = key.to_public_key();
        let compressed = pubkey.to_der_hex();
        assert_eq!(
            compressed,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    // -----------------------------------------------------------------------
    // PrivateKey: sign and verify
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_sign_verify() {
        let key = PrivateKey::from_hex("1").unwrap();
        let sig = key.sign(b"Hello, BSV!", true).unwrap();
        let pubkey = key.to_public_key();

        let msg_hash = sha256(b"Hello, BSV!");
        assert!(
            ecdsa_verify(&msg_hash, &sig, pubkey.point()),
            "Signature should verify"
        );
    }

    #[test]
    fn test_private_key_sign_low_s() {
        let curve = Curve::secp256k1();
        let key = PrivateKey::from_hex("ff").unwrap();
        let sig = key.sign(b"test low s", true).unwrap();
        assert!(
            sig.s().cmp(&curve.half_n) <= 0,
            "s should be low when force_low_s is true"
        );
    }

    // -----------------------------------------------------------------------
    // PrivateKey: to_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_to_bytes() {
        let key = PrivateKey::from_hex("1").unwrap();
        let bytes = key.to_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[0], 0);
    }
}
