//! Public key type derived from a secp256k1 private key.
//!
//! PublicKey wraps a Point on the secp256k1 curve and provides
//! DER encoding/decoding, address derivation, and signature
//! verification. Mirrors the TS SDK PublicKey.ts API.

use crate::primitives::base_point::BasePoint;
use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::ecdsa::ecdsa_verify;
use crate::primitives::error::PrimitivesError;
use crate::primitives::hash::{hash160, sha256, sha256_hmac};
use crate::primitives::point::Point;
use crate::primitives::private_key::PrivateKey;
use crate::primitives::signature::Signature;
use crate::primitives::utils::{base58_check_encode, from_hex, to_hex};

/// A secp256k1 public key (a point on the curve).
///
/// Uses composition with Point, following Rust conventions.
/// The TS SDK uses class inheritance (PublicKey extends Point);
/// we mirror the public API names.
#[derive(Clone, Debug)]
pub struct PublicKey {
    point: Point,
}

impl PublicKey {
    /// Create a PublicKey from a Point.
    pub fn from_point(point: Point) -> Self {
        PublicKey { point }
    }

    /// Derive a public key from a private key.
    pub fn from_private_key(key: &crate::primitives::private_key::PrivateKey) -> Self {
        key.to_public_key()
    }

    /// Parse a public key from a hex string (compressed or uncompressed DER).
    ///
    /// Compressed: 33 bytes (66 hex chars), starts with 02 or 03
    /// Uncompressed: 65 bytes (130 hex chars), starts with 04
    pub fn from_string(s: &str) -> Result<Self, PrimitivesError> {
        let bytes = from_hex(s)?;
        Self::from_der_bytes(&bytes)
    }

    /// Parse a public key from DER-encoded bytes.
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, PrimitivesError> {
        if bytes.is_empty() {
            return Err(PrimitivesError::InvalidPublicKey(
                "empty public key data".to_string(),
            ));
        }

        match bytes[0] {
            0x02 | 0x03 => {
                // Compressed: prefix(1) + x(32) = 33 bytes
                if bytes.len() != 33 {
                    return Err(PrimitivesError::InvalidPublicKey(format!(
                        "compressed key should be 33 bytes, got {}",
                        bytes.len()
                    )));
                }
                let odd = bytes[0] == 0x03;
                let x = BigNumber::from_bytes(&bytes[1..], Endian::Big);
                let point = Point::from_x(&x, odd)?;
                Ok(PublicKey { point })
            }
            0x04 => {
                // Uncompressed: prefix(1) + x(32) + y(32) = 65 bytes
                if bytes.len() != 65 {
                    return Err(PrimitivesError::InvalidPublicKey(format!(
                        "uncompressed key should be 65 bytes, got {}",
                        bytes.len()
                    )));
                }
                let x = BigNumber::from_bytes(&bytes[1..33], Endian::Big);
                let y = BigNumber::from_bytes(&bytes[33..], Endian::Big);
                let point = Point::new(x, y);

                if !point.validate() {
                    return Err(PrimitivesError::InvalidPublicKey(
                        "point not on curve".to_string(),
                    ));
                }

                Ok(PublicKey { point })
            }
            prefix => Err(PrimitivesError::InvalidPublicKey(format!(
                "unknown prefix byte: 0x{:02x}",
                prefix
            ))),
        }
    }

    /// Encode the public key in compressed DER format (33 bytes).
    ///
    /// Format: prefix(1) || x(32)
    /// prefix = 0x02 if y is even, 0x03 if y is odd
    pub fn to_der(&self) -> Vec<u8> {
        self.point.to_der(true)
    }

    /// Encode the public key in compressed DER format as a hex string.
    pub fn to_der_hex(&self) -> String {
        to_hex(&self.to_der())
    }

    /// Encode the public key in uncompressed DER format (65 bytes).
    ///
    /// Format: 0x04 || x(32) || y(32)
    pub fn to_der_uncompressed(&self) -> Vec<u8> {
        self.point.to_der(false)
    }

    /// Hash the compressed public key with hash160 (RIPEMD-160(SHA-256)).
    ///
    /// Returns 20 bytes -- the public key hash used in P2PKH addresses.
    pub fn to_hash(&self) -> Vec<u8> {
        let der = self.to_der();
        hash160(&der).to_vec()
    }

    /// Derive a P2PKH Bitcoin address from this public key.
    ///
    /// Format: Base58Check(prefix || hash160(compressed_der))
    /// Default prefix `[0x00]` for mainnet.
    pub fn to_address(&self, prefix: &[u8]) -> String {
        let pkh = self.to_hash();
        base58_check_encode(&pkh, prefix)
    }

    /// Verify a message signature using this public key.
    ///
    /// The message is hashed with SHA-256 before verification.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let msg_hash = sha256(message);
        ecdsa_verify(&msg_hash, signature, &self.point)
    }

    /// Compute ECDH shared secret: private_key.bn * self.point.
    ///
    /// Returns the resulting point on the curve.
    pub fn derive_shared_secret(&self, private_key: &PrivateKey) -> Result<Point, PrimitivesError> {
        private_key.derive_shared_secret(self)
    }

    /// Derive a child public key using Type-42 key derivation (BRC-42).
    ///
    /// Computes: child_point = self.point + G * HMAC-SHA256(shared_secret_compressed, invoice_number)
    /// where shared_secret = private_key * self.
    pub fn derive_child(
        &self,
        private_key: &PrivateKey,
        invoice_number: &str,
    ) -> Result<PublicKey, PrimitivesError> {
        let shared_secret = private_key.derive_shared_secret(self)?;
        self.derive_child_with_secret(&shared_secret, invoice_number)
    }

    /// Derive a child public key from a *precomputed* ECDH shared secret.
    ///
    /// The per-counterparty ECDH point-multiply (`private_key * self`) is the
    /// caller's responsibility and is passed in as `shared_secret`; it does NOT
    /// depend on `invoice_number`, so it can be cached and reused across
    /// messages. Note this method still performs ONE per-message point-multiply
    /// (`hmac * G`) and a point-add, which are NOT cacheable because the HMAC
    /// embeds the per-message nonce via `invoice_number`. Output is
    /// bit-identical to [`derive_child`] for the same inputs.
    pub fn derive_child_with_secret(
        &self,
        shared_secret: &Point,
        invoice_number: &str,
    ) -> Result<PublicKey, PrimitivesError> {
        let shared_secret_bytes = shared_secret.to_der(true); // 33-byte compressed
        let hmac_result = sha256_hmac(&shared_secret_bytes, invoice_number.as_bytes());
        let hmac_bn = BigNumber::from_bytes(&hmac_result, Endian::Big);
        let base_point = BasePoint::instance();
        let offset_point = base_point.mul(&hmac_bn);
        let child_point = self.point.add(&offset_point);

        Ok(PublicKey::from_point(child_point))
    }

    /// Access the underlying Point.
    pub fn point(&self) -> &Point {
        &self.point
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.point.eq(&other.point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::private_key::PrivateKey;

    // -----------------------------------------------------------------------
    // PublicKey: from_private_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_from_private_key() {
        let priv_key = PrivateKey::from_hex("1").unwrap();
        let pub_key = PublicKey::from_private_key(&priv_key);

        // G point compressed
        assert_eq!(
            pub_key.to_der_hex(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    // -----------------------------------------------------------------------
    // PublicKey: from_string (compressed and uncompressed)
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_from_string_compressed() {
        let hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pub_key = PublicKey::from_string(hex).unwrap();
        assert_eq!(pub_key.to_der_hex(), hex);
    }

    #[test]
    fn test_public_key_from_string_uncompressed() {
        let hex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let pub_key = PublicKey::from_string(hex).unwrap();
        // Should produce the same compressed key
        assert_eq!(
            pub_key.to_der_hex(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    // -----------------------------------------------------------------------
    // PublicKey: DER compression roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_der_roundtrip() {
        let priv_key = PrivateKey::from_hex("ff").unwrap();
        let pub_key = PublicKey::from_private_key(&priv_key);

        let der_hex = pub_key.to_der_hex();
        let recovered = PublicKey::from_string(&der_hex).unwrap();
        assert_eq!(pub_key, recovered, "DER compression roundtrip should work");
    }

    // -----------------------------------------------------------------------
    // PublicKey: to_hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_to_hash() {
        let priv_key = PrivateKey::from_hex("1").unwrap();
        let pub_key = PublicKey::from_private_key(&priv_key);
        let hash = pub_key.to_hash();
        assert_eq!(hash.len(), 20, "hash160 should be 20 bytes");
    }

    // -----------------------------------------------------------------------
    // PublicKey: to_address
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_to_address_mainnet() {
        // Key = 1 -> G -> known address
        let priv_key = PrivateKey::from_hex("1").unwrap();
        let pub_key = PublicKey::from_private_key(&priv_key);
        let address = pub_key.to_address(&[0x00]);
        assert_eq!(address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    // -----------------------------------------------------------------------
    // PublicKey: verify
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_verify() {
        let priv_key = PrivateKey::from_hex("1").unwrap();
        let pub_key = PublicKey::from_private_key(&priv_key);
        let sig = priv_key.sign(b"test verify", true).unwrap();

        assert!(
            pub_key.verify(b"test verify", &sig),
            "Should verify valid signature"
        );
        assert!(
            !pub_key.verify(b"wrong message", &sig),
            "Should reject wrong message"
        );
    }

    // -----------------------------------------------------------------------
    // PublicKey: uncompressed encoding
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_uncompressed() {
        let priv_key = PrivateKey::from_hex("1").unwrap();
        let pub_key = PublicKey::from_private_key(&priv_key);
        let uncompressed = pub_key.to_der_uncompressed();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);
    }

    // -----------------------------------------------------------------------
    // PublicKey: test vectors from JSON
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_der_vectors() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct DerVector {
            private_key_hex: String,
            public_key_compressed: String,
            public_key_uncompressed: String,
            address_mainnet: String,
            #[allow(dead_code)]
            address_prefix: String,
            #[allow(dead_code)]
            description: String,
        }

        let data = include_str!("../../test-vectors/public_key_der.json");
        let vectors: Vec<DerVector> = serde_json::from_str(data).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let priv_key = PrivateKey::from_hex(&v.private_key_hex).unwrap();
            let pub_key = PublicKey::from_private_key(&priv_key);

            // Compressed DER
            assert_eq!(
                pub_key.to_der_hex(),
                v.public_key_compressed,
                "Vector {}: compressed mismatch",
                i
            );

            // Uncompressed DER
            let uncompressed_hex = to_hex(&pub_key.to_der_uncompressed());
            assert_eq!(
                uncompressed_hex, v.public_key_uncompressed,
                "Vector {}: uncompressed mismatch",
                i
            );

            // Address
            let address = pub_key.to_address(&[0x00]);
            assert_eq!(address, v.address_mainnet, "Vector {}: address mismatch", i);
        }
    }

    // -----------------------------------------------------------------------
    // PublicKey: sign then verify roundtrip with multiple keys
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_verify_roundtrip_multiple_keys() {
        for i in 1..=5 {
            let priv_key = PrivateKey::from_hex(&format!("{:064x}", i * 1000)).unwrap();
            let pub_key = PublicKey::from_private_key(&priv_key);
            let msg = format!("Message number {}", i);

            let sig = priv_key.sign(msg.as_bytes(), true).unwrap();
            assert!(
                pub_key.verify(msg.as_bytes(), &sig),
                "Key {} should verify",
                i
            );
        }
    }
}
