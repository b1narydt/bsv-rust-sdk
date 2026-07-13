//! BIP32 Hierarchical Deterministic (HD) key derivation.
//!
//! Implements the BIP32 specification for generating a tree of keypairs
//! from a single seed. Supports extended private and public keys (xprv/xpub),
//! hardened and normal child derivation, and Base58Check serialization.

use crate::compat::error::CompatError;
use crate::primitives::base_point::BasePoint;
use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::curve::Curve;
use crate::primitives::hash::hash256;
use crate::primitives::hash::{hash160, sha512_hmac};
use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;
use crate::primitives::utils::{base58_decode, base58_encode};

/// Version bytes for mainnet extended private key (xprv).
const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];

/// Version bytes for mainnet extended public key (xpub).
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];

/// Offset added to child index for hardened derivation.
const HARDENED_OFFSET: u32 = 0x80000000;

/// A BIP32 extended key (private or public) with chain code and derivation metadata.
///
/// Supports key derivation, serialization to/from Base58Check xprv/xpub strings,
/// and conversion between private and public extended keys.
#[derive(Clone, Debug)]
pub struct ExtendedKey {
    /// Private key bytes (32) or compressed public key bytes (33).
    key: Vec<u8>,
    /// 32-byte chain code for child derivation.
    chain_code: Vec<u8>,
    /// Derivation depth (0 = master).
    depth: u8,
    /// First 4 bytes of parent key's hash160 (0x00000000 for master).
    parent_fingerprint: [u8; 4],
    /// Child index that produced this key (0 for master).
    child_index: u32,
    /// Version bytes (XPRV_VERSION or XPUB_VERSION).
    version: [u8; 4],
    /// Whether this is a private extended key.
    is_private: bool,
}

impl ExtendedKey {
    /// Derive a master extended key from a seed.
    ///
    /// Uses HMAC-SHA512 with key "Bitcoin seed" per BIP32 specification.
    /// Seed must be between 16 and 64 bytes (128-512 bits).
    pub fn from_seed(seed: &[u8]) -> Result<Self, CompatError> {
        if seed.len() < 16 {
            return Err(CompatError::InvalidEntropy(
                "seed must be at least 128 bits".to_string(),
            ));
        }
        if seed.len() > 64 {
            return Err(CompatError::InvalidEntropy(
                "seed must be at most 512 bits".to_string(),
            ));
        }

        let hmac = sha512_hmac(b"Bitcoin seed", seed);
        let secret_key = &hmac[0..32];
        let chain_code = &hmac[32..64];

        // Validate secret key is in valid range [1, n-1]
        let key_num = BigNumber::from_bytes(secret_key, Endian::Big);
        let curve = Curve::secp256k1();
        if key_num.cmp(&curve.n) >= 0 || key_num.is_zero() {
            return Err(CompatError::UnusableSeed);
        }

        Ok(ExtendedKey {
            key: secret_key.to_vec(),
            chain_code: chain_code.to_vec(),
            depth: 0,
            parent_fingerprint: [0, 0, 0, 0],
            child_index: 0,
            version: XPRV_VERSION,
            is_private: true,
        })
    }

    /// Derive a child extended key by path string.
    ///
    /// Path format: "m/0'/1/2'" where apostrophe or "h" suffix means hardened.
    /// Leading "m/" or "m" prefix is stripped.
    pub fn derive(&self, path: &str) -> Result<Self, CompatError> {
        let path = path.trim();

        // Strip leading "m" or "m/"
        let components = if path == "m" || path == "M" {
            return Ok(self.clone());
        } else if let Some(rest) = path.strip_prefix("m/").or_else(|| path.strip_prefix("M/")) {
            rest
        } else {
            path
        };

        let mut current = self.clone();
        for component in components.split('/') {
            let component = component.trim();
            if component.is_empty() {
                continue;
            }

            let (index_str, hardened) = if let Some(s) = component.strip_suffix('\'') {
                (s, true)
            } else if let Some(s) = component.strip_suffix('h') {
                (s, true)
            } else {
                (component, false)
            };

            let index: u32 = index_str
                .parse()
                .map_err(|_| CompatError::InvalidPath(format!("invalid index: {index_str}")))?;

            let child_index = if hardened {
                index
                    .checked_add(HARDENED_OFFSET)
                    .ok_or_else(|| CompatError::InvalidPath("index overflow".to_string()))?
            } else {
                index
            };

            current = current.derive_child(child_index)?;
        }

        Ok(current)
    }

    /// Derive a single child key by index.
    ///
    /// Index >= 0x80000000 is hardened derivation (requires private key).
    /// Index < 0x80000000 is normal derivation (works with public key).
    pub fn derive_child(&self, index: u32) -> Result<Self, CompatError> {
        if self.depth == 255 {
            return Err(CompatError::DepthExceeded);
        }

        let is_hardened = index >= HARDENED_OFFSET;
        if is_hardened && !self.is_private {
            return Err(CompatError::HardenedFromPublic);
        }

        // Build HMAC data
        let mut data = Vec::with_capacity(37);
        if is_hardened {
            // Hardened: 0x00 || private_key(32) || index(4)
            data.push(0x00);
            let padded_key = self.padded_key_bytes(32);
            data.extend_from_slice(&padded_key);
        } else {
            // Normal: compressed_pubkey(33) || index(4)
            let pubkey_bytes = self.compressed_pubkey_bytes()?;
            data.extend_from_slice(&pubkey_bytes);
        }
        data.extend_from_slice(&index.to_be_bytes());

        let hmac = sha512_hmac(&self.chain_code, &data);
        let il = &hmac[0..32];
        let ir = &hmac[32..64];

        let curve = Curve::secp256k1();
        let il_num = BigNumber::from_bytes(il, Endian::Big);

        // Validate IL < n
        if il_num.cmp(&curve.n) >= 0 {
            return Err(CompatError::InvalidChild);
        }

        // Compute parent fingerprint
        let parent_pubkey = self.compressed_pubkey_bytes()?;
        let parent_hash = hash160(&parent_pubkey);
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&parent_hash[..4]);

        if self.is_private {
            // Private child: key = (IL + parent_key) mod n
            let parent_num = BigNumber::from_bytes(&self.key, Endian::Big);
            let child_num = il_num.add(&parent_num).umod(&curve.n).map_err(|e| {
                CompatError::Primitives(crate::primitives::error::PrimitivesError::ArithmeticError(
                    e.to_string(),
                ))
            })?;

            if child_num.is_zero() {
                return Err(CompatError::InvalidChild);
            }

            let child_key = child_num.to_array(Endian::Big, Some(32));

            Ok(ExtendedKey {
                key: child_key,
                chain_code: ir.to_vec(),
                depth: self.depth + 1,
                parent_fingerprint: fingerprint,
                child_index: index,
                version: XPRV_VERSION,
                is_private: true,
            })
        } else {
            // Public child: key = point(IL) + parent_pubkey
            let il_point = BasePoint::instance().mul(&il_num);
            let parent_point = PublicKey::from_der_bytes(&parent_pubkey)?;
            let child_point = il_point.add(parent_point.point());

            if child_point.is_infinity() {
                return Err(CompatError::InvalidChild);
            }

            let child_pubkey = child_point.to_der(true);

            Ok(ExtendedKey {
                key: child_pubkey,
                chain_code: ir.to_vec(),
                depth: self.depth + 1,
                parent_fingerprint: fingerprint,
                child_index: index,
                version: XPUB_VERSION,
                is_private: false,
            })
        }
    }

    /// Convert a private extended key to its public counterpart.
    ///
    /// Returns a new ExtendedKey with the public key and xpub version bytes.
    pub fn to_public(&self) -> Result<Self, CompatError> {
        if !self.is_private {
            return Ok(self.clone());
        }

        let pubkey_bytes = self.compressed_pubkey_bytes()?;

        Ok(ExtendedKey {
            key: pubkey_bytes,
            chain_code: self.chain_code.clone(),
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_index: self.child_index,
            version: XPUB_VERSION,
            is_private: false,
        })
    }

    /// Serialize to a Base58Check string (xprv or xpub).
    ///
    /// 78-byte payload: version(4) || depth(1) || fingerprint(4) ||
    /// child_index(4) || chain_code(32) || key(33, with 0x00 prefix for private).
    pub fn to_base58(&self) -> String {
        let mut payload = Vec::with_capacity(78);
        payload.extend_from_slice(&self.version);
        payload.push(self.depth);
        payload.extend_from_slice(&self.parent_fingerprint);
        payload.extend_from_slice(&self.child_index.to_be_bytes());
        payload.extend_from_slice(&self.chain_code);

        if self.is_private {
            payload.push(0x00);
            let padded = self.padded_key_bytes(32);
            payload.extend_from_slice(&padded);
        } else {
            payload.extend_from_slice(&self.key);
        }

        assert_eq!(payload.len(), 78, "BIP32 payload must be exactly 78 bytes");

        // Manual checksum using hash256 (matches Go SDK pattern and works
        // correctly with the 4-byte version prefix).
        let checksum = hash256(&payload);
        payload.extend_from_slice(&checksum[..4]);

        base58_encode(&payload)
    }

    /// Parse an extended key from a Base58Check string (xprv or xpub).
    pub fn from_string(s: &str) -> Result<Self, CompatError> {
        let decoded = base58_decode(s)
            .map_err(|e| CompatError::InvalidExtendedKey(format!("base58 decode: {e}")))?;

        if decoded.len() != 82 {
            return Err(CompatError::InvalidExtendedKey(format!(
                "expected 82 bytes, got {}",
                decoded.len()
            )));
        }

        // Verify checksum
        let payload = &decoded[..78];
        let checksum = &decoded[78..82];
        let expected_checksum = hash256(payload);
        if checksum != &expected_checksum[..4] {
            return Err(CompatError::ChecksumMismatch);
        }

        let mut version = [0u8; 4];
        version.copy_from_slice(&payload[0..4]);

        let is_private = if version == XPRV_VERSION {
            true
        } else if version == XPUB_VERSION {
            false
        } else {
            return Err(CompatError::InvalidMagic);
        };

        let depth = payload[4];
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&payload[5..9]);
        let child_index = u32::from_be_bytes([payload[9], payload[10], payload[11], payload[12]]);
        let chain_code = payload[13..45].to_vec();

        let key = if is_private {
            // Private key: 0x00 prefix + 32 bytes
            if payload[45] != 0x00 {
                return Err(CompatError::InvalidExtendedKey(
                    "private key must start with 0x00".to_string(),
                ));
            }
            payload[46..78].to_vec()
        } else {
            // Public key: 33 bytes (compressed)
            payload[45..78].to_vec()
        };

        Ok(ExtendedKey {
            key,
            chain_code,
            depth,
            parent_fingerprint,
            child_index,
            version,
            is_private,
        })
    }

    /// Get the public key for this extended key.
    ///
    /// If private, derives the public key. If public, parses the stored key.
    pub fn public_key(&self) -> Result<PublicKey, CompatError> {
        if self.is_private {
            let priv_key = PrivateKey::from_bytes(&self.key)?;
            Ok(priv_key.to_public_key())
        } else {
            Ok(PublicKey::from_der_bytes(&self.key)?)
        }
    }

    /// Whether this is a private extended key.
    pub fn is_private(&self) -> bool {
        self.is_private
    }

    /// Get the derivation depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Get the compressed public key bytes (33 bytes) for this key.
    fn compressed_pubkey_bytes(&self) -> Result<Vec<u8>, CompatError> {
        if self.is_private {
            let priv_key = PrivateKey::from_bytes(&self.key)?;
            Ok(priv_key.to_public_key().to_der())
        } else {
            Ok(self.key.clone())
        }
    }

    /// Get the key bytes padded to the specified length.
    fn padded_key_bytes(&self, len: usize) -> Vec<u8> {
        if self.key.len() >= len {
            self.key[self.key.len() - len..].to_vec()
        } else {
            let mut padded = vec![0u8; len - self.key.len()];
            padded.extend_from_slice(&self.key);
            padded
        }
    }
}

impl std::fmt::Display for ExtendedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[derive(Deserialize)]
    struct ChainVector {
        path: String,
        xprv: String,
        xpub: String,
    }

    #[derive(Deserialize)]
    struct SeedVector {
        seed: String,
        chains: Vec<ChainVector>,
    }

    #[derive(Deserialize)]
    struct Bip32Vectors {
        vectors: Vec<SeedVector>,
    }

    fn load_vectors() -> Bip32Vectors {
        let data = include_str!("../../test-vectors/bip32_vectors.json");
        serde_json::from_str(data).unwrap()
    }

    // Test 1: from_seed with vector 1 produces correct master xprv and xpub
    #[test]
    fn test_vector1_master_key() {
        let vectors = load_vectors();
        let v = &vectors.vectors[0];
        let seed = hex_to_bytes(&v.seed);
        let master = ExtendedKey::from_seed(&seed).unwrap();

        assert_eq!(master.to_string(), v.chains[0].xprv);
        assert_eq!(master.to_public().unwrap().to_string(), v.chains[0].xpub);
    }

    // Test 2: from_seed with vector 2 produces correct master key
    #[test]
    fn test_vector2_master_key() {
        let vectors = load_vectors();
        let v = &vectors.vectors[1];
        let seed = hex_to_bytes(&v.seed);
        let master = ExtendedKey::from_seed(&seed).unwrap();

        assert_eq!(master.to_string(), v.chains[0].xprv);
        assert_eq!(master.to_public().unwrap().to_string(), v.chains[0].xpub);
    }

    // Test 3: derive("m/0'") from master produces correct hardened child
    #[test]
    fn test_vector1_hardened_child() {
        let vectors = load_vectors();
        let v = &vectors.vectors[0];
        let seed = hex_to_bytes(&v.seed);
        let master = ExtendedKey::from_seed(&seed).unwrap();

        let child = master.derive("m/0'").unwrap();
        assert_eq!(child.to_string(), v.chains[1].xprv);
        assert_eq!(child.to_public().unwrap().to_string(), v.chains[1].xpub);
    }

    // Test 4: Full derivation path produces correct keys at each level
    #[test]
    fn test_vector1_full_derivation() {
        let vectors = load_vectors();
        let v = &vectors.vectors[0];
        let seed = hex_to_bytes(&v.seed);
        let master = ExtendedKey::from_seed(&seed).unwrap();

        for chain in &v.chains {
            let derived = master.derive(&chain.path).unwrap();
            assert_eq!(
                derived.to_string(),
                chain.xprv,
                "xprv mismatch for path {}",
                chain.path
            );
            assert_eq!(
                derived.to_public().unwrap().to_string(),
                chain.xpub,
                "xpub mismatch for path {}",
                chain.path
            );
        }
    }

    // Test 4b: Full derivation of vector 2
    #[test]
    fn test_vector2_full_derivation() {
        let vectors = load_vectors();
        let v = &vectors.vectors[1];
        let seed = hex_to_bytes(&v.seed);
        let master = ExtendedKey::from_seed(&seed).unwrap();

        for chain in &v.chains {
            let derived = master.derive(&chain.path).unwrap();
            assert_eq!(
                derived.to_string(),
                chain.xprv,
                "xprv mismatch for path {}",
                chain.path
            );
            assert_eq!(
                derived.to_public().unwrap().to_string(),
                chain.xpub,
                "xpub mismatch for path {}",
                chain.path
            );
        }
    }

    // Test 5: to_public() produces correct xpub serialization
    #[test]
    fn test_to_public() {
        let vectors = load_vectors();
        let v = &vectors.vectors[0];
        let seed = hex_to_bytes(&v.seed);
        let master = ExtendedKey::from_seed(&seed).unwrap();

        let public = master.to_public().unwrap();
        assert!(!public.is_private());
        assert_eq!(public.to_string(), v.chains[0].xpub);
    }

    // Test 6: from_string() round-trips
    #[test]
    fn test_from_string_round_trip() {
        let vectors = load_vectors();
        let v = &vectors.vectors[0];

        // Test xprv round-trip
        let parsed_priv = ExtendedKey::from_string(&v.chains[0].xprv).unwrap();
        assert_eq!(parsed_priv.to_string(), v.chains[0].xprv);

        // Test xpub round-trip
        let parsed_pub = ExtendedKey::from_string(&v.chains[0].xpub).unwrap();
        assert_eq!(parsed_pub.to_string(), v.chains[0].xpub);
    }

    // Test 7: derive from public xpub for normal children
    #[test]
    fn test_public_derivation() {
        let vectors = load_vectors();
        let v = &vectors.vectors[0];
        let seed = hex_to_bytes(&v.seed);
        let master = ExtendedKey::from_seed(&seed).unwrap();

        // Derive m/0' privately, then get the public key
        let child_priv = master.derive("m/0'").unwrap();
        let child_pub = child_priv.to_public().unwrap();

        // From public key, derive normal child m/0'/1
        let grandchild_pub = child_pub.derive("m/1").unwrap();

        // Should match the public key derived from m/0'/1 privately
        assert_eq!(
            grandchild_pub.to_string(),
            v.chains[2].xpub,
            "public derivation of normal child should match"
        );
    }

    // Test 8: derive hardened child from public key returns error
    #[test]
    fn test_hardened_from_public_error() {
        let vectors = load_vectors();
        let v = &vectors.vectors[0];
        let seed = hex_to_bytes(&v.seed);
        let master = ExtendedKey::from_seed(&seed).unwrap();
        let public = master.to_public().unwrap();

        let result = public.derive("m/0'");
        assert!(result.is_err(), "hardened from public should fail");
        match result.unwrap_err() {
            CompatError::HardenedFromPublic => {}
            e => panic!("expected HardenedFromPublic, got {e:?}"),
        }
    }

    // Test 9: depth exceeding 255 returns error
    #[test]
    fn test_depth_exceeded() {
        let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedKey::from_seed(&seed).unwrap();

        // Create a key at depth 255 by manipulating internals
        let deep_key = ExtendedKey {
            key: master.key.clone(),
            chain_code: master.chain_code.clone(),
            depth: 255,
            parent_fingerprint: [0; 4],
            child_index: 0,
            version: XPRV_VERSION,
            is_private: true,
        };

        let result = deep_key.derive_child(0);
        assert!(result.is_err(), "depth 255 derivation should fail");
        match result.unwrap_err() {
            CompatError::DepthExceeded => {}
            e => panic!("expected DepthExceeded, got {e:?}"),
        }
    }

    // Test: from_string/to_string round-trip for all vector keys
    #[test]
    fn test_all_vectors_from_string_round_trip() {
        let vectors = load_vectors();
        for v in &vectors.vectors {
            for chain in &v.chains {
                let priv_key = ExtendedKey::from_string(&chain.xprv).unwrap();
                assert_eq!(
                    priv_key.to_string(),
                    chain.xprv,
                    "xprv round-trip failed for {}",
                    chain.path
                );

                let pub_key = ExtendedKey::from_string(&chain.xpub).unwrap();
                assert_eq!(
                    pub_key.to_string(),
                    chain.xpub,
                    "xpub round-trip failed for {}",
                    chain.path
                );
            }
        }
    }

    // Test: public derivation for vector 1 m/0'/1/2'/2 -> m/0'/1/2'/2/1000000000
    #[test]
    fn test_public_derivation_deep() {
        let vectors = load_vectors();
        let v = &vectors.vectors[0];
        let seed = hex_to_bytes(&v.seed);
        let master = ExtendedKey::from_seed(&seed).unwrap();

        // Derive m/0'/1/2'/2 privately, then get public
        let child_priv = master.derive("m/0'/1/2'/2").unwrap();
        let child_pub = child_priv.to_public().unwrap();

        // From public, derive normal child 1000000000
        let grandchild_pub = child_pub.derive("m/1000000000").unwrap();
        assert_eq!(
            grandchild_pub.to_string(),
            v.chains[5].xpub,
            "public derivation of deep normal child should match"
        );
    }
}
