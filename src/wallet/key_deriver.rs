//! KeyDeriver: Type-42 key derivation for the wallet module.
//!
//! Implements BRC-42 key derivation using a root private key,
//! supporting derivation of private keys, public keys, symmetric keys,
//! and key linkage revelation.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::primitives::hash::sha256_hmac;
use crate::primitives::point::Point;
use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;
use crate::primitives::symmetric_key::SymmetricKey;
use crate::wallet::error::WalletError;
use crate::wallet::types::{anyone_pubkey, Counterparty, CounterpartyType, Protocol};

/// Upper bound on the number of distinct counterparty shared secrets cached.
///
/// Each entry is a single secp256k1 point (~64 bytes of coordinate data plus
/// map overhead), keyed by the counterparty's compressed-DER hex (66 chars).
/// A long-lived relay talking to many peers could otherwise grow this
/// unbounded; when the bound is hit the cache is cleared wholesale (the same
/// coarse eviction strategy `CachedKeyDeriver` uses). 4096 distinct
/// counterparties is generous for a single session/process while keeping the
/// footprint trivially small.
const MAX_SHARED_SECRET_CACHE_SIZE: usize = 4096;

/// KeyDeriver derives various types of keys using a root private key.
///
/// Supports deriving public and private keys, symmetric keys, and
/// revealing key linkages, all using BRC-42 Type-42 derivation.
///
/// ## Per-counterparty shared-secret cache
///
/// Type-42 derivation factors into an expensive ECDH point-multiply
/// (`root_key * counterparty_pubkey`) that depends ONLY on the counterparty,
/// plus cheap per-message HMAC/scalar steps keyed by the invoice number (which
/// embeds the per-message auth nonce). The ECDH result — the *shared secret* —
/// is therefore identical for every message to the same counterparty, so it is
/// memoized here keyed by the counterparty's compressed-DER hex. The cache is a
/// pure compute optimization: every derived key, signature, and HMAC is
/// bit-identical to the uncached path because the per-message invoice number
/// still flows through `derive_child_with_secret` on every call. The cache is
/// guarded by an `RwLock` so derive methods take `&self` and the deriver is
/// `Send + Sync`, safe to share via `Arc` under concurrent access.
pub struct KeyDeriver {
    root_key: PrivateKey,
    /// Cache of `root_key * counterparty_pubkey` ECDH points, keyed by the
    /// counterparty public key's compressed-DER hex.
    shared_secret_cache: RwLock<HashMap<String, Point>>,
}

impl KeyDeriver {
    /// Create a new KeyDeriver from a root private key.
    pub fn new(private_key: PrivateKey) -> Self {
        KeyDeriver {
            root_key: private_key,
            shared_secret_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Create a KeyDeriver using the special "anyone" key (PrivateKey(1)).
    pub fn new_anyone() -> Self {
        KeyDeriver {
            root_key: crate::wallet::types::anyone_private_key(),
            shared_secret_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Compute the ECDH shared secret `root_key * counterparty_pubkey`, using
    /// the per-counterparty cache. The shared secret does not depend on the
    /// protocol, key ID, or invoice number, so it is safe to memoize per
    /// counterparty and reuse across every message.
    fn cached_shared_secret(
        &self,
        counterparty_pubkey: &PublicKey,
    ) -> Result<Point, WalletError> {
        let cache_key = counterparty_pubkey.to_der_hex();

        // Fast path: read lock, return a clone if present.
        {
            let cache = self.shared_secret_cache.read().unwrap();
            if let Some(secret) = cache.get(&cache_key) {
                return Ok(secret.clone());
            }
        }

        // Slow path: compute the ECDH point-multiply, then insert.
        let secret = self.root_key.derive_shared_secret(counterparty_pubkey)?;

        let mut cache = self.shared_secret_cache.write().unwrap();
        // Coarse eviction: if at capacity, clear all and start fresh. Bounds
        // growth for long-lived relays with many distinct peers.
        if cache.len() >= MAX_SHARED_SECRET_CACHE_SIZE && !cache.contains_key(&cache_key) {
            cache.clear();
        }
        cache.insert(cache_key, secret.clone());
        Ok(secret)
    }

    /// Returns the number of cached counterparty shared secrets (test-only).
    #[cfg(test)]
    fn shared_secret_cache_len(&self) -> usize {
        self.shared_secret_cache.read().unwrap().len()
    }

    /// Returns a reference to the root private key.
    pub fn root_key(&self) -> &PrivateKey {
        &self.root_key
    }

    /// Returns the public key corresponding to the root private key.
    pub fn identity_key(&self) -> PublicKey {
        self.root_key.to_public_key()
    }

    /// Returns the identity key as a compressed DER hex string.
    pub fn identity_key_hex(&self) -> String {
        self.identity_key().to_der_hex()
    }

    /// Derive a private key for the given protocol, key ID, and counterparty.
    pub fn derive_private_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey, WalletError> {
        let counterparty_pubkey = self.normalize_counterparty(counterparty)?;
        let invoice_number = Self::compute_invoice_number(protocol, key_id)?;
        // The ECDH shared secret (root_key * counterparty) is counterparty-only
        // and cached; the invoice number (per-message nonce) still flows through
        // the HMAC + scalar-add in derive_child_with_secret, so the output is
        // identical to root_key.derive_child(...).
        let shared_secret = self.cached_shared_secret(&counterparty_pubkey)?;
        let child = self
            .root_key
            .derive_child_with_secret(&shared_secret, &invoice_number)?;
        Ok(child)
    }

    /// Derive a public key for the given protocol, key ID, and counterparty.
    ///
    /// If `for_self` is true, derives the private child key first and returns
    /// its public key. If false, derives directly on the counterparty's public key.
    pub fn derive_public_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<PublicKey, WalletError> {
        let counterparty_pubkey = self.normalize_counterparty(counterparty)?;
        let invoice_number = Self::compute_invoice_number(protocol, key_id)?;

        // Both branches' ECDH is root_key * counterparty_pubkey — the same
        // counterparty-only shared secret, so it is computed once and cached.
        let shared_secret = self.cached_shared_secret(&counterparty_pubkey)?;

        if for_self {
            let priv_child = self
                .root_key
                .derive_child_with_secret(&shared_secret, &invoice_number)?;
            Ok(priv_child.to_public_key())
        } else {
            let pub_child =
                counterparty_pubkey.derive_child_with_secret(&shared_secret, &invoice_number)?;
            Ok(pub_child)
        }
    }

    /// Derive a symmetric key from the ECDH shared secret of the derived
    /// private and public keys.
    ///
    /// The symmetric key is the x-coordinate of the shared secret point.
    pub fn derive_symmetric_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<SymmetricKey, WalletError> {
        // If counterparty is Anyone, treat as Other with anyone pubkey
        let effective_counterparty = if counterparty.counterparty_type == CounterpartyType::Anyone {
            Counterparty {
                counterparty_type: CounterpartyType::Other,
                public_key: Some(anyone_pubkey()),
            }
        } else {
            counterparty.clone()
        };

        let derived_pub =
            self.derive_public_key(protocol, key_id, &effective_counterparty, false)?;
        let derived_priv = self.derive_private_key(protocol, key_id, &effective_counterparty)?;

        let shared_secret = derived_priv.derive_shared_secret(&derived_pub)?;
        let x_bytes = shared_secret
            .x
            .to_array(crate::primitives::big_number::Endian::Big, Some(32));
        let sym_key = SymmetricKey::from_bytes(&x_bytes)?;
        Ok(sym_key)
    }

    /// Reveal the counterparty shared secret as a public key point.
    ///
    /// Cannot be used for counterparty type "self".
    pub fn reveal_counterparty_secret(
        &self,
        counterparty: &Counterparty,
    ) -> Result<PublicKey, WalletError> {
        if counterparty.counterparty_type == CounterpartyType::Self_ {
            return Err(WalletError::InvalidParameter(
                "counterparty secrets cannot be revealed for counterparty=self".to_string(),
            ));
        }

        let counterparty_pubkey = self.normalize_counterparty(counterparty)?;

        // Double-check: verify it is not actually self
        let self_pub = self.root_key.to_public_key();
        let key_derived_by_self = self.root_key.derive_child(&self_pub, "test")?;
        let key_derived_by_counterparty =
            self.root_key.derive_child(&counterparty_pubkey, "test")?;

        if key_derived_by_self.to_bytes() == key_derived_by_counterparty.to_bytes() {
            return Err(WalletError::InvalidParameter(
                "counterparty secrets cannot be revealed if counterparty key is self".to_string(),
            ));
        }

        let shared_secret = self.root_key.derive_shared_secret(&counterparty_pubkey)?;
        Ok(PublicKey::from_point(shared_secret))
    }

    /// Reveal a specific secret for the given protocol and key ID.
    ///
    /// Computes HMAC-SHA256 of the shared secret (compressed) and the
    /// invoice number string.
    pub fn reveal_specific_secret(
        &self,
        counterparty: &Counterparty,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<Vec<u8>, WalletError> {
        let counterparty_pubkey = self.normalize_counterparty(counterparty)?;
        let shared_secret = self.root_key.derive_shared_secret(&counterparty_pubkey)?;
        let invoice_number = Self::compute_invoice_number(protocol, key_id)?;
        let shared_secret_compressed = shared_secret.to_der(true);
        let hmac = sha256_hmac(&shared_secret_compressed, invoice_number.as_bytes());
        Ok(hmac.to_vec())
    }

    /// Normalize a Counterparty to a concrete PublicKey.
    fn normalize_counterparty(
        &self,
        counterparty: &Counterparty,
    ) -> Result<PublicKey, WalletError> {
        match counterparty.counterparty_type {
            CounterpartyType::Self_ => Ok(self.root_key.to_public_key()),
            CounterpartyType::Anyone => Ok(anyone_pubkey()),
            CounterpartyType::Other => counterparty.public_key.clone().ok_or_else(|| {
                WalletError::InvalidParameter(
                    "counterparty public key required for type Other".to_string(),
                )
            }),
            CounterpartyType::Uninitialized => Err(WalletError::InvalidParameter(
                "counterparty type is uninitialized".to_string(),
            )),
        }
    }

    /// Compute the invoice number string from protocol and key ID.
    ///
    /// Format: "{security_level}-{protocol_name}-{key_id}"
    /// Validates security level (0-2), protocol name (5-400 chars, lowercase
    /// alphanumeric + spaces, no consecutive spaces, must not end with " protocol"),
    /// and key ID (1-800 chars).
    fn compute_invoice_number(protocol: &Protocol, key_id: &str) -> Result<String, WalletError> {
        // Validate security level
        if protocol.security_level > 2 {
            return Err(WalletError::InvalidParameter(
                "protocol security level must be 0, 1, or 2".to_string(),
            ));
        }

        // Validate key ID
        if key_id.is_empty() {
            return Err(WalletError::InvalidParameter(
                "key IDs must be 1 character or more".to_string(),
            ));
        }
        if key_id.len() > 800 {
            return Err(WalletError::InvalidParameter(
                "key IDs must be 800 characters or less".to_string(),
            ));
        }

        // Validate protocol name
        let protocol_name = protocol.protocol.trim().to_lowercase();
        if protocol_name.len() < 5 {
            return Err(WalletError::InvalidParameter(
                "protocol names must be 5 characters or more".to_string(),
            ));
        }
        if protocol_name.len() > 400 {
            if protocol_name.starts_with("specific linkage revelation ") {
                if protocol_name.len() > 430 {
                    return Err(WalletError::InvalidParameter(
                        "specific linkage revelation protocol names must be 430 characters or less"
                            .to_string(),
                    ));
                }
            } else {
                return Err(WalletError::InvalidParameter(
                    "protocol names must be 400 characters or less".to_string(),
                ));
            }
        }
        if protocol_name.contains("  ") {
            return Err(WalletError::InvalidParameter(
                "protocol names cannot contain multiple consecutive spaces".to_string(),
            ));
        }
        if !protocol_name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == ' ')
        {
            return Err(WalletError::InvalidParameter(
                "protocol names can only contain letters, numbers and spaces".to_string(),
            ));
        }
        if protocol_name.ends_with(" protocol") {
            return Err(WalletError::InvalidParameter(
                "no need to end your protocol name with \" protocol\"".to_string(),
            ));
        }

        Ok(format!(
            "{}-{}-{}",
            protocol.security_level, protocol_name, key_id
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::types::CounterpartyType;

    #[test]
    fn test_identity_key_known_vector() {
        let priv_key = PrivateKey::from_hex("1").unwrap();
        let kd = KeyDeriver::new(priv_key);
        assert_eq!(
            kd.identity_key_hex(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_anyone_deriver() {
        let kd = KeyDeriver::new_anyone();
        // Anyone key is PrivateKey(1) -> G point
        assert_eq!(
            kd.identity_key_hex(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_compute_invoice_number_valid() {
        let protocol = Protocol {
            security_level: 2,
            protocol: "hello world".to_string(),
        };
        let result = KeyDeriver::compute_invoice_number(&protocol, "1");
        assert_eq!(result.unwrap(), "2-hello world-1");
    }

    #[test]
    fn test_compute_invoice_number_security_level_too_high() {
        let protocol = Protocol {
            security_level: 3,
            protocol: "hello world".to_string(),
        };
        let result = KeyDeriver::compute_invoice_number(&protocol, "1");
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_invoice_number_protocol_too_short() {
        let protocol = Protocol {
            security_level: 0,
            protocol: "abcd".to_string(),
        };
        let result = KeyDeriver::compute_invoice_number(&protocol, "1");
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_invoice_number_protocol_too_long() {
        let protocol = Protocol {
            security_level: 0,
            protocol: "a".repeat(401),
        };
        let result = KeyDeriver::compute_invoice_number(&protocol, "1");
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_invoice_number_consecutive_spaces() {
        let protocol = Protocol {
            security_level: 0,
            protocol: "hello  world".to_string(),
        };
        let result = KeyDeriver::compute_invoice_number(&protocol, "1");
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_invoice_number_ends_with_protocol() {
        let protocol = Protocol {
            security_level: 0,
            protocol: "my cool protocol".to_string(),
        };
        let result = KeyDeriver::compute_invoice_number(&protocol, "1");
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_invoice_number_invalid_chars() {
        let protocol = Protocol {
            security_level: 0,
            protocol: "Hello World".to_string(), // uppercase
        };
        // After lowercasing, "hello world" is valid
        let result = KeyDeriver::compute_invoice_number(&protocol, "1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_invoice_number_special_chars_rejected() {
        let protocol = Protocol {
            security_level: 0,
            protocol: "hello-world".to_string(),
        };
        let result = KeyDeriver::compute_invoice_number(&protocol, "1");
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_invoice_number_key_id_empty() {
        let protocol = Protocol {
            security_level: 0,
            protocol: "hello world".to_string(),
        };
        let result = KeyDeriver::compute_invoice_number(&protocol, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_invoice_number_key_id_too_long() {
        let protocol = Protocol {
            security_level: 0,
            protocol: "hello world".to_string(),
        };
        let result = KeyDeriver::compute_invoice_number(&protocol, &"x".repeat(801));
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_counterparty_self() {
        let priv_key = PrivateKey::from_hex("ff").unwrap();
        let kd = KeyDeriver::new(priv_key.clone());
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        };
        let result = kd.normalize_counterparty(&counterparty).unwrap();
        assert_eq!(result.to_der_hex(), priv_key.to_public_key().to_der_hex());
    }

    #[test]
    fn test_normalize_counterparty_anyone() {
        let priv_key = PrivateKey::from_hex("ff").unwrap();
        let kd = KeyDeriver::new(priv_key);
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Anyone,
            public_key: None,
        };
        let result = kd.normalize_counterparty(&counterparty).unwrap();
        // Anyone = PrivateKey(1).to_public_key() = G point
        assert_eq!(
            result.to_der_hex(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_normalize_counterparty_other_missing_key() {
        let priv_key = PrivateKey::from_hex("ff").unwrap();
        let kd = KeyDeriver::new(priv_key);
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: None,
        };
        let result = kd.normalize_counterparty(&counterparty);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_child_roundtrip() {
        // Key property: priv.derive_child(counterparty_pub, inv).to_public_key()
        //            == counterparty_pub.derive_child(priv, inv) for for_self=true
        let priv_a = PrivateKey::from_hex("aa").unwrap();
        let priv_b = PrivateKey::from_hex("bb").unwrap();
        let pub_b = priv_b.to_public_key();

        let protocol = Protocol {
            security_level: 2,
            protocol: "test derivation".to_string(),
        };
        let key_id = "42";

        let kd_a = KeyDeriver::new(priv_a);
        let counterparty_b = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(pub_b),
        };

        // Derive for_self=true: use own private key to derive child, get pubkey
        let pub_for_self = kd_a
            .derive_public_key(&protocol, key_id, &counterparty_b, true)
            .unwrap();

        // Derive for_self=false: use counterparty's pubkey to derive child pubkey
        let pub_for_other = kd_a
            .derive_public_key(&protocol, key_id, &counterparty_b, false)
            .unwrap();

        // These should be different (for_self vs not for_self derive differently)
        // But the key round-trip property is:
        // KeyDeriver(A).derive_pub(B, for_self=true) ==
        // KeyDeriver(B).derive_pub(A, for_self=false)
        let kd_b = KeyDeriver::new(priv_b);
        let pub_a = kd_a.identity_key();
        let counterparty_a = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(pub_a),
        };
        let pub_from_b = kd_b
            .derive_public_key(&protocol, key_id, &counterparty_a, false)
            .unwrap();

        assert_eq!(
            pub_for_self.to_der_hex(),
            pub_from_b.to_der_hex(),
            "A.derive_pub(B, for_self=true) should equal B.derive_pub(A, for_self=false)"
        );

        // Also verify the other direction
        let pub_from_b_self = kd_b
            .derive_public_key(&protocol, key_id, &counterparty_a, true)
            .unwrap();
        assert_eq!(
            pub_for_other.to_der_hex(),
            pub_from_b_self.to_der_hex(),
            "A.derive_pub(B, for_self=false) should equal B.derive_pub(A, for_self=true)"
        );
    }

    #[test]
    fn test_derive_symmetric_key_deterministic() {
        let priv_key = PrivateKey::from_hex("abcd").unwrap();
        let kd = KeyDeriver::new(priv_key);
        let protocol = Protocol {
            security_level: 2,
            protocol: "test symmetric".to_string(),
        };
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        };
        let key1 = kd
            .derive_symmetric_key(&protocol, "1", &counterparty)
            .unwrap();
        let key2 = kd
            .derive_symmetric_key(&protocol, "1", &counterparty)
            .unwrap();
        assert_eq!(key1.to_hex(), key2.to_hex());
    }

    // -----------------------------------------------------------------------
    // Shared-secret cache regression tests
    //
    // These guard the per-counterparty ECDH shared-secret cache: it must be a
    // pure compute optimization (outputs bit-identical to the uncached path),
    // and it must only memoize the counterparty-invariant secret — never the
    // per-message derived keys, signatures, or HMACs.
    // -----------------------------------------------------------------------

    #[test]
    fn test_shared_secret_cache_matches_raw_derivation_across_messages() {
        // The cached KeyDeriver output must equal the raw primitive
        // `derive_child` (which recomputes the ECDH every call) for *every*
        // distinct per-message invoice number. This proves the cache does not
        // alter outputs and that the per-message nonce (carried in key_id ->
        // invoice number) still flows through on every call.
        let root = PrivateKey::from_hex("abcdef1234567890").unwrap();
        let cp_key = PrivateKey::from_hex("bb").unwrap();
        let cp_pub = cp_key.to_public_key();

        let kd = KeyDeriver::new(root.clone());
        let protocol = Protocol {
            security_level: 2,
            protocol: "auth message signature".to_string(),
        };
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(cp_pub.clone()),
        };

        // Three distinct "nonces" (key IDs) to the same counterparty.
        for nonce in ["nonce one aaa", "nonce two bbb", "nonce three cc"] {
            let invoice = KeyDeriver::compute_invoice_number(&protocol, nonce).unwrap();

            // Raw, uncached reference derivations.
            let raw_priv = root.derive_child(&cp_pub, &invoice).unwrap();
            let raw_pub_for_self = root.derive_child(&cp_pub, &invoice).unwrap().to_public_key();
            let raw_pub_other = cp_pub.derive_child(&root, &invoice).unwrap();

            // Cached KeyDeriver derivations.
            let cached_priv = kd.derive_private_key(&protocol, nonce, &counterparty).unwrap();
            let cached_pub_for_self = kd
                .derive_public_key(&protocol, nonce, &counterparty, true)
                .unwrap();
            let cached_pub_other = kd
                .derive_public_key(&protocol, nonce, &counterparty, false)
                .unwrap();

            assert_eq!(raw_priv.to_hex(), cached_priv.to_hex());
            assert_eq!(raw_pub_for_self.to_der_hex(), cached_pub_for_self.to_der_hex());
            assert_eq!(raw_pub_other.to_der_hex(), cached_pub_other.to_der_hex());
        }

        // Exactly one counterparty was used, so exactly one shared secret is
        // cached — proving we cache the counterparty-invariant secret, not the
        // per-message derived keys.
        assert_eq!(kd.shared_secret_cache_len(), 1);
    }

    #[test]
    fn test_shared_secret_cache_separates_counterparties() {
        let root = PrivateKey::from_hex("abcd").unwrap();
        let kd = KeyDeriver::new(root);
        let protocol = Protocol {
            security_level: 2,
            protocol: "test caching".to_string(),
        };

        for hex in ["bb", "cc", "dd"] {
            let cp = Counterparty {
                counterparty_type: CounterpartyType::Other,
                public_key: Some(PrivateKey::from_hex(hex).unwrap().to_public_key()),
            };
            let _ = kd.derive_private_key(&protocol, "k1", &cp).unwrap();
            // Repeat to the same counterparty must NOT add a cache entry.
            let _ = kd.derive_private_key(&protocol, "k2", &cp).unwrap();
        }
        assert_eq!(kd.shared_secret_cache_len(), 3);
    }

    #[test]
    fn test_signature_roundtrips_with_warm_cache() {
        use crate::primitives::ecdsa::{ecdsa_sign, ecdsa_verify};
        use crate::primitives::hash::sha256;

        // A signs to B, B verifies. The shared secret is warmed by the first
        // call on each side; the second message reuses the cache and must still
        // verify — proving correctness is preserved across the cache hit.
        let sk_a = PrivateKey::from_hex("a1a1a1a1a1a1a1a1").unwrap();
        let sk_b = PrivateKey::from_hex("b2b2b2b2b2b2b2b2").unwrap();
        let kd_a = KeyDeriver::new(sk_a.clone());
        let kd_b = KeyDeriver::new(sk_b.clone());

        let protocol = Protocol {
            security_level: 2,
            protocol: "auth message signature".to_string(),
        };
        let cp_b = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(sk_b.to_public_key()),
        };
        let cp_a = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(sk_a.to_public_key()),
        };

        for nonce in ["msg one xxxx", "msg two yyyy"] {
            let data = sha256(nonce.as_bytes());
            // A signs with its derived child private key.
            let child_priv = kd_a.derive_private_key(&protocol, nonce, &cp_b).unwrap();
            let sig = ecdsa_sign(&data, child_priv.bn(), true).unwrap();
            // B derives A's corresponding child public key and verifies.
            let child_pub = kd_b
                .derive_public_key(&protocol, nonce, &cp_a, false)
                .unwrap();
            assert!(
                ecdsa_verify(&data, &sig, child_pub.point()),
                "signature must verify with warm cache for nonce {nonce}"
            );
        }
        // One counterparty each side -> one cached secret each.
        assert_eq!(kd_a.shared_secret_cache_len(), 1);
        assert_eq!(kd_b.shared_secret_cache_len(), 1);
    }

    /// Load-invariant relative perf probe: times N warm-cache derivations
    /// (shared secret reused) against N cold derivations (fresh KeyDeriver per
    /// call, forcing the ECDH point-multiply every time), back-to-back in the
    /// same process so machine load cancels out of the ratio. Ignored by
    /// default; run with:
    ///   cargo test --features network --lib -- --ignored --nocapture \
    ///     wallet::key_deriver::tests::perf_probe_shared_secret_cache
    #[test]
    #[ignore]
    fn perf_probe_shared_secret_cache() {
        use std::time::Instant;

        let root = PrivateKey::from_hex("abcdef1234567890abcdef1234567890").unwrap();
        let cp_pub = PrivateKey::from_hex("bbccddee").unwrap().to_public_key();
        let protocol = Protocol {
            security_level: 2,
            protocol: "auth message signature".to_string(),
        };
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(cp_pub),
        };

        const N: u32 = 2000;

        // Warm cache: one KeyDeriver reused across all calls.
        let kd = KeyDeriver::new(root.clone());
        let _ = kd.derive_private_key(&protocol, "warmup", &counterparty).unwrap();
        let t_cached = {
            let start = Instant::now();
            for i in 0..N {
                let kid = format!("nonce {i:08}");
                let _ = kd.derive_public_key(&protocol, &kid, &counterparty, false).unwrap();
            }
            start.elapsed()
        };

        // Cold: fresh KeyDeriver each call -> ECDH recomputed every derivation.
        let t_cold = {
            let start = Instant::now();
            for i in 0..N {
                let kid = format!("nonce {i:08}");
                let kd_fresh = KeyDeriver::new(root.clone());
                let _ = kd_fresh
                    .derive_public_key(&protocol, &kid, &counterparty, false)
                    .unwrap();
            }
            start.elapsed()
        };

        let per_cached = t_cached.as_nanos() as f64 / N as f64 / 1000.0;
        let per_cold = t_cold.as_nanos() as f64 / N as f64 / 1000.0;
        println!(
            "perf_probe derive_public_key(for_self=false): cold {per_cold:.1}us/op, \
             cached {per_cached:.1}us/op, speedup {:.2}x",
            per_cold / per_cached
        );
        assert!(
            t_cached < t_cold,
            "warm-cache derivation must be faster than cold (ECDH recomputed)"
        );

        // --- derive_private_key: cold = 1 ECDH; cached = 0 point-mults ---
        let kd2 = KeyDeriver::new(root.clone());
        let _ = kd2.derive_private_key(&protocol, "warmup", &counterparty).unwrap();
        let t_cached_priv = {
            let start = Instant::now();
            for i in 0..N {
                let kid = format!("nonce {i:08}");
                let _ = kd2.derive_private_key(&protocol, &kid, &counterparty).unwrap();
            }
            start.elapsed()
        };
        let t_cold_priv = {
            let start = Instant::now();
            for i in 0..N {
                let kid = format!("nonce {i:08}");
                let kd_fresh = KeyDeriver::new(root.clone());
                let _ = kd_fresh.derive_private_key(&protocol, &kid, &counterparty).unwrap();
            }
            start.elapsed()
        };
        println!(
            "perf_probe derive_private_key: cold {:.1}us/op, cached {:.1}us/op, speedup {:.2}x",
            t_cold_priv.as_nanos() as f64 / N as f64 / 1000.0,
            t_cached_priv.as_nanos() as f64 / N as f64 / 1000.0,
            t_cold_priv.as_nanos() as f64 / t_cached_priv.as_nanos() as f64
        );

        // --- derive_symmetric_key: cold = 3 ECDH; cached = 1 ---
        let kd3 = KeyDeriver::new(root.clone());
        let _ = kd3.derive_symmetric_key(&protocol, "warmup", &counterparty).unwrap();
        let t_cached_sym = {
            let start = Instant::now();
            for i in 0..N {
                let kid = format!("nonce {i:08}");
                let _ = kd3.derive_symmetric_key(&protocol, &kid, &counterparty).unwrap();
            }
            start.elapsed()
        };
        let t_cold_sym = {
            let start = Instant::now();
            for i in 0..N {
                let kid = format!("nonce {i:08}");
                let kd_fresh = KeyDeriver::new(root.clone());
                let _ = kd_fresh.derive_symmetric_key(&protocol, &kid, &counterparty).unwrap();
            }
            start.elapsed()
        };
        println!(
            "perf_probe derive_symmetric_key (HMAC path): cold {:.1}us/op, cached {:.1}us/op, speedup {:.2}x",
            t_cold_sym.as_nanos() as f64 / N as f64 / 1000.0,
            t_cached_sym.as_nanos() as f64 / N as f64 / 1000.0,
            t_cold_sym.as_nanos() as f64 / t_cached_sym.as_nanos() as f64
        );
    }

    #[test]
    fn test_symmetric_key_stable_with_cache() {
        // derive_symmetric_key uses the cache for two of its three point-mults;
        // it must remain deterministic and self-consistent across cache states.
        let root = PrivateKey::from_hex("abcd").unwrap();
        let kd = KeyDeriver::new(root);
        let protocol = Protocol {
            security_level: 2,
            protocol: "test symmetric".to_string(),
        };
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(PrivateKey::from_hex("bb").unwrap().to_public_key()),
        };
        let k1 = kd.derive_symmetric_key(&protocol, "1", &counterparty).unwrap();
        let k2 = kd.derive_symmetric_key(&protocol, "1", &counterparty).unwrap();
        assert_eq!(k1.to_hex(), k2.to_hex());
    }

    #[test]
    fn test_reveal_counterparty_secret_rejects_self() {
        let priv_key = PrivateKey::from_hex("ff").unwrap();
        let kd = KeyDeriver::new(priv_key);
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        };
        let result = kd.reveal_counterparty_secret(&counterparty);
        assert!(result.is_err());
    }
}
