//! KeyDeriver: Type-42 key derivation for the wallet module.
//!
//! Implements BRC-42 key derivation using a root private key,
//! supporting derivation of private keys, public keys, symmetric keys,
//! and key linkage revelation.

use crate::primitives::hash::sha256_hmac;
use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;
use crate::primitives::symmetric_key::SymmetricKey;
use crate::wallet::error::WalletError;
use crate::wallet::types::{anyone_pubkey, Counterparty, CounterpartyType, Protocol};

/// KeyDeriver derives various types of keys using a root private key.
///
/// Supports deriving public and private keys, symmetric keys, and
/// revealing key linkages, all using BRC-42 Type-42 derivation.
pub struct KeyDeriver {
    root_key: PrivateKey,
}

impl KeyDeriver {
    /// Create a new KeyDeriver from a root private key.
    pub fn new(private_key: PrivateKey) -> Self {
        KeyDeriver {
            root_key: private_key,
        }
    }

    /// Create a KeyDeriver using the special "anyone" key (PrivateKey(1)).
    pub fn new_anyone() -> Self {
        KeyDeriver {
            root_key: crate::wallet::types::anyone_private_key(),
        }
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
        let child = self
            .root_key
            .derive_child(&counterparty_pubkey, &invoice_number)?;
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

        if for_self {
            let priv_child = self
                .root_key
                .derive_child(&counterparty_pubkey, &invoice_number)?;
            Ok(priv_child.to_public_key())
        } else {
            let pub_child = counterparty_pubkey.derive_child(&self.root_key, &invoice_number)?;
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
