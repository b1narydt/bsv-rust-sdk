//! Bitcoin address type with Base58Check encoding/decoding.
//!
//! Supports mainnet (prefix 0x00) and testnet (prefix 0x6f) addresses.
//! Translates the Go SDK address.go.

use crate::primitives::public_key::PublicKey;
use crate::primitives::utils::{base58_check_decode, base58_check_encode};
use crate::script::error::ScriptError;
use crate::script::locking_script::LockingScript;
use crate::script::op::Op;
use crate::script::script::Script;
use crate::script::script_chunk::ScriptChunk;

/// Mainnet address prefix byte.
const MAINNET_PREFIX: u8 = 0x00;

/// Testnet address prefix byte.
const TESTNET_PREFIX: u8 = 0x6f;

/// A Bitcoin address derived from a public key hash (P2PKH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    address_string: String,
    public_key_hash: Vec<u8>,
}

impl Address {
    /// Create an address from a 20-byte public key hash.
    ///
    /// Uses mainnet prefix (0x00) when `mainnet` is true,
    /// testnet prefix (0x6f) otherwise.
    pub fn from_public_key_hash(hash: &[u8; 20], mainnet: bool) -> Self {
        let prefix_byte = if mainnet {
            MAINNET_PREFIX
        } else {
            TESTNET_PREFIX
        };
        let address_string = base58_check_encode(hash, &[prefix_byte]);
        Address {
            address_string,
            public_key_hash: hash.to_vec(),
        }
    }

    /// Create an address from a PublicKey.
    ///
    /// Computes hash160 of the compressed public key bytes,
    /// then encodes with the appropriate network prefix.
    pub fn from_public_key(pubkey: &PublicKey, mainnet: bool) -> Self {
        let hash_vec = pubkey.to_hash();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_vec);
        Self::from_public_key_hash(&hash, mainnet)
    }

    /// Decode an address from a Base58Check string.
    ///
    /// Validates that the prefix is 0x00 (mainnet) or 0x6f (testnet)
    /// and that the hash is exactly 20 bytes.
    pub fn from_string(s: &str) -> Result<Self, ScriptError> {
        let (prefix, payload) =
            base58_check_decode(s, 1).map_err(|e| ScriptError::InvalidAddress(e.to_string()))?;

        if prefix.len() != 1 || (prefix[0] != MAINNET_PREFIX && prefix[0] != TESTNET_PREFIX) {
            return Err(ScriptError::InvalidAddress(format!(
                "unknown address prefix: 0x{:02x}",
                prefix.first().copied().unwrap_or(0)
            )));
        }

        if payload.len() != 20 {
            return Err(ScriptError::InvalidAddress(format!(
                "expected 20-byte hash, got {} bytes",
                payload.len()
            )));
        }

        Ok(Address {
            address_string: s.to_string(),
            public_key_hash: payload,
        })
    }

    /// Return the 20-byte public key hash.
    pub fn to_public_key_hash(&self) -> &[u8] {
        &self.public_key_hash
    }

    /// Check whether this is a mainnet address (prefix 0x00).
    pub fn is_mainnet(&self) -> bool {
        // Decode the address to check prefix
        if let Ok((prefix, _)) = base58_check_decode(&self.address_string, 1) {
            prefix.first().copied() == Some(MAINNET_PREFIX)
        } else {
            false
        }
    }

    /// Create a P2PKH locking script for this address.
    ///
    /// Script: `OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG`
    pub fn to_locking_script(&self) -> LockingScript {
        let chunks = vec![
            ScriptChunk::new_opcode(Op::OpDup),
            ScriptChunk::new_opcode(Op::OpHash160),
            ScriptChunk::new_raw(
                self.public_key_hash.len() as u8,
                Some(self.public_key_hash.clone()),
            ),
            ScriptChunk::new_opcode(Op::OpEqualVerify),
            ScriptChunk::new_opcode(Op::OpCheckSig),
        ];
        LockingScript::from_script(Script::from_chunks(chunks))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Known test vector: private key = 1
    /// Compressed public key: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    /// Public key hash (hash160): 751e76e8199196d454941c45d1b3a323f1433bd6
    /// Mainnet address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    #[test]
    fn test_known_mainnet_address() {
        let pubkey_hash =
            crate::primitives::utils::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&pubkey_hash);

        let addr = Address::from_public_key_hash(&hash, true);
        assert_eq!(addr.to_string(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert!(addr.is_mainnet());
    }

    #[test]
    fn test_known_testnet_address() {
        let pubkey_hash =
            crate::primitives::utils::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&pubkey_hash);

        let addr = Address::from_public_key_hash(&hash, false);
        // Testnet address for same pubkey hash
        assert!(!addr.is_mainnet());
        // Testnet addresses start with 'm' or 'n'
        let s = addr.to_string();
        assert!(
            s.starts_with('m') || s.starts_with('n'),
            "testnet address should start with m or n, got: {s}"
        );
    }

    #[test]
    fn test_roundtrip_from_hash_to_string_from_string() {
        let pubkey_hash =
            crate::primitives::utils::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&pubkey_hash);

        let addr = Address::from_public_key_hash(&hash, true);
        let addr_str = addr.to_string();

        let decoded = Address::from_string(&addr_str).unwrap();
        assert_eq!(decoded.to_public_key_hash(), &pubkey_hash[..]);
        assert_eq!(decoded.to_string(), addr_str);
    }

    #[test]
    fn test_invalid_address_string() {
        // Tampered address (checksum mismatch)
        let result = Address::from_string("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAM1");
        assert!(result.is_err());
    }

    #[test]
    fn test_to_locking_script_p2pkh() {
        let pubkey_hash =
            crate::primitives::utils::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&pubkey_hash);

        let addr = Address::from_public_key_hash(&hash, true);
        let script = addr.to_locking_script();

        // Expected: OP_DUP(76) OP_HASH160(a9) PUSH20(14) <20-byte-hash> OP_EQUALVERIFY(88) OP_CHECKSIG(ac)
        let binary = script.to_binary();
        assert_eq!(binary[0], 0x76, "OP_DUP");
        assert_eq!(binary[1], 0xa9, "OP_HASH160");
        assert_eq!(binary[2], 0x14, "push 20 bytes");
        assert_eq!(&binary[3..23], &pubkey_hash[..], "pubkey hash");
        assert_eq!(binary[23], 0x88, "OP_EQUALVERIFY");
        assert_eq!(binary[24], 0xac, "OP_CHECKSIG");
        assert_eq!(binary.len(), 25);
    }

    #[test]
    fn test_from_public_key() {
        // Use private key = 1 to get the known public key
        use crate::primitives::private_key::PrivateKey;

        let pk = PrivateKey::from_bytes(&{
            let mut buf = [0u8; 32];
            buf[31] = 1;
            buf
        })
        .unwrap();
        let pubkey = pk.to_public_key();
        let addr = Address::from_public_key(&pubkey, true);
        assert_eq!(addr.to_string(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn test_display_impl() {
        let pubkey_hash =
            crate::primitives::utils::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&pubkey_hash);

        let addr = Address::from_public_key_hash(&hash, true);
        let display_str = format!("{addr}");
        assert_eq!(display_str, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }
}
