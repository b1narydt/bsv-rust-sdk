//! P2PKH (Pay-to-Public-Key-Hash) script template.
//!
//! The most common Bitcoin transaction type. Locks funds to a public key hash
//! and unlocks with a signature and the corresponding public key.
//! Translates the TS SDK P2PKH.ts.

use crate::primitives::ecdsa::ecdsa_sign;
use crate::primitives::hash::hash256;
use crate::primitives::private_key::PrivateKey;
use crate::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use crate::primitives::utils::base58_check_decode;
use crate::script::error::ScriptError;
use crate::script::locking_script::LockingScript;
use crate::script::op::Op;
use crate::script::script::Script;
use crate::script::script_chunk::ScriptChunk;
use crate::script::templates::{ScriptTemplateLock, ScriptTemplateUnlock};
use crate::script::unlocking_script::UnlockingScript;

/// P2PKH script template for creating standard pay-to-public-key-hash scripts.
///
/// Can be configured for locking (with a public key hash) or unlocking
/// (with a private key). The struct stores both fields; which one is
/// used depends on whether lock() or sign() is called.
#[derive(Clone, Debug)]
pub struct P2PKH {
    /// The 20-byte public key hash for locking.
    pub public_key_hash: Option<[u8; 20]>,
    /// The private key for unlocking (signing).
    pub private_key: Option<PrivateKey>,
    /// Sighash scope for signing (default: SIGHASH_ALL | SIGHASH_FORKID).
    pub sighash_type: u32,
}

impl P2PKH {
    /// Create a P2PKH template configured for locking with a known public key hash.
    pub fn from_public_key_hash(hash: [u8; 20]) -> Self {
        P2PKH {
            public_key_hash: Some(hash),
            private_key: None,
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
        }
    }

    /// Create a P2PKH template from a Base58Check-encoded Bitcoin address.
    ///
    /// Decodes the address, extracts the 20-byte public key hash,
    /// and configures the template for locking.
    pub fn from_address(address: &str) -> Result<Self, ScriptError> {
        let (_prefix, payload) = base58_check_decode(address, 1)
            .map_err(|e| ScriptError::InvalidAddress(format!("invalid address: {e}")))?;

        if payload.len() != 20 {
            return Err(ScriptError::InvalidAddress(format!(
                "address payload should be 20 bytes, got {}",
                payload.len()
            )));
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(&payload);
        Ok(Self::from_public_key_hash(hash))
    }

    /// Create a P2PKH template configured for unlocking with a private key.
    ///
    /// Also derives the public key hash for locking capability.
    pub fn from_private_key(key: PrivateKey) -> Self {
        let pubkey = key.to_public_key();
        let hash_vec = pubkey.to_hash();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_vec);

        P2PKH {
            public_key_hash: Some(hash),
            private_key: Some(key),
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
        }
    }

    /// Create an unlocking script from a sighash preimage.
    ///
    /// Signs the SHA-256 hash of the preimage with the private key and
    /// produces: `<signature_DER + sighash_byte> <compressed_pubkey>`
    pub fn unlock(&self, preimage: &[u8]) -> Result<UnlockingScript, ScriptError> {
        let key = self
            .private_key
            .as_ref()
            .ok_or_else(|| ScriptError::InvalidScript("P2PKH: no private key for unlock".into()))?;

        // Double-hash the preimage (hash256 = sha256(sha256(x))) to match
        // what OP_CHECKSIG uses for verification.
        let msg_hash = hash256(preimage);

        // Sign the 32-byte hash directly
        let sig = ecdsa_sign(&msg_hash, key.bn(), true)
            .map_err(|e| ScriptError::InvalidSignature(format!("ECDSA sign failed: {e}")))?;

        // Build checksig format: DER + sighash byte
        let mut sig_bytes = sig.to_der();
        sig_bytes.push(self.sighash_type as u8);

        // Get compressed public key
        let pubkey = key.to_public_key();
        let pubkey_bytes = pubkey.to_der();

        // Build unlocking script: <sig> <pubkey>
        let chunks = vec![
            ScriptChunk::new_raw(sig_bytes.len() as u8, Some(sig_bytes)),
            ScriptChunk::new_raw(pubkey_bytes.len() as u8, Some(pubkey_bytes)),
        ];

        Ok(UnlockingScript::from_script(Script::from_chunks(chunks)))
    }

    /// Estimate the byte length of the unlocking script.
    ///
    /// Typical P2PKH unlock is approximately 108 bytes:
    /// 1 byte push opcode + 73 bytes max DER sig with sighash byte,
    /// plus 1 byte push opcode + 33 bytes compressed pubkey.
    pub fn estimate_unlock_length(&self) -> usize {
        // 1 (push) + 73 (max DER sig + sighash) + 1 (push) + 33 (compressed pubkey)
        108
    }
}

impl ScriptTemplateLock for P2PKH {
    /// Create a P2PKH locking script.
    ///
    /// Produces: OP_DUP OP_HASH160 <20-byte pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    /// Total: 25 bytes when serialized.
    fn lock(&self) -> Result<LockingScript, ScriptError> {
        let hash = self.public_key_hash.ok_or_else(|| {
            ScriptError::InvalidScript("P2PKH: no public key hash for lock".into())
        })?;

        let chunks = vec![
            ScriptChunk::new_opcode(Op::OpDup),
            ScriptChunk::new_opcode(Op::OpHash160),
            ScriptChunk::new_raw(20, Some(hash.to_vec())),
            ScriptChunk::new_opcode(Op::OpEqualVerify),
            ScriptChunk::new_opcode(Op::OpCheckSig),
        ];

        Ok(LockingScript::from_script(Script::from_chunks(chunks)))
    }
}

impl ScriptTemplateUnlock for P2PKH {
    fn sign(&self, preimage: &[u8]) -> Result<UnlockingScript, ScriptError> {
        self.unlock(preimage)
    }

    fn estimate_length(&self) -> Result<usize, ScriptError> {
        Ok(self.estimate_unlock_length())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // -----------------------------------------------------------------------
    // P2PKH lock: produces correct 25-byte script
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_lock_correct_script() {
        let hash = [0xab; 20];
        let p2pkh = P2PKH::from_public_key_hash(hash);
        let lock_script = p2pkh.lock().unwrap();

        let binary = lock_script.to_binary();
        assert_eq!(binary.len(), 25, "P2PKH locking script should be 25 bytes");

        // OP_DUP(0x76) OP_HASH160(0xa9) PUSH20(0x14) <20 bytes hash> OP_EQUALVERIFY(0x88) OP_CHECKSIG(0xac)
        assert_eq!(binary[0], 0x76, "should start with OP_DUP");
        assert_eq!(binary[1], 0xa9, "second byte should be OP_HASH160");
        assert_eq!(binary[2], 0x14, "third byte should be push-20");
        assert_eq!(&binary[3..23], &hash, "hash should be embedded");
        assert_eq!(binary[23], 0x88, "should have OP_EQUALVERIFY");
        assert_eq!(binary[24], 0xac, "should end with OP_CHECKSIG");
    }

    // -----------------------------------------------------------------------
    // P2PKH lock: hex matches known P2PKH locking script
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_lock_known_hex() {
        let hash = [0xab; 20];
        let p2pkh = P2PKH::from_public_key_hash(hash);
        let lock_script = p2pkh.lock().unwrap();
        let hex = lock_script.to_hex();
        assert_eq!(hex, "76a914abababababababababababababababababababab88ac");
    }

    // -----------------------------------------------------------------------
    // P2PKH lock: from real private key
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_lock_from_private_key() {
        let key = PrivateKey::from_hex("1").unwrap();
        let p2pkh = P2PKH::from_private_key(key.clone());

        let lock_script = p2pkh.lock().unwrap();
        let binary = lock_script.to_binary();
        assert_eq!(binary.len(), 25);

        // Verify the hash matches the key's public key hash
        let pubkey = key.to_public_key();
        let expected_hash = pubkey.to_hash();
        assert_eq!(&binary[3..23], expected_hash.as_slice());
    }

    // -----------------------------------------------------------------------
    // P2PKH unlock: produces 2-chunk script (sig + pubkey)
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_unlock_produces_two_chunks() {
        let key = PrivateKey::from_hex("1").unwrap();
        let p2pkh = P2PKH::from_private_key(key);

        let preimage = b"test sighash preimage";
        let unlock_script = p2pkh.unlock(preimage).unwrap();

        assert_eq!(
            unlock_script.chunks().len(),
            2,
            "P2PKH unlock should have 2 chunks (sig + pubkey)"
        );

        // First chunk: signature (DER + sighash byte)
        let sig_chunk = &unlock_script.chunks()[0];
        assert!(
            sig_chunk.data.is_some(),
            "first chunk should have data (signature)"
        );
        let sig_data = sig_chunk.data.as_ref().unwrap();
        // DER signature is typically 70-73 bytes + 1 sighash byte
        assert!(
            sig_data.len() >= 70 && sig_data.len() <= 74,
            "signature length should be 70-74, got {}",
            sig_data.len()
        );
        // Last byte should be sighash type
        assert_eq!(
            *sig_data.last().unwrap(),
            (SIGHASH_ALL | SIGHASH_FORKID) as u8,
            "last byte should be sighash type"
        );

        // Second chunk: compressed public key (33 bytes)
        let pubkey_chunk = &unlock_script.chunks()[1];
        assert!(pubkey_chunk.data.is_some());
        let pubkey_data = pubkey_chunk.data.as_ref().unwrap();
        assert_eq!(
            pubkey_data.len(),
            33,
            "pubkey should be 33 bytes compressed"
        );
        assert!(
            pubkey_data[0] == 0x02 || pubkey_data[0] == 0x03,
            "pubkey should start with 0x02 or 0x03"
        );
    }

    // -----------------------------------------------------------------------
    // P2PKH estimate_unlock_length
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_estimate_unlock_length() {
        let hash = [0; 20];
        let p2pkh = P2PKH::from_public_key_hash(hash);
        let estimate = p2pkh.estimate_unlock_length();
        // Should be approximately 107-108
        assert!(
            (100..=120).contains(&estimate),
            "estimate should be ~107-108, got {estimate}"
        );
    }

    // -----------------------------------------------------------------------
    // P2PKH from_address: correctly extracts hash and creates lock
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_from_address() {
        // Known address for key=1: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
        let address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        let p2pkh = P2PKH::from_address(address).unwrap();
        let lock_script = p2pkh.lock().unwrap();

        // The hash should match key=1's pubkey hash
        let key = PrivateKey::from_hex("1").unwrap();
        let pubkey = key.to_public_key();
        let expected_hash = pubkey.to_hash();

        let binary = lock_script.to_binary();
        assert_eq!(&binary[3..23], expected_hash.as_slice());
    }

    // -----------------------------------------------------------------------
    // P2PKH lock error: no hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_lock_error_no_hash() {
        let p2pkh = P2PKH {
            public_key_hash: None,
            private_key: None,
            sighash_type: SIGHASH_ALL | SIGHASH_FORKID,
        };
        assert!(p2pkh.lock().is_err());
    }

    // -----------------------------------------------------------------------
    // P2PKH unlock error: no key
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_unlock_error_no_key() {
        let hash = [0; 20];
        let p2pkh = P2PKH::from_public_key_hash(hash);
        assert!(p2pkh.unlock(b"test").is_err());
    }

    // -----------------------------------------------------------------------
    // P2PKH: ScriptTemplateUnlock trait
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_trait_sign() {
        let key = PrivateKey::from_hex("ff").unwrap();
        let p2pkh = P2PKH::from_private_key(key);

        // Use trait method
        let unlock_script = p2pkh.sign(b"sighash data").unwrap();
        assert_eq!(unlock_script.chunks().len(), 2);
    }

    #[test]
    fn test_p2pkh_trait_estimate_length() {
        let key = PrivateKey::from_hex("1").unwrap();
        let p2pkh = P2PKH::from_private_key(key);
        let len = p2pkh.estimate_length().unwrap();
        assert!((100..=120).contains(&len));
    }

    // -----------------------------------------------------------------------
    // P2PKH: ASM format verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_lock_asm() {
        let key = PrivateKey::from_hex("1").unwrap();
        let pubkey = key.to_public_key();
        let hash = pubkey.to_hash();
        let hash_hex = bytes_to_hex(&hash);

        let p2pkh = P2PKH::from_private_key(key);
        let lock_script = p2pkh.lock().unwrap();
        let asm = lock_script.to_asm();

        let expected_asm = format!("OP_DUP OP_HASH160 {hash_hex} OP_EQUALVERIFY OP_CHECKSIG");
        assert_eq!(asm, expected_asm);
    }
}
