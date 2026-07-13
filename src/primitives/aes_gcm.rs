//! AES-GCM authenticated encryption and decryption.
//!
//! Implements NIST SP 800-38D (GCM) with support for both standard 12-byte IVs
//! and non-standard IV lengths (including the TS SDK's 32-byte IV convention).
//!
//! The ciphertext format is: ciphertext || auth_tag (16 bytes appended).

use crate::primitives::aes::{aes_encrypt_block, aes_key_expansion};
use crate::primitives::PrimitivesError;

// R constant for GHASH: 0xe1 followed by 15 zero bytes (in the GF(2^128) representation)
const R_BLOCK: [u8; 16] = [
    0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Shift a 16-byte block right by one bit.
fn right_shift(block: &mut [u8; 16]) {
    let mut carry = 0u8;
    for byte in block.iter_mut() {
        let old_carry = carry;
        carry = *byte & 0x01;
        *byte >>= 1;
        if old_carry != 0 {
            *byte |= 0x80;
        }
    }
}

/// Multiply two elements in GF(2^128) using the GHASH polynomial.
/// Uses mask-based operations to avoid secret-dependent branches.
fn gf128_multiply(block0: &[u8; 16], block1: &[u8; 16]) -> [u8; 16] {
    let mut v = *block1;
    let mut z = [0u8; 16];

    for &b in block0.iter() {
        for j in (0..8).rev() {
            // mask = 0xff if bit is set, 0x00 otherwise
            let bit = (b >> j) & 1;
            let mask = (-(bit as i8)) as u8;
            // z ^= v & mask (branchless)
            for k in 0..16 {
                z[k] ^= v[k] & mask;
            }
            // Compute reduction: if LSB of v is set, XOR with R after shift
            let lsb = v[15] & 1;
            let rmask = (-(lsb as i8)) as u8;
            right_shift(&mut v);
            // v ^= R & rmask
            for k in 0..16 {
                v[k] ^= R_BLOCK[k] & rmask;
            }
        }
    }
    z
}

/// Compute GHASH over input data using the hash sub-key H.
/// Input is processed in 16-byte blocks. If input is not a multiple of 16,
/// the last block is zero-padded.
fn ghash(h: &[u8; 16], input: &[u8]) -> [u8; 16] {
    let mut result = [0u8; 16];

    for i in (0..input.len()).step_by(16) {
        let mut block = result;
        let remaining = std::cmp::min(16, input.len() - i);
        for j in 0..16 {
            if j < remaining {
                block[j] ^= input[i + j];
            }
        }
        result = gf128_multiply(&block, h);
    }

    result
}

/// Build the GHASH auth input per NIST SP 800-38D (standard).
/// Format: AAD || pad(AAD) || ciphertext || pad(CT) || len(AAD)*8 || len(CT)*8
/// where each length is encoded as a 64-bit big-endian integer.
fn build_auth_input_standard(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let aad_pad = if aad.is_empty() || aad.len().is_multiple_of(16) {
        0
    } else {
        16 - (aad.len() % 16)
    };

    let ct_pad = if ciphertext.is_empty() || ciphertext.len().is_multiple_of(16) {
        0
    } else {
        16 - (ciphertext.len() % 16)
    };

    let total = aad.len() + aad_pad + ciphertext.len() + ct_pad + 16;
    let mut out = Vec::with_capacity(total);

    // AAD + padding
    out.extend_from_slice(aad);
    out.extend(std::iter::repeat_n(0u8, aad_pad));

    // Ciphertext + padding
    out.extend_from_slice(ciphertext);
    out.extend(std::iter::repeat_n(0u8, ct_pad));

    // Length block: len(AAD) in bits (64-bit BE) || len(CT) in bits (64-bit BE)
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    out.extend_from_slice(&aad_bits.to_be_bytes());
    out.extend_from_slice(&ct_bits.to_be_bytes());

    out
}

/// Build the GHASH auth input per TS SDK convention (non-standard).
/// The TS SDK always has AAD=empty in its buildAuthInput, prepends a 16-byte
/// zero block for AAD, and adds an extra zero-pad block when ciphertext length
/// is zero or already aligned to 16 bytes.
fn build_auth_input_ts_compat(ciphertext: &[u8]) -> Vec<u8> {
    let pad_len = if ciphertext.is_empty() {
        16
    } else if ciphertext.len().is_multiple_of(16) {
        0
    } else {
        16 - (ciphertext.len() % 16)
    };

    // Total: 16 (empty AAD block) + ciphertext + pad + 16 (lengths)
    let total = 16 + ciphertext.len() + pad_len + 16;
    let mut out = Vec::with_capacity(total);

    // 16 zero bytes for empty AAD
    out.extend_from_slice(&[0u8; 16]);

    // Ciphertext + padding
    out.extend_from_slice(ciphertext);
    out.extend(std::iter::repeat_n(0u8, pad_len));

    // Length block: aad_len_bits = 0, ct_len_bits = ciphertext.len() * 8
    let aad_bits: u64 = 0;
    let ct_bits = (ciphertext.len() as u64) * 8;
    out.extend_from_slice(&aad_bits.to_be_bytes());
    out.extend_from_slice(&ct_bits.to_be_bytes());

    out
}

/// Increment the least significant 32 bits of a 16-byte counter block.
fn increment_counter(block: &[u8; 16]) -> [u8; 16] {
    let mut result = *block;
    for i in (12..16).rev() {
        result[i] = result[i].wrapping_add(1);
        if result[i] != 0 {
            break;
        }
    }
    result
}

/// GCM counter mode (GCTR) encryption/decryption.
fn gctr(input: &[u8], initial_counter: &[u8; 16], round_keys: &[u32]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }

    let mut output = Vec::with_capacity(input.len());
    let mut counter_block = *initial_counter;
    let n = input.len().div_ceil(16);

    let mut pos = 0;
    for i in 0..n {
        let encrypted_counter = aes_encrypt_block(&counter_block, round_keys);
        let chunk = std::cmp::min(16, input.len() - pos);
        for (j, enc_byte) in encrypted_counter.iter().enumerate().take(chunk) {
            output.push(input[pos + j] ^ enc_byte);
        }
        pos += chunk;
        if i + 1 < n {
            counter_block = increment_counter(&counter_block);
        }
    }

    output
}

/// Derive the initial counter block J0 from the IV.
/// - If IV is 12 bytes: J0 = IV || 0x00000001
/// - Otherwise: J0 = GHASH(H, IV || pad || len(IV)*8)
fn derive_j0(h: &[u8; 16], iv: &[u8]) -> [u8; 16] {
    if iv.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 0x01;
        j0
    } else {
        // Pad IV to multiple of 16 bytes
        let mut padded = Vec::from(iv);
        let pad_len = if iv.len().is_multiple_of(16) {
            0
        } else {
            16 - (iv.len() % 16)
        };
        padded.extend(std::iter::repeat_n(0u8, pad_len));
        // Append 8 zero bytes then 8-byte big-endian length in bits
        padded.extend_from_slice(&[0u8; 8]);
        let iv_bits = (iv.len() as u64) * 8;
        padded.extend_from_slice(&iv_bits.to_be_bytes());
        ghash(h, &padded)
    }
}

/// Encrypt plaintext using AES-GCM.
///
/// # Arguments
/// * `key` - AES key (16 or 32 bytes)
/// * `iv` - Initialization vector (typically 12 bytes; 32 bytes for TS SDK compat)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (authenticated but not encrypted)
///
/// # Returns
/// `ciphertext || auth_tag` (auth tag is 16 bytes appended)
pub fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PrimitivesError> {
    if key.len() != 16 && key.len() != 32 {
        return Err(PrimitivesError::InvalidLength(format!(
            "AES key must be 16 or 32 bytes, got {}",
            key.len()
        )));
    }
    if iv.is_empty() {
        return Err(PrimitivesError::InvalidLength(
            "IV must not be empty".to_string(),
        ));
    }

    let round_keys = aes_key_expansion(key)?;

    // H = AES(K, 0^128)
    let h = aes_encrypt_block(&[0u8; 16], &round_keys);

    // Derive J0
    let j0 = derive_j0(&h, iv);

    // CTR encryption starting from inc(J0)
    let ctr_start = increment_counter(&j0);
    let ciphertext = gctr(plaintext, &ctr_start, &round_keys);

    // Compute auth tag
    let auth_input = build_auth_input_standard(aad, &ciphertext);
    let s = ghash(&h, &auth_input);
    let tag_bytes = gctr(&s, &j0, &round_keys);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_bytes);

    // Output: ciphertext || tag
    let mut result = ciphertext;
    result.extend_from_slice(&tag);
    Ok(result)
}

/// Decrypt ciphertext using AES-GCM.
///
/// # Arguments
/// * `key` - AES key (16 or 32 bytes)
/// * `iv` - Initialization vector
/// * `ciphertext_with_tag` - Data to decrypt with 16-byte auth tag appended
/// * `aad` - Additional authenticated data
///
/// # Returns
/// Decrypted plaintext, or `Err(DecryptionFailed)` if auth tag doesn't match.
pub fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PrimitivesError> {
    if key.len() != 16 && key.len() != 32 {
        return Err(PrimitivesError::InvalidLength(format!(
            "AES key must be 16 or 32 bytes, got {}",
            key.len()
        )));
    }
    if iv.is_empty() {
        return Err(PrimitivesError::InvalidLength(
            "IV must not be empty".to_string(),
        ));
    }
    if ciphertext_with_tag.len() < 16 {
        return Err(PrimitivesError::DecryptionFailed);
    }

    let ct_len = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..ct_len];
    let provided_tag = &ciphertext_with_tag[ct_len..];

    let round_keys = aes_key_expansion(key)?;

    // H = AES(K, 0^128)
    let h = aes_encrypt_block(&[0u8; 16], &round_keys);

    // Derive J0
    let j0 = derive_j0(&h, iv);

    // Recompute auth tag
    let auth_input = build_auth_input_standard(aad, ciphertext);
    let s = ghash(&h, &auth_input);
    let computed_tag_bytes = gctr(&s, &j0, &round_keys);

    // Constant-time tag comparison
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= computed_tag_bytes[i] ^ provided_tag[i];
    }
    if diff != 0 {
        return Err(PrimitivesError::DecryptionFailed);
    }

    // CTR decryption
    let ctr_start = increment_counter(&j0);
    let plaintext = gctr(ciphertext, &ctr_start, &round_keys);

    Ok(plaintext)
}

/// Encrypt plaintext using AES-GCM with TS SDK compatible GHASH formatting.
///
/// This uses the non-standard auth input formatting that the TS SDK uses:
/// - AAD is always empty (ignored)
/// - An extra zero block is prepended
///
/// This is needed for SymmetricKey interoperability with the TS SDK.
pub fn aes_gcm_encrypt_ts_compat(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, PrimitivesError> {
    if key.len() != 16 && key.len() != 32 {
        return Err(PrimitivesError::InvalidLength(format!(
            "AES key must be 16 or 32 bytes, got {}",
            key.len()
        )));
    }
    if iv.is_empty() {
        return Err(PrimitivesError::InvalidLength(
            "IV must not be empty".to_string(),
        ));
    }

    let round_keys = aes_key_expansion(key)?;
    let h = aes_encrypt_block(&[0u8; 16], &round_keys);
    let j0 = derive_j0(&h, iv);
    let ctr_start = increment_counter(&j0);
    let ciphertext = gctr(plaintext, &ctr_start, &round_keys);

    // TS SDK non-standard auth input
    let auth_input = build_auth_input_ts_compat(&ciphertext);
    let s = ghash(&h, &auth_input);
    let tag_bytes = gctr(&s, &j0, &round_keys);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_bytes);

    let mut result = ciphertext;
    result.extend_from_slice(&tag);
    Ok(result)
}

/// Decrypt ciphertext using AES-GCM with TS SDK compatible GHASH formatting.
pub fn aes_gcm_decrypt_ts_compat(
    key: &[u8],
    iv: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, PrimitivesError> {
    if key.len() != 16 && key.len() != 32 {
        return Err(PrimitivesError::InvalidLength(format!(
            "AES key must be 16 or 32 bytes, got {}",
            key.len()
        )));
    }
    if iv.is_empty() {
        return Err(PrimitivesError::InvalidLength(
            "IV must not be empty".to_string(),
        ));
    }
    if ciphertext_with_tag.len() < 16 {
        return Err(PrimitivesError::DecryptionFailed);
    }

    let ct_len = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..ct_len];
    let provided_tag = &ciphertext_with_tag[ct_len..];

    let round_keys = aes_key_expansion(key)?;
    let h = aes_encrypt_block(&[0u8; 16], &round_keys);
    let j0 = derive_j0(&h, iv);

    // TS SDK non-standard auth input
    let auth_input = build_auth_input_ts_compat(ciphertext);
    let s = ghash(&h, &auth_input);
    let computed_tag_bytes = gctr(&s, &j0, &round_keys);

    let mut diff = 0u8;
    for i in 0..16 {
        diff |= computed_tag_bytes[i] ^ provided_tag[i];
    }
    if diff != 0 {
        return Err(PrimitivesError::DecryptionFailed);
    }

    let ctr_start = increment_counter(&j0);
    let plaintext = gctr(ciphertext, &ctr_start, &round_keys);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // --- NIST SP 800-38D test vectors ---

    #[test]
    fn test_nist_aes128_gcm_test_case_2() {
        // Test Case 2: AES-128-GCM, 12-byte IV, no AAD, 16-byte plaintext
        let key = hex_to_bytes("00000000000000000000000000000000");
        let iv = hex_to_bytes("000000000000000000000000");
        let pt = hex_to_bytes("00000000000000000000000000000000");
        let expected_ct = hex_to_bytes("0388dace60b6a392f328c2b971b2fe78");
        let expected_tag = hex_to_bytes("ab6e47d42cec13bdf53a67b21257bddf");

        let result = aes_gcm_encrypt(&key, &iv, &pt, &[]).unwrap();
        let ct = &result[..result.len() - 16];
        let tag = &result[result.len() - 16..];

        assert_eq!(
            bytes_to_hex(ct),
            bytes_to_hex(&expected_ct),
            "NIST Test Case 2 ciphertext mismatch"
        );
        assert_eq!(
            bytes_to_hex(tag),
            bytes_to_hex(&expected_tag),
            "NIST Test Case 2 tag mismatch"
        );
    }

    #[test]
    fn test_nist_aes128_gcm_test_case_3() {
        // Test Case 3: AES-128-GCM, 12-byte IV, no AAD, 60-byte plaintext
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888");
        let pt = hex_to_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        let expected_ct = hex_to_bytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985");
        let expected_tag = hex_to_bytes("4d5c2af327cd64a62cf35abd2ba6fab4");

        let result = aes_gcm_encrypt(&key, &iv, &pt, &[]).unwrap();
        let ct = &result[..result.len() - 16];
        let tag = &result[result.len() - 16..];

        assert_eq!(
            bytes_to_hex(ct),
            bytes_to_hex(&expected_ct),
            "NIST Test Case 3 ciphertext mismatch"
        );
        assert_eq!(
            bytes_to_hex(tag),
            bytes_to_hex(&expected_tag),
            "NIST Test Case 3 tag mismatch"
        );
    }

    #[test]
    fn test_nist_aes128_gcm_test_case_4_with_aad() {
        // Test Case 4: AES-128-GCM with AAD
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888");
        let pt = hex_to_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let expected_ct = hex_to_bytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
        let expected_tag = hex_to_bytes("5bc94fbc3221a5db94fae95ae7121a47");

        let result = aes_gcm_encrypt(&key, &iv, &pt, &aad).unwrap();
        let ct = &result[..result.len() - 16];
        let tag = &result[result.len() - 16..];

        assert_eq!(
            bytes_to_hex(ct),
            bytes_to_hex(&expected_ct),
            "NIST Test Case 4 ciphertext mismatch"
        );
        assert_eq!(
            bytes_to_hex(tag),
            bytes_to_hex(&expected_tag),
            "NIST Test Case 4 tag mismatch"
        );
    }

    #[test]
    fn test_nist_aes256_gcm_test_case_14() {
        // Test Case 14: AES-256-GCM, 12-byte IV, no AAD
        let key = hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000000");
        let iv = hex_to_bytes("000000000000000000000000");
        let pt = hex_to_bytes("00000000000000000000000000000000");
        let expected_ct = hex_to_bytes("cea7403d4d606b6e074ec5d3baf39d18");
        let expected_tag = hex_to_bytes("d0d1c8a799996bf0265b98b5d48ab919");

        let result = aes_gcm_encrypt(&key, &iv, &pt, &[]).unwrap();
        let ct = &result[..result.len() - 16];
        let tag = &result[result.len() - 16..];

        assert_eq!(
            bytes_to_hex(ct),
            bytes_to_hex(&expected_ct),
            "NIST Test Case 14 ciphertext mismatch"
        );
        assert_eq!(
            bytes_to_hex(tag),
            bytes_to_hex(&expected_tag),
            "NIST Test Case 14 tag mismatch"
        );
    }

    #[test]
    fn test_nist_aes256_gcm_test_case_16_with_aad() {
        // Test Case 16: AES-256-GCM with AAD
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888");
        let pt = hex_to_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let expected_ct = hex_to_bytes("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
        let expected_tag = hex_to_bytes("76fc6ece0f4e1768cddf8853bb2d551b");

        let result = aes_gcm_encrypt(&key, &iv, &pt, &aad).unwrap();
        let ct = &result[..result.len() - 16];
        let tag = &result[result.len() - 16..];

        assert_eq!(
            bytes_to_hex(ct),
            bytes_to_hex(&expected_ct),
            "NIST Test Case 16 ciphertext mismatch"
        );
        assert_eq!(
            bytes_to_hex(tag),
            bytes_to_hex(&expected_tag),
            "NIST Test Case 16 tag mismatch"
        );
    }

    // --- Round-trip tests ---

    #[test]
    fn test_aes_gcm_roundtrip_12byte_iv() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888");
        let plaintext = b"Hello, AES-GCM!";

        let encrypted = aes_gcm_encrypt(&key, &iv, plaintext, &[]).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &iv, &encrypted, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_roundtrip_with_aad() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888");
        let plaintext = b"Hello, AES-GCM with AAD!";
        let aad = b"additional data";

        let encrypted = aes_gcm_encrypt(&key, &iv, plaintext, aad).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &iv, &encrypted, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_roundtrip_32byte_iv() {
        // TS SDK uses 32-byte IV convention
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888cafebabefacedbaddecaf888cafebabefacedbad");
        let plaintext = b"Testing 32-byte IV for TS SDK compatibility";

        let encrypted = aes_gcm_encrypt(&key, &iv, plaintext, &[]).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &iv, &encrypted, &[]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_roundtrip_empty_plaintext() {
        // Empty plaintext with AAD should still produce a valid tag
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888");
        let aad = hex_to_bytes("feedfacedeadbeef");

        let encrypted = aes_gcm_encrypt(&key, &iv, &[], &aad).unwrap();
        assert_eq!(encrypted.len(), 16); // Just the tag, no ciphertext
        let decrypted = aes_gcm_decrypt(&key, &iv, &encrypted, &aad).unwrap();
        assert!(decrypted.is_empty());
    }

    // --- Tamper detection tests ---

    #[test]
    fn test_aes_gcm_tampered_ciphertext() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888");
        let plaintext = b"Hello, AES-GCM!";

        let mut encrypted = aes_gcm_encrypt(&key, &iv, plaintext, &[]).unwrap();
        // Tamper with ciphertext (flip a bit in first byte)
        encrypted[0] ^= 0x01;
        let result = aes_gcm_decrypt(&key, &iv, &encrypted, &[]);
        assert!(result.is_err());
        match result.unwrap_err() {
            PrimitivesError::DecryptionFailed => {}
            e => panic!("Expected DecryptionFailed, got {e:?}"),
        }
    }

    #[test]
    fn test_aes_gcm_tampered_tag() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888");
        let plaintext = b"Hello, AES-GCM!";

        let mut encrypted = aes_gcm_encrypt(&key, &iv, plaintext, &[]).unwrap();
        // Tamper with auth tag (last byte)
        let len = encrypted.len();
        encrypted[len - 1] ^= 0x01;
        let result = aes_gcm_decrypt(&key, &iv, &encrypted, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_wrong_aad() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888");
        let plaintext = b"Hello, AES-GCM!";
        let aad = b"correct aad";

        let encrypted = aes_gcm_encrypt(&key, &iv, plaintext, aad).unwrap();
        // Try to decrypt with wrong AAD
        let result = aes_gcm_decrypt(&key, &iv, &encrypted, b"wrong aad");
        assert!(result.is_err());
    }

    // --- TS SDK compatibility tests ---

    #[test]
    fn test_aes_gcm_ts_compat_roundtrip() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888cafebabefacedbaddecaf888cafebabefacedbad");
        let plaintext = b"TS SDK compatible encryption";

        let encrypted = aes_gcm_encrypt_ts_compat(&key, &iv, plaintext).unwrap();
        let decrypted = aes_gcm_decrypt_ts_compat(&key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_ts_compat_tampered() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888cafebabefacedbaddecaf888cafebabefacedbad");
        let plaintext = b"TS SDK compatible encryption";

        let mut encrypted = aes_gcm_encrypt_ts_compat(&key, &iv, plaintext).unwrap();
        encrypted[0] ^= 0x01;
        let result = aes_gcm_decrypt_ts_compat(&key, &iv, &encrypted);
        assert!(result.is_err());
    }

    // --- GHASH unit tests ---

    #[test]
    fn test_ghash_zero_input() {
        let h = [0u8; 16];
        let input = [0u8; 16];
        let result = ghash(&h, &input);
        assert_eq!(result, [0u8; 16]);
    }

    #[test]
    fn test_gf128_multiply_identity() {
        // Multiplying by zero should give zero
        let a = [0x01u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let b = [0u8; 16];
        let result = gf128_multiply(&a, &b);
        assert_eq!(result, [0u8; 16]);
    }

    // --- Counter tests ---

    #[test]
    fn test_counter_increment() {
        let counter = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let next = increment_counter(&counter);
        assert_eq!(next[15], 2);
        assert_eq!(next[14], 0);
    }

    #[test]
    fn test_counter_increment_wrap() {
        // Counter wraps from 0xFFFFFFFF to 0x00000000
        let counter = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        let next = increment_counter(&counter);
        assert_eq!(next[12], 0);
        assert_eq!(next[13], 0);
        assert_eq!(next[14], 0);
        assert_eq!(next[15], 0);
        // Upper bytes unchanged
        assert_eq!(next[11], 0);
    }

    // --- Error handling tests ---

    #[test]
    fn test_aes_gcm_invalid_key_length() {
        let result = aes_gcm_encrypt(&[0u8; 24], &[0u8; 12], b"test", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_empty_iv() {
        let result = aes_gcm_encrypt(&[0u8; 16], &[], b"test", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_decrypt_too_short() {
        // Ciphertext must be at least 16 bytes (tag only)
        let result = aes_gcm_decrypt(&[0u8; 16], &[0u8; 12], &[0u8; 15], &[]);
        assert!(result.is_err());
    }

    // --- Various plaintext lengths ---

    #[test]
    fn test_aes_gcm_various_lengths() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888");

        for len in [1, 15, 16, 17, 31, 32, 33, 64, 100] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            let encrypted = aes_gcm_encrypt(&key, &iv, &plaintext, &[]).unwrap();
            assert_eq!(
                encrypted.len(),
                plaintext.len() + 16,
                "Encrypted length wrong for pt len {len}"
            );
            let decrypted = aes_gcm_decrypt(&key, &iv, &encrypted, &[]).unwrap();
            assert_eq!(
                decrypted, plaintext,
                "Round-trip failed for plaintext length {len}"
            );
        }
    }

    #[test]
    fn test_aes256_gcm_with_32byte_iv_various() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_bytes("cafebabefacedbaddecaf888cafebabefacedbaddecaf888cafebabefacedbad");

        for len in [0, 1, 16, 32, 48, 64] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            let encrypted = aes_gcm_encrypt(&key, &iv, &plaintext, &[]).unwrap();
            let decrypted = aes_gcm_decrypt(&key, &iv, &encrypted, &[]).unwrap();
            assert_eq!(
                decrypted, plaintext,
                "32-byte IV round-trip failed for pt len {len}"
            );
        }
    }
}
