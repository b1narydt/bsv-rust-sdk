//! AES-CBC mode encryption and decryption with PKCS7 padding.
//!
//! Follows the Go SDK's clean AES-CBC implementation.

use crate::primitives::aes::{aes_decrypt_block, aes_encrypt_block, aes_key_expansion};
use crate::primitives::PrimitivesError;

/// PKCS7 pad data to the given block size.
/// Always adds at least 1 byte of padding (if data is already aligned, a full padding block is added).
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding = block_size - (data.len() % block_size);
    let mut result = Vec::with_capacity(data.len() + padding);
    result.extend_from_slice(data);
    result.extend(std::iter::repeat_n(padding as u8, padding));
    result
}

/// PKCS7 unpad data. Returns an error if padding is invalid.
pub fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>, PrimitivesError> {
    let length = data.len();

    // Data must be non-empty and aligned to block size
    if length == 0 || !length.is_multiple_of(block_size) {
        return Err(PrimitivesError::InvalidPadding);
    }

    // Get padding length from last byte
    let padding = data[length - 1] as usize;

    // Padding value must be between 1 and block_size
    if padding == 0 || padding > block_size {
        return Err(PrimitivesError::InvalidPadding);
    }

    // Check that padding doesn't exceed data length
    if padding > length {
        return Err(PrimitivesError::InvalidPadding);
    }

    // Verify all padding bytes are consistent
    for &b in &data[length - padding..] {
        if b as usize != padding {
            return Err(PrimitivesError::InvalidPadding);
        }
    }

    Ok(data[..length - padding].to_vec())
}

/// Encrypt plaintext using AES-CBC mode with PKCS7 padding.
///
/// # Arguments
/// * `key` - AES key (16 or 32 bytes)
/// * `iv` - Initialization vector (16 bytes)
/// * `plaintext` - Data to encrypt (any length)
///
/// # Returns
/// Ciphertext (always a multiple of 16 bytes)
pub fn aes_cbc_encrypt(
    key: &[u8],
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, PrimitivesError> {
    if key.len() != 16 && key.len() != 32 {
        return Err(PrimitivesError::InvalidLength(format!(
            "AES key must be 16 or 32 bytes, got {}",
            key.len()
        )));
    }

    let round_keys = aes_key_expansion(key)?;
    let padded = pkcs7_pad(plaintext, 16);
    let num_blocks = padded.len() / 16;
    let mut ciphertext = Vec::with_capacity(padded.len());

    let mut prev_block = *iv;

    for i in 0..num_blocks {
        let start = i * 16;
        let mut block = [0u8; 16];
        for j in 0..16 {
            block[j] = padded[start + j] ^ prev_block[j];
        }
        let encrypted = aes_encrypt_block(&block, &round_keys);
        ciphertext.extend_from_slice(&encrypted);
        prev_block = encrypted;
    }

    Ok(ciphertext)
}

/// Decrypt ciphertext using AES-CBC mode, removing PKCS7 padding.
///
/// # Arguments
/// * `key` - AES key (16 or 32 bytes)
/// * `iv` - Initialization vector (16 bytes)
/// * `ciphertext` - Data to decrypt (must be a multiple of 16 bytes)
///
/// # Returns
/// Decrypted plaintext with padding removed
pub fn aes_cbc_decrypt(
    key: &[u8],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PrimitivesError> {
    if key.len() != 16 && key.len() != 32 {
        return Err(PrimitivesError::InvalidLength(format!(
            "AES key must be 16 or 32 bytes, got {}",
            key.len()
        )));
    }

    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(PrimitivesError::DecryptionFailed);
    }

    let round_keys = aes_key_expansion(key)?;
    let num_blocks = ciphertext.len() / 16;
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    let mut prev_block: [u8; 16] = *iv;

    for i in 0..num_blocks {
        let start = i * 16;
        // SAFETY: slice is exactly 16 bytes, guaranteed by length check above and loop bounds
        let ct_block: [u8; 16] = ciphertext[start..start + 16]
            .try_into()
            .map_err(|_| PrimitivesError::DecryptionFailed)?;
        let decrypted = aes_decrypt_block(&ct_block, &round_keys);
        let mut plain_block = [0u8; 16];
        for j in 0..16 {
            plain_block[j] = decrypted[j] ^ prev_block[j];
        }
        plaintext.extend_from_slice(&plain_block);
        prev_block = ct_block;
    }

    pkcs7_unpad(&plaintext, 16)
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

    // --- PKCS7 tests ---

    #[test]
    fn test_pkcs7_pad_16_bytes() {
        // 16 bytes input should produce 32 bytes (full padding block appended)
        let data = vec![0x01u8; 16];
        let padded = pkcs7_pad(&data, 16);
        assert_eq!(padded.len(), 32);
        // Last 16 bytes should all be 0x10 (16)
        for &b in &padded[16..] {
            assert_eq!(b, 16);
        }
    }

    #[test]
    fn test_pkcs7_pad_15_bytes() {
        let data = vec![0x01u8; 15];
        let padded = pkcs7_pad(&data, 16);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[15], 1); // 1 byte of padding
    }

    #[test]
    fn test_pkcs7_pad_1_byte() {
        let data = vec![0xaa];
        let padded = pkcs7_pad(&data, 16);
        assert_eq!(padded.len(), 16);
        for &b in &padded[1..] {
            assert_eq!(b, 15); // 15 bytes of padding
        }
    }

    #[test]
    fn test_pkcs7_pad_empty() {
        let data: Vec<u8> = vec![];
        let padded = pkcs7_pad(&data, 16);
        assert_eq!(padded.len(), 16);
        for &b in &padded {
            assert_eq!(b, 16);
        }
    }

    #[test]
    fn test_pkcs7_unpad_valid() {
        let mut data = vec![0x01u8; 15];
        data.push(0x01); // 1 byte padding
        let result = pkcs7_unpad(&data, 16).unwrap();
        assert_eq!(result.len(), 15);
    }

    #[test]
    fn test_pkcs7_unpad_invalid_padding_byte() {
        // Last byte says 3, but not all 3 bytes match
        let mut data = vec![0x00u8; 16];
        data[15] = 0x03;
        data[14] = 0x03;
        data[13] = 0x02; // inconsistent
        let result = pkcs7_unpad(&data, 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkcs7_unpad_not_aligned() {
        let data = vec![0x00u8; 15]; // not aligned to 16
        let result = pkcs7_unpad(&data, 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkcs7_unpad_zero_padding() {
        let mut data = vec![0x00u8; 16];
        data[15] = 0x00; // padding = 0 is invalid
        let result = pkcs7_unpad(&data, 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkcs7_unpad_padding_too_large() {
        let mut data = vec![0x00u8; 16];
        data[15] = 0x11; // padding = 17 > block_size
        let result = pkcs7_unpad(&data, 16);
        assert!(result.is_err());
    }

    // --- AES-CBC round-trip tests ---

    #[test]
    fn test_aes_cbc_roundtrip_16_bytes() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plaintext = vec![0x42u8; 16];

        let ct = aes_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_cbc_roundtrip_15_bytes() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plaintext = vec![0x42u8; 15];

        let ct = aes_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_cbc_roundtrip_32_bytes() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plaintext = vec![0x42u8; 32];

        let ct = aes_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_cbc_roundtrip_various_lengths() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();

        for len in [0, 1, 15, 16, 17, 31, 32, 33] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            let ct = aes_cbc_encrypt(&key, &iv, &plaintext).unwrap();
            let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
            assert_eq!(pt, plaintext, "Round-trip failed for length {len}");
        }
    }

    // --- NIST SP 800-38A test vectors ---

    #[test]
    fn test_aes128_cbc_nist_sp800_38a() {
        // NIST SP 800-38A F.2.1 - AES-128-CBC
        // NOTE: These are raw CBC vectors without PKCS7 padding.
        // The plaintext is exactly 4 blocks (64 bytes), so we test the raw CBC behavior
        // by encrypting without padding and checking against expected ciphertext.
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        let expected_ct = hex_to_bytes("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");

        // Use raw CBC encrypt (without PKCS7, manually handle blocks)
        let round_keys = aes_key_expansion(&key).unwrap();
        let mut ciphertext = Vec::new();
        let mut prev = iv;
        for i in 0..4 {
            let start = i * 16;
            let mut block = [0u8; 16];
            for j in 0..16 {
                block[j] = plaintext[start + j] ^ prev[j];
            }
            let encrypted = crate::primitives::aes::aes_encrypt_block(&block, &round_keys);
            ciphertext.extend_from_slice(&encrypted);
            prev = encrypted;
        }

        assert_eq!(
            bytes_to_hex(&ciphertext),
            bytes_to_hex(&expected_ct),
            "AES-128-CBC NIST SP 800-38A F.2.1 failed"
        );
    }

    #[test]
    fn test_aes256_cbc_nist_sp800_38a() {
        // NIST SP 800-38A F.2.5 - AES-256-CBC
        let key = hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        let expected_ct = hex_to_bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b");

        let round_keys = aes_key_expansion(&key).unwrap();
        let mut ciphertext = Vec::new();
        let mut prev = iv;
        for i in 0..4 {
            let start = i * 16;
            let mut block = [0u8; 16];
            for j in 0..16 {
                block[j] = plaintext[start + j] ^ prev[j];
            }
            let encrypted = crate::primitives::aes::aes_encrypt_block(&block, &round_keys);
            ciphertext.extend_from_slice(&encrypted);
            prev = encrypted;
        }

        assert_eq!(
            bytes_to_hex(&ciphertext),
            bytes_to_hex(&expected_ct),
            "AES-256-CBC NIST SP 800-38A F.2.5 failed"
        );
    }

    #[test]
    fn test_aes_cbc_with_pkcs7_roundtrip_nist_data() {
        // Use NIST plaintext but through our PKCS7-enabled encrypt/decrypt
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

        let ct = aes_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        // PKCS7 adds a full padding block since plaintext is 64 bytes (aligned)
        assert_eq!(ct.len(), 80); // 64 + 16 padding block
        let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_cbc_decrypt_invalid_ciphertext_length() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = [0u8; 16];
        let ct = vec![0u8; 15]; // not aligned
        let result = aes_cbc_decrypt(&key, &iv, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_cbc_invalid_key_length() {
        let key = vec![0u8; 24]; // 24 bytes, not supported
        let iv = [0u8; 16];
        let result = aes_cbc_encrypt(&key, &iv, b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn test_aes256_cbc_roundtrip() {
        let key = hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv: [u8; 16] = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plaintext = b"Hello AES-256-CBC world!";

        let ct = aes_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }
}
