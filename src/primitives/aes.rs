//! Core AES block cipher implementation (FIPS 197).
//!
//! Provides AES-128 and AES-256 block encryption/decryption.
//! This is a from-scratch, table-based implementation intended for
//! functional correctness and portability. Not constant-time.

use crate::primitives::PrimitivesError;

// AES S-box (SubBytes lookup table)
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// AES inverse S-box (InvSubBytes lookup table)
#[rustfmt::skip]
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// Round constants for key expansion
#[rustfmt::skip]
const RCON: [u32; 11] = [
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1b000000,
    0x36000000,
];

/// AES key with precomputed round keys.
pub struct AesKey {
    /// Expanded round keys as u32 words.
    pub round_keys: Vec<u32>,
    /// Number of rounds (10 for AES-128, 14 for AES-256).
    pub rounds: usize,
}

impl AesKey {
    /// Create a new AES key from raw bytes (16 or 32 bytes).
    pub fn new(key: &[u8]) -> Result<Self, PrimitivesError> {
        let rounds = match key.len() {
            16 => 10,
            32 => 14,
            _ => {
                return Err(PrimitivesError::InvalidLength(format!(
                    "AES key must be 16 or 32 bytes, got {}",
                    key.len()
                )))
            }
        };
        let round_keys = aes_key_expansion(key)?;
        Ok(AesKey { round_keys, rounds })
    }

    /// Encrypt a single 16-byte block.
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_encrypt_block(block, &self.round_keys)
    }

    /// Decrypt a single 16-byte block.
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        aes_decrypt_block(block, &self.round_keys)
    }
}

/// Multiply by 2 in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1.
#[inline]
fn xtime(a: u8) -> u8 {
    let shifted = (a as u16) << 1;
    let mask = if a & 0x80 != 0 { 0x1b } else { 0x00 };
    (shifted as u8) ^ mask
}

/// Multiply two bytes in GF(2^8).
#[inline]
fn gmul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut aa = a;
    let mut bb = b;
    for _ in 0..8 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        aa = xtime(aa);
        bb >>= 1;
    }
    result
}

/// SubWord: apply S-box to each byte of a 32-bit word.
#[inline]
fn sub_word(w: u32) -> u32 {
    let b0 = SBOX[((w >> 24) & 0xff) as usize] as u32;
    let b1 = SBOX[((w >> 16) & 0xff) as usize] as u32;
    let b2 = SBOX[((w >> 8) & 0xff) as usize] as u32;
    let b3 = SBOX[(w & 0xff) as usize] as u32;
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

/// RotWord: rotate a 32-bit word left by one byte.
#[inline]
fn rot_word(w: u32) -> u32 {
    w.rotate_left(8)
}

/// AES key expansion. Accepts 16-byte (AES-128) or 32-byte (AES-256) keys.
/// Returns the expanded round key words.
pub fn aes_key_expansion(key: &[u8]) -> Result<Vec<u32>, PrimitivesError> {
    let nk = key.len() / 4; // Number of 32-bit words in key (4 or 8)
    let nr = match nk {
        4 => 10,
        8 => 14,
        _ => {
            return Err(PrimitivesError::InvalidLength(format!(
                "invalid AES key length: {} bytes (expected 16 or 32)",
                key.len()
            )))
        }
    };
    let total_words = 4 * (nr + 1);

    let mut w = Vec::with_capacity(total_words);

    // Copy key bytes into initial words
    for i in 0..nk {
        let word = ((key[4 * i] as u32) << 24)
            | ((key[4 * i + 1] as u32) << 16)
            | ((key[4 * i + 2] as u32) << 8)
            | (key[4 * i + 3] as u32);
        w.push(word);
    }

    // Expand
    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp)) ^ RCON[i / nk];
        } else if nk > 6 && (i % nk) == 4 {
            temp = sub_word(temp);
        }
        w.push(w[i - nk] ^ temp);
    }

    Ok(w)
}

/// Encrypt a single 16-byte block using AES.
/// `round_keys` must be the output of `aes_key_expansion`.
pub fn aes_encrypt_block(block: &[u8; 16], round_keys: &[u32]) -> [u8; 16] {
    let nr = (round_keys.len() / 4) - 1; // number of rounds

    // Load state in column-major order (state[col][row])
    let mut state = [[0u8; 4]; 4];
    for c in 0..4 {
        for r in 0..4 {
            state[c][r] = block[c * 4 + r];
        }
    }

    // Initial AddRoundKey
    add_round_key(&mut state, round_keys, 0);

    // Main rounds
    for round in 1..nr {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_keys, round);
    }

    // Final round (no MixColumns)
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, round_keys, nr);

    // Output
    let mut output = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            output[c * 4 + r] = state[c][r];
        }
    }
    output
}

/// Decrypt a single 16-byte block using AES.
/// `round_keys` must be the output of `aes_key_expansion`.
pub fn aes_decrypt_block(block: &[u8; 16], round_keys: &[u32]) -> [u8; 16] {
    let nr = (round_keys.len() / 4) - 1;

    // Load state in column-major order
    let mut state = [[0u8; 4]; 4];
    for c in 0..4 {
        for r in 0..4 {
            state[c][r] = block[c * 4 + r];
        }
    }

    // Initial AddRoundKey (last round key)
    add_round_key(&mut state, round_keys, nr);

    // Main rounds in reverse
    for round in (1..nr).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, round_keys, round);
        inv_mix_columns(&mut state);
    }

    // Final round (no InvMixColumns)
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, round_keys, 0);

    // Output
    let mut output = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            output[c * 4 + r] = state[c][r];
        }
    }
    output
}

// --- Internal AES transformations ---

/// AddRoundKey: XOR state with round key words.
#[inline]
fn add_round_key(state: &mut [[u8; 4]; 4], round_keys: &[u32], round: usize) {
    for c in 0..4 {
        let rk = round_keys[round * 4 + c];
        state[c][0] ^= ((rk >> 24) & 0xff) as u8;
        state[c][1] ^= ((rk >> 16) & 0xff) as u8;
        state[c][2] ^= ((rk >> 8) & 0xff) as u8;
        state[c][3] ^= (rk & 0xff) as u8;
    }
}

/// SubBytes: apply S-box to each byte.
#[inline]
fn sub_bytes(state: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        for r in 0..4 {
            state[c][r] = SBOX[state[c][r] as usize];
        }
    }
}

/// InvSubBytes: apply inverse S-box to each byte.
#[inline]
fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        for r in 0..4 {
            state[c][r] = INV_SBOX[state[c][r] as usize];
        }
    }
}

/// ShiftRows: cyclically shift rows of the state.
/// Row 0: no shift, Row 1: shift left 1, Row 2: shift left 2, Row 3: shift left 3.
/// State is stored column-major: state[col][row].
#[inline]
fn shift_rows(state: &mut [[u8; 4]; 4]) {
    // Row 1: shift left by 1
    let tmp = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = tmp;

    // Row 2: shift left by 2
    let tmp0 = state[0][2];
    let tmp1 = state[1][2];
    state[0][2] = state[2][2];
    state[1][2] = state[3][2];
    state[2][2] = tmp0;
    state[3][2] = tmp1;

    // Row 3: shift left by 3 (= shift right by 1)
    let tmp = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = state[0][3];
    state[0][3] = tmp;
}

/// InvShiftRows: inverse of ShiftRows.
#[inline]
fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    // Row 1: shift right by 1
    let tmp = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = tmp;

    // Row 2: shift right by 2
    let tmp0 = state[0][2];
    let tmp1 = state[1][2];
    state[0][2] = state[2][2];
    state[1][2] = state[3][2];
    state[2][2] = tmp0;
    state[3][2] = tmp1;

    // Row 3: shift right by 3 (= shift left by 1)
    let tmp = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = tmp;
}

/// MixColumns: mix bytes within each column using GF(2^8) arithmetic.
#[inline]
#[allow(clippy::needless_range_loop)]
fn mix_columns(state: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        let s0 = state[c][0];
        let s1 = state[c][1];
        let s2 = state[c][2];
        let s3 = state[c][3];

        state[c][0] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
        state[c][1] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
        state[c][2] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
        state[c][3] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
    }
}

/// InvMixColumns: inverse of MixColumns.
#[inline]
#[allow(clippy::needless_range_loop)]
fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        let s0 = state[c][0];
        let s1 = state[c][1];
        let s2 = state[c][2];
        let s3 = state[c][3];

        state[c][0] = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09);
        state[c][1] = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d);
        state[c][2] = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b);
        state[c][3] = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e);
    }
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

    #[test]
    fn test_aes128_nist_fips197_appendix_b() {
        // NIST FIPS 197 Appendix B test vector
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let plaintext = hex_to_bytes("3243f6a8885a308d313198a2e0370734");
        let expected = hex_to_bytes("3925841d02dc09fbdc118597196a0b32");

        let round_keys = aes_key_expansion(&key).unwrap();
        let block: [u8; 16] = plaintext.try_into().unwrap();
        let result = aes_encrypt_block(&block, &round_keys);

        assert_eq!(
            bytes_to_hex(&result),
            bytes_to_hex(&expected),
            "AES-128 NIST FIPS 197 Appendix B failed"
        );
    }

    #[test]
    fn test_aes256_nist_fips197() {
        // NIST FIPS 197 Appendix C.3 - AES-256
        let key = hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
        let expected = hex_to_bytes("f3eed1bdb5d2a03c064b5a7e3db181f8");

        let round_keys = aes_key_expansion(&key).unwrap();
        let block: [u8; 16] = plaintext.try_into().unwrap();
        let result = aes_encrypt_block(&block, &round_keys);

        assert_eq!(
            bytes_to_hex(&result),
            bytes_to_hex(&expected),
            "AES-256 NIST test vector failed"
        );
    }

    #[test]
    fn test_aes128_encrypt_decrypt_roundtrip() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let plaintext = hex_to_bytes("3243f6a8885a308d313198a2e0370734");
        let round_keys = aes_key_expansion(&key).unwrap();

        let block: [u8; 16] = plaintext.clone().try_into().unwrap();
        let encrypted = aes_encrypt_block(&block, &round_keys);
        let decrypted = aes_decrypt_block(&encrypted, &round_keys);

        assert_eq!(
            &decrypted[..],
            &plaintext[..],
            "AES-128 encrypt+decrypt round-trip failed"
        );
    }

    #[test]
    fn test_aes256_encrypt_decrypt_roundtrip() {
        let key = hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
        let round_keys = aes_key_expansion(&key).unwrap();

        let block: [u8; 16] = plaintext.clone().try_into().unwrap();
        let encrypted = aes_encrypt_block(&block, &round_keys);
        let decrypted = aes_decrypt_block(&encrypted, &round_keys);

        assert_eq!(
            &decrypted[..],
            &plaintext[..],
            "AES-256 encrypt+decrypt round-trip failed"
        );
    }

    #[test]
    fn test_aes128_key_expansion_length() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let round_keys = aes_key_expansion(&key).unwrap();
        // AES-128: 10 rounds, 44 words total (4 * (10+1))
        assert_eq!(
            round_keys.len(),
            44,
            "AES-128 should produce 44 round key words"
        );
    }

    #[test]
    fn test_aes256_key_expansion_length() {
        let key = hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let round_keys = aes_key_expansion(&key).unwrap();
        // AES-256: 14 rounds, 60 words total (4 * (14+1))
        assert_eq!(
            round_keys.len(),
            60,
            "AES-256 should produce 60 round key words"
        );
    }

    #[test]
    fn test_aes_key_struct() {
        let key_bytes = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let aes_key = AesKey::new(&key_bytes).unwrap();
        assert_eq!(aes_key.rounds, 10);

        let plaintext: [u8; 16] = hex_to_bytes("3243f6a8885a308d313198a2e0370734")
            .try_into()
            .unwrap();
        let encrypted = aes_key.encrypt_block(&plaintext);
        let decrypted = aes_key.decrypt_block(&encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_key_invalid_length() {
        let result = AesKey::new(&[0u8; 24]);
        assert!(result.is_err());
    }
}
