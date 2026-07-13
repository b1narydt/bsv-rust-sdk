//! Utility functions shared across primitive modules.
//!
//! Includes hex encoding/decoding, Base58 encoding/decoding,
//! and Base58Check encoding/decoding with checksum verification.

use super::error::PrimitivesError;
use super::hash::hash256;

/// Base58 alphabet used by Bitcoin.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes as a hexadecimal string.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hexadecimal string into bytes.
pub fn from_hex(hex: &str) -> Result<Vec<u8>, PrimitivesError> {
    if !hex.len().is_multiple_of(2) {
        return Err(PrimitivesError::InvalidHex(
            "odd length hex string".to_string(),
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| {
                PrimitivesError::InvalidHex(format!("invalid hex char at position {i}: {e}"))
            })
        })
        .collect()
}

/// Encode bytes to a Base58 string.
///
/// Leading zero bytes in the input are preserved as '1' characters
/// in the output, following the Bitcoin Base58 convention.
pub fn base58_encode(data: &[u8]) -> String {
    // Count leading zeros
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert bytes to base58 using repeated division
    // We work with a mutable copy of the data as big-endian number
    let mut result: Vec<u8> = Vec::new();

    for &byte in data.iter() {
        let mut carry = byte as u32;
        for digit in result.iter_mut() {
            let x = (*digit as u32) * 256 + carry;
            *digit = (x % 58) as u8;
            carry = x / 58;
        }
        while carry > 0 {
            result.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    // Build result string
    let mut s = String::with_capacity(leading_zeros + result.len());

    // Add '1' for each leading zero byte
    for _ in 0..leading_zeros {
        s.push('1');
    }

    // Convert base58 digits to characters (result is in reverse order)
    for &digit in result.iter().rev() {
        s.push(BASE58_ALPHABET[digit as usize] as char);
    }

    s
}

/// Decode a Base58 string to bytes.
///
/// Leading '1' characters in the input are converted back to zero bytes.
pub fn base58_decode(s: &str) -> Result<Vec<u8>, PrimitivesError> {
    if s.is_empty() {
        return Err(PrimitivesError::InvalidFormat(
            "empty base58 string".to_string(),
        ));
    }

    // Build reverse lookup table
    let mut alphabet_map = [255u8; 128];
    for (i, &ch) in BASE58_ALPHABET.iter().enumerate() {
        alphabet_map[ch as usize] = i as u8;
    }

    // Count leading '1' characters (zero bytes)
    let leading_ones = s.chars().take_while(|&c| c == '1').count();

    // Estimate output size
    let size = ((s.len() - leading_ones) as f64 * (58.0_f64.ln() / 256.0_f64.ln()) + 1.0) as usize;
    let mut result = vec![0u8; size];

    for ch in s.chars() {
        let ch_val = ch as usize;
        if ch_val >= 128 || alphabet_map[ch_val] == 255 {
            return Err(PrimitivesError::InvalidFormat(format!(
                "invalid base58 character: {ch}"
            )));
        }
        let mut carry = alphabet_map[ch_val] as u32;
        for byte in result.iter_mut() {
            let x = (*byte as u32) * 58 + carry;
            *byte = (x & 0xff) as u8;
            carry = x >> 8;
        }
    }

    // Remove leading zeros from the result (which is in reverse order)
    result.reverse();
    let skip = result.iter().take_while(|&&b| b == 0).count();
    let result = &result[skip..];

    // Prepend leading zero bytes
    let mut output = vec![0u8; leading_ones];
    output.extend_from_slice(result);

    Ok(output)
}

/// Encode data with a prefix using Base58Check (includes 4-byte checksum).
///
/// Format: Base58(prefix || payload || checksum)
/// where checksum = hash256(prefix || payload)[0..4]
pub fn base58_check_encode(payload: &[u8], prefix: &[u8]) -> String {
    let mut data = Vec::with_capacity(prefix.len() + payload.len() + 4);
    data.extend_from_slice(prefix);
    data.extend_from_slice(payload);

    let checksum = hash256(&data);
    data.extend_from_slice(&checksum[..4]);

    base58_encode(&data)
}

/// Decode a Base58Check string, verifying the checksum.
///
/// Returns (prefix, payload) on success.
/// The prefix_length parameter specifies how many bytes of prefix to expect.
pub fn base58_check_decode(
    s: &str,
    prefix_length: usize,
) -> Result<(Vec<u8>, Vec<u8>), PrimitivesError> {
    let bin = base58_decode(s)?;

    if bin.len() < prefix_length + 4 {
        return Err(PrimitivesError::InvalidFormat(
            "base58check data too short".to_string(),
        ));
    }

    let prefix = bin[..prefix_length].to_vec();
    let payload = bin[prefix_length..bin.len() - 4].to_vec();
    let checksum = &bin[bin.len() - 4..];

    // Verify checksum
    let mut hash_input = Vec::with_capacity(prefix.len() + payload.len());
    hash_input.extend_from_slice(&prefix);
    hash_input.extend_from_slice(&payload);
    let expected_checksum = hash256(&hash_input);

    if checksum != &expected_checksum[..4] {
        return Err(PrimitivesError::ChecksumMismatch);
    }

    Ok((prefix, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Hex utilities
    // -----------------------------------------------------------------------

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let data = vec![0x00, 0x01, 0xff, 0xab, 0xcd];
        let hex = to_hex(&data);
        assert_eq!(hex, "0001ffabcd");
        let decoded = from_hex(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_empty() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_hex_odd_length() {
        assert!(from_hex("abc").is_err());
    }

    #[test]
    fn test_hex_invalid_char() {
        assert!(from_hex("gg").is_err());
    }

    // -----------------------------------------------------------------------
    // Base58
    // -----------------------------------------------------------------------

    #[test]
    fn test_base58_encode_known_vector() {
        // "Hello World" in base58
        let data = b"Hello World";
        let encoded = base58_encode(data);
        assert_eq!(encoded, "JxF12TrwUP45BMd");
    }

    #[test]
    fn test_base58_decode_known_vector() {
        let decoded = base58_decode("JxF12TrwUP45BMd").unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_base58_roundtrip() {
        let test_cases: Vec<&[u8]> =
            vec![b"", &[0], &[0, 0, 0], &[0, 0, 0, 1], b"test", &[0xff; 32]];
        // Note: empty string decodes/encodes specially
        for data in test_cases.iter().skip(1) {
            let encoded = base58_encode(data);
            let decoded = base58_decode(&encoded).unwrap();
            assert_eq!(&decoded, data, "Base58 roundtrip failed for {data:?}");
        }
    }

    #[test]
    fn test_base58_leading_zeros() {
        // Leading zero bytes should map to '1' characters
        let data = vec![0, 0, 0, 1];
        let encoded = base58_encode(&data);
        assert!(
            encoded.starts_with("111"),
            "Expected 3 leading '1's for 3 leading zero bytes, got: {encoded}"
        );
        let decoded = base58_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base58_invalid_char() {
        // '0', 'O', 'I', 'l' are not in Base58 alphabet
        assert!(base58_decode("0abc").is_err());
        assert!(base58_decode("Oabc").is_err());
        assert!(base58_decode("Iabc").is_err());
        assert!(base58_decode("labc").is_err());
    }

    // -----------------------------------------------------------------------
    // Base58Check
    // -----------------------------------------------------------------------

    #[test]
    fn test_base58_check_encode_decode_roundtrip() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let prefix = vec![0x00];

        let encoded = base58_check_encode(&payload, &prefix);
        let (dec_prefix, dec_payload) = base58_check_decode(&encoded, 1).unwrap();

        assert_eq!(dec_prefix, prefix);
        assert_eq!(dec_payload, payload);
    }

    #[test]
    fn test_base58_check_bad_checksum() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let prefix = vec![0x00];

        let encoded = base58_check_encode(&payload, &prefix);

        // Tamper with the encoded string by changing last character
        let mut chars: Vec<char> = encoded.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '1' { '2' } else { '1' };
        let tampered: String = chars.into_iter().collect();

        assert!(
            base58_check_decode(&tampered, 1).is_err(),
            "Should fail with tampered checksum"
        );
    }

    #[test]
    fn test_base58_check_wif_known_vector() {
        // Known WIF: private key = 1
        // hex private key: 0000000000000000000000000000000000000000000000000000000000000001
        // mainnet WIF (compressed): KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let result = base58_check_decode(wif, 1);
        assert!(result.is_ok(), "Known WIF should decode successfully");
        let (prefix, payload) = result.unwrap();
        assert_eq!(prefix, vec![0x80]);
        // payload = 32-byte key + 0x01 compression flag = 33 bytes
        assert_eq!(payload.len(), 33);
        // Key should be 0x01 (32 bytes zero-padded)
        assert_eq!(payload[..31], vec![0u8; 31]);
        assert_eq!(payload[31], 1);
        // Compression flag
        assert_eq!(payload[32], 1);
    }

    #[test]
    fn test_base58_check_encode_wif() {
        // Encode private key 1 as WIF
        let mut key_data = vec![0u8; 32];
        key_data[31] = 1;
        key_data.push(0x01); // compression flag
        let prefix = vec![0x80];

        let wif = base58_check_encode(&key_data, &prefix);
        assert_eq!(wif, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
    }
}
