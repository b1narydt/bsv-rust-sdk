//! BIP276 script encoding/decoding.
//!
//! Format: `{prefix}:{version_hex}{network_hex}{data_hex}{checksum_hex}`
//! where checksum is the first 4 bytes of hash256 of the payload (everything before checksum).
//! Translates the Go SDK bip276.go.

use crate::primitives::hash::hash256;
use crate::primitives::utils::{from_hex, to_hex};
use crate::script::error::ScriptError;
use crate::script::script::Script;

/// Default BIP276 prefix.
pub const BIP276_PREFIX: &str = "bitcoin-script";

/// Encode data in BIP276 format.
///
/// Format: `{prefix}:{version:02x}{network:02x}{data_hex}{checksum_hex}`
///
/// Version and network must be > 0.
pub fn encode_bip276(
    prefix: &str,
    version: u8,
    network: u8,
    data: &[u8],
) -> Result<String, ScriptError> {
    if version == 0 {
        return Err(ScriptError::InvalidFormat(
            "BIP276 version must be > 0".to_string(),
        ));
    }
    if network == 0 {
        return Err(ScriptError::InvalidFormat(
            "BIP276 network must be > 0".to_string(),
        ));
    }

    let data_hex = to_hex(data);
    let payload = format!("{prefix}:{version:02x}{network:02x}{data_hex}");

    let checksum = hash256(payload.as_bytes());
    let checksum_hex = to_hex(&checksum[..4]);

    Ok(format!("{payload}{checksum_hex}"))
}

/// Decode a BIP276 encoded string.
///
/// Returns (prefix, version, network, data_bytes) on success.
/// Validates the checksum against hash256.
pub fn decode_bip276(encoded: &str) -> Result<(String, u8, u8, Vec<u8>), ScriptError> {
    let colon_pos = encoded
        .find(':')
        .ok_or_else(|| ScriptError::InvalidFormat("BIP276: missing ':' separator".to_string()))?;

    let prefix = &encoded[..colon_pos];
    let rest = &encoded[colon_pos + 1..];

    // rest = version(2) + network(2) + data(variable) + checksum(8)
    if rest.len() < 12 {
        // minimum: 2 version + 2 network + 0 data + 8 checksum = 12
        return Err(ScriptError::InvalidFormat(
            "BIP276: encoded data too short".to_string(),
        ));
    }

    let version = u8::from_str_radix(&rest[..2], 16)
        .map_err(|_| ScriptError::InvalidFormat("BIP276: invalid version hex".to_string()))?;
    let network = u8::from_str_radix(&rest[2..4], 16)
        .map_err(|_| ScriptError::InvalidFormat("BIP276: invalid network hex".to_string()))?;

    // Last 8 hex chars are the checksum
    let checksum_hex = &encoded[encoded.len() - 8..];
    let payload = &encoded[..encoded.len() - 8];

    // Verify checksum
    let expected_checksum = hash256(payload.as_bytes());
    let expected_hex = to_hex(&expected_checksum[..4]);
    if checksum_hex != expected_hex {
        return Err(ScriptError::InvalidFormat(
            "BIP276: checksum mismatch".to_string(),
        ));
    }

    // Extract data hex (between network and checksum)
    let data_hex = &rest[4..rest.len() - 8];
    let data = if data_hex.is_empty() {
        Vec::new()
    } else {
        from_hex(data_hex)
            .map_err(|e| ScriptError::InvalidFormat(format!("BIP276: invalid data hex: {e}")))?
    };

    Ok((prefix.to_string(), version, network, data))
}

/// Convenience function: encode a Script in BIP276 format with standard prefix.
pub fn encode_script_bip276(script: &Script, network: u8) -> Result<String, ScriptError> {
    encode_bip276(BIP276_PREFIX, 1, network, &script.to_binary())
}

/// Convenience function: decode a BIP276 string expecting standard script prefix.
pub fn decode_script_bip276(encoded: &str) -> Result<Script, ScriptError> {
    let (prefix, _version, _network, data) = decode_bip276(encoded)?;
    if prefix != BIP276_PREFIX {
        return Err(ScriptError::InvalidFormat(format!(
            "BIP276: expected prefix '{BIP276_PREFIX}', got '{prefix}'"
        )));
    }
    Ok(Script::from_binary(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = vec![0x76, 0xa9, 0x14];
        let encoded = encode_bip276("bitcoin-script", 1, 1, &data).unwrap();

        let (prefix, version, network, decoded_data) = decode_bip276(&encoded).unwrap();
        assert_eq!(prefix, "bitcoin-script");
        assert_eq!(version, 1);
        assert_eq!(network, 1);
        assert_eq!(decoded_data, data);
    }

    #[test]
    fn test_encode_format() {
        let data = vec![0xab, 0xcd];
        let encoded = encode_bip276("bitcoin-script", 1, 2, &data).unwrap();

        // Should start with prefix:
        assert!(encoded.starts_with("bitcoin-script:"));
        // After colon: 01 (version) 02 (network) abcd (data) + 8 hex checksum
        let rest = &encoded["bitcoin-script:".len()..];
        assert!(rest.starts_with("0102abcd"));
        // Total rest length: 4 (version+network) + 4 (data) + 8 (checksum) = 16
        assert_eq!(rest.len(), 16);
    }

    #[test]
    fn test_invalid_checksum() {
        let data = vec![0x76, 0xa9];
        let mut encoded = encode_bip276("bitcoin-script", 1, 1, &data).unwrap();

        // Tamper with last character
        let len = encoded.len();
        let last = encoded.chars().last().unwrap();
        encoded.truncate(len - 1);
        encoded.push(if last == '0' { '1' } else { '0' });

        let result = decode_bip276(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_version_zero() {
        let result = encode_bip276("bitcoin-script", 0, 1, &[0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_network_zero() {
        let result = encode_bip276("bitcoin-script", 1, 0, &[0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_script_bip276_roundtrip() {
        // P2PKH-like script bytes
        let script = Script::from_binary(&[0x76, 0xa9, 0x14, 0xab, 0xab]);
        let encoded = encode_script_bip276(&script, 1).unwrap();
        let decoded = decode_script_bip276(&encoded).unwrap();
        assert_eq!(decoded.to_binary(), script.to_binary());
    }

    #[test]
    fn test_decode_wrong_prefix() {
        // Encode with a custom prefix, try to decode as script
        let encoded = encode_bip276("custom-prefix", 1, 1, &[0x01]).unwrap();
        let result = decode_script_bip276(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_data() {
        let encoded = encode_bip276("bitcoin-script", 1, 1, &[]).unwrap();
        let (_, _, _, data) = decode_bip276(&encoded).unwrap();
        assert!(data.is_empty());
    }
}
