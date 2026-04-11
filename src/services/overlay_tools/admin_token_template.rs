//! OverlayAdminTokenTemplate for SHIP/SLAP advertisement tokens.
//!
//! Translates the TS SDK OverlayAdminTokenTemplate.ts. Encodes and decodes
//! PushDrop-based tokens that advertise overlay service endpoints.

use crate::script::locking_script::LockingScript;
use crate::services::ServicesError;

/// Decoded SHIP or SLAP advertisement token.
#[derive(Debug, Clone, PartialEq)]
pub struct OverlayAdminTokenTemplate {
    /// Protocol type: "SHIP" or "SLAP".
    pub protocol: String,
    /// Hex-encoded identity public key.
    pub identity_key: String,
    /// Domain URL where the service is hosted.
    pub domain: String,
    /// Topic (for SHIP) or service (for SLAP) name.
    pub topic_or_service: String,
}

impl OverlayAdminTokenTemplate {
    /// Create a new admin token template.
    pub fn new(
        protocol: &str,
        identity_key: &str,
        domain: &str,
        topic_or_service: &str,
    ) -> Result<Self, ServicesError> {
        if protocol != "SHIP" && protocol != "SLAP" {
            return Err(ServicesError::Overlay(format!(
                "Invalid protocol: {} (expected SHIP or SLAP)",
                protocol
            )));
        }
        Ok(OverlayAdminTokenTemplate {
            protocol: protocol.to_string(),
            identity_key: identity_key.to_string(),
            domain: domain.to_string(),
            topic_or_service: topic_or_service.to_string(),
        })
    }

    /// Encode this template as a PushDrop locking script.
    ///
    /// Structure: `<protocol> <identityKey> <domain> <topicOrService> OP_2DROP OP_2DROP <pubkey> OP_CHECKSIG`
    ///
    /// Note: This creates a lock-only script (no signing key). For a full
    /// PushDrop with signing, use PushDrop::new() directly with the fields
    /// and a private key.
    pub fn encode_fields(&self) -> Vec<Vec<u8>> {
        vec![
            self.protocol.as_bytes().to_vec(),
            hex_decode(&self.identity_key).unwrap_or_default(),
            self.domain.as_bytes().to_vec(),
            self.topic_or_service.as_bytes().to_vec(),
        ]
    }

    /// Decode a SHIP or SLAP advertisement from a locking script.
    ///
    /// Extracts PushDrop data fields and parses them as an admin token.
    pub fn decode(script: &LockingScript) -> Result<Self, ServicesError> {
        let fields = extract_pushdrop_fields(script)?;
        if fields.len() < 4 {
            return Err(ServicesError::Overlay(
                "Invalid SHIP/SLAP advertisement: fewer than 4 fields".to_string(),
            ));
        }

        let protocol = String::from_utf8(fields[0].clone())
            .map_err(|_| ServicesError::Overlay("Invalid protocol field UTF-8".to_string()))?;

        if protocol != "SHIP" && protocol != "SLAP" {
            return Err(ServicesError::Overlay(format!(
                "Invalid protocol type: {}",
                protocol
            )));
        }

        let identity_key = hex_encode(&fields[1]);

        let domain = String::from_utf8(fields[2].clone())
            .map_err(|_| ServicesError::Overlay("Invalid domain field UTF-8".to_string()))?;

        let topic_or_service = String::from_utf8(fields[3].clone()).map_err(|_| {
            ServicesError::Overlay("Invalid topicOrService field UTF-8".to_string())
        })?;

        Ok(OverlayAdminTokenTemplate {
            protocol,
            identity_key,
            domain,
            topic_or_service,
        })
    }

    /// Decode from BEEF-encoded transaction bytes and a specific output index.
    ///
    /// The overlay lookup service returns BEEF-encoded transactions (not raw
    /// binary). This method hex-encodes the bytes and parses via
    /// `Transaction::from_beef` which handles the BEEF container format.
    ///
    /// Falls back to raw binary parsing if BEEF parsing fails, for backward
    /// compatibility with callers that pass raw transaction bytes.
    pub fn decode_from_beef(tx_bytes: &[u8], output_index: usize) -> Result<Self, ServicesError> {
        // Primary path: parse as BEEF (hex-encoded bytes → from_beef).
        let beef_hex: String = tx_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let tx = crate::transaction::Transaction::from_beef(&beef_hex)
            .or_else(|_| {
                // Fallback: try raw binary in case caller passed non-BEEF bytes.
                crate::transaction::Transaction::from_binary(&mut &tx_bytes[..])
            })
            .map_err(|e| ServicesError::Overlay(format!("Failed to parse transaction: {}", e)))?;

        let output = tx.outputs.get(output_index).ok_or_else(|| {
            ServicesError::Overlay(format!(
                "Output index {} out of range (tx has {} outputs)",
                output_index,
                tx.outputs.len()
            ))
        })?;

        Self::decode(&output.locking_script)
    }
}

/// Extract data fields from a PushDrop locking script.
///
/// PushDrop scripts have the locking pubkey at the start ("before" position):
///   `<lockingPubKey> OP_CHECKSIG <field0> <field1> ... <fieldN> [<signature>] OP_2DROP... OP_DROP`
///
/// Matches TS SDK `PushDrop.decode(script, 'before')` which skips the first
/// two chunks (pubkey + OP_CHECKSIG) and reads data pushes until the next
/// chunk is OP_DROP or OP_2DROP.
fn extract_pushdrop_fields(script: &LockingScript) -> Result<Vec<Vec<u8>>, ServicesError> {
    use crate::script::op::Op;

    let chunks = script.chunks();

    // Skip the locking pubkey (chunk 0) and OP_CHECKSIG (chunk 1).
    // The TS SDK does: startIndex = 2 when lockPosition === 'before'.
    let start = if chunks.len() >= 2
        && chunks[0].data.is_some()
        && chunks[1].op == Op::OpCheckSig
    {
        2
    } else {
        0
    };

    let mut fields = Vec::new();

    for i in start..chunks.len() {
        // Check if NEXT chunk is a DROP — if so, this is the last field.
        let next_is_drop = chunks.get(i + 1).map_or(false, |next| {
            next.op == Op::OpDrop || next.op == Op::Op2Drop
        });

        if let Some(ref data) = chunks[i].data {
            fields.push(data.clone());
        }

        if next_is_drop {
            break;
        }

        // Also stop if THIS chunk is a DROP (shouldn't happen in valid PushDrop
        // but prevents reading into the pubkey + CHECKSIG tail).
        if chunks[i].op == Op::OpDrop || chunks[i].op == Op::Op2Drop {
            break;
        }
    }

    Ok(fields)
}

/// Hex-encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hex-decode a string to bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>, ServicesError> {
    if !hex.len().is_multiple_of(2) {
        return Err(ServicesError::Serialization(
            "hex string has odd length".to_string(),
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| ServicesError::Serialization("invalid hex character".to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::private_key::PrivateKey;
    use crate::script::templates::push_drop::PushDrop;
    use crate::script::templates::ScriptTemplateLock;

    #[test]
    fn test_encode_decode_round_trip() {
        let template = OverlayAdminTokenTemplate::new(
            "SLAP",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "https://overlay.example.com",
            "ls_test_service",
        )
        .unwrap();

        // Create a PushDrop locking script with the fields.
        let key = PrivateKey::from_hex("1").unwrap();
        let pd = PushDrop::new(template.encode_fields(), key);
        let lock_script = pd.lock().unwrap();

        // Decode the locking script.
        let decoded = OverlayAdminTokenTemplate::decode(&lock_script).unwrap();
        assert_eq!(decoded.protocol, "SLAP");
        assert_eq!(
            decoded.identity_key,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(decoded.domain, "https://overlay.example.com");
        assert_eq!(decoded.topic_or_service, "ls_test_service");
    }

    #[test]
    fn test_encode_decode_ship_protocol() {
        let template = OverlayAdminTokenTemplate::new(
            "SHIP",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "https://host.example.com",
            "tm_test_topic",
        )
        .unwrap();

        let key = PrivateKey::from_hex("1").unwrap();
        let pd = PushDrop::new(template.encode_fields(), key);
        let lock_script = pd.lock().unwrap();

        let decoded = OverlayAdminTokenTemplate::decode(&lock_script).unwrap();
        assert_eq!(decoded, template);
    }

    #[test]
    fn test_invalid_protocol_rejected() {
        let result = OverlayAdminTokenTemplate::new("INVALID", "key", "domain", "service");
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_encode_decode_round_trip() {
        let original = vec![0xab, 0xcd, 0xef, 0x01];
        let hex = hex_encode(&original);
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, original);
    }

    #[tokio::test]
    #[ignore] // requires network
    async fn test_decode_production_slap_response() {
        let client = reqwest::Client::new();
        let resp = client.post("https://overlay-us-1.bsvb.tech/lookup")
            .json(&serde_json::json!({"service":"ls_slap","query":{"service":"ls_ship"}}))
            .send().await.expect("SLAP query");
        let data: serde_json::Value = resp.json().await.expect("parse JSON");
        let outputs = data["outputs"].as_array().expect("outputs array");
        assert!(!outputs.is_empty(), "should have SLAP outputs");
        
        let mut parsed_count = 0;
        for out in outputs {
            let beef: Vec<u8> = out["beef"].as_array().unwrap()
                .iter().map(|v| v.as_u64().unwrap() as u8).collect();
            let idx = out["outputIndex"].as_u64().unwrap() as usize;
            
            match OverlayAdminTokenTemplate::decode_from_beef(&beef, idx) {
                Ok(parsed) => {
                    eprintln!("  Parsed: {} {} {}", parsed.protocol, parsed.domain, parsed.topic_or_service);
                    parsed_count += 1;
                }
                Err(e) => {
                    eprintln!("  FAILED output idx={}: {} (beef len={}, first 20 bytes={:?})", idx, e, beef.len(), &beef[..20.min(beef.len())]);
                }
            }
        }
        assert!(parsed_count > 0, "should parse at least one SLAP entry");
    }
}
