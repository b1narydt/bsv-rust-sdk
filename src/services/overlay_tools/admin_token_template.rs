//! OverlayAdminTokenTemplate for SHIP/SLAP advertisement tokens.
//!
//! Translates the TS SDK OverlayAdminTokenTemplate.ts. Encodes and decodes
//! PushDrop-based tokens that advertise overlay service endpoints.

use crate::script::locking_script::LockingScript;
use crate::script::templates::push_drop::{LockPosition, PushDrop};
use crate::services::ServicesError;
use crate::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

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

    /// The BRC-43 protocol ID an advertisement is signed under, per TS
    /// `OverlayAdminTokenTemplate.lock`.
    fn advertisement_protocol(protocol: &str) -> Protocol {
        Protocol {
            security_level: 2,
            protocol: if protocol == "SHIP" {
                "Service Host Interconnect".to_string()
            } else {
                "Service Lookup Availability".to_string()
            },
        }
    }

    /// Mint a SHIP/SLAP advertisement locking script.
    ///
    /// Port of TS `OverlayAdminTokenTemplate.lock`. The identity key is the
    /// wallet's own (`getPublicKey({ identityKey: true })`), and the token is
    /// PushDrop-locked under protocol `[2, "Service Host Interconnect" |
    /// "Service Lookup Availability"]`, keyID `"1"`, counterparty `self`, with
    /// `include_signature` — so the advertisement carries FIVE fields, the fifth
    /// being the signature, exactly as overlays publish them.
    ///
    /// Rust previously had no `lock()` at all: it could decode advertisements but
    /// never mint one, so a Rust overlay node could not advertise itself. (The old
    /// doc here pointed callers at `PushDrop::new(fields, key)`, which locked to a
    /// RAW key and appended no signature — an advertisement no overlay would
    /// accept.)
    pub async fn lock<W: WalletInterface + ?Sized>(
        wallet: &W,
        originator: Option<String>,
        protocol: &str,
        domain: &str,
        topic_or_service: &str,
    ) -> Result<LockingScript, ServicesError> {
        if protocol != "SHIP" && protocol != "SLAP" {
            return Err(ServicesError::Overlay(format!(
                "Invalid protocol: {protocol} (expected SHIP or SLAP)"
            )));
        }

        let identity = wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Overlay(format!("getPublicKey(identityKey): {e}")))?;

        let fields = vec![
            protocol.as_bytes().to_vec(),
            identity.public_key.to_der(),
            domain.as_bytes().to_vec(),
            topic_or_service.as_bytes().to_vec(),
        ];

        PushDrop::new(wallet, originator)
            .lock(
                fields,
                Self::advertisement_protocol(protocol),
                "1",
                Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                false,
                true,
                LockPosition::Before,
            )
            .await
            .map_err(|e| ServicesError::Overlay(format!("PushDrop lock failed: {e}")))
    }

    /// Encode this template's four payload fields (protocol, identityKey, domain,
    /// topicOrService). The signature field is appended by [`Self::lock`].
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
    /// Uses the SDK's PushDrop::decode with "before" lock position (matching
    /// the TS SDK default). The PushDrop fields are [protocol, identityKey,
    /// domain, topicOrService, signature?].
    pub fn decode(script: &LockingScript) -> Result<Self, ServicesError> {
        let pd = crate::script::templates::push_drop::decode(script)
            .map_err(|e| ServicesError::Overlay(format!("PushDrop decode failed: {e}")))?;
        let fields = pd.fields;
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
    use crate::script::templates::push_drop::{LockPosition, PushDrop};
    use crate::wallet::proto_wallet::ProtoWallet;
    use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

    /// Build a PushDrop locking script the way production now does — through a
    /// wallet, with a derived key — so these tests exercise the real path.
    async fn test_lock(fields: Vec<Vec<u8>>) -> LockingScript {
        let w = ProtoWallet::new(PrivateKey::from_hex("1").unwrap());
        PushDrop::new(&w, None)
            .lock(
                fields,
                Protocol {
                    security_level: 2,
                    protocol: "overlay admin".to_string(),
                },
                "admin",
                Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                false,
                true,
                LockPosition::Before,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_encode_decode_round_trip() {
        let template = OverlayAdminTokenTemplate::new(
            "SLAP",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "https://overlay.example.com",
            "ls_test_service",
        )
        .unwrap();

        // Create a PushDrop locking script with the fields.
        let lock_script = test_lock(template.encode_fields()).await;

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

    #[tokio::test]
    async fn test_encode_decode_ship_protocol() {
        let template = OverlayAdminTokenTemplate::new(
            "SHIP",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "https://host.example.com",
            "tm_test_topic",
        )
        .unwrap();

        let lock_script = test_lock(template.encode_fields()).await;

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
        let resp = client
            .post("https://overlay-us-1.bsvb.tech/lookup")
            .json(&serde_json::json!({"service":"ls_slap","query":{"service":"ls_ship"}}))
            .send()
            .await
            .expect("SLAP query");
        let data: serde_json::Value = resp.json().await.expect("parse JSON");
        let outputs = data["outputs"].as_array().expect("outputs array");
        assert!(!outputs.is_empty(), "should have SLAP outputs");

        let mut parsed_count = 0;
        for out in outputs {
            let beef: Vec<u8> = out["beef"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect();
            let idx = out["outputIndex"].as_u64().unwrap() as usize;

            match OverlayAdminTokenTemplate::decode_from_beef(&beef, idx) {
                Ok(parsed) => {
                    eprintln!(
                        "  Parsed: {} {} {}",
                        parsed.protocol, parsed.domain, parsed.topic_or_service
                    );
                    parsed_count += 1;
                }
                Err(e) => {
                    eprintln!(
                        "  FAILED output idx={}: {} (beef len={}, first 20 bytes={:?})",
                        idx,
                        e,
                        beef.len(),
                        &beef[..20.min(beef.len())]
                    );
                }
            }
        }
        assert!(parsed_count > 0, "should parse at least one SLAP entry");
    }
}
