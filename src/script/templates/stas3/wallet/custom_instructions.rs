//! `CustomInstructions` — JSON shape stored in `customInstructions` for every
//! UTXO created or consumed by `Stas3Wallet` (spec §1A.4). Carries the
//! Type-42 triple so subsequent spends can re-derive the signing key via the
//! wallet.
//!
//! Manual JSON serialization (no `serde_json`) keeps this module available
//! when the `network` feature is off — the wrapper is intentionally usable
//! on the no-feature path.

use super::super::error::Stas3Error;
use super::super::key_triple::KeyTriple;
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

/// JSON shape stored in `customInstructions` for every UTXO this wrapper
/// creates or consumes (spec §1A.4). Carries the Type-42 triple so subsequent
/// spends can re-derive the signing key via the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomInstructions {
    /// Discriminator for higher-level handling. Conventional values:
    /// `"stas3-token"` for STAS-3 outputs, `"stas3-fuel"` for funding outputs.
    pub template: String,
    /// `(security_level, protocol_string)` — e.g. `(2, "stas3owner")`.
    pub protocol_id: (u8, String),
    pub key_id: String,
    /// Wire form: `"self"`, `"anyone"`, or DER-hex pubkey for `Other`.
    /// Currently only `self` and `anyone` round-trip; `Other` is rejected on
    /// `to_triple`.
    pub counterparty: String,
    /// Optional schema tag (e.g. `"EAC1"`). `None` is omitted from the JSON.
    pub schema: Option<String>,
}

impl CustomInstructions {
    /// Resolve the embedded triple back into a `KeyTriple` suitable for
    /// passing to a factory call. Returns `InvalidScript` if the
    /// `counterparty` string is not `"self"` or `"anyone"`.
    pub fn to_triple(&self) -> Result<KeyTriple, Stas3Error> {
        let cp = match self.counterparty.as_str() {
            "self" => Counterparty {
                counterparty_type: CounterpartyType::Self_,
                public_key: None,
            },
            "anyone" => Counterparty {
                counterparty_type: CounterpartyType::Anyone,
                public_key: None,
            },
            other => {
                return Err(Stas3Error::InvalidScript(format!(
                    "unsupported counterparty in customInstructions: {other:?} \
                     (only \"self\" and \"anyone\" are supported)"
                )));
            }
        };
        Ok(KeyTriple {
            protocol_id: Protocol {
                security_level: self.protocol_id.0,
                protocol: self.protocol_id.1.clone(),
            },
            key_id: self.key_id.clone(),
            counterparty: cp,
        })
    }

    /// Build a `CustomInstructions` from a triple. Used when registering a
    /// freshly-created STAS-3 output via `internalize_action`.
    pub fn from_triple(triple: &KeyTriple, template: &str, schema: Option<String>) -> Self {
        let cp_str = match triple.counterparty.counterparty_type {
            CounterpartyType::Self_ => "self".to_string(),
            CounterpartyType::Anyone => "anyone".to_string(),
            // Fallback — Other/Uninitialized are not yet supported by
            // to_triple, so we don't emit them here either.
            CounterpartyType::Other | CounterpartyType::Uninitialized => "self".to_string(),
        };
        Self {
            template: template.to_string(),
            protocol_id: (
                triple.protocol_id.security_level,
                triple.protocol_id.protocol.clone(),
            ),
            key_id: triple.key_id.clone(),
            counterparty: cp_str,
            schema,
        }
    }

    /// Serialize as the canonical JSON wire form (spec §1A.4). Manual encode
    /// to avoid pulling in `serde_json` on the no-feature path. Field order
    /// is fixed so byte equality round-trips for fixture comparison.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(160);
        s.push('{');
        s.push_str("\"template\":");
        push_json_string(&mut s, &self.template);
        s.push_str(",\"protocolID\":[");
        s.push_str(&self.protocol_id.0.to_string());
        s.push(',');
        push_json_string(&mut s, &self.protocol_id.1);
        s.push(']');
        s.push_str(",\"keyID\":");
        push_json_string(&mut s, &self.key_id);
        s.push_str(",\"counterparty\":");
        push_json_string(&mut s, &self.counterparty);
        if let Some(schema) = &self.schema {
            s.push_str(",\"schema\":");
            push_json_string(&mut s, schema);
        }
        s.push('}');
        s
    }

    /// Parse the JSON wire form. Tolerant of whitespace; rejects unknown
    /// counterparty strings on `to_triple`, not here.
    pub fn from_json(json: &str) -> Result<Self, Stas3Error> {
        let mut parser = JsonParser::new(json);
        let mut template = None;
        let mut protocol_id: Option<(u8, String)> = None;
        let mut key_id: Option<String> = None;
        let mut counterparty: Option<String> = None;
        let mut schema: Option<String> = None;

        parser.expect('{')?;
        if !parser.peek_is('}') {
            loop {
                let key = parser.read_string()?;
                parser.expect(':')?;
                match key.as_str() {
                    "template" => template = Some(parser.read_string()?),
                    "protocolID" => {
                        parser.expect('[')?;
                        let level: u8 = parser
                            .read_number()?
                            .parse()
                            .map_err(|e| Stas3Error::InvalidScript(format!("bad security_level: {e}")))?;
                        parser.expect(',')?;
                        let proto = parser.read_string()?;
                        parser.expect(']')?;
                        protocol_id = Some((level, proto));
                    }
                    "keyID" => key_id = Some(parser.read_string()?),
                    "counterparty" => counterparty = Some(parser.read_string()?),
                    "schema" => schema = Some(parser.read_string()?),
                    other => {
                        // Skip unknown values — be liberal in what we accept.
                        return Err(Stas3Error::InvalidScript(format!(
                            "unknown customInstructions field: {other}"
                        )));
                    }
                }
                if parser.peek_is(',') {
                    parser.expect(',')?;
                } else {
                    break;
                }
            }
        }
        parser.expect('}')?;

        Ok(Self {
            template: template
                .ok_or_else(|| Stas3Error::InvalidScript("missing template".into()))?,
            protocol_id: protocol_id
                .ok_or_else(|| Stas3Error::InvalidScript("missing protocolID".into()))?,
            key_id: key_id.ok_or_else(|| Stas3Error::InvalidScript("missing keyID".into()))?,
            counterparty: counterparty
                .ok_or_else(|| Stas3Error::InvalidScript("missing counterparty".into()))?,
            schema,
        })
    }
}

fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Minimal JSON micro-parser used only to read the well-known
/// `customInstructions` shape. Not a general JSON parser.
struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            bytes: s.as_bytes(),
            pos: 0,
        }
    }
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }
    fn peek_is(&mut self, c: char) -> bool {
        self.skip_ws();
        self.pos < self.bytes.len() && self.bytes[self.pos] == c as u8
    }
    fn expect(&mut self, c: char) -> Result<(), Stas3Error> {
        self.skip_ws();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == c as u8 {
            self.pos += 1;
            Ok(())
        } else {
            Err(Stas3Error::InvalidScript(format!(
                "expected {c:?} at byte {} in customInstructions JSON",
                self.pos
            )))
        }
    }
    fn read_string(&mut self) -> Result<String, Stas3Error> {
        self.skip_ws();
        if self.pos >= self.bytes.len() || self.bytes[self.pos] != b'"' {
            return Err(Stas3Error::InvalidScript(format!(
                "expected string at byte {} in customInstructions JSON",
                self.pos
            )));
        }
        self.pos += 1;
        let start = self.pos;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                if out.is_empty() {
                    out.push_str(std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|e| {
                        Stas3Error::InvalidScript(format!("non-utf8 in JSON string: {e}"))
                    })?);
                }
                self.pos += 1;
                return Ok(out);
            } else if b == b'\\' {
                // First time we see an escape, materialize what we've seen.
                if out.is_empty() {
                    out.push_str(std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|e| {
                        Stas3Error::InvalidScript(format!("non-utf8 in JSON string: {e}"))
                    })?);
                }
                self.pos += 1;
                if self.pos >= self.bytes.len() {
                    return Err(Stas3Error::InvalidScript("trailing backslash".into()));
                }
                match self.bytes[self.pos] {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    other => {
                        return Err(Stas3Error::InvalidScript(format!(
                            "unsupported JSON escape \\{}",
                            other as char
                        )))
                    }
                }
                self.pos += 1;
            } else {
                if !out.is_empty() {
                    out.push(b as char);
                }
                self.pos += 1;
            }
        }
        Err(Stas3Error::InvalidScript("unterminated JSON string".into()))
    }
    fn read_number(&mut self) -> Result<String, Stas3Error> {
        self.skip_ws();
        let start = self.pos;
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b.is_ascii_digit() || b == b'-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            return Err(Stas3Error::InvalidScript(format!(
                "expected number at byte {}",
                self.pos
            )));
        }
        Ok(String::from_utf8_lossy(&self.bytes[start..self.pos]).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_instructions_to_json_self() {
        let triple = KeyTriple::self_under("stas3owner", "1");
        let ci = CustomInstructions::from_triple(&triple, "stas3-token", None);
        let json = ci.to_json();
        assert_eq!(
            json,
            r#"{"template":"stas3-token","protocolID":[2,"stas3owner"],"keyID":"1","counterparty":"self"}"#
        );
    }

    #[test]
    fn test_custom_instructions_to_json_with_schema() {
        let triple = KeyTriple::self_under("stas3owner", "abc");
        let ci = CustomInstructions::from_triple(&triple, "stas3-token", Some("EAC1".into()));
        let json = ci.to_json();
        assert_eq!(
            json,
            r#"{"template":"stas3-token","protocolID":[2,"stas3owner"],"keyID":"abc","counterparty":"self","schema":"EAC1"}"#
        );
    }

    #[test]
    fn test_custom_instructions_round_trip_self() {
        let triple = KeyTriple::self_under("stas3owner", "key-42");
        let ci = CustomInstructions::from_triple(&triple, "stas3-token", Some("EAC1".into()));
        let json = ci.to_json();
        let parsed = CustomInstructions::from_json(&json).unwrap();
        assert_eq!(ci, parsed);
        let resolved = parsed.to_triple().unwrap();
        assert_eq!(resolved.protocol_id.security_level, 2);
        assert_eq!(resolved.protocol_id.protocol, "stas3owner");
        assert_eq!(resolved.key_id, "key-42");
        assert_eq!(resolved.counterparty.counterparty_type, CounterpartyType::Self_);
    }

    #[test]
    fn test_custom_instructions_round_trip_anyone() {
        let ci = CustomInstructions {
            template: "stas3-fuel".into(),
            protocol_id: (0, "stas3fuel".into()),
            key_id: "fuel-1".into(),
            counterparty: "anyone".into(),
            schema: None,
        };
        let json = ci.to_json();
        let parsed = CustomInstructions::from_json(&json).unwrap();
        assert_eq!(ci, parsed);
        let resolved = parsed.to_triple().unwrap();
        assert_eq!(resolved.counterparty.counterparty_type, CounterpartyType::Anyone);
    }

    #[test]
    fn test_custom_instructions_rejects_other_counterparty() {
        let ci = CustomInstructions {
            template: "stas3-token".into(),
            protocol_id: (2, "stas3owner".into()),
            key_id: "1".into(),
            counterparty: "02deadbeef".into(),
            schema: None,
        };
        // Round-trips through the JSON layer fine — `to_triple` is what fails.
        let json = ci.to_json();
        let parsed = CustomInstructions::from_json(&json).unwrap();
        assert!(parsed.to_triple().is_err());
    }

    #[test]
    fn test_custom_instructions_from_json_tolerates_whitespace() {
        let json = r#"  {  "template" : "stas3-token" , "protocolID" : [ 2 , "stas3owner" ] , "keyID" : "1" , "counterparty" : "self" }  "#;
        let parsed = CustomInstructions::from_json(json).unwrap();
        assert_eq!(parsed.template, "stas3-token");
        assert_eq!(parsed.protocol_id.0, 2);
        assert_eq!(parsed.protocol_id.1, "stas3owner");
        assert_eq!(parsed.key_id, "1");
        assert_eq!(parsed.counterparty, "self");
    }
}
