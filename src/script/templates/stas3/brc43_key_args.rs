//! BRC-43 key derivation arguments — `(securityLevel, protocolID, keyID, counterparty)`.
//!
//! Implements the input shape that BRC-42 / BRC-43 wallet methods consume:
//! - **BRC-42** (Key Derivation): Sender↔receiver child key derivation.
//! - **BRC-43** (Security Levels, Protocol IDs, Key IDs and Counterparties):
//!   defines the constructed "invoice number" string
//!   `securityLevel-protocolName-keyID` and the counterparty model passed
//!   alongside it to derive the actual signing key.
//!
//! See: <https://github.com/bsv-blockchain/BRCs/blob/master/key-derivation/0042.md>
//! and <https://github.com/bsv-blockchain/BRCs/blob/master/key-derivation/0043.md>.

use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

/// BRC-43 key derivation arguments — bundles `(securityLevel, protocolID,
/// keyID, counterparty)` for any wallet method that takes them
/// (`createSignature`, `getPublicKey`, etc.).
///
/// The unit of identity for any key material in the STAS-3 implementation.
/// All owners, authorities, swap recipients, and funding owners are
/// referenced by their `Brc43KeyArgs` — never by a raw `PrivateKey`.
///
/// Re-derive the corresponding `PublicKey` (and HASH160) via
/// `wallet.get_public_key(args.into())`.
#[derive(Clone, Debug)]
pub struct Brc43KeyArgs {
    pub protocol_id: Protocol,
    pub key_id: String,
    pub counterparty: Counterparty,
}

impl Brc43KeyArgs {
    /// Convenience: args with `counterparty: self`.
    ///
    /// Uses security level 2 (per-app + per-counterparty confirmation),
    /// which is the policy required by STAS-3 spec §1A.2 for STAS-3 key
    /// material.
    pub fn self_under(protocol: &str, key_id: impl Into<String>) -> Self {
        Self {
            protocol_id: Protocol {
                security_level: 2,
                protocol: protocol.to_string(),
            },
            key_id: key_id.into(),
            counterparty: Counterparty {
                counterparty_type: CounterpartyType::Self_,
                public_key: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_under_constructs_correctly() {
        let kt = Brc43KeyArgs::self_under("stas3owner", "abc123");
        assert_eq!(kt.protocol_id.security_level, 2);
        assert_eq!(kt.protocol_id.protocol, "stas3owner");
        assert_eq!(kt.key_id, "abc123");
        assert_eq!(kt.counterparty.counterparty_type, CounterpartyType::Self_);
        assert!(kt.counterparty.public_key.is_none());
    }

    #[test]
    fn test_clone_eq() {
        // Brc43KeyArgs does not implement PartialEq (Counterparty/Protocol
        // don't), so verify field-wise equality on a clone.
        let a = Brc43KeyArgs::self_under("stas3owner", "key-1");
        let b = a.clone();
        assert_eq!(a.protocol_id.security_level, b.protocol_id.security_level);
        assert_eq!(a.protocol_id.protocol, b.protocol_id.protocol);
        assert_eq!(a.key_id, b.key_id);
        assert_eq!(
            a.counterparty.counterparty_type,
            b.counterparty.counterparty_type
        );
    }
}
