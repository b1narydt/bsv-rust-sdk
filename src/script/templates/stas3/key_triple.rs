//! Type-42 (BRC-42) key derivation triple per spec §1A.

use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

/// Identifies a wallet-derived key by `(protocolID, keyID, counterparty)`.
///
/// The unit of identity for any key material in the STAS-3 implementation.
/// All owners, authorities, swap recipients, and funding owners are referenced
/// by their `KeyTriple` — never by a raw `PrivateKey`.
///
/// Re-derive the corresponding `PublicKey` (and HASH160) via
/// `wallet.get_public_key(triple.into())`.
#[derive(Clone, Debug)]
pub struct KeyTriple {
    pub protocol_id: Protocol,
    pub key_id: String,
    pub counterparty: Counterparty,
}

impl KeyTriple {
    /// Convenience: a triple with `counterparty: self`.
    ///
    /// Uses security level 2 (per-app + per-counterparty confirmation),
    /// which is the policy required by spec §1A.2 for STAS-3 key material.
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
        let kt = KeyTriple::self_under("stas3owner", "abc123");
        assert_eq!(kt.protocol_id.security_level, 2);
        assert_eq!(kt.protocol_id.protocol, "stas3owner");
        assert_eq!(kt.key_id, "abc123");
        assert_eq!(kt.counterparty.counterparty_type, CounterpartyType::Self_);
        assert!(kt.counterparty.public_key.is_none());
    }

    #[test]
    fn test_clone_eq() {
        // KeyTriple does not implement PartialEq (Counterparty/Protocol don't),
        // so verify field-wise equality on a clone.
        let a = KeyTriple::self_under("stas3owner", "key-1");
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
