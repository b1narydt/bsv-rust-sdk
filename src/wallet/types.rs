//! Semantic type aliases and core types for the wallet module.
//!
//! Mirrors the Go SDK wallet/wallet.go and wallet/interfaces.go type
//! definitions, providing strongly-typed aliases for protocol parameters.

use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;

// ---------------------------------------------------------------------------
// Semantic type aliases
// ---------------------------------------------------------------------------

/// Hex-encoded public key string.
pub type PubKeyHex = String;

/// Satoshi value (unsigned 64-bit integer).
pub type SatoshiValue = u64;

/// Outpoint string in "txid.index" format.
pub type OutpointString = String;

/// Transaction ID as a hex string.
pub type TXIDHexString = String;

/// Description string (5 to 50 bytes).
pub type DescriptionString5to50Bytes = String;

/// Basket name string (under 300 bytes).
pub type BasketStringUnder300Bytes = String;

/// Output tag string (under 300 bytes).
pub type OutputTagStringUnder300Bytes = String;

/// Label string (under 300 bytes).
pub type LabelStringUnder300Bytes = String;

/// Key ID string (under 800 bytes).
pub type KeyIDStringUnder800Bytes = String;

/// Originator domain name string (under 250 bytes).
pub type OriginatorDomainNameStringUnder250Bytes = String;

/// Certificate field name (under 50 bytes).
pub type CertificateFieldNameUnder50Bytes = String;

/// Base64-encoded string.
pub type Base64String = String;

/// Hex-encoded string.
pub type HexString = String;

/// Boolean that defaults to true when None.
///
/// A newtype around `Option<bool>` that dereferences to `true` when the inner
/// value is `None` or `Some(true)`. Serializes transparently as `Option<bool>`
/// on the wire and in JSON.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(transparent))]
pub struct BooleanDefaultTrue(pub Option<bool>);

impl Default for BooleanDefaultTrue {
    fn default() -> Self {
        BooleanDefaultTrue(Some(true))
    }
}

impl std::ops::Deref for BooleanDefaultTrue {
    type Target = bool;
    fn deref(&self) -> &bool {
        static TRUE: bool = true;
        static FALSE: bool = false;
        match self.0 {
            Some(true) | None => &TRUE,
            Some(false) => &FALSE,
        }
    }
}

impl From<BooleanDefaultTrue> for Option<bool> {
    fn from(v: BooleanDefaultTrue) -> Self {
        v.0
    }
}

impl From<Option<bool>> for BooleanDefaultTrue {
    fn from(v: Option<bool>) -> Self {
        BooleanDefaultTrue(v)
    }
}

impl BooleanDefaultTrue {
    /// Returns true if the inner value is None.
    /// Used by serde skip_serializing_if.
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }
}

/// Boolean that defaults to false when None.
///
/// A newtype around `Option<bool>` that dereferences to `false` when the inner
/// value is `None` or `Some(false)`. Serializes transparently as `Option<bool>`
/// on the wire and in JSON.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(transparent))]
pub struct BooleanDefaultFalse(pub Option<bool>);

impl Default for BooleanDefaultFalse {
    fn default() -> Self {
        BooleanDefaultFalse(Some(false))
    }
}

impl std::ops::Deref for BooleanDefaultFalse {
    type Target = bool;
    fn deref(&self) -> &bool {
        static TRUE: bool = true;
        static FALSE: bool = false;
        match self.0 {
            Some(true) => &TRUE,
            Some(false) | None => &FALSE,
        }
    }
}

impl From<BooleanDefaultFalse> for Option<bool> {
    fn from(v: BooleanDefaultFalse) -> Self {
        v.0
    }
}

impl From<Option<bool>> for BooleanDefaultFalse {
    fn from(v: Option<bool>) -> Self {
        BooleanDefaultFalse(v)
    }
}

impl BooleanDefaultFalse {
    /// Returns true if the inner value is None.
    /// Used by serde skip_serializing_if.
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }
}

/// Positive integer defaulting to 10, max 10000.
pub type PositiveIntegerDefault10Max10000 = Option<u32>;

/// Positive integer or zero.
pub type PositiveIntegerOrZero = u32;

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// Defines a protocol with its security level and name.
///
/// The security level determines how strictly the wallet enforces
/// user confirmation:
/// - 0: Silent (no user interaction)
/// - 1: Every app (user confirms per app)
/// - 2: Every app and counterparty (user confirms per app + counterparty)
///
/// Serializes as a JSON array `[securityLevel, "protocolName"]` matching
/// the Go SDK encoding.
#[derive(Clone, Debug)]
pub struct Protocol {
    pub security_level: u8,
    pub protocol: String,
}

#[cfg(feature = "network")]
impl serde::Serialize for Protocol {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.security_level)?;
        seq.serialize_element(&self.protocol)?;
        seq.end()
    }
}

#[cfg(feature = "network")]
impl<'de> serde::Deserialize<'de> for Protocol {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{self, SeqAccess, Visitor};
        use std::fmt;

        struct ProtocolVisitor;

        impl<'de> Visitor<'de> for ProtocolVisitor {
            type Value = Protocol;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array [securityLevel, protocolName]")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Protocol, A::Error> {
                let security_level: u8 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let protocol: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(Protocol {
                    security_level,
                    protocol,
                })
            }
        }

        deserializer.deserialize_seq(ProtocolVisitor)
    }
}

// ---------------------------------------------------------------------------
// Counterparty
// ---------------------------------------------------------------------------

/// The type of counterparty in a cryptographic operation.
#[derive(Clone, Debug, PartialEq)]
pub enum CounterpartyType {
    /// Uninitialized / unknown.
    Uninitialized,
    /// The wallet itself.
    Self_,
    /// The special "anyone" key (PrivateKey(1)).
    Anyone,
    /// A specific other party identified by public key.
    Other,
}

/// Represents the other party in a cryptographic operation.
///
/// Can be a specific public key, or one of the special values
/// "self" or "anyone".
///
/// Serializes as a JSON string: "anyone", "self", or DER hex public key,
/// matching the Go SDK encoding.
#[derive(Clone, Debug)]
pub struct Counterparty {
    pub counterparty_type: CounterpartyType,
    pub public_key: Option<PublicKey>,
}

impl Default for Counterparty {
    fn default() -> Self {
        Self {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        }
    }
}

#[cfg(feature = "network")]
impl serde::Serialize for Counterparty {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.counterparty_type {
            CounterpartyType::Anyone => serializer.serialize_str("anyone"),
            CounterpartyType::Self_ => serializer.serialize_str("self"),
            CounterpartyType::Other => {
                if let Some(ref pk) = self.public_key {
                    serializer.serialize_str(&pk.to_der_hex())
                } else {
                    serializer.serialize_none()
                }
            }
            CounterpartyType::Uninitialized => serializer.serialize_str(""),
        }
    }
}

#[cfg(feature = "network")]
impl<'de> serde::Deserialize<'de> for Counterparty {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "anyone" => Ok(Counterparty {
                counterparty_type: CounterpartyType::Anyone,
                public_key: None,
            }),
            "self" => Ok(Counterparty {
                counterparty_type: CounterpartyType::Self_,
                public_key: None,
            }),
            "" => Ok(Counterparty {
                counterparty_type: CounterpartyType::Uninitialized,
                public_key: None,
            }),
            hex_str => {
                let pk = PublicKey::from_string(hex_str).map_err(serde::de::Error::custom)?;
                Ok(Counterparty {
                    counterparty_type: CounterpartyType::Other,
                    public_key: Some(pk),
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Anyone key helper
// ---------------------------------------------------------------------------

/// Returns the "anyone" public key: the public key corresponding to
/// PrivateKey(1), which is the generator point G.
///
/// This is used when no specific counterparty is specified, making
/// operations available to anyone who knows the protocol.
pub fn anyone_pubkey() -> PublicKey {
    let priv_key = PrivateKey::from_bytes(&{
        let mut buf = [0u8; 32];
        buf[31] = 1;
        buf
    })
    // SAFETY: PrivateKey(1) is always valid -- 1 is within the secp256k1 scalar range.
    .expect("PrivateKey(1) is always valid");
    priv_key.to_public_key()
}

/// Returns the "anyone" private key: PrivateKey(1).
pub fn anyone_private_key() -> PrivateKey {
    PrivateKey::from_bytes(&{
        let mut buf = [0u8; 32];
        buf[31] = 1;
        buf
    })
    // SAFETY: PrivateKey(1) is always valid -- 1 is within the secp256k1 scalar range.
    .expect("PrivateKey(1) is always valid")
}
