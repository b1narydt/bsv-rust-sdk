//! WalletInterface trait and all arg/result structs.
//!
//! Defines the contract that all wallet implementations must satisfy.
//! Translated from Go SDK wallet/interfaces.go and TS SDK Wallet.interfaces.ts.
//! Uses native async fn in traits (RPITIT, Rust 1.75+) -- NOT the async-trait crate.

use std::collections::HashMap;

use crate::primitives::public_key::PublicKey;
use crate::wallet::error::WalletError;
use crate::wallet::types::{
    BasketStringUnder300Bytes, BooleanDefaultFalse, BooleanDefaultTrue, Counterparty,
    DescriptionString5to50Bytes, LabelStringUnder300Bytes, OutpointString,
    OutputTagStringUnder300Bytes, PositiveIntegerDefault10Max10000, PositiveIntegerOrZero,
    Protocol, SatoshiValue, TXIDHexString,
};

// ---------------------------------------------------------------------------
// Serde helper modules (only compiled with "network" feature)
// ---------------------------------------------------------------------------

/// Serde helpers for custom JSON serialization of wallet types.
/// Gated behind the "network" feature since serde is an optional dependency.
#[cfg(feature = "network")]
pub(crate) mod serde_helpers {
    use crate::primitives::public_key::PublicKey;

    /// Serialize/deserialize PublicKey as DER hex string.
    pub mod public_key_hex {
        use super::PublicKey;
        use serde::{self, Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(pk: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&pk.to_der_hex())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            PublicKey::from_string(&s).map_err(serde::de::Error::custom)
        }
    }

    /// Serialize/deserialize `Option<PublicKey>` as optional DER hex string.
    #[allow(dead_code)]
    pub mod option_public_key_hex {
        use super::PublicKey;
        use serde::{self, Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(pk: &Option<PublicKey>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match pk {
                Some(pk) => serializer.serialize_str(&pk.to_der_hex()),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<PublicKey>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt: Option<String> = Option::deserialize(deserializer)?;
            match opt {
                Some(s) if !s.is_empty() => PublicKey::from_string(&s)
                    .map(Some)
                    .map_err(serde::de::Error::custom),
                _ => Ok(None),
            }
        }
    }

    /// Serialize/deserialize `Vec<PublicKey>` as array of DER hex strings.
    pub mod vec_public_key_hex {
        use super::PublicKey;
        use serde::ser::SerializeSeq;
        use serde::{self, Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(pks: &[PublicKey], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq = serializer.serialize_seq(Some(pks.len()))?;
            for pk in pks {
                seq.serialize_element(&pk.to_der_hex())?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<PublicKey>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let strs: Vec<String> = Vec::deserialize(deserializer)?;
            strs.iter()
                .map(|s| PublicKey::from_string(s).map_err(serde::de::Error::custom))
                .collect()
        }
    }

    /// Serialize/deserialize [u8; 32] as base64 string (matches Go SDK Bytes32Base64).
    pub mod bytes32_base64 {
        use serde::{self, Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&base64_encode(bytes))
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let decoded = base64_decode(&s).map_err(serde::de::Error::custom)?;
            if decoded.len() > 32 {
                return Err(serde::de::Error::custom(
                    "base64 decoded value exceeds 32 bytes",
                ));
            }
            let mut buf = [0u8; 32];
            buf[..decoded.len()].copy_from_slice(&decoded);
            Ok(buf)
        }

        fn base64_encode(data: &[u8]) -> String {
            const CHARS: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut result = String::new();
            let chunks = data.chunks(3);
            for chunk in chunks {
                let b0 = chunk[0] as u32;
                let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
                let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
                let triple = (b0 << 16) | (b1 << 8) | b2;
                result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
                result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
                if chunk.len() > 1 {
                    result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
                } else {
                    result.push('=');
                }
                if chunk.len() > 2 {
                    result.push(CHARS[(triple & 0x3F) as usize] as char);
                } else {
                    result.push('=');
                }
            }
            result
        }

        fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
            fn char_to_val(c: u8) -> Result<u8, String> {
                match c {
                    b'A'..=b'Z' => Ok(c - b'A'),
                    b'a'..=b'z' => Ok(c - b'a' + 26),
                    b'0'..=b'9' => Ok(c - b'0' + 52),
                    b'+' => Ok(62),
                    b'/' => Ok(63),
                    _ => Err(format!("invalid base64 character: {}", c as char)),
                }
            }
            let bytes = s.as_bytes();
            let mut result = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'=' {
                    break;
                }
                let a = char_to_val(bytes[i])?;
                let b = if i + 1 < bytes.len() && bytes[i + 1] != b'=' {
                    char_to_val(bytes[i + 1])?
                } else {
                    0
                };
                let c = if i + 2 < bytes.len() && bytes[i + 2] != b'=' {
                    char_to_val(bytes[i + 2])?
                } else {
                    0
                };
                let d = if i + 3 < bytes.len() && bytes[i + 3] != b'=' {
                    char_to_val(bytes[i + 3])?
                } else {
                    0
                };
                let triple =
                    ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
                result.push(((triple >> 16) & 0xFF) as u8);
                if i + 2 < bytes.len() && bytes[i + 2] != b'=' {
                    result.push(((triple >> 8) & 0xFF) as u8);
                }
                if i + 3 < bytes.len() && bytes[i + 3] != b'=' {
                    result.push((triple & 0xFF) as u8);
                }
                i += 4;
            }
            Ok(result)
        }
    }

    /// Serialize/deserialize `Vec<u8>` as JSON array of numbers (matches Go SDK BytesList).
    pub mod bytes_as_array {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.collect_seq(bytes.iter())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where
            D: Deserializer<'de>,
        {
            Vec::<u8>::deserialize(deserializer)
        }
    }

    /// Serialize/deserialize `Option<Vec<u8>>` as optional JSON array of numbers.
    pub mod option_bytes_as_array {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match bytes {
                Some(b) => serializer.collect_seq(b.iter()),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            Option::<Vec<u8>>::deserialize(deserializer)
        }
    }

    /// Serialize/deserialize `Vec<u8>` as hex string (matches Go SDK BytesHex).
    pub mod bytes_as_hex {
        use serde::{self, Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&to_hex(bytes))
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            from_hex(&s).map_err(serde::de::Error::custom)
        }

        fn to_hex(bytes: &[u8]) -> String {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut s = String::with_capacity(bytes.len() * 2);
            for &b in bytes {
                s.push(HEX[(b >> 4) as usize] as char);
                s.push(HEX[(b & 0xf) as usize] as char);
            }
            s
        }

        pub(crate) fn from_hex(s: &str) -> Result<Vec<u8>, String> {
            if !s.len().is_multiple_of(2) {
                return Err("hex string has odd length".to_string());
            }
            let bytes = s.as_bytes();
            let mut result = Vec::with_capacity(bytes.len() / 2);
            for chunk in bytes.chunks(2) {
                let hi = hex_val(chunk[0])?;
                let lo = hex_val(chunk[1])?;
                result.push((hi << 4) | lo);
            }
            Ok(result)
        }

        fn hex_val(b: u8) -> Result<u8, String> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                b'A'..=b'F' => Ok(b - b'A' + 10),
                _ => Err(format!("invalid hex character: {}", b as char)),
            }
        }
    }

    /// Serialize/deserialize `Option<Vec<u8>>` as optional hex string.
    pub mod option_bytes_as_hex {
        use serde::{self, Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match bytes {
                Some(b) => super::bytes_as_hex::serialize(b, serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt: Option<String> = Option::deserialize(deserializer)?;
            match opt {
                Some(s) if !s.is_empty() => super::bytes_as_hex::from_hex(&s)
                    .map(Some)
                    .map_err(serde::de::Error::custom),
                _ => Ok(None),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Current state of a transaction action.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub enum ActionStatus {
    Completed,
    Unprocessed,
    Sending,
    Unproven,
    Unsigned,
    #[cfg_attr(feature = "network", serde(rename = "nosend"))]
    NoSend,
    #[cfg_attr(feature = "network", serde(rename = "nonfinal"))]
    NonFinal,
}

impl ActionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionStatus::Completed => "completed",
            ActionStatus::Unprocessed => "unprocessed",
            ActionStatus::Sending => "sending",
            ActionStatus::Unproven => "unproven",
            ActionStatus::Unsigned => "unsigned",
            ActionStatus::NoSend => "nosend",
            ActionStatus::NonFinal => "nonfinal",
        }
    }
}

/// Status of a transaction result (subset of ActionStatus).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub enum ActionResultStatus {
    Unproven,
    Sending,
    Failed,
}

impl ActionResultStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionResultStatus::Unproven => "unproven",
            ActionResultStatus::Sending => "sending",
            ActionResultStatus::Failed => "failed",
        }
    }
}

/// How multiple criteria are combined in queries.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub enum QueryMode {
    Any,
    All,
}

impl QueryMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            QueryMode::Any => "any",
            QueryMode::All => "all",
        }
    }
}

/// What additional data to include with output listings.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
pub enum OutputInclude {
    #[cfg_attr(feature = "network", serde(rename = "locking scripts"))]
    LockingScripts,
    #[cfg_attr(feature = "network", serde(rename = "entire transactions"))]
    EntireTransactions,
}

impl OutputInclude {
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputInclude::LockingScripts => "locking scripts",
            OutputInclude::EntireTransactions => "entire transactions",
        }
    }
}

/// Protocol for internalizing transaction outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
pub enum InternalizeProtocol {
    #[cfg_attr(feature = "network", serde(rename = "wallet payment"))]
    WalletPayment,
    #[cfg_attr(feature = "network", serde(rename = "basket insertion"))]
    BasketInsertion,
}

impl InternalizeProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            InternalizeProtocol::WalletPayment => "wallet payment",
            InternalizeProtocol::BasketInsertion => "basket insertion",
        }
    }
}

/// Protocol for certificate acquisition.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub enum AcquisitionProtocol {
    Direct,
    Issuance,
}

impl AcquisitionProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            AcquisitionProtocol::Direct => "direct",
            AcquisitionProtocol::Issuance => "issuance",
        }
    }
}

/// Blockchain network type.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }
}

/// Trust level for self-referential operations.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub enum TrustSelf {
    Known,
}

impl TrustSelf {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustSelf::Known => "known",
        }
    }
}

// ---------------------------------------------------------------------------
// Core types: Certificate, CertificateType, SerialNumber, KeyringRevealer
// ---------------------------------------------------------------------------

/// Newtype wrapper for certificate type identifier (32 bytes).
/// Serializes as base64 string matching Go SDK Bytes32Base64.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificateType(pub [u8; 32]);

#[cfg(feature = "network")]
impl serde::Serialize for CertificateType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_helpers::bytes32_base64::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "network")]
impl<'de> serde::Deserialize<'de> for CertificateType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_helpers::bytes32_base64::deserialize(deserializer).map(CertificateType)
    }
}

impl CertificateType {
    pub fn from_string(s: &str) -> Result<Self, WalletError> {
        if s.len() > 32 {
            return Err(WalletError::InvalidParameter(
                "certificate type string longer than 32 bytes".to_string(),
            ));
        }
        let mut buf = [0u8; 32];
        buf[..s.len()].copy_from_slice(s.as_bytes());
        Ok(CertificateType(buf))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Newtype wrapper for certificate serial number (32 bytes).
/// Serializes as base64 string matching Go SDK Bytes32Base64.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SerialNumber(pub [u8; 32]);

#[cfg(feature = "network")]
impl serde::Serialize for SerialNumber {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_helpers::bytes32_base64::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "network")]
impl<'de> serde::Deserialize<'de> for SerialNumber {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_helpers::bytes32_base64::deserialize(deserializer).map(SerialNumber)
    }
}

/// A certificate in the wallet.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct Certificate {
    #[cfg_attr(feature = "network", serde(rename = "type"))]
    pub cert_type: CertificateType,
    pub serial_number: SerialNumber,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub subject: PublicKey,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub certifier: PublicKey,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub revocation_outpoint: Option<String>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub fields: Option<HashMap<String, String>>,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_hex")
    )]
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub signature: Option<Vec<u8>>,
}

/// Identifies who reveals a keyring.
#[derive(Clone, Debug)]
pub enum KeyringRevealer {
    /// The certifier reveals the keyring.
    Certifier,
    /// A specific public key reveals the keyring.
    PubKey(PublicKey),
}

#[cfg(feature = "network")]
impl serde::Serialize for KeyringRevealer {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            KeyringRevealer::Certifier => serializer.serialize_str("certifier"),
            KeyringRevealer::PubKey(pk) => serializer.serialize_str(&pk.to_der_hex()),
        }
    }
}

#[cfg(feature = "network")]
impl<'de> serde::Deserialize<'de> for KeyringRevealer {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "certifier" || s.is_empty() {
            Ok(KeyringRevealer::Certifier)
        } else {
            PublicKey::from_string(&s)
                .map(KeyringRevealer::PubKey)
                .map_err(serde::de::Error::custom)
        }
    }
}

// ---------------------------------------------------------------------------
// Action types (CreateAction, SignAction, AbortAction)
// ---------------------------------------------------------------------------

/// An input to be spent in a new transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct CreateActionInput {
    pub outpoint: OutpointString,
    pub input_description: String,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_hex")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub unlocking_script: Option<Vec<u8>>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub unlocking_script_length: Option<u32>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub sequence_number: Option<u32>,
}

/// An output to be created in a new transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct CreateActionOutput {
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_hex")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub locking_script: Option<Vec<u8>>,
    pub satoshis: SatoshiValue,
    pub output_description: String,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub basket: Option<BasketStringUnder300Bytes>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub custom_instructions: Option<String>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub tags: Vec<OutputTagStringUnder300Bytes>,
}

/// Optional parameters for creating a new transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct CreateActionOptions {
    pub sign_and_process: BooleanDefaultTrue,
    pub accept_delayed_broadcast: BooleanDefaultTrue,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub trust_self: Option<TrustSelf>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub known_txids: Vec<TXIDHexString>,
    pub return_txid_only: BooleanDefaultFalse,
    pub no_send: BooleanDefaultFalse,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub no_send_change: Vec<OutpointString>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub send_with: Vec<TXIDHexString>,
    pub randomize_outputs: BooleanDefaultTrue,
}

/// Arguments for creating a new transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct CreateActionArgs {
    pub description: DescriptionString5to50Bytes,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_array")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    #[cfg_attr(feature = "network", serde(rename = "inputBEEF"))]
    pub input_beef: Option<Vec<u8>>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub inputs: Vec<CreateActionInput>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub outputs: Vec<CreateActionOutput>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub lock_time: Option<u32>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub version: Option<u32>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub labels: Vec<LabelStringUnder300Bytes>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub options: Option<CreateActionOptions>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub reference: Option<String>,
}

/// Data needed to complete signing of a partial transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct SignableTransaction {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub tx: Vec<u8>,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub reference: Vec<u8>,
}

/// Status of a transaction sent as part of a batch.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct SendWithResult {
    pub txid: TXIDHexString,
    pub status: ActionResultStatus,
}

/// Result of creating a transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct CreateActionResult {
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub txid: Option<TXIDHexString>,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_array")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub tx: Option<Vec<u8>>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub no_send_change: Vec<OutpointString>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub send_with_results: Vec<SendWithResult>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub signable_transaction: Option<SignableTransaction>,
}

/// Unlocking script and sequence number for a specific input.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct SignActionSpend {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_hex"))]
    pub unlocking_script: Vec<u8>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub sequence_number: Option<u32>,
}

/// Controls signing and broadcasting behavior.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct SignActionOptions {
    pub accept_delayed_broadcast: BooleanDefaultTrue,
    pub return_txid_only: BooleanDefaultFalse,
    pub no_send: BooleanDefaultFalse,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub send_with: Vec<TXIDHexString>,
}

/// Arguments for signing a previously created transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct SignActionArgs {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub reference: Vec<u8>,
    pub spends: HashMap<u32, SignActionSpend>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub options: Option<SignActionOptions>,
}

/// Result of a successful signing operation.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct SignActionResult {
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub txid: Option<TXIDHexString>,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_array")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub tx: Option<Vec<u8>>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub send_with_results: Vec<SendWithResult>,
}

/// Arguments for aborting a transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct AbortActionArgs {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub reference: Vec<u8>,
}

/// Result of aborting a transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct AbortActionResult {
    pub aborted: bool,
}

// ---------------------------------------------------------------------------
// Action detail types (for listing)
// ---------------------------------------------------------------------------

/// A transaction input with full details.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct ActionInput {
    pub source_outpoint: OutpointString,
    pub source_satoshis: SatoshiValue,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_hex")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub source_locking_script: Option<Vec<u8>>,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_hex")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub unlocking_script: Option<Vec<u8>>,
    pub input_description: String,
    pub sequence_number: u32,
}

/// A transaction output with full details.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct ActionOutput {
    pub satoshis: SatoshiValue,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_hex")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub locking_script: Option<Vec<u8>>,
    pub spendable: bool,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub custom_instructions: Option<String>,
    pub tags: Vec<String>,
    pub output_index: u32,
    pub output_description: String,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub basket: Option<String>,
}

/// Full details about a wallet transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct Action {
    pub txid: TXIDHexString,
    pub satoshis: i64,
    pub status: ActionStatus,
    pub is_outgoing: bool,
    pub description: String,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub labels: Vec<String>,
    pub version: u32,
    pub lock_time: u32,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub inputs: Vec<ActionInput>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub outputs: Vec<ActionOutput>,
}

/// Maximum number of actions or outputs that can be returned.
pub const MAX_ACTIONS_LIMIT: u32 = 10000;

// ---------------------------------------------------------------------------
// ListActions
// ---------------------------------------------------------------------------

/// Filtering and pagination options for listing wallet transactions.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct ListActionsArgs {
    pub labels: Vec<LabelStringUnder300Bytes>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub label_query_mode: Option<QueryMode>,
    pub include_labels: BooleanDefaultFalse,
    pub include_inputs: BooleanDefaultFalse,
    pub include_input_source_locking_scripts: BooleanDefaultFalse,
    pub include_input_unlocking_scripts: BooleanDefaultFalse,
    pub include_outputs: BooleanDefaultFalse,
    pub include_output_locking_scripts: BooleanDefaultFalse,
    pub limit: PositiveIntegerDefault10Max10000,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub offset: Option<PositiveIntegerOrZero>,
    pub seek_permission: BooleanDefaultTrue,
}

/// Paginated list of wallet transactions.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct ListActionsResult {
    pub total_actions: u32,
    pub actions: Vec<Action>,
}

// ---------------------------------------------------------------------------
// InternalizeAction
// ---------------------------------------------------------------------------

/// Derivation and identity data for wallet payment outputs.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct Payment {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub derivation_prefix: Vec<u8>,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub derivation_suffix: Vec<u8>,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub sender_identity_key: PublicKey,
}

/// Metadata for outputs being inserted into baskets.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct BasketInsertion {
    pub basket: BasketStringUnder300Bytes,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub custom_instructions: Option<String>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub tags: Vec<OutputTagStringUnder300Bytes>,
}

/// How to process a transaction output -- as payment or basket insertion.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct InternalizeOutput {
    pub output_index: u32,
    pub protocol: InternalizeProtocol,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub payment_remittance: Option<Payment>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub insertion_remittance: Option<BasketInsertion>,
}

/// Arguments for importing an external transaction into the wallet.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct InternalizeActionArgs {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub tx: Vec<u8>,
    pub description: String,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub labels: Vec<LabelStringUnder300Bytes>,
    pub seek_permission: BooleanDefaultTrue,
    pub outputs: Vec<InternalizeOutput>,
}

/// Result of internalizing a transaction.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct InternalizeActionResult {
    pub accepted: bool,
}

// ---------------------------------------------------------------------------
// ListOutputs
// ---------------------------------------------------------------------------

/// Filtering and options for listing wallet outputs.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct ListOutputsArgs {
    pub basket: BasketStringUnder300Bytes,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub tags: Vec<OutputTagStringUnder300Bytes>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub tag_query_mode: Option<QueryMode>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub include: Option<OutputInclude>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub include_custom_instructions: BooleanDefaultFalse,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub include_tags: BooleanDefaultFalse,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub include_labels: BooleanDefaultFalse,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub limit: PositiveIntegerDefault10Max10000,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub offset: Option<PositiveIntegerOrZero>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub seek_permission: BooleanDefaultTrue,
}

/// A wallet UTXO with its metadata.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct Output {
    pub satoshis: SatoshiValue,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_hex")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub locking_script: Option<Vec<u8>>,
    pub spendable: bool,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub custom_instructions: Option<String>,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub tags: Vec<String>,
    pub outpoint: OutpointString,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Vec::is_empty", default)
    )]
    pub labels: Vec<String>,
}

/// Paginated list of wallet outputs.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct ListOutputsResult {
    pub total_outputs: u32,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_array")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    #[cfg_attr(feature = "network", serde(rename = "BEEF"))]
    pub beef: Option<Vec<u8>>,
    pub outputs: Vec<Output>,
}

// ---------------------------------------------------------------------------
// RelinquishOutput
// ---------------------------------------------------------------------------

/// Arguments for relinquishing ownership of an output.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct RelinquishOutputArgs {
    pub basket: BasketStringUnder300Bytes,
    pub output: OutpointString,
}

/// Result of relinquishing an output.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct RelinquishOutputResult {
    pub relinquished: bool,
}

// ---------------------------------------------------------------------------
// Key/Crypto types
// ---------------------------------------------------------------------------

/// Arguments for getting a public key.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct GetPublicKeyArgs {
    pub identity_key: bool,
    #[cfg_attr(feature = "network", serde(rename = "protocolID"))]
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub protocol_id: Option<Protocol>,
    #[cfg_attr(feature = "network", serde(rename = "keyID"))]
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub key_id: Option<String>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub counterparty: Option<Counterparty>,
    pub privileged: bool,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
    pub for_self: Option<bool>,
    pub seek_permission: Option<bool>,
}

/// Result of getting a public key.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct GetPublicKeyResult {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub public_key: PublicKey,
}

/// Arguments for encryption.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct EncryptArgs {
    #[cfg_attr(feature = "network", serde(rename = "protocolID"))]
    pub protocol_id: Protocol,
    #[cfg_attr(feature = "network", serde(rename = "keyID"))]
    pub key_id: String,
    pub counterparty: Counterparty,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub plaintext: Vec<u8>,
    pub privileged: bool,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
    pub seek_permission: Option<bool>,
}

/// Result of encryption.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct EncryptResult {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub ciphertext: Vec<u8>,
}

/// Arguments for decryption.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct DecryptArgs {
    #[cfg_attr(feature = "network", serde(rename = "protocolID"))]
    pub protocol_id: Protocol,
    #[cfg_attr(feature = "network", serde(rename = "keyID"))]
    pub key_id: String,
    pub counterparty: Counterparty,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub ciphertext: Vec<u8>,
    pub privileged: bool,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
    pub seek_permission: Option<bool>,
}

/// Result of decryption.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct DecryptResult {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub plaintext: Vec<u8>,
}

/// Arguments for creating an HMAC.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct CreateHmacArgs {
    #[cfg_attr(feature = "network", serde(rename = "protocolID"))]
    pub protocol_id: Protocol,
    #[cfg_attr(feature = "network", serde(rename = "keyID"))]
    pub key_id: String,
    pub counterparty: Counterparty,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub data: Vec<u8>,
    pub privileged: bool,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
    pub seek_permission: Option<bool>,
}

/// Result of creating an HMAC.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct CreateHmacResult {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub hmac: Vec<u8>,
}

/// Arguments for verifying an HMAC.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct VerifyHmacArgs {
    #[cfg_attr(feature = "network", serde(rename = "protocolID"))]
    pub protocol_id: Protocol,
    #[cfg_attr(feature = "network", serde(rename = "keyID"))]
    pub key_id: String,
    pub counterparty: Counterparty,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub data: Vec<u8>,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub hmac: Vec<u8>,
    pub privileged: bool,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
    pub seek_permission: Option<bool>,
}

/// Result of verifying an HMAC.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct VerifyHmacResult {
    pub valid: bool,
}

/// Arguments for creating a digital signature.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct CreateSignatureArgs {
    #[cfg_attr(feature = "network", serde(rename = "protocolID"))]
    pub protocol_id: Protocol,
    #[cfg_attr(feature = "network", serde(rename = "keyID"))]
    pub key_id: String,
    pub counterparty: Counterparty,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub data: Vec<u8>,
    pub privileged: bool,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
    pub seek_permission: Option<bool>,
}

/// Result of creating a digital signature.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct CreateSignatureResult {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_hex"))]
    pub signature: Vec<u8>,
}

/// Arguments for verifying a digital signature.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct VerifySignatureArgs {
    #[cfg_attr(feature = "network", serde(rename = "protocolID"))]
    pub protocol_id: Protocol,
    #[cfg_attr(feature = "network", serde(rename = "keyID"))]
    pub key_id: String,
    pub counterparty: Counterparty,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub data: Vec<u8>,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_hex"))]
    pub signature: Vec<u8>,
    pub for_self: Option<bool>,
    pub privileged: bool,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
    pub seek_permission: Option<bool>,
}

/// Result of verifying a digital signature.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct VerifySignatureResult {
    pub valid: bool,
}

// ---------------------------------------------------------------------------
// Certificate operations
// ---------------------------------------------------------------------------

/// Arguments for acquiring a new certificate.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct AcquireCertificateArgs {
    #[cfg_attr(feature = "network", serde(rename = "type"))]
    pub cert_type: CertificateType,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub certifier: PublicKey,
    pub acquisition_protocol: AcquisitionProtocol,
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "HashMap::is_empty", default)
    )]
    pub fields: HashMap<String, String>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub serial_number: Option<SerialNumber>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub revocation_outpoint: Option<String>,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_hex")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub signature: Option<Vec<u8>>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub certifier_url: Option<String>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub keyring_revealer: Option<KeyringRevealer>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub keyring_for_subject: Option<HashMap<String, String>>,
    pub privileged: bool,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
}

/// Arguments for listing certificates.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct ListCertificatesArgs {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::vec_public_key_hex"))]
    pub certifiers: Vec<PublicKey>,
    pub types: Vec<CertificateType>,
    pub limit: PositiveIntegerDefault10Max10000,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub offset: Option<PositiveIntegerOrZero>,
    pub privileged: BooleanDefaultFalse,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
}

/// A certificate with its keyring and verifier.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct CertificateResult {
    #[cfg_attr(feature = "network", serde(flatten))]
    pub certificate: Certificate,
    pub keyring: HashMap<String, String>,
    #[cfg_attr(
        feature = "network",
        serde(with = "serde_helpers::option_bytes_as_hex")
    )]
    #[cfg_attr(
        feature = "network",
        serde(skip_serializing_if = "Option::is_none", default)
    )]
    pub verifier: Option<Vec<u8>>,
}

/// Paginated list of certificates.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct ListCertificatesResult {
    pub total_certificates: u32,
    pub certificates: Vec<CertificateResult>,
}

/// Arguments for creating a verifiable certificate.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct ProveCertificateArgs {
    pub certificate: Certificate,
    pub fields_to_reveal: Vec<String>,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub verifier: PublicKey,
    pub privileged: BooleanDefaultFalse,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
}

/// Result of creating a verifiable certificate.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct ProveCertificateResult {
    pub keyring_for_verifier: HashMap<String, String>,
}

/// Arguments for relinquishing ownership of a certificate.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct RelinquishCertificateArgs {
    #[cfg_attr(feature = "network", serde(rename = "type"))]
    pub cert_type: CertificateType,
    pub serial_number: SerialNumber,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub certifier: PublicKey,
}

/// Result of relinquishing a certificate.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct RelinquishCertificateResult {
    pub relinquished: bool,
}

// ---------------------------------------------------------------------------
// Discovery types
// ---------------------------------------------------------------------------

/// Information about an entity that issues identity certificates.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct IdentityCertifier {
    pub name: String,
    pub icon_url: String,
    pub description: String,
    pub trust: u8,
}

/// An identity certificate with decoded fields and certifier info.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct IdentityCertificate {
    #[cfg_attr(feature = "network", serde(flatten))]
    pub certificate: Certificate,
    pub certifier_info: IdentityCertifier,
    pub publicly_revealed_keyring: HashMap<String, String>,
    pub decrypted_fields: HashMap<String, String>,
}

/// Arguments for discovering certificates by identity key.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct DiscoverByIdentityKeyArgs {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub identity_key: PublicKey,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub limit: Option<u32>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub offset: Option<u32>,
    pub seek_permission: Option<bool>,
}

/// Arguments for discovering certificates by attributes.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct DiscoverByAttributesArgs {
    pub attributes: HashMap<String, String>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub limit: Option<u32>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub offset: Option<u32>,
    pub seek_permission: Option<bool>,
}

/// Paginated list of identity certificates found during discovery.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct DiscoverCertificatesResult {
    pub total_certificates: u32,
    pub certificates: Vec<IdentityCertificate>,
}

// ---------------------------------------------------------------------------
// Key linkage types
// ---------------------------------------------------------------------------

/// Arguments for revealing key linkage between counterparties.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct RevealCounterpartyKeyLinkageArgs {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub counterparty: PublicKey,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub verifier: PublicKey,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged: Option<bool>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
}

/// Result of revealing counterparty key linkage.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct RevealCounterpartyKeyLinkageResult {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub prover: PublicKey,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub counterparty: PublicKey,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub verifier: PublicKey,
    pub revelation_time: String,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub encrypted_linkage: Vec<u8>,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub encrypted_linkage_proof: Vec<u8>,
}

/// Arguments for revealing specific key linkage.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct RevealSpecificKeyLinkageArgs {
    pub counterparty: Counterparty,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub verifier: PublicKey,
    #[cfg_attr(feature = "network", serde(rename = "protocolID"))]
    pub protocol_id: Protocol,
    #[cfg_attr(feature = "network", serde(rename = "keyID"))]
    pub key_id: String,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged: Option<bool>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub privileged_reason: Option<String>,
}

/// Result of revealing specific key linkage.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct RevealSpecificKeyLinkageResult {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub encrypted_linkage: Vec<u8>,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_array"))]
    pub encrypted_linkage_proof: Vec<u8>,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub prover: PublicKey,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub verifier: PublicKey,
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::public_key_hex"))]
    pub counterparty: PublicKey,
    #[cfg_attr(feature = "network", serde(rename = "protocolID"))]
    pub protocol_id: Protocol,
    #[cfg_attr(feature = "network", serde(rename = "keyID"))]
    pub key_id: String,
    pub proof_type: u8,
}

// ---------------------------------------------------------------------------
// Auth/Info types
// ---------------------------------------------------------------------------

/// Whether the current session is authenticated.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct AuthenticatedResult {
    pub authenticated: bool,
}

/// Current blockchain height.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct GetHeightResult {
    pub height: u32,
}

/// Arguments for retrieving a blockchain header at a specific height.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct GetHeaderArgs {
    pub height: u32,
}

/// Blockchain header data for the requested height.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct GetHeaderResult {
    #[cfg_attr(feature = "network", serde(with = "serde_helpers::bytes_as_hex"))]
    pub header: Vec<u8>,
}

/// Current blockchain network.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct GetNetworkResult {
    pub network: Network,
}

/// Version information about the wallet implementation.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct GetVersionResult {
    pub version: String,
}

// ---------------------------------------------------------------------------
// WalletInterface trait
// ---------------------------------------------------------------------------

/// The core wallet interface with all 28 async methods.
///
/// Uses native async fn in traits (RPITIT, Rust 1.75+) so this trait
/// is NOT object-safe. Use generics (not dyn dispatch) when parameterizing
/// over wallet implementations.
///
/// Every method takes `originator: Option<&str>` as the last parameter,
/// identifying the calling application domain.
#[allow(async_fn_in_trait)]
pub trait WalletInterface {
    // -- Action methods --

    async fn create_action(
        &self,
        args: CreateActionArgs,
        originator: Option<&str>,
    ) -> Result<CreateActionResult, WalletError>;

    async fn sign_action(
        &self,
        args: SignActionArgs,
        originator: Option<&str>,
    ) -> Result<SignActionResult, WalletError>;

    async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: Option<&str>,
    ) -> Result<AbortActionResult, WalletError>;

    async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: Option<&str>,
    ) -> Result<ListActionsResult, WalletError>;

    async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        originator: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError>;

    // -- Output methods --

    async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: Option<&str>,
    ) -> Result<ListOutputsResult, WalletError>;

    async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: Option<&str>,
    ) -> Result<RelinquishOutputResult, WalletError>;

    // -- Key/Crypto methods --

    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError>;

    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError>;

    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError>;

    async fn encrypt(
        &self,
        args: EncryptArgs,
        originator: Option<&str>,
    ) -> Result<EncryptResult, WalletError>;

    async fn decrypt(
        &self,
        args: DecryptArgs,
        originator: Option<&str>,
    ) -> Result<DecryptResult, WalletError>;

    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        originator: Option<&str>,
    ) -> Result<CreateHmacResult, WalletError>;

    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        originator: Option<&str>,
    ) -> Result<VerifyHmacResult, WalletError>;

    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError>;

    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: Option<&str>,
    ) -> Result<VerifySignatureResult, WalletError>;

    // -- Certificate methods --

    async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: Option<&str>,
    ) -> Result<Certificate, WalletError>;

    async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        originator: Option<&str>,
    ) -> Result<ListCertificatesResult, WalletError>;

    async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        originator: Option<&str>,
    ) -> Result<ProveCertificateResult, WalletError>;

    async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: Option<&str>,
    ) -> Result<RelinquishCertificateResult, WalletError>;

    // -- Discovery methods --

    async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError>;

    async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError>;

    // -- Auth/Info methods --

    async fn is_authenticated(
        &self,
        originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError>;

    async fn wait_for_authentication(
        &self,
        originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError>;

    async fn get_height(&self, originator: Option<&str>) -> Result<GetHeightResult, WalletError>;

    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        originator: Option<&str>,
    ) -> Result<GetHeaderResult, WalletError>;

    async fn get_network(&self, originator: Option<&str>) -> Result<GetNetworkResult, WalletError>;

    async fn get_version(&self, originator: Option<&str>) -> Result<GetVersionResult, WalletError>;
}
