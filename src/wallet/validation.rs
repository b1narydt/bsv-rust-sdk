//! Validation helpers for all wallet method arguments.
//!
//! Each validator returns `Result<(), WalletError>` using
//! `WalletError::InvalidParameter` on bad input.
//! Translated from TS SDK src/wallet/validationHelpers.ts.

use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;

// ---------------------------------------------------------------------------
// Shared validation helpers
// ---------------------------------------------------------------------------

fn invalid(field: &str, requirement: &str) -> WalletError {
    WalletError::InvalidParameter(format!("{}: must be {}", field, requirement))
}

fn validate_string_length(s: &str, name: &str, min: usize, max: usize) -> Result<(), WalletError> {
    let len = s.len();
    if len < min {
        return Err(invalid(name, &format!("at least {} bytes", min)));
    }
    if len > max {
        return Err(invalid(name, &format!("no more than {} bytes", max)));
    }
    Ok(())
}

fn validate_label(s: &str) -> Result<(), WalletError> {
    validate_string_length(s, "label", 1, 300)
}

fn validate_tag(s: &str) -> Result<(), WalletError> {
    validate_string_length(s, "tag", 1, 300)
}

fn validate_basket(s: &str) -> Result<(), WalletError> {
    validate_basket_name(s)
}

fn validate_description(s: &str, name: &str) -> Result<(), WalletError> {
    validate_string_length(s, name, 5, 2000)
}

fn validate_optional_limit(limit: Option<u32>) -> Result<(), WalletError> {
    if let Some(v) = limit {
        if !(1..=10000).contains(&v) {
            return Err(invalid("limit", "between 1 and 10000"));
        }
    }
    Ok(())
}

/// Normalize an identifier per BRC-100: trim whitespace, lowercase.
/// Matches TS SDK `validateIdentifier` which does `trim().toLowerCase()`.
pub fn normalize_identifier(s: &str) -> String {
    s.trim().to_lowercase()
}

fn validate_protocol_id(protocol: &crate::wallet::types::Protocol) -> Result<(), WalletError> {
    if protocol.security_level > 2 {
        return Err(invalid("protocol_id.security_level", "0, 1, or 2"));
    }
    let normalized = normalize_identifier(&protocol.protocol);
    if normalized.is_empty() {
        return Err(invalid("protocol_id.protocol", "non-empty"));
    }
    validate_string_length(&normalized, "protocol_id.protocol", 1, 400)?;
    // BRC-100: must not contain multiple consecutive spaces
    if normalized.contains("  ") {
        return Err(invalid(
            "protocol_id.protocol",
            "free of consecutive spaces",
        ));
    }
    // BRC-100: must only contain lowercase letters, numbers, and spaces
    if !normalized
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == ' ')
    {
        return Err(invalid(
            "protocol_id.protocol",
            "only lowercase letters, numbers, and spaces",
        ));
    }
    // BRC-100: must not end with "protocol"
    if normalized.ends_with("protocol") {
        return Err(invalid(
            "protocol_id.protocol",
            "not ending with 'protocol'",
        ));
    }
    // BRC-98: must not start with "p"
    if normalized.starts_with('p') {
        return Err(invalid(
            "protocol_id.protocol",
            "not starting with 'p' (reserved per BRC-98)",
        ));
    }
    Ok(())
}

fn validate_basket_name(s: &str) -> Result<(), WalletError> {
    let normalized = normalize_identifier(s);
    validate_string_length(&normalized, "basket", 5, 300)?;
    // BRC-100: must only contain lowercase letters, numbers, and spaces
    if !normalized
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == ' ')
    {
        return Err(invalid(
            "basket",
            "only lowercase letters, numbers, and spaces",
        ));
    }
    // BRC-100: must not contain consecutive spaces
    if normalized.contains("  ") {
        return Err(invalid("basket", "free of consecutive spaces"));
    }
    // BRC-100: must not end with "basket"
    if normalized.ends_with("basket") {
        return Err(invalid("basket", "not ending with 'basket'"));
    }
    // BRC-100: must not start with "admin"
    if normalized.starts_with("admin") {
        return Err(invalid("basket", "not starting with 'admin'"));
    }
    // BRC-100: must not be "default"
    if normalized == "default" {
        return Err(invalid("basket", "not 'default'"));
    }
    // BRC-99: must not start with "p"
    if normalized.starts_with('p') {
        return Err(invalid(
            "basket",
            "not starting with 'p' (reserved per BRC-99)",
        ));
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), WalletError> {
    if key_id.is_empty() {
        return Err(invalid("key_id", "non-empty"));
    }
    validate_string_length(key_id, "key_id", 1, 800)
}

fn validate_privileged_reason(
    privileged: bool,
    reason: &Option<String>,
) -> Result<(), WalletError> {
    if privileged {
        if let Some(r) = reason {
            validate_string_length(r, "privileged_reason", 5, 50)?;
        } else {
            return Err(invalid(
                "privileged_reason",
                "provided when privileged is true",
            ));
        }
    }
    Ok(())
}

fn validate_optional_privileged_reason(
    privileged: Option<bool>,
    reason: &Option<String>,
) -> Result<(), WalletError> {
    if privileged.unwrap_or(false) {
        if let Some(r) = reason {
            validate_string_length(r, "privileged_reason", 5, 50)?;
        } else {
            return Err(invalid(
                "privileged_reason",
                "provided when privileged is true",
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public validation functions -- one per wallet method's args
// ---------------------------------------------------------------------------

/// Validate CreateActionArgs.
pub fn validate_create_action_args(args: &CreateActionArgs) -> Result<(), WalletError> {
    validate_description(&args.description, "description")?;

    for label in &args.labels {
        validate_label(label)?;
    }

    for output in &args.outputs {
        if output.locking_script.is_none() && output.output_description.is_empty() {
            return Err(invalid(
                "output",
                "has locking_script or output_description",
            ));
        }
        for tag in &output.tags {
            validate_tag(tag)?;
        }
        if let Some(ref basket) = output.basket {
            validate_basket(basket)?;
        }
    }

    for input in &args.inputs {
        if input.unlocking_script.is_none() && input.unlocking_script_length.is_none() {
            return Err(invalid(
                "input",
                "has unlocking_script or unlocking_script_length",
            ));
        }
    }

    Ok(())
}

/// Validate SignActionArgs.
pub fn validate_sign_action_args(args: &SignActionArgs) -> Result<(), WalletError> {
    if args.reference.is_empty() {
        return Err(invalid("reference", "non-empty"));
    }
    if args.spends.is_empty() {
        return Err(invalid("spends", "at least one spend"));
    }
    for spend in args.spends.values() {
        if spend.unlocking_script.is_empty() {
            return Err(invalid("unlocking_script", "non-empty"));
        }
    }
    Ok(())
}

/// Validate AbortActionArgs.
pub fn validate_abort_action_args(args: &AbortActionArgs) -> Result<(), WalletError> {
    if args.reference.is_empty() {
        return Err(invalid("reference", "non-empty"));
    }
    Ok(())
}

/// Validate ListActionsArgs.
pub fn validate_list_actions_args(args: &ListActionsArgs) -> Result<(), WalletError> {
    if args.labels.is_empty() {
        return Err(invalid("labels", "non-empty"));
    }
    for label in &args.labels {
        validate_label(label)?;
    }
    validate_optional_limit(args.limit)?;
    Ok(())
}

/// Validate InternalizeActionArgs.
pub fn validate_internalize_action_args(args: &InternalizeActionArgs) -> Result<(), WalletError> {
    if args.tx.is_empty() {
        return Err(invalid("tx", "non-empty"));
    }
    if args.outputs.is_empty() {
        return Err(invalid("outputs", "at least one output"));
    }
    validate_description(&args.description, "description")?;
    for label in &args.labels {
        validate_label(label)?;
    }
    // InternalizeOutput enum variants guarantee that the correct remittance
    // data is always present -- impossible states are unrepresentable.
    let _ = &args.outputs;
    Ok(())
}

/// Validate ListOutputsArgs.
pub fn validate_list_outputs_args(args: &ListOutputsArgs) -> Result<(), WalletError> {
    validate_basket(&args.basket)?;
    validate_optional_limit(args.limit)?;
    for tag in &args.tags {
        validate_tag(tag)?;
    }
    Ok(())
}

/// Validate RelinquishOutputArgs.
pub fn validate_relinquish_output_args(args: &RelinquishOutputArgs) -> Result<(), WalletError> {
    validate_basket(&args.basket)?;
    if args.output.is_empty() {
        return Err(invalid("output", "non-empty"));
    }
    Ok(())
}

/// Validate GetPublicKeyArgs.
pub fn validate_get_public_key_args(args: &GetPublicKeyArgs) -> Result<(), WalletError> {
    if !args.identity_key {
        if args.protocol_id.is_none() {
            return Err(invalid(
                "protocol_id",
                "provided when identity_key is false",
            ));
        }
        if args.key_id.is_none() {
            return Err(invalid("key_id", "provided when identity_key is false"));
        }
        if let Some(ref p) = args.protocol_id {
            validate_protocol_id(p)?;
        }
        if let Some(ref k) = args.key_id {
            validate_key_id(k)?;
        }
    }
    Ok(())
}

/// Validate EncryptArgs.
pub fn validate_encrypt_args(args: &EncryptArgs) -> Result<(), WalletError> {
    validate_protocol_id(&args.protocol_id)?;
    validate_key_id(&args.key_id)?;
    if args.plaintext.is_empty() {
        return Err(invalid("plaintext", "non-empty"));
    }
    validate_privileged_reason(args.privileged, &args.privileged_reason)?;
    Ok(())
}

/// Validate DecryptArgs.
pub fn validate_decrypt_args(args: &DecryptArgs) -> Result<(), WalletError> {
    validate_protocol_id(&args.protocol_id)?;
    validate_key_id(&args.key_id)?;
    if args.ciphertext.is_empty() {
        return Err(invalid("ciphertext", "non-empty"));
    }
    validate_privileged_reason(args.privileged, &args.privileged_reason)?;
    Ok(())
}

/// Validate CreateHmacArgs.
pub fn validate_create_hmac_args(args: &CreateHmacArgs) -> Result<(), WalletError> {
    validate_protocol_id(&args.protocol_id)?;
    validate_key_id(&args.key_id)?;
    if args.data.is_empty() {
        return Err(invalid("data", "non-empty"));
    }
    validate_privileged_reason(args.privileged, &args.privileged_reason)?;
    Ok(())
}

/// Validate VerifyHmacArgs.
pub fn validate_verify_hmac_args(args: &VerifyHmacArgs) -> Result<(), WalletError> {
    validate_protocol_id(&args.protocol_id)?;
    validate_key_id(&args.key_id)?;
    if args.data.is_empty() {
        return Err(invalid("data", "non-empty"));
    }
    if args.hmac.is_empty() {
        return Err(invalid("hmac", "non-empty"));
    }
    validate_privileged_reason(args.privileged, &args.privileged_reason)?;
    Ok(())
}

/// Validate CreateSignatureArgs.
pub fn validate_create_signature_args(args: &CreateSignatureArgs) -> Result<(), WalletError> {
    validate_protocol_id(&args.protocol_id)?;
    validate_key_id(&args.key_id)?;
    let has_data = args.data.as_ref().is_some_and(|d| !d.is_empty());
    let has_hash = args
        .hash_to_directly_sign
        .as_ref()
        .is_some_and(|h| !h.is_empty());
    if !has_data && !has_hash {
        return Err(invalid(
            "data",
            "provided (either data or hash_to_directly_sign)",
        ));
    }
    if has_hash {
        if let Some(ref h) = args.hash_to_directly_sign {
            if h.len() != 32 {
                return Err(invalid("hash_to_directly_sign", "exactly 32 bytes"));
            }
        }
    }
    validate_privileged_reason(args.privileged, &args.privileged_reason)?;
    Ok(())
}

/// Validate VerifySignatureArgs.
pub fn validate_verify_signature_args(args: &VerifySignatureArgs) -> Result<(), WalletError> {
    validate_protocol_id(&args.protocol_id)?;
    validate_key_id(&args.key_id)?;
    let has_data = args.data.as_ref().is_some_and(|d| !d.is_empty());
    let has_hash = args
        .hash_to_directly_verify
        .as_ref()
        .is_some_and(|h| !h.is_empty());
    if !has_data && !has_hash {
        return Err(invalid(
            "data",
            "provided (either data or hash_to_directly_verify)",
        ));
    }
    if has_hash {
        if let Some(ref h) = args.hash_to_directly_verify {
            if h.len() != 32 {
                return Err(invalid("hash_to_directly_verify", "exactly 32 bytes"));
            }
        }
    }
    if args.signature.is_empty() {
        return Err(invalid("signature", "non-empty"));
    }
    validate_privileged_reason(args.privileged, &args.privileged_reason)?;
    Ok(())
}

/// Validate AcquireCertificateArgs.
pub fn validate_acquire_certificate_args(args: &AcquireCertificateArgs) -> Result<(), WalletError> {
    match args.acquisition_protocol {
        AcquisitionProtocol::Direct => {
            if args.serial_number.is_none() {
                return Err(invalid("serial_number", "provided for direct acquisition"));
            }
            if args.signature.is_none() {
                return Err(invalid("signature", "provided for direct acquisition"));
            }
            if args.revocation_outpoint.is_none() {
                return Err(invalid(
                    "revocation_outpoint",
                    "provided for direct acquisition",
                ));
            }
            if args.keyring_revealer.is_none() {
                return Err(invalid(
                    "keyring_revealer",
                    "provided for direct acquisition",
                ));
            }
            if args.keyring_for_subject.is_none() {
                return Err(invalid(
                    "keyring_for_subject",
                    "provided for direct acquisition",
                ));
            }
        }
        AcquisitionProtocol::Issuance => {
            if args.certifier_url.is_none() {
                return Err(invalid(
                    "certifier_url",
                    "provided for issuance acquisition",
                ));
            }
        }
    }
    validate_privileged_reason(args.privileged, &args.privileged_reason)?;
    // Validate certificate field names
    for field_name in args.fields.keys() {
        validate_string_length(field_name, "field_name", 1, 50)?;
    }
    Ok(())
}

/// Validate ListCertificatesArgs.
pub fn validate_list_certificates_args(args: &ListCertificatesArgs) -> Result<(), WalletError> {
    validate_optional_limit(args.limit)?;
    validate_optional_privileged_reason(args.privileged.0, &args.privileged_reason)?;
    Ok(())
}

/// Validate ProveCertificateArgs.
pub fn validate_prove_certificate_args(args: &ProveCertificateArgs) -> Result<(), WalletError> {
    if args.fields_to_reveal.is_empty() {
        return Err(invalid("fields_to_reveal", "non-empty"));
    }
    for field in &args.fields_to_reveal {
        validate_string_length(field, "fields_to_reveal entry", 1, 50)?;
    }
    validate_optional_privileged_reason(args.privileged.0, &args.privileged_reason)?;
    Ok(())
}

/// Validate RelinquishCertificateArgs.
pub fn validate_relinquish_certificate_args(
    args: &RelinquishCertificateArgs,
) -> Result<(), WalletError> {
    // cert_type, serial_number, certifier are required typed fields -- presence is enforced by struct.
    let _ = args;
    Ok(())
}

/// Validate DiscoverByIdentityKeyArgs.
pub fn validate_discover_by_identity_key_args(
    args: &DiscoverByIdentityKeyArgs,
) -> Result<(), WalletError> {
    // identity_key is a required typed field.
    let _ = args;
    Ok(())
}

/// Validate DiscoverByAttributesArgs.
pub fn validate_discover_by_attributes_args(
    args: &DiscoverByAttributesArgs,
) -> Result<(), WalletError> {
    if args.attributes.is_empty() {
        return Err(invalid("attributes", "non-empty"));
    }
    Ok(())
}

/// Validate RevealCounterpartyKeyLinkageArgs.
pub fn validate_reveal_counterparty_key_linkage_args(
    args: &RevealCounterpartyKeyLinkageArgs,
) -> Result<(), WalletError> {
    validate_optional_privileged_reason(args.privileged, &args.privileged_reason)?;
    Ok(())
}

/// Validate RevealSpecificKeyLinkageArgs.
pub fn validate_reveal_specific_key_linkage_args(
    args: &RevealSpecificKeyLinkageArgs,
) -> Result<(), WalletError> {
    validate_protocol_id(&args.protocol_id)?;
    validate_key_id(&args.key_id)?;
    validate_optional_privileged_reason(args.privileged, &args.privileged_reason)?;
    Ok(())
}

/// Validate GetHeaderArgs.
pub fn validate_get_header_args(args: &GetHeaderArgs) -> Result<(), WalletError> {
    if args.height == 0 {
        return Err(invalid("height", "greater than 0"));
    }
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::types::{
        BooleanDefaultFalse, BooleanDefaultTrue, Counterparty, CounterpartyType, Protocol,
    };

    fn test_pubkey() -> crate::primitives::public_key::PublicKey {
        let pk = PrivateKey::from_bytes(&{
            let mut buf = [0u8; 32];
            buf[31] = 42;
            buf
        })
        .unwrap();
        pk.to_public_key()
    }

    fn test_counterparty() -> Counterparty {
        Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(test_pubkey()),
        }
    }

    fn test_protocol() -> Protocol {
        Protocol {
            security_level: 1,
            protocol: "test signing".to_string(),
        }
    }

    // ---- CreateActionArgs ----

    #[test]
    fn test_create_action_valid() {
        let args = CreateActionArgs {
            description: "Valid description text".to_string(),
            input_beef: None,
            inputs: vec![],
            outputs: vec![],
            lock_time: None,
            version: None,
            labels: vec![],
            options: None,
            reference: None,
        };
        assert!(validate_create_action_args(&args).is_ok());
    }

    #[test]
    fn test_create_action_short_description() {
        let args = CreateActionArgs {
            description: "Hi".to_string(),
            input_beef: None,
            inputs: vec![],
            outputs: vec![],
            lock_time: None,
            version: None,
            labels: vec![],
            options: None,
            reference: None,
        };
        assert!(validate_create_action_args(&args).is_err());
    }

    #[test]
    fn test_create_action_label_too_long() {
        let args = CreateActionArgs {
            description: "Valid description text".to_string(),
            input_beef: None,
            inputs: vec![],
            outputs: vec![],
            lock_time: None,
            version: None,
            labels: vec!["x".repeat(301)],
            options: None,
            reference: None,
        };
        assert!(validate_create_action_args(&args).is_err());
    }

    #[test]
    fn test_create_action_input_needs_script_or_length() {
        let args = CreateActionArgs {
            description: "Valid description text".to_string(),
            input_beef: None,
            inputs: vec![CreateActionInput {
                outpoint: "abc.0".to_string(),
                input_description: "test input".to_string(),
                unlocking_script: None,
                unlocking_script_length: None,
                sequence_number: None,
            }],
            outputs: vec![],
            lock_time: None,
            version: None,
            labels: vec![],
            options: None,
            reference: None,
        };
        assert!(validate_create_action_args(&args).is_err());
    }

    // ---- SignActionArgs ----

    #[test]
    fn test_sign_action_valid() {
        let mut spends = HashMap::new();
        spends.insert(
            0,
            SignActionSpend {
                unlocking_script: vec![1, 2, 3],
                sequence_number: None,
            },
        );
        let args = SignActionArgs {
            reference: vec![1, 2, 3],
            spends,
            options: None,
        };
        assert!(validate_sign_action_args(&args).is_ok());
    }

    #[test]
    fn test_sign_action_empty_reference() {
        let mut spends = HashMap::new();
        spends.insert(
            0,
            SignActionSpend {
                unlocking_script: vec![1],
                sequence_number: None,
            },
        );
        let args = SignActionArgs {
            reference: vec![],
            spends,
            options: None,
        };
        assert!(validate_sign_action_args(&args).is_err());
    }

    #[test]
    fn test_sign_action_empty_spends() {
        let args = SignActionArgs {
            reference: vec![1, 2, 3],
            spends: HashMap::new(),
            options: None,
        };
        assert!(validate_sign_action_args(&args).is_err());
    }

    #[test]
    fn test_sign_action_empty_unlocking_script() {
        let mut spends = HashMap::new();
        spends.insert(
            0,
            SignActionSpend {
                unlocking_script: vec![],
                sequence_number: None,
            },
        );
        let args = SignActionArgs {
            reference: vec![1, 2, 3],
            spends,
            options: None,
        };
        assert!(validate_sign_action_args(&args).is_err());
    }

    // ---- AbortActionArgs ----

    #[test]
    fn test_abort_action_valid() {
        let args = AbortActionArgs {
            reference: vec![1, 2, 3],
        };
        assert!(validate_abort_action_args(&args).is_ok());
    }

    #[test]
    fn test_abort_action_empty_reference() {
        let args = AbortActionArgs { reference: vec![] };
        assert!(validate_abort_action_args(&args).is_err());
    }

    // ---- ListActionsArgs ----

    #[test]
    fn test_list_actions_valid() {
        let args = ListActionsArgs {
            labels: vec!["test".to_string()],
            label_query_mode: None,
            include_labels: BooleanDefaultFalse(None),
            include_inputs: BooleanDefaultFalse(None),
            include_input_source_locking_scripts: BooleanDefaultFalse(None),
            include_input_unlocking_scripts: BooleanDefaultFalse(None),
            include_outputs: BooleanDefaultFalse(None),
            include_output_locking_scripts: BooleanDefaultFalse(None),
            limit: Some(10),
            offset: None,
            seek_permission: BooleanDefaultTrue(None),
        };
        assert!(validate_list_actions_args(&args).is_ok());
    }

    #[test]
    fn test_list_actions_empty_labels() {
        let args = ListActionsArgs {
            labels: vec![],
            label_query_mode: None,
            include_labels: BooleanDefaultFalse(None),
            include_inputs: BooleanDefaultFalse(None),
            include_input_source_locking_scripts: BooleanDefaultFalse(None),
            include_input_unlocking_scripts: BooleanDefaultFalse(None),
            include_outputs: BooleanDefaultFalse(None),
            include_output_locking_scripts: BooleanDefaultFalse(None),
            limit: None,
            offset: None,
            seek_permission: BooleanDefaultTrue(None),
        };
        assert!(validate_list_actions_args(&args).is_err());
    }

    #[test]
    fn test_list_actions_limit_too_high() {
        let args = ListActionsArgs {
            labels: vec!["test".to_string()],
            label_query_mode: None,
            include_labels: BooleanDefaultFalse(None),
            include_inputs: BooleanDefaultFalse(None),
            include_input_source_locking_scripts: BooleanDefaultFalse(None),
            include_input_unlocking_scripts: BooleanDefaultFalse(None),
            include_outputs: BooleanDefaultFalse(None),
            include_output_locking_scripts: BooleanDefaultFalse(None),
            limit: Some(10001),
            offset: None,
            seek_permission: BooleanDefaultTrue(None),
        };
        assert!(validate_list_actions_args(&args).is_err());
    }

    #[test]
    fn test_list_actions_limit_zero() {
        let args = ListActionsArgs {
            labels: vec!["test".to_string()],
            label_query_mode: None,
            include_labels: BooleanDefaultFalse(None),
            include_inputs: BooleanDefaultFalse(None),
            include_input_source_locking_scripts: BooleanDefaultFalse(None),
            include_input_unlocking_scripts: BooleanDefaultFalse(None),
            include_outputs: BooleanDefaultFalse(None),
            include_output_locking_scripts: BooleanDefaultFalse(None),
            limit: Some(0),
            offset: None,
            seek_permission: BooleanDefaultTrue(None),
        };
        assert!(validate_list_actions_args(&args).is_err());
    }

    // ---- InternalizeActionArgs ----

    #[test]
    fn test_internalize_action_valid() {
        let args = InternalizeActionArgs {
            tx: vec![1, 2, 3],
            description: "Valid description text".to_string(),
            labels: vec![],
            seek_permission: BooleanDefaultTrue(None),
            outputs: vec![InternalizeOutput::BasketInsertion {
                output_index: 0,
                insertion: BasketInsertion {
                    basket: "test-basket".to_string(),
                    custom_instructions: None,
                    tags: vec![],
                },
            }],
        };
        assert!(validate_internalize_action_args(&args).is_ok());
    }

    #[test]
    fn test_internalize_action_empty_tx() {
        let args = InternalizeActionArgs {
            tx: vec![],
            description: "Valid description text".to_string(),
            labels: vec![],
            seek_permission: BooleanDefaultTrue(None),
            outputs: vec![InternalizeOutput::BasketInsertion {
                output_index: 0,
                insertion: BasketInsertion {
                    basket: "test".to_string(),
                    custom_instructions: None,
                    tags: vec![],
                },
            }],
        };
        assert!(validate_internalize_action_args(&args).is_err());
    }

    #[test]
    fn test_internalize_action_empty_outputs() {
        let args = InternalizeActionArgs {
            tx: vec![1, 2, 3],
            description: "Valid description text".to_string(),
            labels: vec![],
            seek_permission: BooleanDefaultTrue(None),
            outputs: vec![],
        };
        assert!(validate_internalize_action_args(&args).is_err());
    }

    // ---- ListOutputsArgs ----

    #[test]
    fn test_list_outputs_valid() {
        let args = ListOutputsArgs {
            basket: "token store".to_string(),
            tags: vec![],
            tag_query_mode: None,
            include: None,
            include_custom_instructions: BooleanDefaultFalse(None),
            include_tags: BooleanDefaultFalse(None),
            include_labels: BooleanDefaultFalse(None),
            limit: Some(10),
            offset: None,
            seek_permission: BooleanDefaultTrue(None),
        };
        assert!(validate_list_outputs_args(&args).is_ok());
    }

    #[test]
    fn test_list_outputs_empty_basket() {
        let args = ListOutputsArgs {
            basket: "".to_string(),
            tags: vec![],
            tag_query_mode: None,
            include: None,
            include_custom_instructions: BooleanDefaultFalse(None),
            include_tags: BooleanDefaultFalse(None),
            include_labels: BooleanDefaultFalse(None),
            limit: None,
            offset: None,
            seek_permission: BooleanDefaultTrue(None),
        };
        assert!(validate_list_outputs_args(&args).is_err());
    }

    #[test]
    fn test_list_outputs_limit_too_high() {
        let args = ListOutputsArgs {
            basket: "token store".to_string(),
            tags: vec![],
            tag_query_mode: None,
            include: None,
            include_custom_instructions: BooleanDefaultFalse(None),
            include_tags: BooleanDefaultFalse(None),
            include_labels: BooleanDefaultFalse(None),
            limit: Some(10001),
            offset: None,
            seek_permission: BooleanDefaultTrue(None),
        };
        assert!(validate_list_outputs_args(&args).is_err());
    }

    // ---- RelinquishOutputArgs ----

    #[test]
    fn test_relinquish_output_valid() {
        let args = RelinquishOutputArgs {
            basket: "token store".to_string(),
            output: "abc123.0".to_string(),
        };
        assert!(validate_relinquish_output_args(&args).is_ok());
    }

    #[test]
    fn test_relinquish_output_empty_basket() {
        let args = RelinquishOutputArgs {
            basket: "".to_string(),
            output: "abc123.0".to_string(),
        };
        assert!(validate_relinquish_output_args(&args).is_err());
    }

    #[test]
    fn test_relinquish_output_empty_output() {
        let args = RelinquishOutputArgs {
            basket: "token store".to_string(),
            output: "".to_string(),
        };
        assert!(validate_relinquish_output_args(&args).is_err());
    }

    // ---- GetPublicKeyArgs ----

    #[test]
    fn test_get_public_key_identity() {
        let args = GetPublicKeyArgs {
            identity_key: true,
            protocol_id: None,
            key_id: None,
            counterparty: None,
            privileged: false,
            privileged_reason: None,
            for_self: None,
            seek_permission: None,
        };
        assert!(validate_get_public_key_args(&args).is_ok());
    }

    #[test]
    fn test_get_public_key_derived_valid() {
        let args = GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(test_protocol()),
            key_id: Some("my-key".to_string()),
            counterparty: Some(test_counterparty()),
            privileged: false,
            privileged_reason: None,
            for_self: None,
            seek_permission: None,
        };
        assert!(validate_get_public_key_args(&args).is_ok());
    }

    #[test]
    fn test_get_public_key_derived_missing_protocol() {
        let args = GetPublicKeyArgs {
            identity_key: false,
            protocol_id: None,
            key_id: Some("my-key".to_string()),
            counterparty: None,
            privileged: false,
            privileged_reason: None,
            for_self: None,
            seek_permission: None,
        };
        assert!(validate_get_public_key_args(&args).is_err());
    }

    #[test]
    fn test_get_public_key_derived_missing_key_id() {
        let args = GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(test_protocol()),
            key_id: None,
            counterparty: None,
            privileged: false,
            privileged_reason: None,
            for_self: None,
            seek_permission: None,
        };
        assert!(validate_get_public_key_args(&args).is_err());
    }

    // ---- EncryptArgs ----

    #[test]
    fn test_encrypt_valid() {
        let args = EncryptArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            plaintext: vec![1, 2, 3],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_encrypt_args(&args).is_ok());
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let args = EncryptArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            plaintext: vec![],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_encrypt_args(&args).is_err());
    }

    #[test]
    fn test_encrypt_empty_protocol() {
        let args = EncryptArgs {
            protocol_id: Protocol {
                security_level: 1,
                protocol: "".to_string(),
            },
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            plaintext: vec![1, 2, 3],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_encrypt_args(&args).is_err());
    }

    #[test]
    fn test_encrypt_empty_key_id() {
        let args = EncryptArgs {
            protocol_id: test_protocol(),
            key_id: "".to_string(),
            counterparty: test_counterparty(),
            plaintext: vec![1, 2, 3],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_encrypt_args(&args).is_err());
    }

    #[test]
    fn test_encrypt_invalid_security_level() {
        let args = EncryptArgs {
            protocol_id: Protocol {
                security_level: 5,
                protocol: "test".to_string(),
            },
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            plaintext: vec![1, 2, 3],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_encrypt_args(&args).is_err());
    }

    // ---- DecryptArgs ----

    #[test]
    fn test_decrypt_valid() {
        let args = DecryptArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            ciphertext: vec![1, 2, 3],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_decrypt_args(&args).is_ok());
    }

    #[test]
    fn test_decrypt_empty_ciphertext() {
        let args = DecryptArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            ciphertext: vec![],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_decrypt_args(&args).is_err());
    }

    // ---- CreateHmacArgs ----

    #[test]
    fn test_create_hmac_valid() {
        let args = CreateHmacArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            data: vec![1, 2, 3],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_create_hmac_args(&args).is_ok());
    }

    #[test]
    fn test_create_hmac_empty_data() {
        let args = CreateHmacArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            data: vec![],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_create_hmac_args(&args).is_err());
    }

    // ---- VerifyHmacArgs ----

    #[test]
    fn test_verify_hmac_valid() {
        let args = VerifyHmacArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            data: vec![1, 2, 3],
            hmac: vec![4, 5, 6],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_verify_hmac_args(&args).is_ok());
    }

    #[test]
    fn test_verify_hmac_empty_hmac() {
        let args = VerifyHmacArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            data: vec![1, 2, 3],
            hmac: vec![],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_verify_hmac_args(&args).is_err());
    }

    // ---- CreateSignatureArgs ----

    #[test]
    fn test_create_signature_valid() {
        let args = CreateSignatureArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            data: Some(vec![1, 2, 3]),
            hash_to_directly_sign: None,
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_create_signature_args(&args).is_ok());
    }

    #[test]
    fn test_create_signature_empty_data() {
        let args = CreateSignatureArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            data: Some(vec![]),
            hash_to_directly_sign: None,
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_create_signature_args(&args).is_err());
    }

    // ---- VerifySignatureArgs ----

    #[test]
    fn test_verify_signature_valid() {
        let args = VerifySignatureArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            data: Some(vec![1, 2, 3]),
            hash_to_directly_verify: None,
            signature: vec![4, 5, 6],
            for_self: None,
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_verify_signature_args(&args).is_ok());
    }

    #[test]
    fn test_verify_signature_empty_signature() {
        let args = VerifySignatureArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            data: Some(vec![1, 2, 3]),
            hash_to_directly_verify: None,
            signature: vec![],
            for_self: None,
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_verify_signature_args(&args).is_err());
    }

    // ---- AcquireCertificateArgs ----

    #[test]
    fn test_acquire_certificate_direct_valid() {
        let args = AcquireCertificateArgs {
            cert_type: CertificateType([0u8; 32]),
            certifier: test_pubkey(),
            acquisition_protocol: AcquisitionProtocol::Direct,
            fields: HashMap::new(),
            serial_number: Some(SerialNumber([0u8; 32])),
            revocation_outpoint: Some("abc.0".to_string()),
            signature: Some(vec![1, 2, 3]),
            certifier_url: None,
            keyring_revealer: Some(KeyringRevealer::Certifier),
            keyring_for_subject: Some(HashMap::new()),
            privileged: false,
            privileged_reason: None,
        };
        assert!(validate_acquire_certificate_args(&args).is_ok());
    }

    #[test]
    fn test_acquire_certificate_direct_missing_serial() {
        let args = AcquireCertificateArgs {
            cert_type: CertificateType([0u8; 32]),
            certifier: test_pubkey(),
            acquisition_protocol: AcquisitionProtocol::Direct,
            fields: HashMap::new(),
            serial_number: None,
            revocation_outpoint: Some("abc.0".to_string()),
            signature: Some(vec![1, 2, 3]),
            certifier_url: None,
            keyring_revealer: Some(KeyringRevealer::Certifier),
            keyring_for_subject: Some(HashMap::new()),
            privileged: false,
            privileged_reason: None,
        };
        assert!(validate_acquire_certificate_args(&args).is_err());
    }

    #[test]
    fn test_acquire_certificate_issuance_valid() {
        let args = AcquireCertificateArgs {
            cert_type: CertificateType([0u8; 32]),
            certifier: test_pubkey(),
            acquisition_protocol: AcquisitionProtocol::Issuance,
            fields: HashMap::new(),
            serial_number: None,
            revocation_outpoint: None,
            signature: None,
            certifier_url: Some("https://example.com".to_string()),
            keyring_revealer: None,
            keyring_for_subject: None,
            privileged: false,
            privileged_reason: None,
        };
        assert!(validate_acquire_certificate_args(&args).is_ok());
    }

    #[test]
    fn test_acquire_certificate_issuance_missing_url() {
        let args = AcquireCertificateArgs {
            cert_type: CertificateType([0u8; 32]),
            certifier: test_pubkey(),
            acquisition_protocol: AcquisitionProtocol::Issuance,
            fields: HashMap::new(),
            serial_number: None,
            revocation_outpoint: None,
            signature: None,
            certifier_url: None,
            keyring_revealer: None,
            keyring_for_subject: None,
            privileged: false,
            privileged_reason: None,
        };
        assert!(validate_acquire_certificate_args(&args).is_err());
    }

    // ---- ListCertificatesArgs ----

    #[test]
    fn test_list_certificates_valid() {
        let args = ListCertificatesArgs {
            certifiers: vec![],
            types: vec![],
            limit: Some(10),
            offset: None,
            privileged: BooleanDefaultFalse(None),
            privileged_reason: None,
        };
        assert!(validate_list_certificates_args(&args).is_ok());
    }

    #[test]
    fn test_list_certificates_limit_too_high() {
        let args = ListCertificatesArgs {
            certifiers: vec![],
            types: vec![],
            limit: Some(10001),
            offset: None,
            privileged: BooleanDefaultFalse(None),
            privileged_reason: None,
        };
        assert!(validate_list_certificates_args(&args).is_err());
    }

    // ---- ProveCertificateArgs ----

    #[test]
    fn test_prove_certificate_valid() {
        let args = ProveCertificateArgs {
            certificate: Certificate {
                cert_type: CertificateType([0u8; 32]),
                serial_number: SerialNumber([0u8; 32]),
                subject: test_pubkey(),
                certifier: test_pubkey(),
                revocation_outpoint: None,
                fields: None,
                signature: None,
            }
            .into(),
            fields_to_reveal: vec!["name".to_string()],
            verifier: test_pubkey(),
            privileged: BooleanDefaultFalse(None),
            privileged_reason: None,
        };
        assert!(validate_prove_certificate_args(&args).is_ok());
    }

    #[test]
    fn test_prove_certificate_empty_fields() {
        let args = ProveCertificateArgs {
            certificate: Certificate {
                cert_type: CertificateType([0u8; 32]),
                serial_number: SerialNumber([0u8; 32]),
                subject: test_pubkey(),
                certifier: test_pubkey(),
                revocation_outpoint: None,
                fields: None,
                signature: None,
            }
            .into(),
            fields_to_reveal: vec![],
            verifier: test_pubkey(),
            privileged: BooleanDefaultFalse(None),
            privileged_reason: None,
        };
        assert!(validate_prove_certificate_args(&args).is_err());
    }

    // ---- RelinquishCertificateArgs ----

    #[test]
    fn test_relinquish_certificate_valid() {
        let args = RelinquishCertificateArgs {
            cert_type: CertificateType([0u8; 32]),
            serial_number: SerialNumber([0u8; 32]),
            certifier: test_pubkey(),
        };
        assert!(validate_relinquish_certificate_args(&args).is_ok());
    }

    // ---- DiscoverByIdentityKeyArgs ----

    #[test]
    fn test_discover_by_identity_key_valid() {
        let args = DiscoverByIdentityKeyArgs {
            identity_key: test_pubkey(),
            limit: None,
            offset: None,
            seek_permission: None,
        };
        assert!(validate_discover_by_identity_key_args(&args).is_ok());
    }

    // ---- DiscoverByAttributesArgs ----

    #[test]
    fn test_discover_by_attributes_valid() {
        let mut attrs = HashMap::new();
        attrs.insert("name".to_string(), "Alice".to_string());
        let args = DiscoverByAttributesArgs {
            attributes: attrs,
            limit: None,
            offset: None,
            seek_permission: None,
        };
        assert!(validate_discover_by_attributes_args(&args).is_ok());
    }

    #[test]
    fn test_discover_by_attributes_empty() {
        let args = DiscoverByAttributesArgs {
            attributes: HashMap::new(),
            limit: None,
            offset: None,
            seek_permission: None,
        };
        assert!(validate_discover_by_attributes_args(&args).is_err());
    }

    // ---- RevealCounterpartyKeyLinkageArgs ----

    #[test]
    fn test_reveal_counterparty_key_linkage_valid() {
        let args = RevealCounterpartyKeyLinkageArgs {
            counterparty: test_pubkey(),
            verifier: test_pubkey(),
            privileged: None,
            privileged_reason: None,
        };
        assert!(validate_reveal_counterparty_key_linkage_args(&args).is_ok());
    }

    // ---- RevealSpecificKeyLinkageArgs ----

    #[test]
    fn test_reveal_specific_key_linkage_valid() {
        let args = RevealSpecificKeyLinkageArgs {
            counterparty: test_counterparty(),
            verifier: test_pubkey(),
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            privileged: None,
            privileged_reason: None,
        };
        assert!(validate_reveal_specific_key_linkage_args(&args).is_ok());
    }

    #[test]
    fn test_reveal_specific_key_linkage_empty_key_id() {
        let args = RevealSpecificKeyLinkageArgs {
            counterparty: test_counterparty(),
            verifier: test_pubkey(),
            protocol_id: test_protocol(),
            key_id: "".to_string(),
            privileged: None,
            privileged_reason: None,
        };
        assert!(validate_reveal_specific_key_linkage_args(&args).is_err());
    }

    // ---- GetHeaderArgs ----

    #[test]
    fn test_get_header_valid() {
        let args = GetHeaderArgs { height: 100 };
        assert!(validate_get_header_args(&args).is_ok());
    }

    #[test]
    fn test_get_header_zero_height() {
        let args = GetHeaderArgs { height: 0 };
        assert!(validate_get_header_args(&args).is_err());
    }

    // ---- Privileged reason validation ----

    #[test]
    fn test_privileged_without_reason() {
        let args = EncryptArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            plaintext: vec![1, 2, 3],
            privileged: true,
            privileged_reason: None,
            seek_permission: None,
        };
        assert!(validate_encrypt_args(&args).is_err());
    }

    #[test]
    fn test_privileged_with_short_reason() {
        let args = EncryptArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            plaintext: vec![1, 2, 3],
            privileged: true,
            privileged_reason: Some("ab".to_string()),
            seek_permission: None,
        };
        assert!(validate_encrypt_args(&args).is_err());
    }

    #[test]
    fn test_privileged_with_valid_reason() {
        let args = EncryptArgs {
            protocol_id: test_protocol(),
            key_id: "my-key".to_string(),
            counterparty: test_counterparty(),
            plaintext: vec![1, 2, 3],
            privileged: true,
            privileged_reason: Some("Admin access required".to_string()),
            seek_permission: None,
        };
        assert!(validate_encrypt_args(&args).is_ok());
    }
}
