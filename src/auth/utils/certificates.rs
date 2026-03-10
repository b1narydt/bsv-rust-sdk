//! Certificate utility functions for the auth module.
//!
//! Provides validate_certificates (verifies certificate signatures and identity)
//! and get_verifiable_certificates (retrieves and prepares selectively revealed
//! certificates for a verifier).
//!
//! Translated from TS SDK validateCertificates.ts / getVerifiableCertificates.ts
//! and Go SDK validate_certificates.go / get_verifiable_certificates.go.

use crate::auth::certificates::certificate::{base64_decode, base64_encode, AuthCertificate};
use crate::auth::certificates::verifiable::VerifiableCertificate;
use crate::auth::error::AuthError;
use crate::auth::types::RequestedCertificateSet;
use crate::primitives::public_key::PublicKey;
use crate::wallet::interfaces::{
    CertificateType, ListCertificatesArgs, ProveCertificateArgs, WalletInterface,
};
use crate::wallet::types::BooleanDefaultFalse;

// ---------------------------------------------------------------------------
// validate_certificates
// ---------------------------------------------------------------------------

/// Validate certificates received from a peer during authentication.
///
/// For each certificate:
/// 1. Verifies the subject matches the sender's identity key
/// 2. Verifies the certificate signature using AuthCertificate::verify
/// 3. If a RequestedCertificateSet is provided, checks that the certifier
///    and certificate type are in the requested set
///
/// Returns Ok(true) if all certificates pass validation, Ok(false) if any fail.
/// Returns Err on infrastructure errors (wallet, parsing).
///
/// Translated from TS validateCertificates and Go ValidateCertificates.
pub async fn validate_certificates<W: WalletInterface + ?Sized>(
    verifier_wallet: &W,
    certificates: &[VerifiableCertificate],
    sender_identity_key: &PublicKey,
    requested: Option<&RequestedCertificateSet>,
) -> Result<bool, AuthError> {
    if certificates.is_empty() {
        return Err(AuthError::CertificateValidation(
            "no certificates were provided".to_string(),
        ));
    }

    for cert in certificates {
        // 1. Verify subject matches sender identity key
        if cert.certificate.subject != *sender_identity_key {
            return Ok(false);
        }

        // 2. Verify certificate signature
        let valid = AuthCertificate::verify(&cert.certificate, verifier_wallet).await?;
        if !valid {
            return Ok(false);
        }

        // 3. Check against requested certificates if provided
        if let Some(req) = requested {
            // Check certificate type is in the requested types
            let cert_type_b64 = base64_encode(&cert.certificate.cert_type.0);
            if !req.contains_key(&cert_type_b64) {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// get_verifiable_certificates
// ---------------------------------------------------------------------------

/// Retrieve and prepare verifiable certificates for a verifier.
///
/// Queries the wallet for certificates matching the requested types,
/// then creates VerifiableCertificates with selectively revealed fields
/// using wallet.prove_certificate for each match.
///
/// Translated from TS getVerifiableCertificates and Go GetVerifiableCertificates.
pub async fn get_verifiable_certificates<W: WalletInterface + ?Sized>(
    wallet: &W,
    requested: &RequestedCertificateSet,
    verifier_identity_key: &PublicKey,
) -> Result<Vec<VerifiableCertificate>, AuthError> {
    if requested.is_empty() {
        return Ok(Vec::new());
    }

    // Convert base64 type keys to CertificateType for the wallet query
    let mut cert_types: Vec<CertificateType> = Vec::new();
    for type_key_b64 in requested.keys() {
        let decoded = base64_decode(type_key_b64)?;
        if decoded.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            cert_types.push(CertificateType(arr));
        }
    }

    // Query wallet for matching certificates
    let list_result = wallet
        .list_certificates(
            ListCertificatesArgs {
                certifiers: Vec::new(),
                types: cert_types,
                limit: Some(100),
                offset: Some(0),
                privileged: BooleanDefaultFalse(None),
                privileged_reason: None,
            },
            None,
        )
        .await?;

    let mut result = Vec::new();

    for cert_result in &list_result.certificates {
        let cert = &cert_result.certificate;
        let cert_type_b64 = base64_encode(&cert.cert_type.0);

        // Check if this certificate type was requested and get requested fields
        let fields_to_reveal = match requested.get(&cert_type_b64) {
            Some(fields) if !fields.is_empty() => fields.clone(),
            _ => continue,
        };

        // Prove the certificate to the verifier (creates keyring for verifier)
        let prove_result = wallet
            .prove_certificate(
                ProveCertificateArgs {
                    certificate: cert.clone().into(),
                    fields_to_reveal,
                    verifier: verifier_identity_key.clone(),
                    privileged: BooleanDefaultFalse(None),
                    privileged_reason: None,
                },
                None,
            )
            .await?;

        let verifiable =
            VerifiableCertificate::new(cert.clone(), prove_result.keyring_for_verifier);
        result.push(verifiable);
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Field encryption key ID helpers
// ---------------------------------------------------------------------------

/// Get the encryption key ID for a certificate field in a verifier keyring.
///
/// Returns "{serial_number} {field_name}" -- the serial_number should be
/// base64-encoded. This matches the TS SDK getCertificateFieldEncryptionDetails
/// with a serial number.
pub fn get_certificate_field_encryption_key_id(field_name: &str, serial_number: &str) -> String {
    format!("{} {}", serial_number, field_name)
}

/// Get the encryption key ID for a master certificate field.
///
/// Returns just the field_name (master keys have no serial number prefix).
/// This matches the TS SDK getCertificateFieldEncryptionDetails without a
/// serial number.
pub fn get_master_field_encryption_key_id(field_name: &str) -> String {
    field_name.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::certificates::certificate::AuthCertificate;
    use crate::auth::certificates::master::MasterCertificate;
    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::error::WalletError;
    use crate::wallet::interfaces::*;
    use crate::wallet::types::{Counterparty, CounterpartyType, Protocol as WalletProtocol};
    use crate::wallet::ProtoWallet;
    use std::collections::HashMap;

    // -----------------------------------------------------------------------
    // TestWallet reuse (same pattern as master.rs tests)
    // -----------------------------------------------------------------------

    struct TestWallet {
        inner: ProtoWallet,
    }

    impl TestWallet {
        fn new(pk: PrivateKey) -> Self {
            TestWallet {
                inner: ProtoWallet::new(pk),
            }
        }
    }

    /// Uses desugared async-trait form so it works inside #[async_trait] impl blocks.
    macro_rules! stub_method {
        ($name:ident, $args:ty, $ret:ty) => {
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _args: $args,
                _originator: Option<&'life1 str>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<Output = Result<$ret, WalletError>>
                        + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    unimplemented!(concat!(
                        stringify!($name),
                        " not needed for cert util tests"
                    ))
                })
            }
        };
        ($name:ident, $ret:ty) => {
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _originator: Option<&'life1 str>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<Output = Result<$ret, WalletError>>
                        + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    unimplemented!(concat!(
                        stringify!($name),
                        " not needed for cert util tests"
                    ))
                })
            }
        };
    }

    #[async_trait::async_trait]
    impl WalletInterface for TestWallet {
        stub_method!(create_action, CreateActionArgs, CreateActionResult);
        stub_method!(sign_action, SignActionArgs, SignActionResult);
        stub_method!(abort_action, AbortActionArgs, AbortActionResult);
        stub_method!(list_actions, ListActionsArgs, ListActionsResult);
        stub_method!(
            internalize_action,
            InternalizeActionArgs,
            InternalizeActionResult
        );
        stub_method!(list_outputs, ListOutputsArgs, ListOutputsResult);
        stub_method!(
            relinquish_output,
            RelinquishOutputArgs,
            RelinquishOutputResult
        );

        async fn get_public_key(
            &self,
            args: GetPublicKeyArgs,
            _originator: Option<&str>,
        ) -> Result<GetPublicKeyResult, WalletError> {
            let protocol = args.protocol_id.unwrap_or(WalletProtocol {
                security_level: 0,
                protocol: String::new(),
            });
            let key_id = args.key_id.unwrap_or_default();
            let counterparty = args.counterparty.unwrap_or(Counterparty {
                counterparty_type: CounterpartyType::Uninitialized,
                public_key: None,
            });
            let pk = self.inner.get_public_key_sync(
                &protocol,
                &key_id,
                &counterparty,
                args.for_self.unwrap_or(false),
                args.identity_key,
            )?;
            Ok(GetPublicKeyResult { public_key: pk })
        }

        stub_method!(
            reveal_counterparty_key_linkage,
            RevealCounterpartyKeyLinkageArgs,
            RevealCounterpartyKeyLinkageResult
        );
        stub_method!(
            reveal_specific_key_linkage,
            RevealSpecificKeyLinkageArgs,
            RevealSpecificKeyLinkageResult
        );

        async fn encrypt(
            &self,
            args: EncryptArgs,
            _originator: Option<&str>,
        ) -> Result<EncryptResult, WalletError> {
            let ciphertext = self.inner.encrypt_sync(
                &args.plaintext,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(EncryptResult { ciphertext })
        }

        async fn decrypt(
            &self,
            args: DecryptArgs,
            _originator: Option<&str>,
        ) -> Result<DecryptResult, WalletError> {
            let plaintext = self.inner.decrypt_sync(
                &args.ciphertext,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(DecryptResult { plaintext })
        }

        async fn create_hmac(
            &self,
            args: CreateHmacArgs,
            _originator: Option<&str>,
        ) -> Result<CreateHmacResult, WalletError> {
            let hmac = self.inner.create_hmac_sync(
                &args.data,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(CreateHmacResult { hmac })
        }

        async fn verify_hmac(
            &self,
            args: VerifyHmacArgs,
            _originator: Option<&str>,
        ) -> Result<VerifyHmacResult, WalletError> {
            let valid = self.inner.verify_hmac_sync(
                &args.data,
                &args.hmac,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(VerifyHmacResult { valid })
        }

        async fn create_signature(
            &self,
            args: CreateSignatureArgs,
            _originator: Option<&str>,
        ) -> Result<CreateSignatureResult, WalletError> {
            let signature = self.inner.create_signature_sync(
                args.data.as_deref(),
                args.hash_to_directly_sign.as_deref(),
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(CreateSignatureResult { signature })
        }

        async fn verify_signature(
            &self,
            args: VerifySignatureArgs,
            _originator: Option<&str>,
        ) -> Result<VerifySignatureResult, WalletError> {
            let valid = self.inner.verify_signature_sync(
                args.data.as_deref(),
                args.hash_to_directly_verify.as_deref(),
                &args.signature,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
                args.for_self.unwrap_or(false),
            )?;
            Ok(VerifySignatureResult { valid })
        }

        stub_method!(acquire_certificate, AcquireCertificateArgs, Certificate);
        stub_method!(
            list_certificates,
            ListCertificatesArgs,
            ListCertificatesResult
        );
        stub_method!(
            prove_certificate,
            ProveCertificateArgs,
            ProveCertificateResult
        );
        stub_method!(
            relinquish_certificate,
            RelinquishCertificateArgs,
            RelinquishCertificateResult
        );
        stub_method!(
            discover_by_identity_key,
            DiscoverByIdentityKeyArgs,
            DiscoverCertificatesResult
        );
        stub_method!(
            discover_by_attributes,
            DiscoverByAttributesArgs,
            DiscoverCertificatesResult
        );
        stub_method!(is_authenticated, AuthenticatedResult);
        stub_method!(wait_for_authentication, AuthenticatedResult);
        stub_method!(get_height, GetHeightResult);
        stub_method!(get_header_for_height, GetHeaderArgs, GetHeaderResult);
        stub_method!(get_network, GetNetworkResult);
        stub_method!(get_version, GetVersionResult);
    }

    #[tokio::test]
    async fn test_validate_certificates_with_valid_signed_cert() {
        // Issue a certificate using a certifier wallet
        let certifier_pk = PrivateKey::from_random().unwrap();
        let certifier_wallet = TestWallet::new(certifier_pk.clone());

        let subject_pk = PrivateKey::from_random().unwrap();
        let subject_pubkey = subject_pk.to_public_key();

        let cert_type = CertificateType([5u8; 32]);

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Test User".to_string());

        let master_cert = MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            &subject_pubkey,
            fields,
            &certifier_wallet,
        )
        .await
        .expect("issue failed");

        // Create a VerifiableCertificate from the master cert
        let verifiable = VerifiableCertificate::new(
            master_cert.certificate.clone(),
            HashMap::new(), // empty keyring for validation test
        );

        // Verify using an "anyone" wallet (PrivateKey(1))
        let anyone_wallet = TestWallet::new(
            PrivateKey::from_bytes(&{
                let mut buf = [0u8; 32];
                buf[31] = 1;
                buf
            })
            .unwrap(),
        );

        let valid = validate_certificates(&anyone_wallet, &[verifiable], &subject_pubkey, None)
            .await
            .expect("validate_certificates failed");
        assert!(valid, "properly signed certificate should validate");
    }

    #[tokio::test]
    async fn test_validate_certificates_rejects_wrong_subject() {
        let certifier_pk = PrivateKey::from_random().unwrap();
        let certifier_wallet = TestWallet::new(certifier_pk.clone());

        let subject_pk = PrivateKey::from_random().unwrap();
        let subject_pubkey = subject_pk.to_public_key();

        let cert_type = CertificateType([6u8; 32]);

        let mut fields = HashMap::new();
        fields.insert("data".to_string(), "value".to_string());

        let master_cert = MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            &subject_pubkey,
            fields,
            &certifier_wallet,
        )
        .await
        .expect("issue failed");

        let verifiable =
            VerifiableCertificate::new(master_cert.certificate.clone(), HashMap::new());

        // Use a DIFFERENT identity key as the sender -- should fail subject check
        let wrong_identity = PrivateKey::from_random().unwrap().to_public_key();

        let anyone_wallet = TestWallet::new(
            PrivateKey::from_bytes(&{
                let mut buf = [0u8; 32];
                buf[31] = 1;
                buf
            })
            .unwrap(),
        );

        let valid = validate_certificates(&anyone_wallet, &[verifiable], &wrong_identity, None)
            .await
            .expect("validate_certificates failed");
        assert!(!valid, "certificate with wrong subject should not validate");
    }

    #[tokio::test]
    async fn test_validate_certificates_empty_returns_error() {
        let anyone_wallet = TestWallet::new(
            PrivateKey::from_bytes(&{
                let mut buf = [0u8; 32];
                buf[31] = 1;
                buf
            })
            .unwrap(),
        );
        let identity = PrivateKey::from_random().unwrap().to_public_key();

        let result = validate_certificates(&anyone_wallet, &[], &identity, None).await;
        assert!(result.is_err(), "empty certificates should return error");
    }

    #[test]
    fn test_field_encryption_key_id_helpers() {
        let key_id = get_certificate_field_encryption_key_id("name", "AAAA");
        assert_eq!(key_id, "AAAA name");

        let master_key_id = get_master_field_encryption_key_id("email");
        assert_eq!(master_key_id, "email");
    }

    #[tokio::test]
    async fn test_validate_certificates_rejects_unrequested_type() {
        let certifier_pk = PrivateKey::from_random().unwrap();
        let certifier_wallet = TestWallet::new(certifier_pk.clone());

        let subject_pk = PrivateKey::from_random().unwrap();
        let subject_pubkey = subject_pk.to_public_key();

        let cert_type = CertificateType([7u8; 32]);

        let mut fields = HashMap::new();
        fields.insert("field".to_string(), "val".to_string());

        let master_cert = MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            &subject_pubkey,
            fields,
            &certifier_wallet,
        )
        .await
        .expect("issue failed");

        let verifiable =
            VerifiableCertificate::new(master_cert.certificate.clone(), HashMap::new());

        // Create a requested set that does NOT include this cert type
        let mut requested: RequestedCertificateSet = HashMap::new();
        let different_type_b64 = crate::auth::certificates::certificate::base64_encode(&[99u8; 32]);
        requested.insert(different_type_b64, vec!["field".to_string()]);

        let anyone_wallet = TestWallet::new(
            PrivateKey::from_bytes(&{
                let mut buf = [0u8; 32];
                buf[31] = 1;
                buf
            })
            .unwrap(),
        );

        let valid = validate_certificates(
            &anyone_wallet,
            &[verifiable],
            &subject_pubkey,
            Some(&requested),
        )
        .await
        .expect("validate_certificates failed");
        assert!(
            !valid,
            "certificate with unrequested type should not validate"
        );
    }
}
