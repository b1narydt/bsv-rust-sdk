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
#[cfg(feature = "network")]
use futures_util::{stream::FuturesUnordered, StreamExt};

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
/// 4. Decrypts the selectively revealed fields with the verifier wallet
///
/// Returns Ok(true) if all certificates pass validation, Ok(false) if any fail.
/// Returns Err on infrastructure errors and field-decryption failures.
///
/// Translated from TS validateCertificates and Go ValidateCertificates.
///
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

    #[cfg(feature = "network")]
    {
        // The certificate count is peer-controlled, so match Go's worker-pool
        // policy rather than TS's unbounded Promise.all: at most one validation
        // per available CPU, and never more workers than certificates. Returning
        // on the first completed rejection/error drops buffered sibling futures.
        let concurrency = certificates.len().min(
            std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
        );
        let mut next = 0;
        let mut validations = FuturesUnordered::new();
        while next < concurrency {
            validations.push(validate_certificate(
                verifier_wallet,
                &certificates[next],
                sender_identity_key,
                requested,
            ));
            next += 1;
        }
        while let Some(result) = validations.next().await {
            if !result? {
                return Ok(false);
            }
            if next < certificates.len() {
                validations.push(validate_certificate(
                    verifier_wallet,
                    &certificates[next],
                    sender_identity_key,
                    requested,
                ));
                next += 1;
            }
        }
        Ok(true)
    }

    #[cfg(not(feature = "network"))]
    {
        for certificate in certificates {
            if !validate_certificate(verifier_wallet, certificate, sender_identity_key, requested)
                .await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

async fn validate_certificate<W: WalletInterface + ?Sized>(
    verifier_wallet: &W,
    cert: &VerifiableCertificate,
    sender_identity_key: &PublicKey,
    requested: Option<&RequestedCertificateSet>,
) -> Result<bool, AuthError> {
    if cert.certificate.subject != *sender_identity_key {
        return Ok(false);
    }

    let valid = AuthCertificate::verify(&cert.certificate, verifier_wallet).await?;
    if !valid {
        return Ok(false);
    }

    if let Some(req) = requested {
        // TS checks certifier before type for each certificate. Across multiple
        // failures, bounded concurrent completion makes the surfaced failure
        // nondeterministic, as Promise.all is in TS.
        let certifier = cert.certificate.certifier.to_der_hex();
        if !req
            .certifiers
            .iter()
            .any(|requested| requested.eq_ignore_ascii_case(&certifier))
        {
            return Ok(false);
        }

        let cert_type_b64 = base64_encode(&cert.certificate.cert_type.0);
        if !req.contains_key(&cert_type_b64) {
            return Ok(false);
        }
    }

    let mut cert_to_verify = cert.clone();
    cert_to_verify.decrypt_fields(verifier_wallet).await?;
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

    // TS forwards certifiers as opaque strings. Rust's wallet interface is
    // strongly typed, so malformed strings cannot be forwarded; skip them
    // rather than aborting the entire handshake response.
    let certifiers = requested
        .certifiers
        .iter()
        .filter_map(|certifier| PublicKey::from_string(certifier).ok())
        .collect();

    // Query wallet for matching certificates
    let list_result = wallet
        .list_certificates(
            ListCertificatesArgs {
                certifiers,
                types: cert_types,
                // TS omits this argument. `None` selects the wallet-interface
                // default of 10 (`PositiveIntegerDefault10Max10000`).
                limit: None,
                offset: Some(0),
                privileged: BooleanDefaultFalse(None),
                privileged_reason: None,
                partial: None,
            },
            None,
        )
        .await?;

    let mut result = Vec::new();

    // Intentional Layer-2 choice: keep prove_certificate sequential. The Go
    // implementation deliberately does so; TS Promise.all only interleaves
    // wallet I/O and is not authority for Rust parallelism here.
    for cert_result in &list_result.certificates {
        let cert = &cert_result.certificate;
        let cert_type_b64 = base64_encode(&cert.cert_type.0);

        // Check if this certificate type was requested and get requested fields
        let fields_to_reveal = match requested.get(&cert_type_b64) {
            Some(fields) => fields.clone(),
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
    format!("{serial_number} {field_name}")
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

    use crate::auth::certificates::master::{default_get_revocation_outpoint, MasterCertificate};
    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::error::WalletError;
    use crate::wallet::interfaces::*;
    use crate::wallet::types::{Counterparty, CounterpartyType, Protocol as WalletProtocol};
    use crate::wallet::ProtoWallet;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // TestWallet reuse (same pattern as master.rs tests)
    // -----------------------------------------------------------------------

    struct TestWallet {
        inner: ProtoWallet,
        listed_with: StdMutex<Option<ListCertificatesArgs>>,
        certificates_to_list: StdMutex<Vec<CertificateResult>>,
        proved_with: StdMutex<Vec<ProveCertificateArgs>>,
        decrypt_probe: Option<Arc<DecryptProbe>>,
    }

    #[derive(Default)]
    struct DecryptProbe {
        active: AtomicUsize,
        peak: AtomicUsize,
        calls: AtomicUsize,
        delay: Duration,
    }

    struct ActiveDecrypt<'a>(&'a DecryptProbe);

    impl Drop for ActiveDecrypt<'_> {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl TestWallet {
        fn new(pk: PrivateKey) -> Self {
            TestWallet {
                inner: ProtoWallet::new(pk),
                listed_with: StdMutex::new(None),
                certificates_to_list: StdMutex::new(Vec::new()),
                proved_with: StdMutex::new(Vec::new()),
                decrypt_probe: None,
            }
        }

        fn with_decrypt_probe(pk: PrivateKey, probe: Arc<DecryptProbe>) -> Self {
            Self {
                inner: ProtoWallet::new(pk),
                listed_with: StdMutex::new(None),
                certificates_to_list: StdMutex::new(Vec::new()),
                proved_with: StdMutex::new(Vec::new()),
                decrypt_probe: Some(probe),
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
            let _active = self.decrypt_probe.as_ref().map(|probe| {
                probe.calls.fetch_add(1, Ordering::SeqCst);
                let active = probe.active.fetch_add(1, Ordering::SeqCst) + 1;
                probe.peak.fetch_max(active, Ordering::SeqCst);
                ActiveDecrypt(probe.as_ref())
            });
            if let Some(probe) = &self.decrypt_probe {
                tokio::time::sleep(probe.delay).await;
            }
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
        async fn list_certificates(
            &self,
            args: ListCertificatesArgs,
            _originator: Option<&str>,
        ) -> Result<ListCertificatesResult, WalletError> {
            *self.listed_with.lock().unwrap() = Some(args);
            let certificates = self.certificates_to_list.lock().unwrap().clone();
            Ok(ListCertificatesResult {
                total_certificates: certificates.len() as u32,
                certificates,
            })
        }
        async fn prove_certificate(
            &self,
            args: ProveCertificateArgs,
            _originator: Option<&str>,
        ) -> Result<ProveCertificateResult, WalletError> {
            self.proved_with.lock().unwrap().push(args);
            Ok(ProveCertificateResult {
                keyring_for_verifier: HashMap::new(),
                certificate: None,
                verifier: None,
            })
        }
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
        let subject_wallet = TestWallet::new(subject_pk.clone());
        let subject_pubkey = subject_pk.to_public_key();

        let cert_type = CertificateType([5u8; 32]);

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Test User".to_string());

        let master_cert = MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            &subject_pubkey,
            fields,
            &certifier_wallet,
            default_get_revocation_outpoint,
            None,
        )
        .await
        .expect("issue failed");

        // Verification must work from an ordinary receiving wallet, not only
        // from a wallet whose identity happens to be the special anyone key.
        let receiver_pk = PrivateKey::from_random().unwrap();
        let receiver_wallet = TestWallet::new(receiver_pk.clone());
        let verifier_keyring = master_cert
            .create_keyring_for_verifier(
                &receiver_pk.to_public_key(),
                &["name".to_string()],
                &certifier_pk.to_public_key(),
                &subject_wallet,
            )
            .await
            .expect("create verifier keyring");
        let verifiable =
            VerifiableCertificate::new(master_cert.certificate.clone(), verifier_keyring);

        let valid = validate_certificates(&receiver_wallet, &[verifiable], &subject_pubkey, None)
            .await
            .expect("validate_certificates failed");
        assert!(valid, "properly signed certificate should validate");
    }

    #[tokio::test]
    async fn test_validate_certificates_rejects_undecryptable_keyring() {
        let certifier_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let subject_pubkey = PrivateKey::from_random().unwrap().to_public_key();
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Test User".to_string());
        let master_cert = MasterCertificate::issue_certificate_for_subject(
            &CertificateType([8u8; 32]),
            &subject_pubkey,
            fields,
            &certifier_wallet,
            default_get_revocation_outpoint,
            None,
        )
        .await
        .expect("issue failed");
        let verifiable = VerifiableCertificate::new(master_cert.certificate, HashMap::new());
        let verifier_wallet = TestWallet::new(PrivateKey::from_random().unwrap());

        let result =
            validate_certificates(&verifier_wallet, &[verifiable], &subject_pubkey, None).await;

        assert!(
            matches!(result, Err(AuthError::CertificateValidation(_))),
            "a certificate whose revealed-field keyring cannot decrypt must be rejected, got {result:?}"
        );
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
            default_get_revocation_outpoint,
            None,
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
            default_get_revocation_outpoint,
            None,
        )
        .await
        .expect("issue failed");

        let verifiable =
            VerifiableCertificate::new(master_cert.certificate.clone(), HashMap::new());

        // Create a requested set that does NOT include this cert type
        let mut requested = RequestedCertificateSet::default();
        requested
            .certifiers
            .push(master_cert.certificate.certifier.to_der_hex());
        let different_type_b64 = crate::auth::certificates::certificate::base64_encode(&[99u8; 32]);
        requested
            .types
            .insert(different_type_b64, vec!["field".to_string()]);

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

    #[tokio::test]
    async fn test_validate_certificates_rejects_unrequested_certifier_before_decryption() {
        let certifier_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let subject_pubkey = PrivateKey::from_random().unwrap().to_public_key();
        let cert_type = CertificateType([9u8; 32]);
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Test User".to_string());
        let master_cert = MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            &subject_pubkey,
            fields,
            &certifier_wallet,
            default_get_revocation_outpoint,
            None,
        )
        .await
        .expect("issue failed");
        let verifiable = VerifiableCertificate::new(master_cert.certificate, HashMap::new());
        let mut requested = RequestedCertificateSet::default();
        requested.certifiers.push(
            PrivateKey::from_random()
                .unwrap()
                .to_public_key()
                .to_der_hex(),
        );
        requested.insert(
            crate::auth::certificates::certificate::base64_encode(&cert_type.0),
            vec!["name".to_string()],
        );
        let verifier_wallet = TestWallet::new(PrivateKey::from_random().unwrap());

        let valid = validate_certificates(
            &verifier_wallet,
            &[verifiable],
            &subject_pubkey,
            Some(&requested),
        )
        .await
        .expect("certifier mismatch is a validation rejection");

        assert!(
            !valid,
            "certificate from an unrequested certifier was accepted"
        );
    }

    #[tokio::test]
    async fn test_get_verifiable_certificates_passes_requested_certifiers_to_wallet() {
        let wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let requested_certifier = PrivateKey::from_random().unwrap().to_public_key();
        let mut requested = RequestedCertificateSet::default();
        requested.certifiers.push(requested_certifier.to_der_hex());
        requested.insert(
            crate::auth::certificates::certificate::base64_encode(&[10u8; 32]),
            vec!["name".to_string()],
        );
        let verifier = PrivateKey::from_random().unwrap().to_public_key();

        let certificates = get_verifiable_certificates(&wallet, &requested, &verifier)
            .await
            .expect("listing certificates should succeed");

        assert!(certificates.is_empty());
        let listed_with = wallet.listed_with.lock().unwrap();
        let args = listed_with.as_ref().expect("wallet was queried");
        assert_eq!(args.certifiers, vec![requested_certifier]);
    }

    #[tokio::test]
    async fn test_get_verifiable_certificates_skips_unparseable_certifiers() {
        let wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let valid = PrivateKey::from_random().unwrap().to_public_key();
        let mut requested = RequestedCertificateSet {
            certifiers: vec!["not-a-public-key".to_string(), valid.to_der_hex()],
            ..Default::default()
        };
        requested.insert(base64_encode(&[11; 32]), vec!["name".to_string()]);

        get_verifiable_certificates(
            &wallet,
            &requested,
            &PrivateKey::from_random().unwrap().to_public_key(),
        )
        .await
        .expect("an opaque malformed certifier must not abort the response");

        let listed_with = wallet.listed_with.lock().unwrap();
        assert_eq!(
            listed_with.as_ref().unwrap().certifiers,
            vec![valid],
            "only parseable certifiers can be forwarded to the strongly typed Rust wallet"
        );
    }

    #[tokio::test]
    async fn test_get_verifiable_certificates_uses_wallet_default_limit() {
        let wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let mut requested = RequestedCertificateSet::default();
        requested.certifiers.push(
            PrivateKey::from_random()
                .unwrap()
                .to_public_key()
                .to_der_hex(),
        );
        requested.insert(base64_encode(&[12; 32]), vec!["name".to_string()]);

        get_verifiable_certificates(
            &wallet,
            &requested,
            &PrivateKey::from_random().unwrap().to_public_key(),
        )
        .await
        .unwrap();

        assert_eq!(
            wallet.listed_with.lock().unwrap().as_ref().unwrap().limit,
            None,
            "TS omits limit, selecting the wallet interface default of 10"
        );
    }

    #[tokio::test]
    async fn test_get_verifiable_certificates_proves_empty_requested_field_list() {
        let subject = PrivateKey::from_random().unwrap();
        let certifier_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let cert = MasterCertificate::issue_certificate_for_subject(
            &CertificateType([13; 32]),
            &subject.to_public_key(),
            HashMap::new(),
            &certifier_wallet,
            default_get_revocation_outpoint,
            None,
        )
        .await
        .unwrap()
        .certificate;
        let wallet = TestWallet::new(subject);
        wallet
            .certificates_to_list
            .lock()
            .unwrap()
            .push(CertificateResult {
                certificate: cert.clone(),
                keyring: None,
                verifier: None,
            });
        let mut requested = RequestedCertificateSet::default();
        requested.certifiers.push(cert.certifier.to_der_hex());
        requested.insert(base64_encode(&cert.cert_type.0), Vec::new());

        let result = get_verifiable_certificates(
            &wallet,
            &requested,
            &PrivateKey::from_random().unwrap().to_public_key(),
        )
        .await
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(wallet.proved_with.lock().unwrap().len(), 1);
        assert!(wallet.proved_with.lock().unwrap()[0]
            .fields_to_reveal
            .is_empty());
    }

    #[tokio::test]
    async fn test_validate_certificates_matches_requested_certifier_case_insensitively() {
        let certifier_pk = PrivateKey::from_random().unwrap();
        let certifier_wallet = TestWallet::new(certifier_pk.clone());
        let subject_pk = PrivateKey::from_random().unwrap();
        let subject_wallet = TestWallet::new(subject_pk.clone());
        let verifier_pk = PrivateKey::from_random().unwrap();
        let verifier_wallet = TestWallet::new(verifier_pk.clone());
        let cert_type = CertificateType([14; 32]);
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Case Test".to_string());
        let master = MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            &subject_pk.to_public_key(),
            fields,
            &certifier_wallet,
            default_get_revocation_outpoint,
            None,
        )
        .await
        .unwrap();
        let keyring = master
            .create_keyring_for_verifier(
                &verifier_pk.to_public_key(),
                &["name".to_string()],
                &certifier_pk.to_public_key(),
                &subject_wallet,
            )
            .await
            .unwrap();
        let verifiable = VerifiableCertificate::new(master.certificate.clone(), keyring);
        let mut requested = RequestedCertificateSet::default();
        requested
            .certifiers
            .push(master.certificate.certifier.to_der_hex().to_uppercase());
        requested.insert(base64_encode(&cert_type.0), vec!["name".to_string()]);

        assert!(
            validate_certificates(
                &verifier_wallet,
                &[verifiable],
                &subject_pk.to_public_key(),
                Some(&requested),
            )
            .await
            .unwrap(),
            "hex casing must not change certifier membership"
        );
    }

    async fn concurrent_validation_fixture(
        count: usize,
        delay: Duration,
    ) -> (
        TestWallet,
        Arc<DecryptProbe>,
        Vec<VerifiableCertificate>,
        PublicKey,
    ) {
        let certifier_pk = PrivateKey::from_random().unwrap();
        let certifier_wallet = TestWallet::new(certifier_pk.clone());
        let subject_pk = PrivateKey::from_random().unwrap();
        let subject_wallet = TestWallet::new(subject_pk.clone());
        let verifier_pk = PrivateKey::from_random().unwrap();
        let probe = Arc::new(DecryptProbe {
            delay,
            ..DecryptProbe::default()
        });
        let verifier_wallet = TestWallet::with_decrypt_probe(verifier_pk.clone(), probe.clone());
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Concurrency Test".to_string());
        let master = MasterCertificate::issue_certificate_for_subject(
            &CertificateType([15; 32]),
            &subject_pk.to_public_key(),
            fields,
            &certifier_wallet,
            default_get_revocation_outpoint,
            None,
        )
        .await
        .unwrap();
        let keyring = master
            .create_keyring_for_verifier(
                &verifier_pk.to_public_key(),
                &["name".to_string()],
                &certifier_pk.to_public_key(),
                &subject_wallet,
            )
            .await
            .unwrap();
        let certificate = VerifiableCertificate::new(master.certificate, keyring);
        (
            verifier_wallet,
            probe,
            vec![certificate; count],
            subject_pk.to_public_key(),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn test_validate_certificates_is_bounded_and_concurrent() {
        let parallelism = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        if parallelism == 1 {
            return;
        }
        let certificate_count = parallelism + 2;
        let delay = Duration::from_millis(100);
        let (wallet, probe, certificates, subject) =
            concurrent_validation_fixture(certificate_count, delay).await;
        let started = tokio::time::Instant::now();

        assert!(
            validate_certificates(&wallet, &certificates, &subject, None)
                .await
                .unwrap()
        );

        let elapsed = started.elapsed();
        let expected_waves = certificate_count.div_ceil(parallelism) as u32;
        assert_eq!(
            elapsed,
            delay * expected_waves,
            "validation should take one delay per bounded concurrency wave"
        );
        assert_eq!(probe.peak.load(Ordering::SeqCst), parallelism);
        assert_eq!(probe.calls.load(Ordering::SeqCst), certificate_count);
    }

    #[tokio::test(start_paused = true)]
    async fn test_validate_certificates_cancels_siblings_on_first_error() {
        let parallelism = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        if parallelism == 1 {
            return;
        }
        let (wallet, probe, mut certificates, subject) =
            concurrent_validation_fixture(parallelism, Duration::from_secs(1)).await;
        certificates
            .last_mut()
            .unwrap()
            .keyring
            .insert("name".to_string(), "!".to_string());
        let started = tokio::time::Instant::now();

        let result = validate_certificates(&wallet, &certificates, &subject, None).await;

        assert!(result.is_err());
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "the first completed error must drop in-flight sibling futures"
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), parallelism - 1);
        assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_get_verifiable_certificates_queries_wallet_for_empty_types() {
        let wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let requested = RequestedCertificateSet::default();

        let result = get_verifiable_certificates(
            &wallet,
            &requested,
            &PrivateKey::from_random().unwrap().to_public_key(),
        )
        .await
        .unwrap();

        assert!(result.is_empty());
        assert!(
            wallet.listed_with.lock().unwrap().is_some(),
            "TS calls listCertificates even when requested types is empty"
        );
    }
}
