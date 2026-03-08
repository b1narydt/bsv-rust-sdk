//! MasterCertificate: certificate with master keyring management.
//!
//! Wraps a wallet::Certificate with a master keyring enabling creation
//! of verifier-specific keyrings for selective field revelation.
//! Translates from TS SDK MasterCertificate.ts and Go SDK master.go.

use std::collections::HashMap;
use std::ops::Deref;

use crate::auth::certificates::certificate::{base64_decode, base64_encode, AuthCertificate};
use crate::auth::error::AuthError;
use crate::primitives::public_key::PublicKey;
use crate::primitives::random::random_bytes;
use crate::primitives::symmetric_key::SymmetricKey;
use crate::wallet::interfaces::{
    Certificate, CertificateType, DecryptArgs, EncryptArgs, GetPublicKeyArgs, SerialNumber,
    WalletInterface,
};
use crate::wallet::types::{Counterparty, CounterpartyType};

/// A certificate with a master keyring for managing field encryption keys.
///
/// The master keyring contains field encryption keys that are encrypted for
/// the certificate subject. The MasterCertificate can create verifier-specific
/// keyrings by decrypting the master keys and re-encrypting them for a verifier.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct MasterCertificate {
    /// The underlying wallet Certificate.
    #[cfg_attr(feature = "network", serde(flatten))]
    pub certificate: Certificate,
    /// Maps field names to base64-encoded master encryption keys.
    pub master_keyring: HashMap<String, String>,
}

impl Deref for MasterCertificate {
    type Target = Certificate;
    fn deref(&self) -> &Self::Target {
        &self.certificate
    }
}

impl MasterCertificate {
    /// Create a new MasterCertificate from a certificate and master keyring.
    ///
    /// Validates that every field in the certificate has a corresponding
    /// key in the master keyring.
    pub fn new(
        certificate: Certificate,
        master_keyring: HashMap<String, String>,
    ) -> Result<Self, AuthError> {
        if let Some(ref fields) = certificate.fields {
            for field_name in fields.keys() {
                if !master_keyring.contains_key(field_name) || master_keyring[field_name].is_empty()
                {
                    return Err(AuthError::CertificateValidation(format!(
                        "master keyring must contain a value for every field. Missing or empty key for field: \"{}\"",
                        field_name
                    )));
                }
            }
        }
        Ok(MasterCertificate {
            certificate,
            master_keyring,
        })
    }

    /// Encrypt certificate fields and produce both encrypted fields and a master keyring.
    ///
    /// For each field:
    /// 1. Generate a random symmetric key
    /// 2. Encrypt the field value with the symmetric key
    /// 3. Encrypt the symmetric key using the wallet for the given counterparty
    ///
    /// The counterparty is typically the subject (for subject-certifier key derivation).
    /// IMPORTANT: Uses only fieldName as keyID (no serial number), because
    /// master keys are created before the serial number exists.
    ///
    /// Returns (encrypted_fields, master_keyring).
    pub async fn create_certificate_fields<W: WalletInterface>(
        fields: &HashMap<String, String>,
        certifier_wallet: &W,
        subject: &PublicKey,
    ) -> Result<(HashMap<String, String>, HashMap<String, String>), AuthError> {
        // Use encrypt_fields with serial_number=None for master cert creation
        AuthCertificate::encrypt_fields(fields, None, subject, certifier_wallet).await
    }

    /// Create a keyring for a verifier, enabling them to decrypt specific fields.
    ///
    /// For each field to reveal:
    /// 1. Decrypt the master key using the subject wallet (counterparty = certifier)
    /// 2. Verify the decrypted key can actually decrypt the field value
    /// 3. Re-encrypt the symmetric key for the verifier
    ///
    /// The protocol uses serial_number in the keyID when creating verifier keyrings
    /// (unlike master key creation which uses only fieldName).
    ///
    /// Translated from TS SDK MasterCertificate.createKeyringForVerifier().
    pub async fn create_keyring_for_verifier<W: WalletInterface>(
        &self,
        verifier_public_key: &PublicKey,
        fields_to_reveal: &[String],
        certifier: &PublicKey,
        wallet: &W,
    ) -> Result<HashMap<String, String>, AuthError> {
        let fields = self.certificate.fields.clone().unwrap_or_default();
        let serial_number_b64 = base64_encode(&self.certificate.serial_number.0);
        let mut verifier_keyring = HashMap::new();

        for field_name in fields_to_reveal {
            // Verify field exists in the certificate
            if !fields.contains_key(field_name) || fields[field_name].is_empty() {
                return Err(AuthError::CertificateValidation(format!(
                    "fields to reveal must be a subset of the certificate fields. Missing the \"{}\" field",
                    field_name
                )));
            }

            // Decrypt master key for this field (no serial number in keyID for master keys)
            let master_key_encrypted = match self.master_keyring.get(field_name) {
                Some(k) => base64_decode(k)?,
                None => {
                    return Err(AuthError::CertificateValidation(format!(
                        "master keyring missing key for field: \"{}\"",
                        field_name
                    )));
                }
            };

            let (protocol, key_id) =
                AuthCertificate::get_certificate_field_encryption_details(field_name, None);

            let decrypt_result = wallet
                .decrypt(
                    DecryptArgs {
                        ciphertext: master_key_encrypted,
                        protocol_id: protocol,
                        key_id,
                        counterparty: Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: Some(certifier.clone()),
                        },
                        privileged: false,
                        privileged_reason: None,
                        seek_permission: None,
                    },
                    None,
                )
                .await?;

            let field_revelation_key = decrypt_result.plaintext;

            // Verify the key actually decrypts the field (validation step)
            let sym_key = SymmetricKey::from_bytes(&field_revelation_key)?;
            let encrypted_field_value = base64_decode(&fields[field_name])?;
            let _ = sym_key.decrypt(&encrypted_field_value).map_err(|_| {
                AuthError::CertificateValidation(format!(
                    "master key for field \"{}\" failed to decrypt the field value",
                    field_name
                ))
            })?;

            // Re-encrypt the symmetric key for the verifier
            // Uses serial_number in keyID for verifier keyrings
            let (verifier_protocol, verifier_key_id) =
                AuthCertificate::get_certificate_field_encryption_details(
                    field_name,
                    Some(&serial_number_b64),
                );

            let encrypt_result = wallet
                .encrypt(
                    EncryptArgs {
                        plaintext: field_revelation_key,
                        protocol_id: verifier_protocol,
                        key_id: verifier_key_id,
                        counterparty: Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: Some(verifier_public_key.clone()),
                        },
                        privileged: false,
                        privileged_reason: None,
                        seek_permission: None,
                    },
                    None,
                )
                .await?;

            verifier_keyring.insert(
                field_name.clone(),
                base64_encode(&encrypt_result.ciphertext),
            );
        }

        Ok(verifier_keyring)
    }

    /// Issue a new signed MasterCertificate for a subject.
    ///
    /// 1. Generate random serial number (32 bytes)
    /// 2. Encrypt fields using create_certificate_fields
    /// 3. Build Certificate struct
    /// 4. Sign using AuthCertificate::sign
    /// 5. Return MasterCertificate { certificate, master_keyring }
    ///
    /// Translated from TS SDK MasterCertificate.issueCertificateForSubject().
    pub async fn issue_certificate_for_subject<W: WalletInterface>(
        cert_type: &CertificateType,
        subject: &PublicKey,
        fields: HashMap<String, String>,
        certifier_wallet: &W,
    ) -> Result<MasterCertificate, AuthError> {
        // Generate random serial number
        let serial_bytes = random_bytes(32);
        let mut serial_arr = [0u8; 32];
        serial_arr.copy_from_slice(&serial_bytes);
        let serial_number = SerialNumber(serial_arr);

        // Create encrypted fields and master keyring
        let (encrypted_fields, master_keyring) =
            Self::create_certificate_fields(&fields, certifier_wallet, subject).await?;

        // Get certifier identity key
        let certifier_identity = certifier_wallet
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
                None,
            )
            .await?;

        // Default revocation outpoint (placeholder)
        let revocation_outpoint = format!("{}.0", "00".repeat(32));

        // Build certificate
        let mut certificate = Certificate {
            cert_type: cert_type.clone(),
            serial_number,
            subject: subject.clone(),
            certifier: certifier_identity.public_key,
            revocation_outpoint: Some(revocation_outpoint),
            fields: Some(encrypted_fields),
            signature: None,
        };

        // Sign the certificate
        AuthCertificate::sign(&mut certificate, certifier_wallet).await?;

        MasterCertificate::new(certificate, master_keyring)
    }

    /// Decrypt all fields using the subject's or certifier's wallet.
    ///
    /// Decrypts the master keyring entries and uses them to decrypt field values.
    /// The counterparty should be the other party involved in certificate creation.
    pub async fn decrypt_fields<W: WalletInterface>(
        &self,
        wallet: &W,
        counterparty: &PublicKey,
    ) -> Result<HashMap<String, String>, AuthError> {
        if self.master_keyring.is_empty() {
            return Err(AuthError::CertificateValidation(
                "a MasterCertificate must have a valid master_keyring".to_string(),
            ));
        }

        let fields = self.certificate.fields.clone().unwrap_or_default();
        let mut decrypted = HashMap::new();

        for (field_name, encrypted_value) in &fields {
            let master_key_encrypted = match self.master_keyring.get(field_name) {
                Some(k) => base64_decode(k)?,
                None => continue, // Field not in master keyring, skip
            };

            let (protocol, key_id) =
                AuthCertificate::get_certificate_field_encryption_details(field_name, None);

            let decrypt_result = wallet
                .decrypt(
                    DecryptArgs {
                        ciphertext: master_key_encrypted,
                        protocol_id: protocol,
                        key_id,
                        counterparty: Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: Some(counterparty.clone()),
                        },
                        privileged: false,
                        privileged_reason: None,
                        seek_permission: None,
                    },
                    None,
                )
                .await?;

            let sym_key = SymmetricKey::from_bytes(&decrypt_result.plaintext)?;
            let encrypted_field_bytes = base64_decode(encrypted_value)?;
            let plaintext_bytes = sym_key.decrypt(&encrypted_field_bytes)?;
            let plaintext = String::from_utf8(plaintext_bytes).map_err(|e| {
                AuthError::CertificateValidation(format!(
                    "decrypted field '{}' is not valid UTF-8: {}",
                    field_name, e
                ))
            })?;
            decrypted.insert(field_name.clone(), plaintext);
        }

        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::certificates::verifiable::VerifiableCertificate;
    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::error::WalletError;
    use crate::wallet::interfaces::*;
    use crate::wallet::types::Protocol as WalletProtocol;
    use crate::wallet::ProtoWallet;

    /// WalletInterface wrapper around ProtoWallet for certificate tests.
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
            ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = Result<$ret, WalletError>> + ::core::marker::Send + 'async_trait>>
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    unimplemented!(concat!(stringify!($name), " not needed for cert tests"))
                })
            }
        };
        ($name:ident, $ret:ty) => {
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _originator: Option<&'life1 str>,
            ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = Result<$ret, WalletError>> + ::core::marker::Send + 'async_trait>>
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    unimplemented!(concat!(stringify!($name), " not needed for cert tests"))
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
            let pk = self.inner.get_public_key(
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
            let ciphertext = self.inner.encrypt(
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
            let plaintext = self.inner.decrypt(
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
            let hmac = self.inner.create_hmac(
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
            let valid = self.inner.verify_hmac(
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
            let signature = self.inner.create_signature(
                &args.data,
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
            let valid = self.inner.verify_signature(
                &args.data,
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
    async fn test_issue_and_verify_certificate() {
        let certifier_pk = PrivateKey::from_random().unwrap();
        let certifier_wallet = TestWallet::new(certifier_pk);

        let subject_pk = PrivateKey::from_random().unwrap();
        let subject_pubkey = subject_pk.to_public_key();

        let cert_type = CertificateType([1u8; 32]);

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Alice".to_string());
        fields.insert("email".to_string(), "alice@example.com".to_string());

        let master_cert = MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            &subject_pubkey,
            fields,
            &certifier_wallet,
        )
        .await
        .expect("issue_certificate_for_subject failed");

        // Verify the certificate was signed
        assert!(master_cert.certificate.signature.is_some());

        // Verify signature using an anyone wallet
        let anyone_wallet = TestWallet::new(
            PrivateKey::from_bytes(&{
                let mut buf = [0u8; 32];
                buf[31] = 1;
                buf
            })
            .unwrap(),
        );
        let valid = AuthCertificate::verify(&master_cert.certificate, &anyone_wallet)
            .await
            .expect("verify failed");
        assert!(valid, "certificate signature should be valid");

        // Verify master keyring has entries for both fields
        assert!(master_cert.master_keyring.contains_key("name"));
        assert!(master_cert.master_keyring.contains_key("email"));
    }

    #[tokio::test]
    async fn test_full_round_trip_issue_keyring_decrypt() {
        // Certifier issues a certificate for subject
        let certifier_pk = PrivateKey::from_random().unwrap();
        let certifier_wallet = TestWallet::new(certifier_pk.clone());

        let subject_pk = PrivateKey::from_random().unwrap();
        let subject_wallet = TestWallet::new(subject_pk.clone());
        let subject_pubkey = subject_pk.to_public_key();

        let verifier_pk = PrivateKey::from_random().unwrap();
        let verifier_wallet = TestWallet::new(verifier_pk.clone());
        let verifier_pubkey = verifier_pk.to_public_key();

        let cert_type = CertificateType([2u8; 32]);
        let certifier_pubkey = certifier_pk.to_public_key();

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Bob".to_string());
        fields.insert("age".to_string(), "30".to_string());
        fields.insert("country".to_string(), "USA".to_string());

        // 1. Issue certificate
        let master_cert = MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            &subject_pubkey,
            fields.clone(),
            &certifier_wallet,
        )
        .await
        .expect("issue failed");

        // 2. Subject creates keyring for verifier (revealing only name and country)
        let fields_to_reveal = vec!["name".to_string(), "country".to_string()];
        let verifier_keyring = master_cert
            .create_keyring_for_verifier(
                &verifier_pubkey,
                &fields_to_reveal,
                &certifier_pubkey,
                &subject_wallet,
            )
            .await
            .expect("create_keyring_for_verifier failed");

        // Verifier keyring should have exactly the revealed fields
        assert_eq!(verifier_keyring.len(), 2);
        assert!(verifier_keyring.contains_key("name"));
        assert!(verifier_keyring.contains_key("country"));
        assert!(!verifier_keyring.contains_key("age"));

        // 3. Verifier decrypts fields using VerifiableCertificate
        let mut verifiable =
            VerifiableCertificate::new(master_cert.certificate.clone(), verifier_keyring);

        let decrypted = verifiable
            .decrypt_fields(&verifier_wallet)
            .await
            .expect("decrypt_fields failed");

        assert_eq!(decrypted.get("name").unwrap(), "Bob");
        assert_eq!(decrypted.get("country").unwrap(), "USA");
        // "age" should not be in decrypted results (not in keyring)
        assert!(!decrypted.contains_key("age"));

        // Verify cached fields
        assert!(verifiable.decrypted_fields.is_some());
    }

    #[tokio::test]
    async fn test_master_cert_decrypt_fields() {
        let certifier_pk = PrivateKey::from_random().unwrap();
        let certifier_wallet = TestWallet::new(certifier_pk.clone());
        let certifier_pubkey = certifier_pk.to_public_key();

        let subject_pk = PrivateKey::from_random().unwrap();
        let subject_wallet = TestWallet::new(subject_pk.clone());
        let subject_pubkey = subject_pk.to_public_key();

        let cert_type = CertificateType([3u8; 32]);

        let mut fields = HashMap::new();
        fields.insert("secret".to_string(), "hidden_value".to_string());

        let master_cert = MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            &subject_pubkey,
            fields.clone(),
            &certifier_wallet,
        )
        .await
        .expect("issue failed");

        // Subject decrypts fields using their wallet (counterparty = certifier)
        let decrypted = master_cert
            .decrypt_fields(&subject_wallet, &certifier_pubkey)
            .await
            .expect("decrypt_fields failed");

        assert_eq!(decrypted.get("secret").unwrap(), "hidden_value");
    }
}
