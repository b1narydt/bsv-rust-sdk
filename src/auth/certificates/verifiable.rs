//! VerifiableCertificate: certificate with verifier-specific keyring.
//!
//! Wraps a wallet::Certificate with a keyring that allows selective
//! decryption of certificate fields for authorized verifiers.
//! Translates from TS SDK VerifiableCertificate.ts.

use std::collections::HashMap;
use std::ops::Deref;

use crate::auth::certificates::certificate::AuthCertificate;
use crate::auth::error::AuthError;
use crate::wallet::interfaces::{Certificate, WalletInterface};

/// A certificate paired with a verifier-specific keyring for selective field revelation.
///
/// The keyring maps field names to base64-encoded encrypted symmetric keys.
/// When decrypted with the verifier's wallet, each key can decrypt the
/// corresponding encrypted field value in the certificate.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct VerifiableCertificate {
    /// The underlying wallet Certificate.
    #[cfg_attr(feature = "network", serde(flatten))]
    pub certificate: Certificate,
    /// Maps field names to base64-encoded encrypted symmetric keys for the verifier.
    pub keyring: HashMap<String, String>,
    /// Cached decrypted fields (populated after decrypt_fields is called).
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub decrypted_fields: Option<HashMap<String, String>>,
}

impl Deref for VerifiableCertificate {
    type Target = Certificate;
    fn deref(&self) -> &Self::Target {
        &self.certificate
    }
}

impl VerifiableCertificate {
    /// Create a VerifiableCertificate from a certificate and keyring.
    pub fn new(certificate: Certificate, keyring: HashMap<String, String>) -> Self {
        VerifiableCertificate {
            certificate,
            keyring,
            decrypted_fields: None,
        }
    }

    /// Decrypt the selectively revealed certificate fields using the verifier's wallet.
    ///
    /// For each field in the keyring:
    /// 1. Decrypts the keyring entry to get the field's symmetric key
    /// 2. Uses the symmetric key to decrypt the field value
    ///
    /// The counterparty is the certificate subject (the party who created the keyring).
    /// Results are cached in `self.decrypted_fields`.
    ///
    /// Translated from TS SDK VerifiableCertificate.decryptFields().
    pub async fn decrypt_fields<W: WalletInterface + ?Sized>(
        &mut self,
        verifier_wallet: &W,
    ) -> Result<HashMap<String, String>, AuthError> {
        if self.keyring.is_empty() {
            return Err(AuthError::CertificateValidation(
                "a keyring is required to decrypt certificate fields for the verifier".to_string(),
            ));
        }

        let encrypted_fields = self.certificate.fields.clone().unwrap_or_default();
        let serial_number = crate::auth::certificates::certificate::base64_encode(
            &self.certificate.serial_number.0,
        );

        let result = AuthCertificate::decrypt_fields(
            &encrypted_fields,
            &self.keyring,
            &serial_number,
            &self.certificate.subject,
            verifier_wallet,
        )
        .await
        .map_err(|e| {
            AuthError::CertificateValidation(format!(
                "failed to decrypt selectively revealed certificate fields using keyring: {}",
                e
            ))
        })?;

        self.decrypted_fields = Some(result.clone());
        Ok(result)
    }
}
