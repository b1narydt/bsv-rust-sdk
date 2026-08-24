//! VerifiableCertificate: certificate with verifier-specific keyring.
//!
//! Wraps a wallet::Certificate with a keyring that allows selective
//! decryption of certificate fields for authorized verifiers.
//! Translates from TS SDK VerifiableCertificate.ts.

use std::ops::Deref;

use indexmap::IndexMap;

use crate::auth::certificates::certificate::AuthCertificate;
use crate::auth::error::AuthError;
use crate::wallet::interfaces::{Certificate, WalletInterface};

/// A certificate paired with a verifier-specific keyring for selective field revelation.
///
/// The keyring maps field names to base64-encoded encrypted symmetric keys.
/// When decrypted with the verifier's wallet, each key can decrypt the
/// corresponding encrypted field value in the certificate.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct VerifiableCertificate {
    /// The underlying wallet Certificate.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub certificate: Certificate,
    /// Maps field names to base64-encoded encrypted symmetric keys for the verifier.
    pub keyring: IndexMap<String, String>,
    /// Optional decrypted fields explicitly supplied by a caller.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub decrypted_fields: Option<IndexMap<String, String>>,
}

impl Deref for VerifiableCertificate {
    type Target = Certificate;
    fn deref(&self) -> &Self::Target {
        &self.certificate
    }
}

impl VerifiableCertificate {
    /// Create a VerifiableCertificate from a certificate and keyring.
    pub fn new(certificate: Certificate, keyring: IndexMap<String, String>) -> Self {
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
    /// Translated from TS SDK VerifiableCertificate.decryptFields().
    pub async fn decrypt_fields<W: WalletInterface + ?Sized>(
        &self,
        verifier_wallet: &W,
    ) -> Result<IndexMap<String, String>, AuthError> {
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
                "failed to decrypt selectively revealed certificate fields using keyring: {e}"
            ))
        })?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::interfaces::{CertificateType, SerialNumber};

    #[test]
    fn new_preserves_caller_keyring_order() {
        let public_key = PrivateKey::from_random().unwrap().to_public_key();
        let certificate = Certificate {
            cert_type: CertificateType([1; 32]),
            serial_number: SerialNumber([2; 32]),
            subject: public_key.clone(),
            certifier: public_key,
            revocation_outpoint: None,
            fields: None,
            signature: None,
        };
        let mut keyring = IndexMap::new();
        keyring.insert("zeta".to_string(), "eg==".to_string());
        keyring.insert("alpha".to_string(), "YQ==".to_string());
        keyring.insert("middle".to_string(), "bQ==".to_string());

        let verifiable = VerifiableCertificate::new(certificate, keyring);

        assert_eq!(
            verifiable
                .keyring
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["zeta", "alpha", "middle"]
        );
    }
}
