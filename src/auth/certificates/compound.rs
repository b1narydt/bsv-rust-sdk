//! CompoundMerklePathCertificate: certificate + merkle proof wrapper.
//!
//! A minimal wrapper combining a wallet::Certificate with a MerklePath.
//! Provides Deref to the inner Certificate for transparent field access.

use std::ops::Deref;

use crate::transaction::merkle_path::MerklePath;
use crate::wallet::interfaces::Certificate;

/// A certificate paired with its merkle path proof.
///
/// This is a minimal wrapper -- no additional methods beyond construction.
/// The MerklePath can be used to verify the certificate's inclusion in a block.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CompoundMerklePathCertificate {
    /// The underlying wallet Certificate.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub certificate: Certificate,
    /// The merkle path proving inclusion of the certificate's transaction.
    #[cfg_attr(feature = "serde", serde(skip, default = "default_merkle_path"))]
    pub merkle_path: MerklePath,
}

#[cfg(feature = "serde")]
fn default_merkle_path() -> MerklePath {
    MerklePath {
        block_height: 0,
        path: vec![],
    }
}

impl Deref for CompoundMerklePathCertificate {
    type Target = Certificate;
    fn deref(&self) -> &Self::Target {
        &self.certificate
    }
}

impl CompoundMerklePathCertificate {
    /// Create a new CompoundMerklePathCertificate.
    pub fn new(certificate: Certificate, merkle_path: MerklePath) -> Self {
        CompoundMerklePathCertificate {
            certificate,
            merkle_path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::public_key::PublicKey;
    use crate::wallet::interfaces::{CertificateType, SerialNumber};

    #[test]
    fn test_compound_certificate_deref() {
        // Create a minimal Certificate
        let cert = Certificate {
            cert_type: CertificateType([0u8; 32]),
            serial_number: SerialNumber([1u8; 32]),
            subject: PublicKey::from_string(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .unwrap(),
            certifier: PublicKey::from_string(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .unwrap(),
            revocation_outpoint: Some(format!("{}.0", "00".repeat(32))),
            fields: None,
            signature: None,
        };

        let merkle_path = MerklePath {
            block_height: 100,
            path: vec![],
        };

        let compound = CompoundMerklePathCertificate::new(cert.clone(), merkle_path);

        // Deref should provide access to Certificate fields
        assert_eq!(compound.cert_type.0, [0u8; 32]);
        assert_eq!(compound.serial_number.0, [1u8; 32]);
        assert_eq!(compound.merkle_path.block_height, 100);
    }
}
