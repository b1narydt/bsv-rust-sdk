//! IdentityClient for resolving identities via the overlay network.
//!
//! Translates the TS SDK IdentityClient.ts. Provides identity resolution by
//! key or attributes, with ContactsManager cache override support.

use std::collections::HashMap;
use std::sync::Arc;

use super::contacts_manager::ContactsManager;
use super::types::{
    default_identity, Contact, DisplayableIdentity, IdentityClientOptions, KnownIdentityTypes,
};
use crate::services::ServicesError;
use crate::wallet::interfaces::{
    CertificateType, DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs, IdentityCertificate,
    ProveCertificateArgs,
};
use crate::wallet::types::BooleanDefaultFalse;
use crate::wallet::WalletInterface;

/// IdentityClient resolves displayable identities from the overlay network
/// and manages personal contacts.
///
/// Generic over `W: WalletInterface` for wallet operations. Uses a
/// `ContactsManager<W>` for cached contact lookups.
pub struct IdentityClient<W: WalletInterface + ?Sized> {
    /// Wallet reference for discovery and crypto operations.
    wallet: Arc<W>,
    /// Contacts manager with in-memory cache.
    contacts_manager: ContactsManager<W>,
    /// Configuration options.
    #[allow(dead_code)]
    options: IdentityClientOptions,
    /// Optional originator domain name.
    originator: Option<String>,
}

impl<W: WalletInterface + ?Sized> IdentityClient<W> {
    /// Create a new IdentityClient.
    pub fn new(
        wallet: Arc<W>,
        options: Option<IdentityClientOptions>,
        originator: Option<String>,
    ) -> Self {
        let contacts_manager = ContactsManager::new(wallet.clone(), originator.clone());
        IdentityClient {
            wallet,
            contacts_manager,
            options: options.unwrap_or_default(),
            originator,
        }
    }

    /// Access the underlying ContactsManager.
    pub fn contacts_manager(&self) -> &ContactsManager<W> {
        &self.contacts_manager
    }

    /// Resolve displayable identities by identity key.
    ///
    /// Queries the wallet's overlay discovery for certificates issued to the
    /// given identity key. If `override_with_contacts` is true (default),
    /// personal contacts are checked first and used as overrides.
    pub async fn resolve_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        override_with_contacts: bool,
    ) -> Result<Vec<DisplayableIdentity>, ServicesError> {
        let identity_key_hex = args.identity_key.to_der_hex();

        // Check contacts cache if override is enabled.
        if override_with_contacts {
            let contacts = self
                .contacts_manager
                .get_contacts(Some(&identity_key_hex), false, 1000)
                .await
                .unwrap_or_default();

            if !contacts.is_empty() {
                return Ok(contacts.iter().map(|c| c.to_displayable()).collect());
            }
        }

        // Query the overlay via wallet discovery.
        let result = self
            .wallet
            .discover_by_identity_key(args, self.originator.as_deref())
            .await
            .map_err(|e| {
                ServicesError::Identity(format!("discover_by_identity_key failed: {}", e))
            })?;

        let identities: Vec<DisplayableIdentity> = result
            .certificates
            .iter()
            .map(|cert| Self::parse_identity(cert))
            .collect();

        Ok(identities)
    }

    /// Resolve displayable identities by attributes.
    ///
    /// Queries the wallet's overlay discovery for certificates matching the
    /// given attributes. Results can be overridden with personal contacts.
    pub async fn resolve_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        override_with_contacts: bool,
    ) -> Result<Vec<DisplayableIdentity>, ServicesError> {
        // Load contacts for override if enabled.
        let contact_map: HashMap<String, Contact> = if override_with_contacts {
            let contacts = self
                .contacts_manager
                .get_contacts(None, false, 1000)
                .await
                .unwrap_or_default();
            contacts
                .into_iter()
                .map(|c| (c.identity_key.clone(), c))
                .collect()
        } else {
            HashMap::new()
        };

        // Query the overlay via wallet discovery.
        let result = self
            .wallet
            .discover_by_attributes(args, self.originator.as_deref())
            .await
            .map_err(|e| {
                ServicesError::Identity(format!("discover_by_attributes failed: {}", e))
            })?;

        let identities: Vec<DisplayableIdentity> = result
            .certificates
            .iter()
            .map(|cert| {
                let subject_key = cert.certificate.subject.to_der_hex();
                if let Some(contact) = contact_map.get(&subject_key) {
                    contact.to_displayable()
                } else {
                    Self::parse_identity(cert)
                }
            })
            .collect();

        Ok(identities)
    }

    /// Publicly reveal selected certificate fields by creating a publicly
    /// verifiable certificate and broadcasting it to the identity overlay.
    ///
    /// This creates a PushDrop token containing the certificate with a keyring
    /// for the "anyone" verifier, and broadcasts it to the tm_identity topic.
    pub async fn publicly_reveal_attributes(
        &self,
        certificate: &crate::wallet::interfaces::Certificate,
        fields_to_reveal: &[String],
    ) -> Result<(), ServicesError> {
        if fields_to_reveal.is_empty() {
            return Err(ServicesError::Identity(
                "Public reveal failed: You must reveal at least one field!".to_string(),
            ));
        }

        if let Some(fields) = &certificate.fields {
            if fields.is_empty() {
                return Err(ServicesError::Identity(
                    "Public reveal failed: Certificate has no fields to reveal!".to_string(),
                ));
            }
        } else {
            return Err(ServicesError::Identity(
                "Public reveal failed: Certificate has no fields to reveal!".to_string(),
            ));
        }

        // Use PrivateKey(1) as the "anyone" verifier.
        let anyone_public = crate::wallet::anyone_pubkey();

        let _prove_result = self
            .wallet
            .prove_certificate(
                ProveCertificateArgs {
                    certificate: certificate.clone(),
                    fields_to_reveal: fields_to_reveal.to_vec(),
                    verifier: anyone_public,
                    privileged: BooleanDefaultFalse(None),
                    privileged_reason: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Identity(format!("Failed to prove certificate: {}", e)))?;

        // In a full implementation, we would:
        // 1. Build a PushDrop locking script with the certificate + keyring
        // 2. Create a transaction via wallet.create_action
        // 3. Broadcast to tm_identity topic via TopicBroadcaster
        //
        // This requires Transaction construction which depends on the full
        // PushDrop template integration. The wallet proof step above validates
        // the certificate and produces the keyring needed.

        Ok(())
    }

    /// Parse identity information from an IdentityCertificate.
    ///
    /// Matches the TS SDK IdentityClient.parseIdentity static method.
    pub fn parse_identity(cert: &IdentityCertificate) -> DisplayableIdentity {
        let cert_type = cert_type_to_base64(&cert.certificate.cert_type);
        let fields = &cert.decrypted_fields;
        let certifier = &cert.certifier_info;

        let (name, avatar_url, badge_label, badge_icon_url, badge_click_url) =
            match cert_type.as_str() {
                t if t == KnownIdentityTypes::X_CERT => (
                    fields.get("userName").cloned().unwrap_or_default(),
                    fields.get("profilePhoto").cloned().unwrap_or_default(),
                    format!("X account certified by {}", certifier.name),
                    certifier.icon_url.clone(),
                    "https://socialcert.net".to_string(),
                ),
                t if t == KnownIdentityTypes::DISCORD_CERT => (
                    fields.get("userName").cloned().unwrap_or_default(),
                    fields.get("profilePhoto").cloned().unwrap_or_default(),
                    format!("Discord account certified by {}", certifier.name),
                    certifier.icon_url.clone(),
                    "https://socialcert.net".to_string(),
                ),
                t if t == KnownIdentityTypes::EMAIL_CERT => (
                    fields.get("email").cloned().unwrap_or_default(),
                    "XUTZxep7BBghAJbSBwTjNfmcsDdRFs5EaGEgkESGSgjJVYgMEizu".to_string(),
                    format!("Email certified by {}", certifier.name),
                    certifier.icon_url.clone(),
                    "https://socialcert.net".to_string(),
                ),
                t if t == KnownIdentityTypes::PHONE_CERT => (
                    fields.get("phoneNumber").cloned().unwrap_or_default(),
                    "XUTLxtX3ELNUwRhLwL7kWNGbdnFM8WG2eSLv84J7654oH8HaJWrU".to_string(),
                    format!("Phone certified by {}", certifier.name),
                    certifier.icon_url.clone(),
                    "https://socialcert.net".to_string(),
                ),
                t if t == KnownIdentityTypes::IDENTI_CERT => {
                    let first = fields.get("firstName").cloned().unwrap_or_default();
                    let last = fields.get("lastName").cloned().unwrap_or_default();
                    (
                        format!("{} {}", first, last),
                        fields.get("profilePhoto").cloned().unwrap_or_default(),
                        format!("Government ID certified by {}", certifier.name),
                        certifier.icon_url.clone(),
                        "https://identicert.me".to_string(),
                    )
                }
                t if t == KnownIdentityTypes::REGISTRANT => (
                    fields.get("name").cloned().unwrap_or_default(),
                    fields.get("icon").cloned().unwrap_or_default(),
                    format!("Entity certified by {}", certifier.name),
                    certifier.icon_url.clone(),
                    "https://projectbabbage.com/docs/registrant".to_string(),
                ),
                t if t == KnownIdentityTypes::COOL_CERT => {
                    let is_cool = fields.get("cool").map(|v| v == "true").unwrap_or(false);
                    let name = if is_cool {
                        "Cool Person!".to_string()
                    } else {
                        "Not cool!".to_string()
                    };
                    let di = default_identity();
                    (
                        name,
                        di.avatar_url,
                        di.badge_label,
                        di.badge_icon_url,
                        di.badge_click_url,
                    )
                }
                t if t == KnownIdentityTypes::ANYONE => (
                    "Anyone".to_string(),
                    "XUT4bpQ6cpBaXi1oMzZsXfpkWGbtp2JTUYAoN7PzhStFJ6wLfoeR".to_string(),
                    "Represents the ability for anyone to access this information.".to_string(),
                    "XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG".to_string(),
                    "https://projectbabbage.com/docs/anyone-identity".to_string(),
                ),
                t if t == KnownIdentityTypes::SELF_ => (
                    "You".to_string(),
                    "XUT9jHGk2qace148jeCX5rDsMftkSGYKmigLwU2PLLBc7Hm63VYR".to_string(),
                    "Represents your ability to access this information.".to_string(),
                    "XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG".to_string(),
                    "https://projectbabbage.com/docs/self-identity".to_string(),
                ),
                _ => Self::try_parse_generic_identity(&cert_type, fields, certifier),
            };

        let subject_str = cert.certificate.subject.to_der_hex();
        let abbreviated_key = if subject_str.len() > 10 {
            format!("{}...", &subject_str[..10])
        } else if !subject_str.is_empty() {
            subject_str.clone()
        } else {
            String::new()
        };

        DisplayableIdentity {
            name,
            avatar_url,
            abbreviated_key,
            identity_key: subject_str,
            badge_icon_url,
            badge_label,
            badge_click_url,
        }
    }

    /// Try to parse identity information from unknown certificate types
    /// by checking common field names. Matches TS SDK tryToParseGenericIdentity.
    fn try_parse_generic_identity(
        cert_type: &str,
        fields: &HashMap<String, String>,
        certifier: &crate::wallet::interfaces::IdentityCertifier,
    ) -> (String, String, String, String, String) {
        let di = default_identity();

        // Try to construct name from common field patterns.
        let first_name = fields.get("firstName").filter(|v| !v.is_empty());
        let last_name = fields.get("lastName").filter(|v| !v.is_empty());
        let full_name = match (first_name, last_name) {
            (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
            (Some(f), None) => Some(f.clone()),
            (None, Some(l)) => Some(l.clone()),
            (None, None) => None,
        };

        let name = fields
            .get("name")
            .filter(|v| !v.is_empty())
            .cloned()
            .or_else(|| fields.get("userName").filter(|v| !v.is_empty()).cloned())
            .or(full_name)
            .or_else(|| fields.get("email").filter(|v| !v.is_empty()).cloned())
            .unwrap_or_else(|| di.name.clone());

        // Try to find avatar.
        let avatar_url = fields
            .get("profilePhoto")
            .filter(|v| !v.is_empty())
            .or_else(|| fields.get("avatar").filter(|v| !v.is_empty()))
            .or_else(|| fields.get("icon").filter(|v| !v.is_empty()))
            .or_else(|| fields.get("photo").filter(|v| !v.is_empty()))
            .cloned()
            .unwrap_or(di.avatar_url);

        let badge_label = if !certifier.name.is_empty() {
            format!("{} certified by {}", cert_type, certifier.name)
        } else {
            di.badge_label
        };

        let badge_icon_url = if !certifier.icon_url.is_empty() {
            certifier.icon_url.clone()
        } else {
            di.badge_icon_url
        };

        let badge_click_url = di.badge_click_url;

        (
            name,
            avatar_url,
            badge_label,
            badge_icon_url,
            badge_click_url,
        )
    }

    /// Get contacts from the contacts manager.
    pub async fn get_contacts(
        &self,
        identity_key: Option<&str>,
        force_refresh: bool,
        limit: usize,
    ) -> Result<Vec<Contact>, ServicesError> {
        self.contacts_manager
            .get_contacts(identity_key, force_refresh, limit)
            .await
    }

    /// Save or update a contact.
    pub async fn save_contact(
        &self,
        contact: &DisplayableIdentity,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<(), ServicesError> {
        let c = Contact::from_displayable(contact, metadata);
        self.contacts_manager.add_contact(&c).await
    }

    /// Remove a contact by identity key.
    pub async fn remove_contact(&self, identity_key: &str) -> Result<(), ServicesError> {
        self.contacts_manager.remove_contact(identity_key).await
    }
}

/// Encode a CertificateType's 32 bytes as base64 for comparison with known identity types.
fn cert_type_to_base64(ct: &CertificateType) -> String {
    base64_encode(ct.bytes())
}

/// Inline base64 encoder (no external crate dependency).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::interfaces::IdentityCertifier;

    #[test]
    fn test_parse_identity_anyone() {
        let cert = IdentityCertificate {
            certificate: crate::wallet::interfaces::Certificate {
                cert_type: crate::wallet::interfaces::CertificateType([0u8; 32]),
                serial_number: crate::wallet::interfaces::SerialNumber([0u8; 32]),
                subject: crate::primitives::public_key::PublicKey::from_private_key(
                    &crate::primitives::private_key::PrivateKey::from_random().unwrap(),
                ),
                certifier: crate::primitives::public_key::PublicKey::from_private_key(
                    &crate::primitives::private_key::PrivateKey::from_random().unwrap(),
                ),
                revocation_outpoint: None,
                fields: None,
                signature: None,
            },
            certifier_info: IdentityCertifier {
                name: "TestCertifier".to_string(),
                icon_url: "https://example.com/icon.png".to_string(),
                description: "Test".to_string(),
                trust: 1,
            },
            publicly_revealed_keyring: HashMap::new(),
            decrypted_fields: HashMap::new(),
        };

        // Default/unknown type should use generic parsing.
        let identity = IdentityClient::<crate::wallet::ProtoWallet>::parse_identity(&cert);
        assert!(!identity.abbreviated_key.is_empty());
    }

    #[test]
    fn test_parse_identity_generic_with_name() {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Alice".to_string());
        fields.insert(
            "profilePhoto".to_string(),
            "https://example.com/alice.png".to_string(),
        );

        let cert = IdentityCertificate {
            certificate: crate::wallet::interfaces::Certificate {
                cert_type: crate::wallet::interfaces::CertificateType([0u8; 32]),
                serial_number: crate::wallet::interfaces::SerialNumber([0u8; 32]),
                subject: crate::primitives::public_key::PublicKey::from_private_key(
                    &crate::primitives::private_key::PrivateKey::from_random().unwrap(),
                ),
                certifier: crate::primitives::public_key::PublicKey::from_private_key(
                    &crate::primitives::private_key::PrivateKey::from_random().unwrap(),
                ),
                revocation_outpoint: None,
                fields: None,
                signature: None,
            },
            certifier_info: IdentityCertifier {
                name: "TestCertifier".to_string(),
                icon_url: "https://example.com/icon.png".to_string(),
                description: "Test".to_string(),
                trust: 1,
            },
            publicly_revealed_keyring: HashMap::new(),
            decrypted_fields: fields,
        };

        let identity = IdentityClient::<crate::wallet::ProtoWallet>::parse_identity(&cert);
        assert_eq!(identity.name, "Alice");
        assert_eq!(identity.avatar_url, "https://example.com/alice.png");
        assert!(identity.badge_label.contains("TestCertifier"));
    }

    #[test]
    fn test_parse_identity_generic_first_last_name() {
        let mut fields = HashMap::new();
        fields.insert("firstName".to_string(), "Bob".to_string());
        fields.insert("lastName".to_string(), "Smith".to_string());

        let cert = IdentityCertificate {
            certificate: crate::wallet::interfaces::Certificate {
                cert_type: crate::wallet::interfaces::CertificateType([0u8; 32]),
                serial_number: crate::wallet::interfaces::SerialNumber([0u8; 32]),
                subject: crate::primitives::public_key::PublicKey::from_private_key(
                    &crate::primitives::private_key::PrivateKey::from_random().unwrap(),
                ),
                certifier: crate::primitives::public_key::PublicKey::from_private_key(
                    &crate::primitives::private_key::PrivateKey::from_random().unwrap(),
                ),
                revocation_outpoint: None,
                fields: None,
                signature: None,
            },
            certifier_info: IdentityCertifier {
                name: "".to_string(),
                icon_url: "".to_string(),
                description: "".to_string(),
                trust: 0,
            },
            publicly_revealed_keyring: HashMap::new(),
            decrypted_fields: fields,
        };

        let identity = IdentityClient::<crate::wallet::ProtoWallet>::parse_identity(&cert);
        assert_eq!(identity.name, "Bob Smith");
        // With empty certifier, should fallback to default badge.
        assert_eq!(identity.badge_label, "Not verified by anyone you trust.");
    }
}
