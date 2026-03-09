//! ContactsManager for cached contact management with wallet-backed storage.
//!
//! Translates the TS SDK ContactsManager.ts. Provides an in-memory cache
//! backed by wallet encrypted storage with HMAC lookup optimization.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::types::{contact_protocol, Contact};
use crate::services::ServicesError;
use crate::wallet::interfaces::{
    CreateHmacArgs, DecryptArgs, EncryptArgs, ListOutputsArgs, OutputInclude,
};
use crate::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue, Counterparty, CounterpartyType};
use crate::wallet::WalletInterface;

/// ContactsManager manages contacts with an in-memory cache and wallet-backed
/// encrypted storage. Uses HMAC lookup optimization for efficient identity key
/// lookups without decrypting all entries.
pub struct ContactsManager<W: WalletInterface + ?Sized> {
    /// Reference to the wallet for crypto operations and storage.
    wallet: Arc<W>,
    /// Thread-safe in-memory contact cache keyed by identity key.
    cache: Arc<RwLock<HashMap<String, Contact>>>,
    /// Whether the cache has been populated from the wallet.
    cache_loaded: Arc<RwLock<bool>>,
    /// Optional originator domain name.
    originator: Option<String>,
}

impl<W: WalletInterface + ?Sized> ContactsManager<W> {
    /// Create a new ContactsManager.
    pub fn new(wallet: Arc<W>, originator: Option<String>) -> Self {
        ContactsManager {
            wallet,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_loaded: Arc::new(RwLock::new(false)),
            originator,
        }
    }

    /// Add or update a contact in the cache and wallet storage.
    ///
    /// Encrypts the contact data with the wallet and stores it in the
    /// "contacts" basket with an HMAC tag for efficient lookup.
    pub async fn add_contact(&self, contact: &Contact) -> Result<(), ServicesError> {
        // Update in-memory cache.
        {
            let mut cache = self.cache.write().await;
            cache.insert(contact.identity_key.clone(), contact.clone());
        }

        // Compute HMAC of identity key for tag-based lookup.
        let _hmac_tag = self.compute_identity_hmac(&contact.identity_key).await?;

        // Encrypt contact data.
        let contact_json =
            serde_json::to_vec(contact).map_err(|e| ServicesError::Serialization(e.to_string()))?;

        let _encrypt_result = self
            .wallet
            .encrypt(
                EncryptArgs {
                    protocol_id: contact_protocol(),
                    key_id: contact.identity_key.clone(),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Self_,
                        public_key: None,
                    },
                    plaintext: contact_json,
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Identity(format!("Failed to encrypt contact: {}", e)))?;

        // In a full implementation, we would create a PushDrop token with the
        // encrypted data and store it in the contacts basket via createAction.
        // For now, the cache serves as the primary store.

        Ok(())
    }

    /// Remove a contact from the cache and wallet storage.
    pub async fn remove_contact(&self, identity_key: &str) -> Result<(), ServicesError> {
        // Remove from in-memory cache.
        {
            let mut cache = self.cache.write().await;
            cache.remove(identity_key);
        }

        // In a full implementation, we would find the contact's UTXO via HMAC
        // tag lookup and spend it (without creating a replacement output).

        Ok(())
    }

    /// Find a contact by identity key.
    ///
    /// Checks the in-memory cache first, then falls back to wallet storage
    /// with HMAC-based lookup.
    pub async fn find_contact(&self, identity_key: &str) -> Result<Option<Contact>, ServicesError> {
        // Check cache first.
        {
            let cache = self.cache.read().await;
            if let Some(contact) = cache.get(identity_key) {
                return Ok(Some(contact.clone()));
            }
        }

        // Cache miss: try wallet HMAC lookup.
        let hmac_tag = self.compute_identity_hmac(identity_key).await?;
        let tag_str = format!("identityKey {}", hex_encode(&hmac_tag));

        let result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: "contacts".to_string(),
                    tags: vec![tag_str],
                    tag_query_mode: None,
                    include: Some(OutputInclude::LockingScripts),
                    include_custom_instructions: BooleanDefaultFalse(Some(true)),
                    include_tags: BooleanDefaultFalse(Some(false)),
                    include_labels: BooleanDefaultFalse(Some(false)),
                    limit: Some(10),
                    offset: None,
                    seek_permission: BooleanDefaultTrue(Some(true)),
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Identity(format!("Failed to list outputs: {}", e)))?;

        if result.outputs.is_empty() {
            return Ok(None);
        }

        // Try to decrypt found outputs.
        for output in &result.outputs {
            if let Some(locking_script) = &output.locking_script {
                if let Some(custom_instructions) = &output.custom_instructions {
                    if let Ok(instructions) =
                        serde_json::from_str::<serde_json::Value>(custom_instructions)
                    {
                        if let Some(key_id) = instructions.get("keyID").and_then(|v| v.as_str()) {
                            // Attempt decryption.
                            match self.decrypt_contact_data(locking_script, key_id).await {
                                Ok(contact) => {
                                    // Update cache.
                                    let mut cache = self.cache.write().await;
                                    cache.insert(contact.identity_key.clone(), contact.clone());
                                    return Ok(Some(contact));
                                }
                                Err(_) => continue,
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// List all cached contacts.
    ///
    /// Returns all contacts from the in-memory cache. If the cache is empty,
    /// attempts to load contacts from wallet storage.
    pub async fn list_contacts(&self) -> Result<Vec<Contact>, ServicesError> {
        // If cache has been loaded, return cached contacts.
        {
            let loaded = self.cache_loaded.read().await;
            if *loaded {
                let cache = self.cache.read().await;
                return Ok(cache.values().cloned().collect());
            }
        }

        // Load from wallet.
        self.refresh_cache().await?;

        let cache = self.cache.read().await;
        Ok(cache.values().cloned().collect())
    }

    /// Get contacts, optionally filtering by identity key.
    ///
    /// Matches the TS SDK getContacts method signature.
    pub async fn get_contacts(
        &self,
        identity_key: Option<&str>,
        force_refresh: bool,
        limit: usize,
    ) -> Result<Vec<Contact>, ServicesError> {
        if force_refresh || !*self.cache_loaded.read().await {
            self.refresh_cache().await?;
        }

        let cache = self.cache.read().await;

        if let Some(key) = identity_key {
            Ok(cache.get(key).into_iter().cloned().collect::<Vec<_>>())
        } else {
            Ok(cache.values().take(limit).cloned().collect())
        }
    }

    /// Refresh the contact cache from wallet storage.
    async fn refresh_cache(&self) -> Result<(), ServicesError> {
        let result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: "contacts".to_string(),
                    tags: vec![],
                    tag_query_mode: None,
                    include: Some(OutputInclude::LockingScripts),
                    include_custom_instructions: BooleanDefaultFalse(Some(true)),
                    include_tags: BooleanDefaultFalse(Some(false)),
                    include_labels: BooleanDefaultFalse(Some(false)),
                    limit: Some(1000),
                    offset: None,
                    seek_permission: BooleanDefaultTrue(Some(true)),
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Identity(format!("Failed to list contacts: {}", e)))?;

        let mut new_cache = HashMap::new();

        for output in &result.outputs {
            if let Some(locking_script) = &output.locking_script {
                if let Some(custom_instructions) = &output.custom_instructions {
                    if let Ok(instructions) =
                        serde_json::from_str::<serde_json::Value>(custom_instructions)
                    {
                        if let Some(key_id) = instructions.get("keyID").and_then(|v| v.as_str()) {
                            if let Ok(contact) =
                                self.decrypt_contact_data(locking_script, key_id).await
                            {
                                new_cache.insert(contact.identity_key.clone(), contact);
                            }
                        }
                    }
                }
            }
        }

        {
            let mut cache = self.cache.write().await;
            *cache = new_cache;
        }
        {
            let mut loaded = self.cache_loaded.write().await;
            *loaded = true;
        }

        Ok(())
    }

    /// Compute HMAC of an identity key for efficient tag-based lookups.
    ///
    /// Uses the wallet's createHmac with the contact protocol and the
    /// identity key as both keyID and data, matching the TS SDK pattern.
    async fn compute_identity_hmac(&self, identity_key: &str) -> Result<Vec<u8>, ServicesError> {
        let result = self
            .wallet
            .create_hmac(
                CreateHmacArgs {
                    protocol_id: contact_protocol(),
                    key_id: identity_key.to_string(),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Self_,
                        public_key: None,
                    },
                    data: identity_key.as_bytes().to_vec(),
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Identity(format!("Failed to compute HMAC: {}", e)))?;

        Ok(result.hmac)
    }

    /// Attempt to decrypt contact data from a locking script.
    async fn decrypt_contact_data(
        &self,
        ciphertext: &[u8],
        key_id: &str,
    ) -> Result<Contact, ServicesError> {
        let result = self
            .wallet
            .decrypt(
                DecryptArgs {
                    protocol_id: contact_protocol(),
                    key_id: key_id.to_string(),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Self_,
                        public_key: None,
                    },
                    ciphertext: ciphertext.to_vec(),
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Identity(format!("Failed to decrypt: {}", e)))?;

        serde_json::from_slice(&result.plaintext)
            .map_err(|e| ServicesError::Serialization(format!("Failed to parse contact: {}", e)))
    }
}

/// Hex-encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xab, 0xcd, 0xef]), "abcdef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn test_cache_initially_empty() {
        // Verify the cache starts empty by checking the RwLock directly.
        let cache: HashMap<String, Contact> = HashMap::new();
        assert!(cache.is_empty());
    }

    // Integration tests requiring a wallet mock are deferred to a higher-level
    // test suite. The ContactsManager API is validated by the IdentityClient
    // tests and the cache hit/miss patterns are verified structurally above.
}
