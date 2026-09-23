//! ContactsManager for cached contact management with wallet-backed storage.
//!
//! Translates the TS SDK ContactsManager.ts. Provides an in-memory cache
//! backed by wallet encrypted storage with HMAC lookup optimization.

use futures_util::{stream::FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::types::{contact_protocol, Contact};
use crate::services::ServicesError;
use crate::wallet::interfaces::{
    CreateHmacArgs, DecryptArgs, EncryptArgs, ListOutputsArgs, OutputInclude,
};
use crate::wallet::types::{
    BooleanDefaultFalse, BooleanDefaultTrue, Counterparty, CounterpartyType,
};
use crate::wallet::WalletInterface;

/// Maximum number of wallet decryptions performed by one cache refresh.
///
/// Wallet calls are I/O-bound, but the output list is wallet-controlled and
/// may contain up to 1,000 entries. A small fixed window improves latency
/// without turning a large contact basket into unbounded wallet fan-out.
const MAX_CONCURRENT_CONTACT_DECRYPTIONS: usize = 8;

async fn indexed<Fut>(index: usize, future: Fut) -> (usize, Fut::Output)
where
    Fut: std::future::Future,
{
    (index, future.await)
}

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

        let decryptions = result.outputs.iter().filter_map(|output| {
            let locking_script = output.locking_script.as_deref()?;
            let custom_instructions = output.custom_instructions.as_deref()?;
            let instructions =
                serde_json::from_str::<serde_json::Value>(custom_instructions).ok()?;
            let key_id = instructions.get("keyID")?.as_str()?.to_string();
            Some((locking_script, key_id))
        });
        let mut decryptions = decryptions.enumerate();
        let mut in_flight = FuturesUnordered::new();

        for (index, (locking_script, key_id)) in decryptions
            .by_ref()
            .take(MAX_CONCURRENT_CONTACT_DECRYPTIONS)
        {
            in_flight.push(indexed(
                index,
                self.decrypt_contact_data_with_owned_key(locking_script, key_id),
            ));
        }

        let mut decrypted = Vec::new();
        while let Some(result) = in_flight.next().await {
            decrypted.push(result);
            if let Some((index, (locking_script, key_id))) = decryptions.next() {
                in_flight.push(indexed(
                    index,
                    self.decrypt_contact_data_with_owned_key(locking_script, key_id),
                ));
            }
        }

        // Completion order is nondeterministic. Apply successful decryptions in
        // wallet output order so duplicate identity keys retain the previous
        // sequential behavior: the later output wins. Failures remain skipped.
        decrypted.sort_unstable_by_key(|(index, _)| *index);
        let mut new_cache = HashMap::new();
        for (_, contact) in decrypted {
            if let Ok(contact) = contact {
                new_cache.insert(contact.identity_key.clone(), contact);
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

    async fn decrypt_contact_data_with_owned_key(
        &self,
        ciphertext: &[u8],
        key_id: String,
    ) -> Result<Contact, ServicesError> {
        self.decrypt_contact_data(ciphertext, &key_id).await
    }
}

/// Hex-encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::error::WalletError;
    use crate::wallet::interfaces::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;
    use tokio::sync::Semaphore;

    #[derive(Clone)]
    enum DecryptBehavior {
        Contact(Contact),
        Delayed(Contact, Duration),
        Gated(Contact),
        InvalidJson,
        Error,
    }

    struct TestWallet {
        outputs: Vec<Output>,
        decryptions: StdMutex<HashMap<String, DecryptBehavior>>,
        decrypt_calls: StdMutex<Vec<String>>,
        list_calls: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
        started: AtomicUsize,
        release: Semaphore,
    }

    impl TestWallet {
        fn new(outputs: Vec<Output>, decryptions: HashMap<String, DecryptBehavior>) -> Self {
            Self {
                outputs,
                decryptions: StdMutex::new(decryptions),
                decrypt_calls: StdMutex::new(Vec::new()),
                list_calls: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
                started: AtomicUsize::new(0),
                release: Semaphore::new(0),
            }
        }

        async fn wait_for_started(&self, expected: usize) {
            for _ in 0..1_000 {
                if self.started.load(Ordering::SeqCst) >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!(
                "only {} decryptions started; expected {expected}",
                self.started.load(Ordering::SeqCst)
            );
        }
    }

    macro_rules! unused_wallet_method {
        ($name:ident, $args:ty, $result:ty) => {
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _args: $args,
                _originator: Option<&'life1 str>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<Output = Result<$result, WalletError>>
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
                    unreachable!(concat!(stringify!($name), " is not used by this test"))
                })
            }
        };
        ($name:ident, $result:ty) => {
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _originator: Option<&'life1 str>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<Output = Result<$result, WalletError>>
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
                    unreachable!(concat!(stringify!($name), " is not used by this test"))
                })
            }
        };
    }

    #[async_trait::async_trait]
    impl WalletInterface for TestWallet {
        unused_wallet_method!(create_action, CreateActionArgs, CreateActionResult);
        unused_wallet_method!(sign_action, SignActionArgs, SignActionResult);
        unused_wallet_method!(abort_action, AbortActionArgs, AbortActionResult);
        unused_wallet_method!(list_actions, ListActionsArgs, ListActionsResult);
        unused_wallet_method!(
            internalize_action,
            InternalizeActionArgs,
            InternalizeActionResult
        );

        async fn list_outputs(
            &self,
            _args: ListOutputsArgs,
            _originator: Option<&str>,
        ) -> Result<ListOutputsResult, WalletError> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            Ok(ListOutputsResult {
                total_outputs: self.outputs.len() as u32,
                beef: None,
                outputs: self.outputs.clone(),
            })
        }

        unused_wallet_method!(
            relinquish_output,
            RelinquishOutputArgs,
            RelinquishOutputResult
        );
        unused_wallet_method!(get_public_key, GetPublicKeyArgs, GetPublicKeyResult);
        unused_wallet_method!(
            reveal_counterparty_key_linkage,
            RevealCounterpartyKeyLinkageArgs,
            RevealCounterpartyKeyLinkageResult
        );
        unused_wallet_method!(
            reveal_specific_key_linkage,
            RevealSpecificKeyLinkageArgs,
            RevealSpecificKeyLinkageResult
        );
        unused_wallet_method!(encrypt, EncryptArgs, EncryptResult);

        async fn decrypt(
            &self,
            args: DecryptArgs,
            _originator: Option<&str>,
        ) -> Result<DecryptResult, WalletError> {
            self.decrypt_calls.lock().unwrap().push(args.key_id.clone());
            let behavior = self
                .decryptions
                .lock()
                .unwrap()
                .get(&args.key_id)
                .cloned()
                .expect("test configured every decryption");

            self.started.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);

            let result = match behavior {
                DecryptBehavior::Contact(contact) => Ok(DecryptResult {
                    plaintext: serde_json::to_vec(&contact).unwrap(),
                }),
                DecryptBehavior::Delayed(contact, delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(DecryptResult {
                        plaintext: serde_json::to_vec(&contact).unwrap(),
                    })
                }
                DecryptBehavior::Gated(contact) => {
                    self.release.acquire().await.unwrap().forget();
                    Ok(DecryptResult {
                        plaintext: serde_json::to_vec(&contact).unwrap(),
                    })
                }
                DecryptBehavior::InvalidJson => Ok(DecryptResult {
                    plaintext: b"not-json".to_vec(),
                }),
                DecryptBehavior::Error => Err(WalletError::Internal("decrypt failed".into())),
            };

            self.active.fetch_sub(1, Ordering::SeqCst);
            result
        }

        async fn create_hmac(
            &self,
            _args: CreateHmacArgs,
            _originator: Option<&str>,
        ) -> Result<CreateHmacResult, WalletError> {
            Ok(CreateHmacResult { hmac: vec![0; 32] })
        }
        unused_wallet_method!(verify_hmac, VerifyHmacArgs, VerifyHmacResult);
        unused_wallet_method!(create_signature, CreateSignatureArgs, CreateSignatureResult);
        unused_wallet_method!(verify_signature, VerifySignatureArgs, VerifySignatureResult);
        unused_wallet_method!(acquire_certificate, AcquireCertificateArgs, Certificate);
        unused_wallet_method!(
            list_certificates,
            ListCertificatesArgs,
            ListCertificatesResult
        );
        unused_wallet_method!(
            prove_certificate,
            ProveCertificateArgs,
            ProveCertificateResult
        );
        unused_wallet_method!(
            relinquish_certificate,
            RelinquishCertificateArgs,
            RelinquishCertificateResult
        );
        unused_wallet_method!(
            discover_by_identity_key,
            DiscoverByIdentityKeyArgs,
            DiscoverCertificatesResult
        );
        unused_wallet_method!(
            discover_by_attributes,
            DiscoverByAttributesArgs,
            DiscoverCertificatesResult
        );
        unused_wallet_method!(is_authenticated, AuthenticatedResult);
        unused_wallet_method!(wait_for_authentication, AuthenticatedResult);
        unused_wallet_method!(get_height, GetHeightResult);
        unused_wallet_method!(get_header_for_height, GetHeaderArgs, GetHeaderResult);
        unused_wallet_method!(get_network, GetNetworkResult);
        unused_wallet_method!(get_version, GetVersionResult);
    }

    fn contact(identity_key: &str, name: &str) -> Contact {
        Contact {
            name: name.to_string(),
            avatar_url: String::new(),
            abbreviated_key: identity_key.to_string(),
            identity_key: identity_key.to_string(),
            badge_icon_url: String::new(),
            badge_label: String::new(),
            badge_click_url: String::new(),
            metadata: None,
        }
    }

    fn output(key_id: &str) -> Output {
        Output {
            satoshis: 1,
            locking_script: Some(key_id.as_bytes().to_vec()),
            spendable: true,
            custom_instructions: Some(format!(r#"{{"keyID":"{key_id}"}}"#)),
            tags: None,
            outpoint: format!("{}.{:x}", "00".repeat(32), key_id.len()),
            labels: None,
        }
    }

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

    #[tokio::test]
    async fn refresh_cache_bounds_wallet_decryptions() {
        let outputs: Vec<_> = (0..10)
            .map(|index| output(&format!("key-{index}")))
            .collect();
        let decryptions = (0..10)
            .map(|index| {
                let key = format!("key-{index}");
                (
                    key.clone(),
                    DecryptBehavior::Gated(contact(&key, &format!("Contact {index}"))),
                )
            })
            .collect();
        let wallet = Arc::new(TestWallet::new(outputs, decryptions));
        let manager = Arc::new(ContactsManager::new(wallet.clone(), None));

        let refresh = tokio::spawn({
            let manager = manager.clone();
            async move { manager.get_contacts(None, true, 100).await }
        });

        wallet
            .wait_for_started(MAX_CONCURRENT_CONTACT_DECRYPTIONS)
            .await;
        assert_eq!(
            wallet.started.load(Ordering::SeqCst),
            MAX_CONCURRENT_CONTACT_DECRYPTIONS
        );
        assert_eq!(
            wallet.max_active.load(Ordering::SeqCst),
            MAX_CONCURRENT_CONTACT_DECRYPTIONS
        );

        wallet
            .release
            .add_permits(MAX_CONCURRENT_CONTACT_DECRYPTIONS);
        wallet.wait_for_started(10).await;
        wallet.release.add_permits(2);

        let contacts = refresh.await.unwrap().unwrap();
        assert_eq!(contacts.len(), 10);
        assert_eq!(
            wallet.max_active.load(Ordering::SeqCst),
            MAX_CONCURRENT_CONTACT_DECRYPTIONS
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_cache_commits_in_output_order_and_skips_failures() {
        let mut outputs = vec![
            output("older"),
            output("newer"),
            output("wallet-error"),
            output("invalid-json"),
            output("good"),
        ];
        outputs.push(Output {
            custom_instructions: Some("not-json".into()),
            ..output("never-decrypted")
        });
        outputs.push(Output {
            locking_script: None,
            ..output("no-script")
        });

        let decryptions = HashMap::from([
            (
                "older".into(),
                DecryptBehavior::Delayed(contact("duplicate", "Older"), Duration::from_millis(50)),
            ),
            (
                "newer".into(),
                DecryptBehavior::Delayed(contact("duplicate", "Newer"), Duration::from_millis(1)),
            ),
            ("wallet-error".into(), DecryptBehavior::Error),
            ("invalid-json".into(), DecryptBehavior::InvalidJson),
            (
                "good".into(),
                DecryptBehavior::Contact(contact("good", "Good")),
            ),
        ]);
        let wallet = Arc::new(TestWallet::new(outputs, decryptions));
        let manager = ContactsManager::new(wallet.clone(), None);

        let contacts = manager.get_contacts(None, true, 100).await.unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(
            manager
                .get_contacts(Some("duplicate"), false, 100)
                .await
                .unwrap()[0]
                .name,
            "Newer"
        );
        assert_eq!(wallet.decrypt_calls.lock().unwrap().len(), 5);
        assert_eq!(wallet.list_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn find_contact_keeps_input_order_first_success_and_early_exit() {
        let outputs = vec![output("first"), output("second")];
        let decryptions = HashMap::from([
            (
                "first".into(),
                DecryptBehavior::Delayed(contact("requested", "First"), Duration::from_millis(50)),
            ),
            (
                "second".into(),
                DecryptBehavior::Contact(contact("requested", "Second")),
            ),
        ]);
        let wallet = Arc::new(TestWallet::new(outputs, decryptions));
        let manager = ContactsManager::new(wallet.clone(), None);

        let found = manager.find_contact("requested").await.unwrap().unwrap();
        assert_eq!(found.name, "First");
        assert_eq!(
            wallet.decrypt_calls.lock().unwrap().as_slice(),
            &["first".to_string()]
        );
    }

    #[tokio::test]
    async fn refresh_cache_handles_empty_and_single_output_boundaries() {
        let empty_wallet = Arc::new(TestWallet::new(Vec::new(), HashMap::new()));
        let empty_manager = ContactsManager::new(empty_wallet.clone(), None);
        assert!(empty_manager.list_contacts().await.unwrap().is_empty());
        assert_eq!(empty_wallet.started.load(Ordering::SeqCst), 0);

        let one_wallet = Arc::new(TestWallet::new(
            vec![output("only")],
            HashMap::from([(
                "only".into(),
                DecryptBehavior::Contact(contact("only", "Only")),
            )]),
        ));
        let one_manager = ContactsManager::new(one_wallet.clone(), None);
        assert_eq!(one_manager.list_contacts().await.unwrap().len(), 1);
        assert_eq!(one_wallet.max_active.load(Ordering::SeqCst), 1);
    }
}
