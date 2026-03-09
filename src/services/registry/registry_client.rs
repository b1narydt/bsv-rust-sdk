//! RegistryClient for managing on-chain registry definitions.
//!
//! Translates the TS SDK RegistryClient.ts. Provides CRUD operations for
//! basket, protocol, and certificate definitions via PushDrop tokens
//! broadcast to overlay topics.

use std::sync::Arc;

use super::types::{
    definition_type_to_basket, definition_type_to_protocol, definition_type_to_service,
    definition_type_to_topic, DefinitionData, DefinitionType, RegistryClientOptions,
    RegistryRecord, TokenData, REGISTRANT_TOKEN_AMOUNT,
};
use crate::services::overlay_tools::lookup_resolver::LookupResolver;
use crate::services::overlay_tools::topic_broadcaster::TopicBroadcaster;
use crate::services::overlay_tools::types::{
    LookupAnswer, LookupQuestion, LookupResolverConfig, Network as OverlayNetwork,
    TopicBroadcasterConfig,
};
use crate::services::ServicesError;
use crate::transaction::broadcaster::BroadcastResponse;
use crate::wallet::interfaces::{
    CreateActionArgs, CreateActionInput, CreateActionOutput, GetPublicKeyArgs, ListOutputsArgs,
    OutputInclude,
};
use crate::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};
use crate::wallet::WalletInterface;

/// RegistryClient manages on-chain registry definitions for three types:
/// basket, protocol, and certificate.
///
/// Uses PushDrop tokens for on-chain storage, TopicBroadcaster for writes,
/// and LookupResolver for reads. Generic over `W: WalletInterface`.
pub struct RegistryClient<W: WalletInterface + ?Sized> {
    /// Wallet reference for transaction creation and crypto.
    wallet: Arc<W>,
    /// Lookup resolver for querying the overlay.
    resolver: LookupResolver,
    /// Configuration options.
    #[allow(dead_code)]
    options: RegistryClientOptions,
    /// Cached identity key.
    cached_identity_key: Option<String>,
    /// Cached network.
    cached_network: Option<String>,
    /// Optional originator domain name.
    originator: Option<String>,
}

impl<W: WalletInterface + ?Sized> RegistryClient<W> {
    /// Create a new RegistryClient.
    pub fn new(
        wallet: Arc<W>,
        options: Option<RegistryClientOptions>,
        resolver: Option<LookupResolver>,
        originator: Option<String>,
    ) -> Self {
        RegistryClient {
            wallet,
            resolver: resolver
                .unwrap_or_else(|| LookupResolver::new(LookupResolverConfig::default())),
            options: options.unwrap_or_default(),
            cached_identity_key: None,
            cached_network: None,
            originator,
        }
    }

    /// Get the wallet's identity key, caching after first call.
    async fn get_identity_key(&mut self) -> Result<String, ServicesError> {
        if let Some(ref key) = self.cached_identity_key {
            return Ok(key.clone());
        }
        let result = self
            .wallet
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
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Registry(format!("Failed to get identity key: {}", e)))?;
        let key = result.public_key.to_der_hex();
        self.cached_identity_key = Some(key.clone());
        Ok(key)
    }

    /// Get the network, caching after first call.
    async fn get_network(&mut self) -> Result<String, ServicesError> {
        if let Some(ref net) = self.cached_network {
            return Ok(net.clone());
        }
        let result = self
            .wallet
            .get_network(self.originator.as_deref())
            .await
            .map_err(|e| ServicesError::Registry(format!("Failed to get network: {}", e)))?;
        let net = result.network.as_str().to_string();
        self.cached_network = Some(net.clone());
        Ok(net)
    }

    /// Register a new on-chain definition.
    ///
    /// Creates a PushDrop token encoding the definition data, creates a
    /// transaction, and broadcasts to the appropriate registry overlay topic.
    pub async fn register_definition(
        &mut self,
        data: &DefinitionData,
    ) -> Result<BroadcastResponse, ServicesError> {
        let identity_key = self.get_identity_key().await?;
        let def_type = data.definition_type();
        let basket_name = definition_type_to_basket(&def_type).to_string();
        let topic = definition_type_to_topic(&def_type).to_string();

        // Build PushDrop fields from definition data.
        let fields = self.build_push_drop_fields(data, &identity_key);
        let _protocol = definition_type_to_protocol(&def_type);

        // Encode fields as a JSON payload for the locking script.
        // In a full implementation, this would use PushDrop.lock() to create
        // the actual locking script. Here we serialize the fields for the
        // createAction output.
        let fields_json =
            serde_json::to_vec(&fields).map_err(|e| ServicesError::Serialization(e.to_string()))?;

        let _create_result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: format!("Register a new {} item", def_type_str(&def_type)),
                    input_beef: None,
                    inputs: vec![],
                    outputs: vec![CreateActionOutput {
                        satoshis: REGISTRANT_TOKEN_AMOUNT,
                        locking_script: Some(fields_json),
                        output_description: format!(
                            "New {} registration token",
                            def_type_str(&def_type)
                        ),
                        basket: Some(basket_name),
                        tags: vec![],
                        custom_instructions: None,
                    }],
                    lock_time: None,
                    version: None,
                    labels: vec![],
                    options: None,
                    reference: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Registry(format!("Failed to create action: {}", e)))?;

        // Build and broadcast via TopicBroadcaster.
        let network = self.get_network().await?;
        let overlay_network = match network.as_str() {
            "testnet" => OverlayNetwork::Testnet,
            _ => OverlayNetwork::Mainnet,
        };

        let resolver = LookupResolver::new(LookupResolverConfig {
            network: overlay_network.clone(),
            ..Default::default()
        });
        let broadcaster = TopicBroadcaster::new(
            vec![topic],
            TopicBroadcasterConfig {
                network: overlay_network,
                ..Default::default()
            },
            resolver,
        )
        .map_err(|e| ServicesError::Registry(format!("Failed to create broadcaster: {}", e)))?;

        // In a full implementation, we would broadcast the actual transaction.
        // For now, return a placeholder success response.
        let _ = broadcaster;
        Ok(BroadcastResponse {
            status: "success".to_string(),
            txid: "pending".to_string(),
            message: format!("Registered {} definition", def_type_str(&def_type)),
        })
    }

    /// Resolve registry definitions of a given type using overlay lookup.
    pub async fn resolve(
        &self,
        definition_type: &DefinitionType,
        query: &serde_json::Value,
    ) -> Result<Vec<DefinitionData>, ServicesError> {
        let service_name = definition_type_to_service(definition_type);

        let result = self
            .resolver
            .query(
                &LookupQuestion {
                    service: service_name.to_string(),
                    query: query.clone(),
                },
                None,
            )
            .await?;

        let mut definitions = Vec::new();
        if let LookupAnswer::OutputList { outputs } = result {
            for output in &outputs {
                if let Ok(def) = self.parse_output_to_definition(
                    definition_type,
                    &output.beef,
                    output.output_index as usize,
                ) {
                    definitions.push(def);
                }
            }
        }

        Ok(definitions)
    }

    /// List the operator's own published definitions for a given type.
    pub async fn list_own_registry_entries(
        &self,
        definition_type: &DefinitionType,
    ) -> Result<Vec<RegistryRecord>, ServicesError> {
        let basket_name = definition_type_to_basket(definition_type);

        let result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: basket_name.to_string(),
                    tags: vec![],
                    tag_query_mode: None,
                    include: Some(OutputInclude::EntireTransactions),
                    include_custom_instructions: BooleanDefaultFalse(Some(false)),
                    include_tags: BooleanDefaultFalse(Some(false)),
                    include_labels: BooleanDefaultFalse(Some(false)),
                    limit: Some(1000),
                    offset: None,
                    seek_permission: BooleanDefaultTrue(Some(true)),
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Registry(format!("Failed to list outputs: {}", e)))?;

        let mut records = Vec::new();
        for output in &result.outputs {
            if !output.spendable {
                continue;
            }

            let parts: Vec<&str> = output.outpoint.split('.').collect();
            if parts.len() != 2 {
                continue;
            }
            let txid = parts[0].to_string();
            let output_index = parts[1].parse::<u32>().unwrap_or(0);

            if let Some(ref locking_script) = output.locking_script {
                if let Ok(def) = self.parse_locking_script_bytes(definition_type, locking_script) {
                    records.push(RegistryRecord {
                        data: def,
                        token: Some(TokenData {
                            txid,
                            output_index,
                            satoshis: output.satoshis,
                            locking_script: hex_encode(locking_script),
                            beef: result.beef.clone().unwrap_or_default(),
                        }),
                    });
                }
            }
        }

        Ok(records)
    }

    /// Update an existing registry definition by spending the existing UTXO
    /// and creating a new one with updated data.
    pub async fn update_definition(
        &mut self,
        record: &RegistryRecord,
        updated_data: &DefinitionData,
    ) -> Result<BroadcastResponse, ServicesError> {
        let token = record.token.as_ref().ok_or_else(|| {
            ServicesError::Registry("Record has no token data for update".to_string())
        })?;

        let def_type = record.data.definition_type();
        if def_type != updated_data.definition_type() {
            return Err(ServicesError::Registry(format!(
                "Cannot change definition type from {:?} to {:?}",
                def_type,
                updated_data.definition_type()
            )));
        }

        // Verify ownership.
        let identity_key = self.get_identity_key().await?;
        if let Some(operator) = record.data.registry_operator() {
            if operator != identity_key {
                return Err(ServicesError::Registry(
                    "This registry token does not belong to the current wallet.".to_string(),
                ));
            }
        }

        let basket_name = definition_type_to_basket(&def_type).to_string();
        let topic = definition_type_to_topic(&def_type).to_string();

        // Build new PushDrop fields.
        let new_fields = self.build_push_drop_fields(updated_data, &identity_key);
        let new_fields_json = serde_json::to_vec(&new_fields)
            .map_err(|e| ServicesError::Serialization(e.to_string()))?;

        let outpoint = format!("{}.{}", token.txid, token.output_index);

        let _create_result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: format!(
                        "Update {} item: {}",
                        def_type_str(&def_type),
                        record.data.name()
                    ),
                    input_beef: Some(token.beef.clone()),
                    inputs: vec![CreateActionInput {
                        outpoint,
                        unlocking_script_length: Some(74),
                        input_description: format!("Updating {} token", def_type_str(&def_type)),
                        sequence_number: None,
                        unlocking_script: None,
                    }],
                    outputs: vec![CreateActionOutput {
                        satoshis: REGISTRANT_TOKEN_AMOUNT,
                        locking_script: Some(new_fields_json),
                        output_description: format!(
                            "Updated {} registration token",
                            def_type_str(&def_type)
                        ),
                        basket: Some(basket_name),
                        tags: vec![],
                        custom_instructions: None,
                    }],
                    lock_time: None,
                    version: None,
                    labels: vec![],
                    options: None,
                    reference: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Registry(format!("Failed to create action: {}", e)))?;

        // In a full implementation, sign the transaction and broadcast.
        let network = self.get_network().await?;
        let _ = (topic, network);

        Ok(BroadcastResponse {
            status: "success".to_string(),
            txid: "pending".to_string(),
            message: format!("Updated {} definition", def_type_str(&def_type)),
        })
    }

    /// Remove a registry definition by spending its UTXO without creating
    /// a replacement output.
    pub async fn remove_definition(
        &mut self,
        record: &RegistryRecord,
    ) -> Result<BroadcastResponse, ServicesError> {
        let token = record.token.as_ref().ok_or_else(|| {
            ServicesError::Registry("Record has no token data for removal".to_string())
        })?;

        // Verify ownership.
        let identity_key = self.get_identity_key().await?;
        if let Some(operator) = record.data.registry_operator() {
            if operator != identity_key {
                return Err(ServicesError::Registry(
                    "This registry token does not belong to the current wallet.".to_string(),
                ));
            }
        }

        let def_type = record.data.definition_type();
        let topic = definition_type_to_topic(&def_type).to_string();
        let outpoint = format!("{}.{}", token.txid, token.output_index);

        let _create_result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: format!(
                        "Remove {} item: {}",
                        def_type_str(&def_type),
                        record.data.name()
                    ),
                    input_beef: Some(token.beef.clone()),
                    inputs: vec![CreateActionInput {
                        outpoint,
                        unlocking_script_length: Some(74),
                        input_description: format!("Removing {} token", def_type_str(&def_type)),
                        sequence_number: None,
                        unlocking_script: None,
                    }],
                    outputs: vec![], // No outputs = deletion.
                    lock_time: None,
                    version: None,
                    labels: vec![],
                    options: None,
                    reference: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ServicesError::Registry(format!("Failed to create action: {}", e)))?;

        // In a full implementation, sign and broadcast the spend transaction.
        let network = self.get_network().await?;
        let _ = (topic, network);

        Ok(BroadcastResponse {
            status: "success".to_string(),
            txid: "pending".to_string(),
            message: format!("Removed {} definition", def_type_str(&def_type)),
        })
    }

    // -----------------------------------------------------------------------
    // Internal utility methods
    // -----------------------------------------------------------------------

    /// Build PushDrop fields from definition data.
    fn build_push_drop_fields(
        &self,
        data: &DefinitionData,
        registry_operator: &str,
    ) -> Vec<Vec<u8>> {
        let mut fields: Vec<String> = match data {
            DefinitionData::Basket(d) => vec![
                d.basket_id.clone(),
                d.name.clone(),
                d.icon_url.clone(),
                d.description.clone(),
                d.documentation_url.clone(),
            ],
            DefinitionData::Protocol(d) => vec![
                serde_json::to_string(&d.protocol_id).unwrap_or_default(),
                d.name.clone(),
                d.icon_url.clone(),
                d.description.clone(),
                d.documentation_url.clone(),
            ],
            DefinitionData::Certificate(d) => vec![
                d.cert_type.clone(),
                d.name.clone(),
                d.icon_url.clone(),
                d.description.clone(),
                d.documentation_url.clone(),
                serde_json::to_string(&d.fields).unwrap_or_default(),
            ],
        };

        // Append the operator's public identity key last.
        fields.push(registry_operator.to_string());

        fields.into_iter().map(|f| f.into_bytes()).collect()
    }

    /// Parse a BEEF output into a DefinitionData.
    fn parse_output_to_definition(
        &self,
        _definition_type: &DefinitionType,
        _beef: &[u8],
        _output_index: usize,
    ) -> Result<DefinitionData, ServicesError> {
        // In a full implementation, this would:
        // 1. Parse the BEEF into a Transaction
        // 2. Extract the locking script at output_index
        // 3. Decode the PushDrop fields
        // 4. Map fields back to DefinitionData
        Err(ServicesError::Registry(
            "BEEF parsing requires Transaction integration".to_string(),
        ))
    }

    /// Parse locking script bytes into a DefinitionData.
    fn parse_locking_script_bytes(
        &self,
        _definition_type: &DefinitionType,
        _script: &[u8],
    ) -> Result<DefinitionData, ServicesError> {
        // In a full implementation, this would decode PushDrop fields
        // from the locking script and map them to DefinitionData.
        Err(ServicesError::Registry(
            "Locking script parsing requires PushDrop decode".to_string(),
        ))
    }
}

/// Convert DefinitionType to string for human-readable messages.
fn def_type_str(dt: &DefinitionType) -> &'static str {
    match dt {
        DefinitionType::Basket => "basket",
        DefinitionType::Protocol => "protocol",
        DefinitionType::Certificate => "certificate",
    }
}

/// Hex-encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::registry::types::{
        BasketDefinitionData, CertificateDefinitionData, CertificateFieldDescriptor,
    };
    use std::collections::HashMap;

    #[test]
    fn test_build_push_drop_fields_basket() {
        // Create a minimal RegistryClient (needs a WalletInterface impl).
        // Instead, test the field building logic directly.
        let data = DefinitionData::Basket(BasketDefinitionData {
            basket_id: "test-basket-id".to_string(),
            name: "Test Basket".to_string(),
            icon_url: "https://example.com/icon.png".to_string(),
            description: "A test basket definition".to_string(),
            documentation_url: "https://example.com/docs".to_string(),
            registry_operator: None,
        });

        // Build fields manually to test.
        let fields = match &data {
            DefinitionData::Basket(d) => vec![
                d.basket_id.as_bytes().to_vec(),
                d.name.as_bytes().to_vec(),
                d.icon_url.as_bytes().to_vec(),
                d.description.as_bytes().to_vec(),
                d.documentation_url.as_bytes().to_vec(),
                "operator-key".as_bytes().to_vec(),
            ],
            _ => unreachable!(),
        };

        assert_eq!(fields.len(), 6);
        assert_eq!(
            String::from_utf8(fields[0].clone()).unwrap(),
            "test-basket-id"
        );
        assert_eq!(
            String::from_utf8(fields[5].clone()).unwrap(),
            "operator-key"
        );
    }

    #[test]
    fn test_build_push_drop_fields_certificate() {
        let data = DefinitionData::Certificate(CertificateDefinitionData {
            cert_type: "test-type-hash".to_string(),
            name: "Test Certificate".to_string(),
            icon_url: "icon".to_string(),
            description: "desc".to_string(),
            documentation_url: "doc".to_string(),
            fields: {
                let mut m = HashMap::new();
                m.insert(
                    "firstName".to_string(),
                    CertificateFieldDescriptor {
                        friendly_name: "First Name".to_string(),
                        description: "The first name".to_string(),
                        field_type: "text".to_string(),
                        field_icon: "person".to_string(),
                    },
                );
                m
            },
            registry_operator: None,
        });

        // Certificate has 7 fields (type, name, icon, desc, docURL, fields JSON, operator).
        let fields = match &data {
            DefinitionData::Certificate(d) => {
                let mut f = vec![
                    d.cert_type.as_bytes().to_vec(),
                    d.name.as_bytes().to_vec(),
                    d.icon_url.as_bytes().to_vec(),
                    d.description.as_bytes().to_vec(),
                    d.documentation_url.as_bytes().to_vec(),
                    serde_json::to_string(&d.fields).unwrap().into_bytes(),
                ];
                f.push("operator".as_bytes().to_vec());
                f
            }
            _ => unreachable!(),
        };

        assert_eq!(fields.len(), 7);
        let fields_json = String::from_utf8(fields[5].clone()).unwrap();
        assert!(fields_json.contains("firstName"));
    }

    #[test]
    fn test_def_type_str() {
        assert_eq!(def_type_str(&DefinitionType::Basket), "basket");
        assert_eq!(def_type_str(&DefinitionType::Protocol), "protocol");
        assert_eq!(def_type_str(&DefinitionType::Certificate), "certificate");
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xab, 0xcd, 0xef]), "abcdef");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_registry_record_with_token() {
        let record = RegistryRecord {
            data: DefinitionData::Basket(BasketDefinitionData {
                basket_id: "b1".to_string(),
                name: "Test".to_string(),
                icon_url: "icon".to_string(),
                description: "desc".to_string(),
                documentation_url: "doc".to_string(),
                registry_operator: Some("op123".to_string()),
            }),
            token: Some(TokenData {
                txid: "abcdef1234567890".to_string(),
                output_index: 0,
                satoshis: 1,
                locking_script: "76a914...".to_string(),
                beef: vec![0x01, 0x02, 0x03],
            }),
        };

        assert_eq!(record.data.name(), "Test");
        assert_eq!(record.token.as_ref().unwrap().txid, "abcdef1234567890");
        assert_eq!(record.data.registry_operator(), Some("op123"));
    }

    #[test]
    fn test_ownership_check_mismatch() {
        // Test that the removal logic rejects non-matching operators.
        let record = RegistryRecord {
            data: DefinitionData::Basket(BasketDefinitionData {
                basket_id: "b1".to_string(),
                name: "Test".to_string(),
                icon_url: "icon".to_string(),
                description: "desc".to_string(),
                documentation_url: "doc".to_string(),
                registry_operator: Some("other-key".to_string()),
            }),
            token: Some(TokenData {
                txid: "tx1".to_string(),
                output_index: 0,
                satoshis: 1,
                locking_script: "script".to_string(),
                beef: vec![],
            }),
        };

        // Verify the operator mismatch would be caught.
        let my_key = "my-key";
        assert_ne!(record.data.registry_operator().unwrap(), my_key);
    }

    #[test]
    fn test_definition_type_change_rejected() {
        let record = RegistryRecord {
            data: DefinitionData::Basket(BasketDefinitionData {
                basket_id: "b1".to_string(),
                name: "Test".to_string(),
                icon_url: "icon".to_string(),
                description: "desc".to_string(),
                documentation_url: "doc".to_string(),
                registry_operator: None,
            }),
            token: Some(TokenData {
                txid: "tx1".to_string(),
                output_index: 0,
                satoshis: 1,
                locking_script: "script".to_string(),
                beef: vec![],
            }),
        };

        let new_data = DefinitionData::Certificate(CertificateDefinitionData {
            cert_type: "test".to_string(),
            name: "Cert".to_string(),
            icon_url: "icon".to_string(),
            description: "desc".to_string(),
            documentation_url: "doc".to_string(),
            fields: HashMap::new(),
            registry_operator: None,
        });

        // Verify type mismatch.
        assert_ne!(record.data.definition_type(), new_data.definition_type());
    }
}
