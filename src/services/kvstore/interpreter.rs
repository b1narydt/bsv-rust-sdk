//! KVStore interpreter for Historian.
//!
//! Translates the TS SDK kvStoreInterpreter.ts. Provides the interpreter
//! callback used by Historian to extract key-value data from PushDrop
//! transaction outputs.

use crate::transaction::Transaction;

use super::types::{KvContext, KvProtocol};

/// KVStore interpreter function for use with Historian.
///
/// Decodes PushDrop outputs from a transaction and extracts the value
/// for a matching key. Returns None if the output is not a valid KVStore
/// token or does not match the target key in the context.
///
/// This function matches the `InterpreterFn<String, KvContext>` signature
/// expected by Historian.
pub fn kv_store_interpreter(
    tx: &Transaction,
    output_index: usize,
    ctx: Option<&KvContext>,
) -> Option<String> {
    let ctx = ctx?;

    if output_index >= tx.outputs.len() {
        return None;
    }

    let output = &tx.outputs[output_index];

    // Decode the KVStore PushDrop token via the SDK decoder — matches the TS
    // `kvStoreInterpreter`, which calls `PushDrop.decode`. This correctly handles
    // the "before" lock layout `<pubkey> OP_CHECKSIG <fields...> OP_DROP…`: the
    // previous hand-rolled "collect data pushes before the first opcode" grabbed
    // the leading pubkey, immediately hit OP_CHECKSIG, and bailed with one field.
    // `decode` returns the data fields, including the trailing signature field.
    let decoded = crate::script::templates::push_drop::decode(&output.locking_script).ok()?;
    let fields = &decoded.fields;

    // Support both old format (5 fields: [protocolID, key, value, controller,
    // signature]) and new format with tags (6 fields: [..., tags, signature]).
    let has_tags = fields.len() == KvProtocol::FIELD_COUNT;
    let is_old_format = fields.len() == KvProtocol::OLD_FIELD_COUNT;

    if !has_tags && !is_old_format {
        return None;
    }

    // Extract key from the PushDrop field.
    let key = String::from_utf8(fields.get(KvProtocol::KEY)?.clone()).ok()?;
    if key != ctx.key {
        return None;
    }

    // Extract and verify protocolID.
    let protocol_str = String::from_utf8(fields.get(KvProtocol::PROTOCOL_ID)?.clone()).ok()?;
    let expected_protocol = format!("[{},\"{}\"]", ctx.protocol_id.0, ctx.protocol_id.1);
    if protocol_str != expected_protocol {
        return None;
    }

    // Extract value.
    String::from_utf8(fields.get(KvProtocol::VALUE)?.clone()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::private_key::PrivateKey;
    use crate::script::templates::push_drop::{LockPosition, PushDrop};
    use crate::transaction::{Transaction, TransactionOutput};
    use crate::wallet::proto_wallet::ProtoWallet;
    use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

    async fn make_kv_tx(key: &str, value: &str, protocol_id: &str) -> Transaction {
        let pk = PrivateKey::from_hex("1").unwrap();
        let w = ProtoWallet::new(pk.clone());
        let fields = vec![
            protocol_id.as_bytes().to_vec(),
            key.as_bytes().to_vec(),
            value.as_bytes().to_vec(),
            pk.to_public_key().to_der(), // controller
            b"[]".to_vec(),              // tags (empty)
        ];
        let lock_script = PushDrop::new(&w, None)
            .lock(
                fields,
                Protocol {
                    security_level: 2,
                    protocol: "kvstore".to_string(),
                },
                key,
                Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                false,
                true,
                LockPosition::Before,
            )
            .await
            .unwrap();

        let mut tx = Transaction::new();
        tx.outputs.push(TransactionOutput {
            satoshis: Some(1),
            locking_script: lock_script,
            change: false,
        });
        tx
    }

    #[tokio::test]
    async fn test_interpreter_extracts_matching_key() {
        let tx = make_kv_tx("mykey", "myvalue", "[1,\"kvstore\"]").await;
        let ctx = KvContext {
            key: "mykey".to_string(),
            protocol_id: (1, "kvstore".to_string()),
        };

        let result = kv_store_interpreter(&tx, 0, Some(&ctx));
        assert_eq!(result, Some("myvalue".to_string()));
    }

    #[tokio::test]
    async fn test_interpreter_returns_none_for_wrong_key() {
        let tx = make_kv_tx("mykey", "myvalue", "[1,\"kvstore\"]").await;
        let ctx = KvContext {
            key: "otherkey".to_string(),
            protocol_id: (1, "kvstore".to_string()),
        };

        let result = kv_store_interpreter(&tx, 0, Some(&ctx));
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_interpreter_returns_none_for_wrong_protocol() {
        let tx = make_kv_tx("mykey", "myvalue", "[2,\"other\"]").await;
        let ctx = KvContext {
            key: "mykey".to_string(),
            protocol_id: (1, "kvstore".to_string()),
        };

        let result = kv_store_interpreter(&tx, 0, Some(&ctx));
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_interpreter_returns_none_no_context() {
        let tx = make_kv_tx("mykey", "myvalue", "[1,\"kvstore\"]").await;
        let result = kv_store_interpreter(&tx, 0, None);
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_interpreter_returns_none_empty_tx() {
        let tx = Transaction::new();
        let ctx = KvContext {
            key: "mykey".to_string(),
            protocol_id: (1, "kvstore".to_string()),
        };
        let result = kv_store_interpreter(&tx, 0, Some(&ctx));
        assert_eq!(result, None);
    }
}
