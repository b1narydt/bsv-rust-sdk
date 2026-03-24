//! Wire-format roundtrip tests for remittance protocol structs.
//!
//! Verifies that all structs serialize to JSON matching the TypeScript SDK wire format:
//! camelCase field names, absent (not null) optional fields, correct type mappings.

use std::collections::HashMap;

use serde_json::json;

use bsv::remittance::types::{
    sat_unit, Amount, RemittanceCertificate, IdentityRequest, IdentityVerificationAcknowledgment,
    IdentityVerificationRequest, IdentityVerificationResponse, InstrumentBase, Invoice, LineItem,
    PeerMessage, Receipt, RemittanceEnvelope, RemittanceKind, Settlement, Termination, Unit,
};

// ---------------------------------------------------------------------------
// Unit
// ---------------------------------------------------------------------------

#[test]
fn test_unit_roundtrip() {
    let unit = Unit {
        namespace: "bsv".into(),
        code: "sat".into(),
        decimals: Some(0),
    };
    let json_str = serde_json::to_string(&unit).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(val["namespace"], "bsv");
    assert_eq!(val["code"], "sat");
    assert_eq!(val["decimals"], 0);
    let roundtripped: Unit = serde_json::from_str(&json_str).unwrap();
    assert_eq!(roundtripped, unit);
}

#[test]
fn test_unit_optional_decimals_omitted() {
    let unit = Unit {
        namespace: "usd".into(),
        code: "cents".into(),
        decimals: None,
    };
    let json_str = serde_json::to_string(&unit).unwrap();
    assert!(
        !json_str.contains("decimals"),
        "decimals should be absent when None"
    );
}

// ---------------------------------------------------------------------------
// Amount
// ---------------------------------------------------------------------------

#[test]
fn test_amount_value_is_string() {
    let amount = Amount {
        value: "1000".into(),
        unit: Unit {
            namespace: "bsv".into(),
            code: "sat".into(),
            decimals: None,
        },
    };
    let json_str = serde_json::to_string(&amount).unwrap();
    assert!(
        json_str.contains(r#""value":"1000""#),
        "value should be a JSON string: {}",
        json_str
    );
}

// ---------------------------------------------------------------------------
// sat_unit
// ---------------------------------------------------------------------------

#[test]
fn test_sat_unit_values() {
    let u = sat_unit();
    assert_eq!(u.namespace, "bsv");
    assert_eq!(u.code, "sat");
    assert_eq!(u.decimals, Some(0));
}

// ---------------------------------------------------------------------------
// LineItem
// ---------------------------------------------------------------------------

#[test]
fn test_line_item_optional_fields_omitted() {
    let item = LineItem {
        id: None,
        description: "Widget".into(),
        quantity: None,
        unit_price: None,
        amount: None,
        metadata: None,
    };
    let val: serde_json::Value = serde_json::to_value(&item).unwrap();
    let obj = val.as_object().unwrap();
    assert_eq!(
        obj.len(),
        1,
        "Only 'description' should be present: {:?}",
        obj
    );
    assert_eq!(obj["description"], "Widget");
}

#[test]
fn test_line_item_full_roundtrip() {
    let item = LineItem {
        id: Some("item-1".into()),
        description: "Widget".into(),
        quantity: Some("3".into()),
        unit_price: Some(Amount {
            value: "100".into(),
            unit: sat_unit(),
        }),
        amount: Some(Amount {
            value: "300".into(),
            unit: sat_unit(),
        }),
        metadata: Some({
            let mut m = HashMap::new();
            m.insert("color".into(), json!("red"));
            m
        }),
    };
    let json_str = serde_json::to_string(&item).unwrap();
    let roundtripped: LineItem = serde_json::from_str(&json_str).unwrap();
    assert_eq!(roundtripped, item);
}

// ---------------------------------------------------------------------------
// Invoice (with InstrumentBase flatten)
// ---------------------------------------------------------------------------

#[test]
fn test_invoice_flattens_base() {
    let invoice = Invoice {
        kind: RemittanceKind::Invoice,
        expires_at: None,
        options: HashMap::new(),
        base: InstrumentBase {
            thread_id: "t1".into(),
            payee: "alice".into(),
            payer: "bob".into(),
            note: None,
            line_items: vec![],
            total: Amount {
                value: "1000".into(),
                unit: sat_unit(),
            },
            invoice_number: "INV-001".into(),
            created_at: 1700000000,
            arbitrary: None,
        },
    };
    let val: serde_json::Value = serde_json::to_value(&invoice).unwrap();
    // InstrumentBase fields at top level (not nested under "base")
    assert_eq!(val["threadId"], "t1");
    assert_eq!(val["payee"], "alice");
    assert_eq!(val["lineItems"], json!([]));
    assert_eq!(val["kind"], "invoice");
    assert!(
        val.get("base").is_none(),
        "base should not appear as a nested key"
    );
    // Optional fields absent
    assert!(val.get("expiresAt").is_none());
    assert!(val.get("note").is_none());
    assert!(val.get("arbitrary").is_none());
}

#[test]
fn test_invoice_options_map() {
    let mut options = HashMap::new();
    options.insert(
        "optionId1".into(),
        json!({"module": "bsv-direct", "fee": 50}),
    );
    let invoice = Invoice {
        kind: RemittanceKind::Invoice,
        expires_at: Some(1700001000),
        options,
        base: InstrumentBase {
            thread_id: "t2".into(),
            payee: "alice".into(),
            payer: "bob".into(),
            note: None,
            line_items: vec![],
            total: Amount {
                value: "500".into(),
                unit: sat_unit(),
            },
            invoice_number: "INV-002".into(),
            created_at: 1700000000,
            arbitrary: None,
        },
    };
    let val: serde_json::Value = serde_json::to_value(&invoice).unwrap();
    assert_eq!(val["options"]["optionId1"]["module"], "bsv-direct");
}

// ---------------------------------------------------------------------------
// Identity types
// ---------------------------------------------------------------------------

#[test]
fn test_identity_request_nested() {
    let req = IdentityVerificationRequest {
        kind: RemittanceKind::IdentityVerificationRequest,
        thread_id: "t3".into(),
        request: IdentityRequest {
            types: {
                let mut m = HashMap::new();
                m.insert("kyc".into(), vec!["name".into(), "email".into()]);
                m
            },
            certifiers: vec!["certifier1".into()],
        },
    };
    let val: serde_json::Value = serde_json::to_value(&req).unwrap();
    assert_eq!(val["kind"], "identityVerificationRequest");
    assert!(val["request"]["types"]["kyc"].is_array());
    assert!(val["request"]["certifiers"].is_array());
}

#[test]
fn test_identity_certificate_type_field() {
    let cert = RemittanceCertificate {
        cert_type: "someType".into(),
        certifier: "cert1".into(),
        subject: "sub1".into(),
        fields: HashMap::new(),
        signature: "sig".into(),
        serial_number: "sn1".into(),
        revocation_outpoint: "out1".into(),
        keyring_for_verifier: HashMap::new(),
    };
    let val: serde_json::Value = serde_json::to_value(&cert).unwrap();
    assert_eq!(
        val["type"], "someType",
        "cert_type should serialize as 'type'"
    );
    assert!(
        val.get("certType").is_none(),
        "certType should not appear"
    );
}

#[test]
fn test_identity_response_roundtrip() {
    let resp = IdentityVerificationResponse {
        kind: RemittanceKind::IdentityVerificationResponse,
        thread_id: "t4".into(),
        certificates: vec![RemittanceCertificate {
            cert_type: "kyc".into(),
            certifier: "c1".into(),
            subject: "s1".into(),
            fields: {
                let mut m = HashMap::new();
                m.insert("name".into(), "Alice".into());
                m
            },
            signature: "sig1".into(),
            serial_number: "sn1".into(),
            revocation_outpoint: "op1".into(),
            keyring_for_verifier: HashMap::new(),
        }],
    };
    let json_str = serde_json::to_string(&resp).unwrap();
    let roundtripped: IdentityVerificationResponse = serde_json::from_str(&json_str).unwrap();
    assert_eq!(
        roundtripped.kind,
        RemittanceKind::IdentityVerificationResponse
    );
    assert_eq!(roundtripped.certificates.len(), 1);
    assert_eq!(roundtripped.certificates[0].cert_type, "kyc");
}

#[test]
fn test_identity_ack_minimal() {
    let ack = IdentityVerificationAcknowledgment {
        kind: RemittanceKind::IdentityVerificationAcknowledgment,
        thread_id: "t5".into(),
    };
    let val: serde_json::Value = serde_json::to_value(&ack).unwrap();
    let obj = val.as_object().unwrap();
    assert_eq!(obj.len(), 2, "Only 'kind' and 'threadId' should be present");
    assert_eq!(val["kind"], "identityVerificationAcknowledgment");
    assert_eq!(val["threadId"], "t5");
}

// ---------------------------------------------------------------------------
// Settlement
// ---------------------------------------------------------------------------

#[test]
fn test_settlement_artifact_arbitrary() {
    let settlement = Settlement {
        kind: RemittanceKind::Settlement,
        thread_id: "t6".into(),
        module_id: "mod1".into(),
        option_id: "opt1".into(),
        sender: "alice".into(),
        created_at: 1700000000,
        artifact: json!({"tx": "beef1234", "proof": [1, 2, 3]}),
        note: None,
    };
    let json_str = serde_json::to_string(&settlement).unwrap();
    let roundtripped: Settlement = serde_json::from_str(&json_str).unwrap();
    assert_eq!(roundtripped.artifact["tx"], "beef1234");
    assert_eq!(roundtripped.artifact["proof"], json!([1, 2, 3]));
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_receipt_data_camel_case() {
    let receipt = Receipt {
        kind: RemittanceKind::Receipt,
        thread_id: "t7".into(),
        module_id: "mod1".into(),
        option_id: "opt1".into(),
        payee: "alice".into(),
        payer: "bob".into(),
        created_at: 1700000000,
        receipt_data: json!({"confirmed": true}),
    };
    let json_str = serde_json::to_string(&receipt).unwrap();
    assert!(
        json_str.contains("receiptData"),
        "receipt_data should serialize as receiptData"
    );
    assert!(
        !json_str.contains("receipt_data"),
        "should not contain snake_case"
    );
}

// ---------------------------------------------------------------------------
// Termination
// ---------------------------------------------------------------------------

#[test]
fn test_termination_details_omitted() {
    let term = Termination {
        code: "user_cancel".into(),
        message: "User cancelled".into(),
        details: None,
    };
    let json_str = serde_json::to_string(&term).unwrap();
    assert!(
        !json_str.contains("details"),
        "details should be absent when None"
    );
    let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let obj = val.as_object().unwrap();
    assert_eq!(obj.len(), 2);
}

#[test]
fn test_termination_with_details() {
    let term = Termination {
        code: "error".into(),
        message: "Something went wrong".into(),
        details: Some(json!({"extra": true})),
    };
    let val: serde_json::Value = serde_json::to_value(&term).unwrap();
    assert_eq!(val["details"]["extra"], true);
}

// ---------------------------------------------------------------------------
// PeerMessage
// ---------------------------------------------------------------------------

#[test]
fn test_peer_message_camel_case() {
    let msg = PeerMessage {
        message_id: "msg1".into(),
        sender: "alice".into(),
        recipient: "bob".into(),
        message_box: "remittance_inbox".into(),
        body: "hello".into(),
    };
    let json_str = serde_json::to_string(&msg).unwrap();
    assert!(
        json_str.contains("messageId"),
        "message_id should be messageId"
    );
    assert!(
        json_str.contains("messageBox"),
        "message_box should be messageBox"
    );
}

// ---------------------------------------------------------------------------
// RemittanceEnvelope
// ---------------------------------------------------------------------------

#[test]
fn test_envelope_v_is_integer() {
    let env = RemittanceEnvelope {
        v: 1,
        id: "env1".into(),
        kind: RemittanceKind::Invoice,
        thread_id: "t8".into(),
        created_at: 1700000000,
        payload: json!({}),
    };
    let json_str = serde_json::to_string(&env).unwrap();
    assert!(
        json_str.contains(r#""v":1"#),
        "v should be integer 1: {}",
        json_str
    );
}

#[test]
fn test_envelope_payload_arbitrary() {
    let env = RemittanceEnvelope {
        v: 1,
        id: "env2".into(),
        kind: RemittanceKind::Settlement,
        thread_id: "t9".into(),
        created_at: 1700000000,
        payload: json!({"nested": [1, 2, 3], "flag": true}),
    };
    let json_str = serde_json::to_string(&env).unwrap();
    let roundtripped: RemittanceEnvelope = serde_json::from_str(&json_str).unwrap();
    assert_eq!(roundtripped.payload["nested"], json!([1, 2, 3]));
    assert_eq!(roundtripped.payload["flag"], true);
}

// ---------------------------------------------------------------------------
// Cross-cutting: Optional fields never produce null
// ---------------------------------------------------------------------------

#[test]
fn test_optional_fields_never_null() {
    // Unit with None decimals
    let unit_json = serde_json::to_string(&Unit {
        namespace: "x".into(),
        code: "y".into(),
        decimals: None,
    })
    .unwrap();
    assert!(!unit_json.contains(":null"), "Unit: {}", unit_json);

    // LineItem with all None optional fields
    let li_json = serde_json::to_string(&LineItem {
        id: None,
        description: "d".into(),
        quantity: None,
        unit_price: None,
        amount: None,
        metadata: None,
    })
    .unwrap();
    assert!(!li_json.contains(":null"), "LineItem: {}", li_json);

    // InstrumentBase with None optional fields
    let ib_json = serde_json::to_string(&InstrumentBase {
        thread_id: "t".into(),
        payee: "a".into(),
        payer: "b".into(),
        note: None,
        line_items: vec![],
        total: Amount {
            value: "0".into(),
            unit: sat_unit(),
        },
        invoice_number: "i".into(),
        created_at: 0,
        arbitrary: None,
    })
    .unwrap();
    assert!(
        !ib_json.contains(":null"),
        "InstrumentBase: {}",
        ib_json
    );

    // Settlement with None note
    let s_json = serde_json::to_string(&Settlement {
        kind: RemittanceKind::Settlement,
        thread_id: "t".into(),
        module_id: "m".into(),
        option_id: "o".into(),
        sender: "s".into(),
        created_at: 0,
        artifact: json!({}),
        note: None,
    })
    .unwrap();
    assert!(!s_json.contains(":null"), "Settlement: {}", s_json);

    // Termination with None details
    let t_json = serde_json::to_string(&Termination {
        code: "c".into(),
        message: "m".into(),
        details: None,
    })
    .unwrap();
    assert!(!t_json.contains(":null"), "Termination: {}", t_json);

    // Invoice with None expires_at
    let inv_json = serde_json::to_string(&Invoice {
        kind: RemittanceKind::Invoice,
        expires_at: None,
        options: HashMap::new(),
        base: InstrumentBase {
            thread_id: "t".into(),
            payee: "a".into(),
            payer: "b".into(),
            note: None,
            line_items: vec![],
            total: Amount {
                value: "0".into(),
                unit: sat_unit(),
            },
            invoice_number: "i".into(),
            created_at: 0,
            arbitrary: None,
        },
    })
    .unwrap();
    assert!(!inv_json.contains(":null"), "Invoice: {}", inv_json);
}
