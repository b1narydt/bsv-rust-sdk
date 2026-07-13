//! Integration tests for WalletClient parameter validation,
//! ported from ts-sdk WalletClient.test.ts.
//!
//! Tests that validation functions correctly reject invalid arguments
//! for createAction and other wallet methods, returning
//! WalletError::InvalidParameter with the correct field name.
//!
//! Since WalletClient requires a WalletWire implementation and the
//! validation is done before wire transmission, we test the validation
//! functions directly (which is what WalletClient delegates to).

use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::{
    CreateActionArgs, CreateActionInput, CreateActionOptions, CreateActionOutput,
};
use bsv::wallet::validation::validate_create_action_args;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_options() -> Option<CreateActionOptions> {
    None
}

fn valid_args() -> CreateActionArgs {
    CreateActionArgs {
        description: "12345".to_string(), // minimum 5 chars
        input_beef: None,
        inputs: vec![],
        outputs: vec![],
        lock_time: None,
        version: None,
        labels: vec![],
        options: default_options(),
        reference: None,
    }
}

fn assert_invalid_parameter(result: Result<(), WalletError>, field_substring: &str) {
    match result {
        Err(WalletError::InvalidParameter(msg)) => {
            assert!(
                msg.contains(field_substring),
                "expected error message to contain '{field_substring}', got: {msg}"
            );
        }
        Err(other) => {
            panic!("expected InvalidParameter containing '{field_substring}', got: {other:?}")
        }
        Ok(()) => panic!("expected InvalidParameter containing '{field_substring}', got Ok"),
    }
}

// ---------------------------------------------------------------------------
// 1. createAction: description too short
// ---------------------------------------------------------------------------

#[test]
fn create_action_rejects_description_too_short() {
    let mut args = valid_args();
    args.description = "t".to_string(); // < 5 chars
    let result = validate_create_action_args(&args);
    assert_invalid_parameter(result, "description");
}

// ---------------------------------------------------------------------------
// 2. createAction: empty lockingScript in output
// ---------------------------------------------------------------------------

#[test]
fn create_action_rejects_empty_locking_script_with_empty_description() {
    let mut args = valid_args();
    args.outputs = vec![CreateActionOutput {
        locking_script: None, // empty/missing
        satoshis: 0,
        output_description: String::new(), // empty
        basket: None,
        custom_instructions: None,
        tags: vec![],
    }];
    let result = validate_create_action_args(&args);
    assert_invalid_parameter(result, "output");
}

// ---------------------------------------------------------------------------
// 3. createAction: valid args pass validation
// ---------------------------------------------------------------------------

#[test]
fn create_action_accepts_valid_args() {
    let args = valid_args();
    let result = validate_create_action_args(&args);
    assert!(result.is_ok(), "valid args should pass validation");
}

// ---------------------------------------------------------------------------
// 4. createAction: valid args with outputs pass validation
// ---------------------------------------------------------------------------

#[test]
fn create_action_accepts_valid_output_with_locking_script() {
    let mut args = valid_args();
    args.outputs = vec![CreateActionOutput {
        locking_script: Some(vec![0x12, 0x34]),
        satoshis: 100,
        output_description: "test output".to_string(),
        basket: None,
        custom_instructions: None,
        tags: vec![],
    }];
    let result = validate_create_action_args(&args);
    assert!(
        result.is_ok(),
        "output with locking_script and description should be valid"
    );
}

// ---------------------------------------------------------------------------
// 5. createAction: output with locking_script but empty outputDescription
// ---------------------------------------------------------------------------

#[test]
fn create_action_accepts_output_with_locking_script_and_empty_description() {
    let mut args = valid_args();
    args.outputs = vec![CreateActionOutput {
        locking_script: Some(vec![0x12, 0x34]),
        satoshis: 0,
        output_description: String::new(), // empty but locking_script is present
        basket: None,
        custom_instructions: None,
        tags: vec![],
    }];
    // The validation checks: locking_script.is_none() AND output_description.is_empty()
    // Since locking_script is Some, this should pass
    let result = validate_create_action_args(&args);
    assert!(
        result.is_ok(),
        "output with locking_script should be valid even with empty description"
    );
}

// ---------------------------------------------------------------------------
// 6. createAction: input without unlocking_script or length
// ---------------------------------------------------------------------------

#[test]
fn create_action_rejects_input_without_unlocking_script_or_length() {
    let mut args = valid_args();
    args.inputs = vec![CreateActionInput {
        outpoint: "abc123.0".to_string(),
        input_description: "test input".to_string(),
        unlocking_script: None,
        unlocking_script_length: None,
        sequence_number: None,
    }];
    let result = validate_create_action_args(&args);
    assert_invalid_parameter(result, "input");
}

// ---------------------------------------------------------------------------
// 7. createAction: label too long
// ---------------------------------------------------------------------------

#[test]
fn create_action_rejects_label_too_long() {
    let mut args = valid_args();
    args.labels = vec!["x".repeat(301)];
    let result = validate_create_action_args(&args);
    assert_invalid_parameter(result, "label");
}

// ---------------------------------------------------------------------------
// 8. createAction: description too long (> 2000)
// ---------------------------------------------------------------------------

#[test]
fn create_action_rejects_description_too_long() {
    let mut args = valid_args();
    args.description = "x".repeat(2001);
    let result = validate_create_action_args(&args);
    assert_invalid_parameter(result, "description");
}
