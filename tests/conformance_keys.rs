//! Official BSV SDK key conformance corpus.
//!
//! Assertion sites mirror `runner/ts/dispatchers/sdk.ts` at the upstream SHA
//! pinned in `conformance/SOURCE`. In particular, TypeScript-only constructor
//! shapes remain dispatcher no-ops instead of becoming stronger Rust checks.

mod conformance_harness;

use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use conformance_harness::{
    bool_value, ensure, hex_string, run_corpora, string, Corpus, KnownDivergence, Vector,
};

const KEY_DERIVATION: &str = include_str!("../conformance/vectors/sdk/keys/key-derivation.json");
const PRIVATE_KEY: &str = include_str!("../conformance/vectors/sdk/keys/private-key.json");
const PUBLIC_KEY: &str = include_str!("../conformance/vectors/sdk/keys/public-key.json");

const CORPORA: &[Corpus<'_>] = &[
    Corpus {
        category: "key-derivation",
        json: KEY_DERIVATION,
        expected_count: 33,
    },
    Corpus {
        category: "private-key",
        json: PRIVATE_KEY,
        expected_count: 11,
    },
    Corpus {
        category: "public-key",
        json: PUBLIC_KEY,
        expected_count: 15,
    },
];

const KNOWN_DIVERGENCES: &[KnownDivergence<'_>] = &[];

fn parse_private(hex: &str) -> Result<PrivateKey, String> {
    PrivateKey::from_hex(hex).map_err(|error| error.to_string())
}

fn parse_public(hex: &str) -> Result<PublicKey, String> {
    PublicKey::from_string(hex).map_err(|error| error.to_string())
}

fn assert_private_fields(
    key: &PrivateKey,
    expected: &serde_json::Value,
    roundtrip_field: &str,
) -> Result<(), String> {
    let roundtrip = string(expected, roundtrip_field);
    if !roundtrip.is_empty() {
        ensure(key.to_hex() == roundtrip, || {
            format!(
                "expected {roundtrip_field} {roundtrip}, got {}",
                key.to_hex()
            )
        })?;
    }
    let public = string(expected, "pubkey_hex");
    if !public.is_empty() {
        let got = key.to_public_key().to_der_hex();
        ensure(got == public, || {
            format!("expected pubkey_hex {public}, got {got}")
        })?;
    }
    Ok(())
}

fn dispatch_key_derivation(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;

    let private_hex = string(input, "privkey_hex");
    if !private_hex.is_empty() {
        let key = parse_private(private_hex)?;
        let roundtrip = string(expected, "privkey_hex_roundtrip");
        if !roundtrip.is_empty() {
            // Mirrors sdk.ts:333-353: only the requested round-trip is asserted.
            return ensure(key.to_hex() == roundtrip, || {
                format!(
                    "expected private-key round-trip {roundtrip}, got {}",
                    key.to_hex()
                )
            });
        }
        let prefix = string(expected, "pubkey_der_prefix");
        if !prefix.is_empty() {
            // Mirrors sdk.ts:342-351; pubkey_der_hex_length_chars is deliberately
            // not asserted because the official dispatcher does not assert it.
            let der = key.to_public_key().to_der();
            if expected.get("pubkey_der_length_bytes").is_some() {
                let want = expected["pubkey_der_length_bytes"].as_u64().unwrap() as usize;
                ensure(der.len() == want, || {
                    format!("expected DER length {want}, got {}", der.len())
                })?;
            }
            let got = hex_string(&der[..1]);
            let accepted = prefix.split(" or ").map(str::trim).any(|item| item == got);
            return ensure(accepted, || {
                format!("expected DER prefix in {prefix:?}, got {got}")
            });
        }
    }

    let recipient_private = string(input, "recipient_private_key_hex");
    if !recipient_private.is_empty() {
        // Mirrors sdk.ts:377-385.
        let sender = parse_public(string(input, "sender_public_key_hex"))?;
        let derived = parse_private(recipient_private)?
            .derive_child(&sender, string(input, "invoice_number"))
            .map_err(|error| error.to_string())?;
        let want = string(expected, "derived_private_key_hex");
        return ensure(derived.to_hex() == want, || {
            format!(
                "expected derived private key {want}, got {}",
                derived.to_hex()
            )
        });
    }

    let sender_private = string(input, "sender_private_key_hex");
    if !sender_private.is_empty() {
        // Mirrors sdk.ts:387-396.
        let recipient = parse_public(string(input, "recipient_public_key_hex"))?;
        let derived = recipient
            .derive_child(
                &parse_private(sender_private)?,
                string(input, "invoice_number"),
            )
            .map_err(|error| error.to_string())?;
        let got = derived.to_der_hex();
        let want = string(expected, "derived_public_key_hex");
        return ensure(got == want, || {
            format!("expected derived public key {want}, got {got}")
        });
    }

    if input.get("pubkey_x").is_some() && bool_value(expected, "throws") {
        // Mirrors sdk.ts:356-365 and 399-402. This vector uses the small
        // coordinates (10, 13), so the TS Math.round conversion is exact.
        let x = input["pubkey_x"].as_u64().unwrap();
        let y = input["pubkey_y"].as_u64().unwrap();
        let encoded = format!("04{x:064x}{y:064x}");
        return ensure(PublicKey::from_string(&encoded).is_err(), || {
            "off-curve public key unexpectedly parsed".to_string()
        });
    }

    // Mirrors sdk.ts:405-406: direct_constructor is TS-specific and a no-op.
    Ok(())
}

fn dispatch_private_key(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    let wif = string(input, "wif");
    if !wif.is_empty() {
        // Mirrors sdk.ts:441-448.
        let key = PrivateKey::from_wif(wif).map_err(|error| error.to_string())?;
        return assert_private_fields(&key, expected, "privkey_hex");
    }
    let private_hex = string(input, "privkey_hex");
    if !private_hex.is_empty() {
        // Mirrors sdk.ts:451-458.
        let key = parse_private(private_hex)?;
        return assert_private_fields(&key, expected, "privkey_hex_roundtrip");
    }
    // Mirrors sdk.ts:461-464 by delegating the BRC-42 shape.
    if !string(input, "recipient_private_key_hex").is_empty() {
        return dispatch_key_derivation(vector);
    }
    Ok(())
}

fn dispatch_public_key(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    let private_hex = string(input, "privkey_hex");
    if !private_hex.is_empty() {
        // Mirrors sdk.ts:469-473 and 487-491: length metadata is not asserted.
        let want = string(expected, "pubkey_der_hex");
        if want.is_empty() {
            return Ok(());
        }
        let got = parse_private(private_hex)?.to_public_key().to_der_hex();
        return ensure(got == want, || {
            format!("expected public key {want}, got {got}")
        });
    }
    let public_hex = string(input, "pubkey_der_hex");
    if !public_hex.is_empty() {
        // Mirrors sdk.ts:476-480 and 494-499.
        let want = string(expected, "pubkey_der_hex_roundtrip");
        if want.is_empty() {
            return Ok(());
        }
        let got = parse_public(public_hex)?.to_der_hex();
        return ensure(got == want, || {
            format!("expected public-key round-trip {want}, got {got}")
        });
    }
    if !string(input, "sender_private_key_hex").is_empty() || input.get("pubkey_x").is_some() {
        // Mirrors sdk.ts:501-504.
        return dispatch_key_derivation(vector);
    }
    // Mirrors sdk.ts:507-508: constructor_arg is TS-specific and a no-op.
    Ok(())
}

fn dispatch(category: &str, vector: &Vector) -> Result<(), String> {
    match category {
        "key-derivation" => dispatch_key_derivation(vector),
        "private-key" => dispatch_private_key(vector),
        "public-key" => dispatch_public_key(vector),
        _ => Err(format!("unknown key category {category}")),
    }
}

#[test]
fn official_key_conformance() {
    run_corpora(CORPORA, &[], KNOWN_DIVERGENCES, dispatch);
}
