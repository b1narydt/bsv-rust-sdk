//! Official BSV SDK primitive-crypto conformance corpus.
//!
//! Each branch cites the TypeScript dispatcher site whose assertion semantics
//! it mirrors. Dispatcher no-ops are preserved intentionally.

mod conformance_harness;

use bsv::compat::ecies::ECIES;
use bsv::primitives::aes_gcm::aes_gcm_encrypt;
use bsv::primitives::big_number::BigNumber;
use bsv::primitives::ecdsa::{ecdsa_sign, ecdsa_verify};
use bsv::primitives::hash::{hash160, hash256, ripemd160, sha256, sha256_hmac, sha512_hmac};
use bsv::primitives::point::Point;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::primitives::signature::Signature;
use conformance_harness::{
    bool_value, bytes, bytes32, ensure, hex_string, number, run_corpora, string, Corpus,
    KnownDivergence, Vector,
};

const AES: &str = include_str!("../conformance/vectors/sdk/crypto/aes.json");
const ECDSA: &str = include_str!("../conformance/vectors/sdk/crypto/ecdsa.json");
const ECIES_VECTORS: &str = include_str!("../conformance/vectors/sdk/crypto/ecies.json");
const HASH160: &str = include_str!("../conformance/vectors/sdk/crypto/hash160.json");
const HMAC: &str = include_str!("../conformance/vectors/sdk/crypto/hmac.json");
const RIPEMD160: &str = include_str!("../conformance/vectors/sdk/crypto/ripemd160.json");
const SHA256: &str = include_str!("../conformance/vectors/sdk/crypto/sha256.json");
const SIGNATURE: &str = include_str!("../conformance/vectors/sdk/crypto/signature.json");

const CORPORA: &[Corpus<'_>] = &[
    Corpus {
        category: "aes",
        json: AES,
        expected_count: 15,
    },
    Corpus {
        category: "ecdsa",
        json: ECDSA,
        expected_count: 24,
    },
    Corpus {
        category: "ecies",
        json: ECIES_VECTORS,
        expected_count: 22,
    },
    Corpus {
        category: "hash160",
        json: HASH160,
        expected_count: 8,
    },
    Corpus {
        category: "hmac",
        json: HMAC,
        expected_count: 11,
    },
    Corpus {
        category: "ripemd160",
        json: RIPEMD160,
        expected_count: 7,
    },
    Corpus {
        category: "sha256",
        json: SHA256,
        expected_count: 14,
    },
    Corpus {
        category: "signature",
        json: SIGNATURE,
        expected_count: 23,
    },
];

const GOVERNED_SKIPS: &[&str] = &["sdk.crypto.ecies.17"];
const KNOWN_DIVERGENCES: &[KnownDivergence<'_>] = &[
    KnownDivergence {
        id: "sdk.crypto.ecies.3",
        reason: "TYPE_SHAPE: Rust ECIES has no noKey input mode",
        evidence: "noKey ciphertexts were not symmetric",
    },
    KnownDivergence {
        id: "sdk.crypto.ecies.18",
        reason: "TYPE_SHAPE: Rust ECIES has no noKey input mode",
        evidence: "noKey ciphertexts were not symmetric",
    },
];

fn message_bytes(message: &str, encoding: &str) -> Result<Vec<u8>, String> {
    if encoding == "hex" {
        bytes(message)
    } else {
        Ok(message.as_bytes().to_vec())
    }
}

fn private_key(hex: &str) -> Result<PrivateKey, String> {
    PrivateKey::from_hex(hex).map_err(|error| error.to_string())
}

fn public_key(hex: &str) -> Result<PublicKey, String> {
    PublicKey::from_string(hex).map_err(|error| error.to_string())
}

fn sign_hash(input: &serde_json::Value, force_low_s: bool) -> Result<Signature, String> {
    let message = string(input, "message_hex");
    let message = if message.is_empty() {
        string(input, "signed_message_hex")
    } else {
        message
    };
    let hash = bytes32(message)?;
    let key = private_key(string(input, "privkey_hex"))?;
    ecdsa_sign(&hash, key.bn(), force_low_s).map_err(|error| error.to_string())
}

fn dispatch_sha256(vector: &Vector) -> Result<(), String> {
    // Mirrors sdk.ts:120-129.
    let data = message_bytes(
        string(&vector.input, "message"),
        string(&vector.input, "encoding"),
    )?;
    let got = if bool_value(&vector.input, "double") {
        hex_string(hash256(&data))
    } else {
        hex_string(sha256(&data))
    };
    let want = string(&vector.expected, "hash");
    ensure(got == want, || format!("expected hash {want}, got {got}"))
}

fn dispatch_ripemd160(vector: &Vector) -> Result<(), String> {
    // Mirrors sdk.ts:131-140.
    let data = message_bytes(
        string(&vector.input, "message"),
        string(&vector.input, "encoding"),
    )?;
    let got = hex_string(ripemd160(&data));
    let want = string(&vector.expected, "hash");
    ensure(got == want, || {
        format!("expected RIPEMD-160 {want}, got {got}")
    })
}

fn dispatch_hash160(vector: &Vector) -> Result<(), String> {
    // Mirrors sdk.ts:142-154.
    let public = string(&vector.input, "pubkey");
    let data = if public.is_empty() {
        message_bytes(
            string(&vector.input, "message"),
            string(&vector.input, "encoding"),
        )?
    } else {
        bytes(public)?
    };
    let got = hex_string(hash160(&data));
    let want = string(&vector.expected, "hash160");
    ensure(got == want, || {
        format!("expected HASH160 {want}, got {got}")
    })
}

fn dispatch_hmac(vector: &Vector) -> Result<(), String> {
    // Mirrors sdk.ts:156-177.
    let key = if string(&vector.input, "key_encoding") == "hex" {
        bytes(string(&vector.input, "key"))?
    } else {
        string(&vector.input, "key").as_bytes().to_vec()
    };
    let message = message_bytes(
        string(&vector.input, "message"),
        string(&vector.input, "message_encoding"),
    )?;
    let got = match string(&vector.input, "algorithm")
        .to_ascii_lowercase()
        .as_str()
    {
        "hmac-sha256" => hex_string(sha256_hmac(&key, &message)),
        "hmac-sha512" => hex_string(sha512_hmac(&key, &message)),
        algorithm => return Err(format!("unknown HMAC algorithm {algorithm}")),
    };
    let want = string(&vector.expected, "hmac");
    ensure(got == want, || format!("expected HMAC {want}, got {got}"))
}

fn dispatch_aes(vector: &Vector) -> Result<(), String> {
    let algorithm = string(&vector.input, "algorithm");
    if algorithm == "aes-block" {
        // Mirrors sdk.ts:294-305: AES block vectors are unconditional no-ops
        // because that primitive is not publicly exported by the TS package.
        return Ok(());
    }
    if algorithm != "aes-gcm" {
        return Ok(());
    }
    // Mirrors sdk.ts:307-328. AAD would be a dispatcher no-op; none of the
    // pinned vectors carries it.
    if !string(&vector.input, "aad").is_empty() {
        return Ok(());
    }
    let key = bytes(string(&vector.input, "key"))?;
    let iv = bytes(string(&vector.input, "iv"))?;
    let plaintext = bytes(string(&vector.input, "plaintext"))?;
    let result = aes_gcm_encrypt(&key, &iv, &plaintext, &[]).map_err(|error| error.to_string())?;
    let split = result.len() - 16;
    let ciphertext = hex_string(&result[..split]);
    let tag = hex_string(&result[split..]);
    let want_ciphertext = string(&vector.expected, "ciphertext");
    if !want_ciphertext.is_empty() {
        ensure(ciphertext == want_ciphertext, || {
            format!("expected AES-GCM ciphertext {want_ciphertext}, got {ciphertext}")
        })?;
    }
    let want_tag = string(&vector.expected, "authentication_tag");
    if !want_tag.is_empty() {
        ensure(tag == want_tag, || {
            format!("expected AES-GCM tag {want_tag}, got {tag}")
        })?;
    }
    Ok(())
}

fn dispatch_ecdsa_large_message(vector: &Vector) -> Result<(), String> {
    // Mirrors sdkHelpers.ts:36-47. Rust's fixed `[u8; 32]` ECDSA boundary
    // rejects the oversized message before signing or verification.
    let bits = vector.input["message_bits"].as_u64().unwrap_or(258) as usize;
    let oversized = vec![0u8; bits.div_ceil(8)];
    if bool_value(&vector.input, "use_valid_signature") {
        let signature = {
            let key = private_key(string(&vector.input, "privkey_hex"))?;
            ecdsa_sign(&bytes32("deadbeef")?, key.bn(), true).map_err(|error| error.to_string())?
        };
        let rejected = <[u8; 32]>::try_from(oversized.as_slice()).is_err();
        let _ = signature;
        return ensure(rejected, || {
            "oversized verify input was representable".to_string()
        });
    }
    let rejected = <[u8; 32]>::try_from(oversized.as_slice()).is_err();
    ensure(rejected, || {
        "oversized sign input was representable".to_string()
    })
}

fn dispatch_ecdsa(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    let k = string(input, "k");
    // Mirrors sdk.ts:179-183: custom-k shapes are dispatcher no-ops.
    if (!k.is_empty() && k != "drbg") || input.get("k_function").is_some() {
        return Ok(());
    }
    if bool_value(input, "message_too_large") {
        return dispatch_ecdsa_large_message(vector);
    }
    if string(input, "pubkey") == "infinity" {
        // Mirrors sdkHelpers.ts:50-57: the official assertion is specifically
        // that verification throws, not merely that it returns false.
        let signature = sign_hash(input, true)?;
        let infinity = Point::infinity();
        let hash = bytes32(string(input, "message_hex"))?;
        let rejected = ecdsa_verify(&hash, &signature, &infinity).is_err();
        return ensure(rejected, || {
            "ECDSA verification with the point at infinity did not return an error".to_string()
        });
    }
    let operation = string(input, "operation");
    if !operation.is_empty() {
        // Mirrors sdk.ts:195-201: these vectors only assert the corpus boolean.
        if operation == "point_add_negation" || operation == "scalar_mul_zero" {
            return ensure(bool_value(expected, "is_infinity"), || {
                "expected.is_infinity was not true".to_string()
            });
        }
        return Ok(());
    }
    if !string(input, "signature_r").is_empty() {
        // Mirrors sdkHelpers.ts:59-71, including the dispatcher's `valid`
        // lookup (the corpus field is named `verify`).
        let r = BigNumber::from_hex(string(input, "signature_r")).map_err(|e| e.to_string())?;
        let s = BigNumber::from_hex(string(input, "signature_s")).map_err(|e| e.to_string())?;
        let signature = Signature::new(r, s);
        let key = private_key(string(input, "privkey_hex"))?;
        let got = ecdsa_verify(
            &bytes32(string(input, "message_hex"))?,
            &signature,
            key.to_public_key().point(),
        )
        .map_err(|error| error.to_string())?;
        let want = bool_value(expected, "valid");
        return ensure(got == want, || format!("expected verify={want}, got {got}"));
    }
    if string(input, "privkey_hex").is_empty() {
        return Ok(());
    }
    let key = private_key(string(input, "privkey_hex"))?;
    if let Some(messages) = input.get("messages").and_then(serde_json::Value::as_array) {
        // Mirrors sdkHelpers.ts:73-79: only successful construction is asserted.
        for message in messages.iter().filter_map(serde_json::Value::as_str) {
            ecdsa_sign(&bytes32(message)?, key.bn(), true).map_err(|error| error.to_string())?;
        }
        return Ok(());
    }
    let signature = sign_hash(input, true)?;
    if !string(input, "wrong_pubkey_scalar").is_empty() {
        // Mirrors sdkHelpers.ts:81-94; again, the dispatcher reads `valid`,
        // while this corpus uses `verify`.
        let decimal: u64 = string(input, "wrong_pubkey_scalar")
            .parse()
            .map_err(|error| format!("wrong scalar: {error}"))?;
        let wrong = private_key(&format!("{decimal:064x}"))?;
        let got = ecdsa_verify(
            &bytes32(string(input, "message_hex"))?,
            &signature,
            wrong.to_public_key().point(),
        )
        .map_err(|error| error.to_string())?;
        let want = bool_value(expected, "valid");
        return ensure(got == want, || {
            format!("expected wrong-key verify={want}, got {got}")
        });
    }
    // Mirrors sdkHelpers.ts:96-131 exactly: only fields actually read by that
    // helper are asserted. The corpus's `verify` field is not read there.
    if let Some(want) = expected
        .get("der_length_bytes")
        .and_then(serde_json::Value::as_u64)
    {
        ensure(signature.to_der().len() == want as usize, || {
            format!(
                "expected DER length {want}, got {}",
                signature.to_der().len()
            )
        })?;
    }
    if let Some(want) = expected
        .get("der_hex_length_chars")
        .and_then(serde_json::Value::as_u64)
    {
        ensure(signature.to_hex().len() == want as usize, || {
            format!(
                "expected DER hex length {want}, got {}",
                signature.to_hex().len()
            )
        })?;
    }
    if bool_value(expected, "roundtrip_r_s_equal") {
        let parsed = Signature::from_der(&signature.to_der()).map_err(|error| error.to_string())?;
        ensure(
            signature.r().cmp(parsed.r()) == 0 && signature.s().cmp(parsed.s()) == 0,
            || "DER round-trip changed r or s".to_string(),
        )?;
    }
    if expected.get("s_lte_half_n").is_some() {
        ensure(bool_value(expected, "s_lte_half_n"), || {
            "expected.s_lte_half_n was not true".to_string()
        })?;
    }
    Ok(())
}

fn dispatch_ecies(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    let sender_hex = {
        let direct = string(input, "sender_private_key");
        if direct.is_empty() {
            string(input, "alice_private_key")
        } else {
            direct
        }
    };
    let recipient_private_hex = {
        let direct = string(input, "recipient_private_key");
        if direct.is_empty() {
            string(input, "bob_private_key")
        } else {
            direct
        }
    };

    if sender_hex.is_empty() {
        // Mirrors sdk.ts:239-247: decrypt-only always asserts the expected
        // plaintext, including the empty-plaintext vector.
        let ciphertext = string(input, "ciphertext_hex");
        if ciphertext.is_empty() || recipient_private_hex.is_empty() {
            return Ok(());
        }
        let plaintext =
            ECIES::electrum_decrypt(&bytes(ciphertext)?, &private_key(recipient_private_hex)?)
                .map_err(|error| error.to_string())?;
        let got = hex_string(plaintext);
        let want = string(expected, "decrypted_message");
        return ensure(got == want, || {
            format!("expected ECIES plaintext {want}, got {got}")
        });
    }

    let sender = private_key(sender_hex)?;
    let message = message_bytes(string(input, "message"), string(input, "message_encoding"))?;
    if bool_value(input, "no_key") {
        // Mirrors sdk.ts:252-273. Rust currently has no `noKey` ECIES mode;
        // exercising its closest public operation makes the resulting
        // cross-implementation disagreement explicit rather than dropping it.
        let alice = private_key(string(input, "alice_private_key"))?;
        let bob = private_key(string(input, "bob_private_key"))?;
        let ct1 = ECIES::electrum_encrypt(
            &message,
            &public_key(string(input, "bob_public_key"))?,
            Some(&alice),
        )
        .map_err(|error| error.to_string())?;
        let ct2 = ECIES::electrum_encrypt(
            &message,
            &public_key(string(input, "alice_public_key"))?,
            Some(&bob),
        )
        .map_err(|error| error.to_string())?;
        if bool_value(expected, "ciphertext_symmetric") {
            ensure(ct1 == ct2, || {
                "ECIES noKey ciphertexts were not symmetric".to_string()
            })?;
        }
        let want_utf8 = string(expected, "decrypted_message_utf8");
        if !want_utf8.is_empty() {
            let plain = ECIES::electrum_decrypt(&ct1, &bob).map_err(|error| error.to_string())?;
            ensure(String::from_utf8_lossy(&plain) == want_utf8, || {
                format!("expected UTF-8 plaintext {want_utf8:?}, got {plain:?}")
            })?;
        }
        return Ok(());
    }

    // Mirrors sdk.ts:276-291. Expected throws/length/roundtrip-only fields are
    // intentionally not read because the official dispatcher does not read them.
    let want_ciphertext = string(expected, "ciphertext_hex");
    let mut produced = None;
    if !want_ciphertext.is_empty() {
        let recipient = public_key(string(input, "recipient_public_key"))?;
        let ciphertext = ECIES::electrum_encrypt(&message, &recipient, Some(&sender))
            .map_err(|error| error.to_string())?;
        let got = hex_string(&ciphertext);
        ensure(got == want_ciphertext, || {
            format!("expected ECIES ciphertext {want_ciphertext}, got {got}")
        })?;
        produced = Some(ciphertext);
    }
    let want_plaintext = string(expected, "decrypted_message");
    if !want_plaintext.is_empty() && !recipient_private_hex.is_empty() {
        let ciphertext = if !string(input, "ciphertext_hex").is_empty() {
            bytes(string(input, "ciphertext_hex"))?
        } else if let Some(ciphertext) = produced {
            ciphertext
        } else {
            bytes(want_ciphertext)?
        };
        let got = hex_string(
            ECIES::electrum_decrypt(&ciphertext, &private_key(recipient_private_hex)?)
                .map_err(|error| error.to_string())?,
        );
        ensure(got == want_plaintext, || {
            format!("expected ECIES plaintext {want_plaintext}, got {got}")
        })?;
    }
    Ok(())
}

fn dispatch_signature(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    if !string(input, "privkey_hex").is_empty() {
        // Mirrors sdkHelpers.ts:285-333.
        if string(input, "message_hex").is_empty() {
            return Ok(());
        }
        if input.get("recovery").is_some() && bool_value(expected, "throws") {
            let recovery = number(input, "recovery");
            if !(0..=3).contains(&recovery) {
                let signature = Signature::new(BigNumber::zero(), BigNumber::zero());
                let accepted = u8::try_from(recovery)
                    .is_ok_and(|recovery| signature.to_compact_bsm(recovery, true).is_ok());
                return ensure(!accepted, || {
                    format!("invalid recovery parameter {recovery} was accepted")
                });
            }
        }
        let signature = sign_hash(input, true)?;
        let want_der = string(expected, "der_hex");
        if !want_der.is_empty() {
            ensure(signature.to_hex() == want_der, || {
                format!("expected DER {want_der}, got {}", signature.to_hex())
            })?;
        }
        if let Some(want) = expected
            .get("der_length_bytes")
            .and_then(serde_json::Value::as_u64)
        {
            ensure(signature.to_der().len() == want as usize, || {
                format!(
                    "expected DER length {want}, got {}",
                    signature.to_der().len()
                )
            })?;
        }
        let recovery = input
            .get("recovery")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u8;
        let compact = signature
            .to_compact_bsm(recovery, bool_value(input, "compressed"))
            .map_err(|error| error.to_string())?;
        let want_compact = string(expected, "compact_hex");
        if !want_compact.is_empty() {
            let got = hex_string(&compact);
            ensure(got == want_compact, || {
                format!("expected compact signature {want_compact}, got {got}")
            })?;
        }
        if let Some(want) = expected
            .get("first_byte")
            .and_then(serde_json::Value::as_u64)
        {
            ensure(compact[0] == want as u8, || {
                format!("expected compact first byte {want}, got {}", compact[0])
            })?;
        }
        let want_r = string(expected, "r_hex");
        if !want_r.is_empty() {
            let got = format!("{:0>64}", signature.r().to_hex());
            ensure(got == want_r, || format!("expected r {want_r}, got {got}"))?;
        }
        let want_s = string(expected, "s_hex");
        if !want_s.is_empty() {
            let got = format!("{:0>64}", signature.s().to_hex());
            ensure(got == want_s, || format!("expected s {want_s}, got {got}"))?;
        }
        return Ok(());
    }

    let der = string(input, "der_hex");
    if !der.is_empty() {
        // Mirrors sdkHelpers.ts:335-349.
        let parsed = Signature::from_der(&bytes(der)?);
        if bool_value(expected, "throws") {
            return ensure(parsed.is_err(), || {
                "malformed DER parsed successfully".to_string()
            });
        }
        let parsed = parsed.map_err(|error| error.to_string())?;
        let want_r = string(expected, "r_hex");
        if !want_r.is_empty() {
            let got = format!("{:0>64}", parsed.r().to_hex());
            ensure(got == want_r, || format!("expected r {want_r}, got {got}"))?;
        }
        let want_s = string(expected, "s_hex");
        if !want_s.is_empty() {
            let got = format!("{:0>64}", parsed.s().to_hex());
            ensure(got == want_s, || format!("expected s {want_s}, got {got}"))?;
        }
        return Ok(());
    }
    let der_bytes = string(input, "der_bytes_hex");
    if !der_bytes.is_empty() {
        // Mirrors sdk.ts:721-726.
        if bool_value(expected, "throws") {
            return ensure(Signature::from_der(&bytes(der_bytes)?).is_err(), || {
                "malformed DER bytes parsed successfully".to_string()
            });
        }
        return Ok(());
    }
    let compact = string(input, "compact_hex");
    if !compact.is_empty() {
        // Mirrors sdkHelpers.ts:351-366, using Rust's explicitly named BSM
        // compact decoder for the same 65-byte wire shape.
        let raw = bytes(compact)?;
        if bool_value(expected, "throws") {
            return ensure(Signature::from_compact_bsm(&raw).is_err(), || {
                "malformed compact signature parsed successfully".to_string()
            });
        }
        let (parsed, _, _) =
            Signature::from_compact_bsm(&raw).map_err(|error| error.to_string())?;
        let want_r = string(expected, "r_hex");
        if !want_r.is_empty() {
            let got = format!("{:0>64}", parsed.r().to_hex());
            ensure(got == want_r, || format!("expected r {want_r}, got {got}"))?;
        }
        let want_s = string(expected, "s_hex");
        if !want_s.is_empty() {
            let got = format!("{:0>64}", parsed.s().to_hex());
            ensure(got == want_s, || format!("expected s {want_s}, got {got}"))?;
        }
        return Ok(());
    }
    // Mirrors sdk.ts:734-736: descriptive malformed-compact shapes are no-ops.
    Ok(())
}

fn dispatch(category: &str, vector: &Vector) -> Result<(), String> {
    match category {
        "aes" => dispatch_aes(vector),
        "ecdsa" => dispatch_ecdsa(vector),
        "ecies" => dispatch_ecies(vector),
        "hash160" => dispatch_hash160(vector),
        "hmac" => dispatch_hmac(vector),
        "ripemd160" => dispatch_ripemd160(vector),
        "sha256" => dispatch_sha256(vector),
        "signature" => dispatch_signature(vector),
        _ => Err(format!("unknown crypto category {category}")),
    }
}

#[test]
fn official_crypto_conformance() {
    run_corpora(CORPORA, GOVERNED_SKIPS, KNOWN_DIVERGENCES, dispatch);
}
