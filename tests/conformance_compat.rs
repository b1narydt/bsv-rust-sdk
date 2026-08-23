//! Official BSV SDK compatibility conformance corpus.

mod conformance_harness;

use bsv::compat::bsm::BSM;
use bsv::primitives::big_number::{BigNumber, Endian};
use bsv::primitives::ecdsa::{ecdsa_sign, ecdsa_verify};
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::primitives::signature::Signature;
use conformance_harness::{
    bool_value, bytes, ensure, hex_string, run_corpora, string, Corpus, KnownDivergence, Vector,
};

const BSM_VECTORS: &str = include_str!("../conformance/vectors/sdk/compat/bsm.json");
const CORPORA: &[Corpus<'_>] = &[Corpus {
    category: "bsm",
    json: BSM_VECTORS,
    expected_count: 9,
}];
const KNOWN_DIVERGENCES: &[KnownDivergence<'_>] = &[];

fn private_key(input: &serde_json::Value) -> Result<Option<PrivateKey>, String> {
    let wif = string(input, "privkey_wif");
    if !wif.is_empty() {
        return PrivateKey::from_wif(wif)
            .map(Some)
            .map_err(|error| error.to_string());
    }
    let hex = string(input, "privkey_hex");
    if !hex.is_empty() {
        return PrivateKey::from_hex(hex)
            .map(Some)
            .map_err(|error| error.to_string());
    }
    Ok(None)
}

fn public_key(hex: &str) -> Result<PublicKey, String> {
    PublicKey::from_string(hex).map_err(|error| error.to_string())
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let a = chunk[0] as u32;
        let b = chunk.get(1).copied().unwrap_or(0) as u32;
        let c = chunk.get(2).copied().unwrap_or(0) as u32;
        let bits = (a << 16) | (b << 8) | c;
        out.push(ALPHABET[((bits >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((bits >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((bits >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(bits & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn dispatch_bsm(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    let message = bytes(string(input, "message_hex"))?;
    let magic_hash = BSM::magic_hash(&message);

    let want_magic = string(expected, "magic_hash_hex");
    if !want_magic.is_empty() {
        // Mirrors sdk.ts:739-745. magic_hash_length_bytes is not read by the
        // official dispatcher and therefore is not added here.
        let got = hex_string(magic_hash);
        return ensure(got == want_magic, || {
            format!("expected BSM magic hash {want_magic}, got {got}")
        });
    }

    let private = private_key(input)?;
    let want_der = string(expected, "der_hex");
    if !want_der.is_empty() {
        // Mirrors sdk.ts:757-761. Rust exposes compact BSM signing, so the
        // same public magic-hash and ECDSA primitives produce the requested
        // raw DER representation without asserting an extra property.
        let key = private.as_ref().ok_or("missing private key")?;
        let signature =
            ecdsa_sign(&magic_hash, key.bn(), true).map_err(|error| error.to_string())?;
        let got = signature.to_hex();
        return ensure(got == want_der, || {
            format!("expected BSM DER {want_der}, got {got}")
        });
    }

    let want_base64 = string(expected, "base64_compact_sig");
    if !want_base64.is_empty() {
        // Mirrors sdk.ts:764-767.
        let signature = BSM::sign(&message, private.as_ref().ok_or("missing private key")?)
            .map_err(|error| error.to_string())?;
        let got = base64_encode(&signature);
        return ensure(got == want_base64, || {
            format!("expected compact BSM base64 {want_base64}, got {got}")
        });
    }

    if expected.get("valid").is_some() {
        let want_valid = bool_value(expected, "valid");
        let magic_bn = BigNumber::from_bytes(&magic_hash, Endian::Big);
        let der = string(input, "der_hex");
        if !der.is_empty() {
            // Mirrors sdkHelpers.ts:370-385: malformed DER maps to false.
            let got = match Signature::from_der(&bytes(der)?) {
                Ok(signature) => ecdsa_verify(
                    &magic_hash,
                    &signature,
                    public_key(string(input, "pubkey_hex"))?.point(),
                )
                .map_err(|error| error.to_string())?,
                Err(_) => false,
            };
            return ensure(got == want_valid, || {
                format!("expected DER BSM valid={want_valid}, got {got}")
            });
        }
        let compact = string(input, "compact_sig_hex");
        if !compact.is_empty() {
            // Mirrors sdkHelpers.ts:387-404.
            let got = match Signature::from_compact_bsm(&bytes(compact)?) {
                Ok((signature, recovery, _)) => signature
                    .recover_public_key(recovery, &magic_bn)
                    .map(|key| key.to_der_hex() == string(input, "pubkey_hex"))
                    .unwrap_or(false),
                Err(_) => false,
            };
            return ensure(got == want_valid, || {
                format!("expected compact BSM valid={want_valid}, got {got}")
            });
        }
    }

    if !string(expected, "recovered_pubkey_hex").is_empty()
        || expected.get("recovery_factor").is_some()
    {
        // Mirrors sdkHelpers.ts:406-428.
        let compact = string(input, "compact_sig_hex");
        if compact.is_empty() {
            return Ok(());
        }
        let (signature, recovery, _) =
            Signature::from_compact_bsm(&bytes(compact)?).map_err(|error| error.to_string())?;
        let recovered = signature
            .recover_public_key(recovery, &BigNumber::from_bytes(&magic_hash, Endian::Big))
            .map_err(|error| error.to_string())?;
        let want_key = string(expected, "recovered_pubkey_hex");
        if !want_key.is_empty() {
            let got = recovered.to_der_hex();
            ensure(got == want_key, || {
                format!("expected recovered key {want_key}, got {got}")
            })?;
        }
        if let Some(want) = expected
            .get("recovery_factor")
            .and_then(serde_json::Value::as_u64)
        {
            ensure(recovery as u64 == want, || {
                format!("expected recovery factor {want}, got {recovery}")
            })?;
        }
    }
    Ok(())
}

#[test]
fn official_compat_conformance() {
    run_corpora(CORPORA, &[], KNOWN_DIVERGENCES, |category, vector| {
        if category == "bsm" {
            dispatch_bsm(vector)
        } else {
            Err(format!("unknown compat category {category}"))
        }
    });
}
