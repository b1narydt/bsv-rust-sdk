//! Requires the `network` feature: `services::overlay_tools` (LookupResolver,
//! TopicBroadcaster, OverlayAdminTokenTemplate) is gated behind it, so this file
//! must compile away on the `--no-default-features` CI matrix legs.
#![cfg(feature = "network")]

//! Does Rust decode a REAL SHIP/SLAP advertisement minted by @bsv/sdk?
//!
//! Vectors from `OverlayAdminTokenTemplate.lock()` in @bsv/sdk 2.0.13
//! (ProtoWallet, key = 0x77*32, domain `https://overlay.example.com`,
//! topicOrService `ls_test_service`). Both carry FIVE PushDrop fields —
//! `includeSignature` defaults to true, so the signature is field[4].

use bsv::script::locking_script::LockingScript;
use bsv::script::templates::push_drop::decode;
use bsv::services::overlay_tools::admin_token_template::OverlayAdminTokenTemplate;

const SLAP: &str = "2102a14398acfc923abcf127de81e45962de790416dff5b9cea3c2ba8dd9dff71cd9ac04534c415021037962d45b38e8bcf82fa8efa8432a01f20c9a53e24c7d3f11df197cb8e70926da1b68747470733a2f2f6f7665726c61792e6578616d706c652e636f6d0f6c735f746573745f7365727669636546304402202fb7e0dc5da882b2388f2722f5506115aceb59c651bf1764681f3061e198f10502200c851c11e75e057555077d2dc6c43843decb91d1f2ffce7b9dcbd93ae7e12c486d6d75";
const SHIP: &str = "2103a96c2b1799c0f4a64f0de422b5da32f1abe4eb0925c4f82bf01b744b4faec22cac045348495021037962d45b38e8bcf82fa8efa8432a01f20c9a53e24c7d3f11df197cb8e70926da1b68747470733a2f2f6f7665726c61792e6578616d706c652e636f6d0f6c735f746573745f73657276696365463044022073ae653108063a6c21cfca81f179786e5879d05a9d3b2320dd285d8221fd615b022069ec1c258cc6835f8a42596f9a71ad58d52a0c41745b5318fa9db7f29a52a2326d6d75";

const IDENTITY_KEY: &str = "037962d45b38e8bcf82fa8efa8432a01f20c9a53e24c7d3f11df197cb8e70926da";

/// A real advertisement carries FIVE fields: the four payload fields plus the
/// appended `createSignature`. Pinning this because the OLD Rust `PushDrop::lock`
/// never appended a signature — any ad it minted would have had only four, and
/// would not have matched what overlays actually publish.
#[test]
fn a_real_ts_advertisement_has_five_pushdrop_fields() {
    for (name, hex_script) in [("SLAP", SLAP), ("SHIP", SHIP)] {
        let script = LockingScript::from_hex(hex_script).expect("script parses");
        let d = decode(&script).expect("PushDrop decode");
        assert_eq!(
            d.fields.len(),
            5,
            "{name}: 4 payload fields + the appended signature"
        );
    }
}

/// The actual thing LookupResolver depends on: decoding a real overlay-published
/// SLAP ad into (protocol, identityKey, domain, topicOrService).
#[test]
fn rust_decodes_a_real_ts_slap_advertisement() {
    let script = LockingScript::from_hex(SLAP).expect("script parses");
    let ad = OverlayAdminTokenTemplate::decode(&script).expect("SLAP must decode");

    assert_eq!(ad.protocol, "SLAP");
    assert_eq!(ad.identity_key, IDENTITY_KEY);
    assert_eq!(ad.domain, "https://overlay.example.com");
    assert_eq!(ad.topic_or_service, "ls_test_service");
}

#[test]
fn rust_decodes_a_real_ts_ship_advertisement() {
    let script = LockingScript::from_hex(SHIP).expect("script parses");
    let ad = OverlayAdminTokenTemplate::decode(&script).expect("SHIP must decode");

    assert_eq!(ad.protocol, "SHIP");
    assert_eq!(ad.identity_key, IDENTITY_KEY);
    assert_eq!(ad.domain, "https://overlay.example.com");
    assert_eq!(ad.topic_or_service, "ls_test_service");
}

/// CROSS-CHECK: would the OLD (pre-fix) decoder have failed on these ads?
///
/// The old `decode_before` collected ONLY chunks carrying a `data` payload,
/// silently dropping fields that PushDrop had minimally encoded as bare opcodes.
/// That is a real bug — but it can only bite when a field is empty, a single byte
/// in 1..=16, or 0x81. This replays that exact logic over the REAL advertisement
/// vectors to check whether SHIP/SLAP ever hit it.
///
/// It does not: every advertisement field (protocol tag, 33-byte identity key,
/// domain, topicOrService, DER signature) is multi-byte. So the old decoder
/// recovered all five fields too, and the PushDrop incompatibility does NOT
/// explain any overlay resolve failure. Recorded so nobody re-litigates it.
#[test]
fn cross_check_the_old_decoder_also_handled_these_ads() {
    use bsv::script::op::Op;

    for (name, hex_script) in [("SLAP", SLAP), ("SHIP", SHIP)] {
        let script = LockingScript::from_hex(hex_script).unwrap();
        let chunks = script.chunks();

        // Verbatim replay of the OLD decode_before field loop.
        let mut old_fields: Vec<Vec<u8>> = Vec::new();
        for i in 2..chunks.len() {
            let next_is_drop = chunks
                .get(i + 1)
                .is_some_and(|n| n.op == Op::OpDrop || n.op == Op::Op2Drop);
            if chunks[i].op == Op::OpDrop || chunks[i].op == Op::Op2Drop {
                break;
            }
            if let Some(ref data) = chunks[i].data {
                old_fields.push(data.clone()); // <-- the bug: no-data chunks skipped
            }
            if next_is_drop {
                break;
            }
        }

        let new_fields = decode(&script).unwrap().fields;
        assert_eq!(
            old_fields, new_fields,
            "{name}: the old decoder handled advertisements identically — no \
             advertisement field is minimally encoded, so the PushDrop decode bug \
             never affected SHIP/SLAP resolution"
        );
        assert_eq!(old_fields.len(), 5, "{name}: old decoder saw all 5 fields");
    }
}

/// END-TO-END: a Rust-minted advertisement must be byte-identical to the one
/// @bsv/sdk publishes from the same wallet — same derived locking key, same
/// appended signature. This is what makes a Rust overlay node advertisable.
#[tokio::test]
async fn rust_minted_advertisements_are_byte_identical_to_ts() {
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::proto_wallet::ProtoWallet;

    let w = ProtoWallet::new(PrivateKey::from_bytes(&[0x77u8; 32]).unwrap());

    for (proto, expected) in [("SLAP", SLAP), ("SHIP", SHIP)] {
        let script = OverlayAdminTokenTemplate::lock(
            &w,
            None,
            proto,
            "https://overlay.example.com",
            "ls_test_service",
        )
        .await
        .expect("mint advertisement");

        assert_eq!(
            script.to_hex(),
            expected,
            "{proto}: Rust-minted advertisement must match @bsv/sdk byte-for-byte"
        );
    }
}
