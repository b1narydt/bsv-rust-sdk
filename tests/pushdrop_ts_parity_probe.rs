//! PushDrop conformance against the reference SDKs.
//!
//! Vectors produced by `mpc-cosigner-sdk/pushdrop_parity.mjs` against the REAL
//! @bsv/sdk 2.0.13: key = 0x55*32, protocolID `[2,"did revocation"]`,
//! keyID `"serial-1"`, counterparty `"self"`,
//! fields = `["did:revocation", [0x05], [0x81], "abc"]`.
//!
//! Cross-checked against go-sdk v1.2.24 (`transaction/template/pushdrop`).

use bsv::primitives::private_key::PrivateKey;
use bsv::script::locking_script::LockingScript;
use bsv::script::templates::push_drop::{decode, LockPosition, PushDrop};
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};

/// TS `pd.lock(fields, [2,"did revocation"], "serial-1", "self", false, false)`.
const TS_LOCK_NO_SIG: &str = "21034ffa95e44c9ed2a4cc4fa6b5f51a389799b2e451d3fc03ccecb76bfb441805feac0e6469643a7265766f636174696f6e554f036162636d6d";
/// The same, with TS's DEFAULT `includeSignature = true`.
const TS_LOCK_WITH_SIG: &str = "21034ffa95e44c9ed2a4cc4fa6b5f51a389799b2e451d3fc03ccecb76bfb441805feac0e6469643a7265766f636174696f6e554f03616263473045022100d5f2e5c02731e6e442f3cb40a481a10400955e251bac351bd9a9fc2ddd60f34a02205cc075ce856b897dfc0f9f58cf7a36f8b7d2d5d763f67efc70b88ca66a0736c36d6d75";
/// TS `lock([[16],[15]], …, includeSignature=false)`. TS's OWN decoder reads this
/// back as `["", "0f"]` — `OP_16` (0x60) falls outside its `op <= 95` range check,
/// so the field is silently LOST. go-sdk gates `0x50..=0x60` and recovers it.
const TS_LOCK_OP16: &str =
    "2102398e506e15a327ffc81206edf2cbb9122a612ca2b76306cb9bfab30de246ef80ac605f6d";

fn wallet() -> ProtoWallet {
    ProtoWallet::new(PrivateKey::from_bytes(&[0x55u8; 32]).unwrap())
}

fn self_counterparty() -> Counterparty {
    Counterparty {
        counterparty_type: CounterpartyType::Self_,
        public_key: None,
    }
}

fn protocol() -> Protocol {
    Protocol {
        security_level: 2,
        protocol: "did revocation".to_string(),
    }
}

fn fields() -> Vec<Vec<u8>> {
    vec![
        b"did:revocation".to_vec(),
        vec![0x05],
        vec![0x81],
        b"abc".to_vec(),
    ]
}

/// THE conformance test: our locking script must be byte-identical to the one
/// @bsv/sdk produces from the same wallet key, protocol, keyID and counterparty —
/// derived pubkey and all.
#[tokio::test]
async fn lock_is_byte_identical_to_ts_sdk() {
    let w = wallet();
    let script = PushDrop::new(&w, None)
        .lock(
            fields(),
            protocol(),
            "serial-1",
            self_counterparty(),
            false,
            false,
            LockPosition::Before,
        )
        .await
        .expect("lock");

    assert_eq!(
        script.to_hex(),
        TS_LOCK_NO_SIG,
        "locking script must be byte-identical to @bsv/sdk 2.0.13"
    );
}

/// With `include_signature` (the TS/Go DEFAULT), the signature is appended as an
/// extra field. ECDSA here is RFC-6979 deterministic, so this too is byte-exact.
#[tokio::test]
async fn lock_with_signature_is_byte_identical_to_ts_sdk() {
    let w = wallet();
    let script = PushDrop::new(&w, None)
        .lock(
            fields(),
            protocol(),
            "serial-1",
            self_counterparty(),
            false,
            true,
            LockPosition::Before,
        )
        .await
        .expect("lock");

    assert_eq!(
        script.to_hex(),
        TS_LOCK_WITH_SIG,
        "the appended createSignature field must match @bsv/sdk byte-for-byte"
    );
}

/// We must recover every field from a TS-minted script, including the ones TS
/// encodes as bare opcodes (`OP_5`, `OP_1NEGATE`). The old port silently dropped
/// them, returning 2 fields where TS returns 4.
#[test]
fn decode_recovers_every_field_of_a_ts_script() {
    let script = LockingScript::from_hex(TS_LOCK_NO_SIG).expect("TS script parses");
    let got: Vec<String> = decode(&script)
        .expect("decode")
        .fields
        .iter()
        .map(hex::encode)
        .collect();

    assert_eq!(
        got,
        vec!["6469643a7265766f636174696f6e", "05", "81", "616263"],
        "Rust decode must match TS decode field-for-field"
    );
}

/// `decode` also returns the locking public key — TS and Go both do; the old Rust
/// port threw it away.
#[test]
fn decode_returns_the_locking_public_key() {
    let script = LockingScript::from_hex(TS_LOCK_NO_SIG).unwrap();
    let d = decode(&script).unwrap();
    assert_eq!(
        d.locking_public_key.to_der_hex(),
        "034ffa95e44c9ed2a4cc4fa6b5f51a389799b2e451d3fc03ccecb76bfb441805fe",
        "must recover the DERIVED locking key TS used"
    );
}

/// TS cannot round-trip its own `[16]` field (encodes `OP_16` = 0x60, but its
/// decoder gates `op <= 95`). go-sdk fixed this; we follow Go. Being
/// byte-identical to BOTH is impossible here — this pins which one we chose.
#[test]
fn op16_field_ts_loses_but_we_recover_like_go() {
    let script = LockingScript::from_hex(TS_LOCK_OP16).expect("TS script parses");
    let got: Vec<String> = decode(&script)
        .expect("decode")
        .fields
        .iter()
        .map(hex::encode)
        .collect();

    assert_eq!(
        got,
        vec!["10", "0f"],
        "OP_16 must round-trip to [16]; TS drops it, go-sdk keeps it, we follow Go"
    );
}
