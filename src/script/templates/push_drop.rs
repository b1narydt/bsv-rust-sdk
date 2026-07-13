//! PushDrop script template for embedding data in Bitcoin scripts.
//!
//! PushDrop creates scripts that embed arbitrary data fields followed by
//! OP_DROP operations to clean the stack, then lock with OP_CHECKSIG.
//! This enables data storage on-chain while maintaining spending control.
//!
//! Supports two lock positions matching the TS SDK:
//! - **Before** (default): `<pubkey> OP_CHECKSIG <fields...> OP_2DROP... OP_DROP`
//! - **After**: `<fields...> OP_2DROP... OP_DROP <pubkey> OP_CHECKSIG`
//!
//! # This template is wallet-driven, not private-key-driven
//!
//! [`PushDrop`] holds a [`WalletInterface`], exactly as `@bsv/sdk`'s
//! `PushDrop` (TS) and `go-sdk`'s `pushdrop.PushDrop` (Go) do. The locking key is
//! a **BRC-42 derived child key** obtained via `getPublicKey`, and the signature
//! field is produced via `createSignature` — never from a raw local key.
//!
//! An earlier revision of this port took a `PrivateKey` and locked to the RAW
//! public key, omitted the signature field entirely, and shipped a `lock_only()`
//! constructor that could never produce a script (it left the key `None`, which
//! `lock()` then rejected). That shape exists in neither reference SDK, and the
//! scripts it produced were not interoperable. It is gone.
//!
//! Deriving from the wallet is also what lets an MPC- or HSM-backed wallet own
//! the spending key: the template never sees private material.

use crate::primitives::hash::sha256;
use crate::primitives::public_key::PublicKey;
use crate::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use crate::script::error::ScriptError;
use crate::script::locking_script::LockingScript;
use crate::script::op::Op;
use crate::script::script::Script;
use crate::script::script_chunk::ScriptChunk;
use crate::script::unlocking_script::UnlockingScript;
use crate::wallet::interfaces::{CreateSignatureArgs, GetPublicKeyArgs, WalletInterface};
use crate::wallet::types::{Counterparty, Protocol};

/// Lock position for the public key in the PushDrop script.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum LockPosition {
    /// `<pubkey> OP_CHECKSIG <fields...> OP_2DROP...` (TS default)
    #[default]
    Before,
    /// `<fields...> OP_2DROP... <pubkey> OP_CHECKSIG`
    After,
}

/// The result of decoding a PushDrop locking script.
///
/// Mirrors TS `PushDrop.decode` / Go `pushdrop.Decode`, both of which return the
/// locking public key ALONGSIDE the fields. The old Rust port returned a keyless
/// `PushDrop`, discarding the pubkey.
#[derive(Clone, Debug)]
pub struct PushDropData {
    /// The public key the output is locked to.
    pub locking_public_key: PublicKey,
    /// The embedded data fields, with minimally-encoded opcode forms decoded back
    /// to their byte values.
    pub fields: Vec<Vec<u8>>,
}

/// PushDrop script template for embedding data with spending control.
///
/// Holds a [`WalletInterface`] (see the module docs); the locking key is derived
/// per `(protocol_id, key_id, counterparty)`, never supplied directly.
/// The wallet is BORROWED. Go stores a `wallet.Interface` (an interface value,
/// i.e. a pointer); a borrow is the Rust analogue and keeps the template usable
/// from a store that owns its wallet (`&self.wallet`) and from one that holds it
/// behind an `Arc` (`&*arc`) alike, with no clone and no `Arc` requirement.
pub struct PushDrop<'a, W: WalletInterface + ?Sized> {
    /// The wallet that derives keys and produces signatures.
    pub wallet: &'a W,
    /// Originator passed through on every wallet request.
    pub originator: Option<String>,
}

impl<'a, W: WalletInterface + ?Sized> PushDrop<'a, W> {
    /// Construct a PushDrop template bound to `wallet`.
    pub fn new(wallet: &'a W, originator: Option<String>) -> Self {
        Self { wallet, originator }
    }

    /// Create a PushDrop locking script.
    ///
    /// Port of TS `PushDrop.lock` / Go `PushDrop.Lock`, in that order of authority.
    ///
    /// - The locking pubkey is derived: `getPublicKey({protocol_id, key_id, counterparty, for_self})`.
    /// - When `include_signature` (the TS/Go default is **true**), a
    ///   `createSignature` over the CONCATENATED fields is appended **as an extra
    ///   field** — so it participates in the OP_2DROP/OP_DROP tail count.
    /// - Fields are minimally encoded (see [`make_data_push`]).
    #[allow(clippy::too_many_arguments)]
    pub async fn lock(
        &self,
        mut fields: Vec<Vec<u8>>,
        protocol_id: Protocol,
        key_id: &str,
        counterparty: Counterparty,
        for_self: bool,
        include_signature: bool,
        lock_position: LockPosition,
    ) -> Result<LockingScript, ScriptError> {
        if fields.is_empty() && !include_signature {
            return Err(ScriptError::InvalidScript(
                "PushDrop: at least one data field required".into(),
            ));
        }

        let pk = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(protocol_id.clone()),
                    key_id: Some(key_id.to_string()),
                    counterparty: Some(counterparty.clone()),
                    privileged: false,
                    privileged_reason: None,
                    for_self: Some(for_self),
                    seek_permission: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| ScriptError::InvalidScript(format!("PushDrop lock: getPublicKey: {e}")))?;

        let pubkey_bytes = pk.public_key.to_der();
        let mut lock_chunks = vec![
            ScriptChunk::new_raw(pubkey_bytes.len() as u8, Some(pubkey_bytes)),
            ScriptChunk::new_opcode(Op::OpCheckSig),
        ];

        if include_signature {
            // Signed data is the concatenation of the fields, BEFORE the signature
            // itself is appended (TS `fields.reduce`, Go's `dataToSign` loop).
            let data_to_sign: Vec<u8> = fields.concat();
            let sig = self
                .wallet
                .create_signature(
                    CreateSignatureArgs {
                        protocol_id: protocol_id.clone(),
                        key_id: key_id.to_string(),
                        counterparty: counterparty.clone(),
                        data: Some(data_to_sign),
                        hash_to_directly_sign: None,
                        privileged: false,
                        privileged_reason: None,
                        seek_permission: None,
                    },
                    self.originator.as_deref(),
                )
                .await
                .map_err(|e| {
                    ScriptError::InvalidScript(format!("PushDrop lock: createSignature: {e}"))
                })?;
            fields.push(sig.signature);
        }

        let mut push_drop_chunks: Vec<ScriptChunk> =
            fields.iter().map(|f| make_data_push(f)).collect();

        // Drop tail. Counted over the fields INCLUDING the appended signature.
        let mut not_yet_dropped = fields.len();
        while not_yet_dropped > 1 {
            push_drop_chunks.push(ScriptChunk::new_opcode(Op::Op2Drop));
            not_yet_dropped -= 2;
        }
        if not_yet_dropped != 0 {
            push_drop_chunks.push(ScriptChunk::new_opcode(Op::OpDrop));
        }

        let chunks = match lock_position {
            LockPosition::Before => {
                lock_chunks.extend(push_drop_chunks);
                lock_chunks
            }
            LockPosition::After => {
                push_drop_chunks.extend(lock_chunks);
                push_drop_chunks
            }
        };

        Ok(LockingScript::from_script(Script::from_chunks(chunks)))
    }

    /// Produce the unlocking script for a PushDrop output, signing `preimage`
    /// (the BIP-143/BSV sighash preimage) through the wallet.
    ///
    /// Matches TS/Go: the wallet is handed `sha256(preimage)` as `data`, and
    /// hashes once more internally — so the signed digest is `sha256d(preimage)`,
    /// the correct BSV sighash. (The previous private-key implementation signed a
    /// SINGLE sha256 of the preimage, which is not a valid BSV sighash.)
    pub async fn unlock(
        &self,
        preimage: &[u8],
        protocol_id: Protocol,
        key_id: &str,
        counterparty: Counterparty,
        sighash_type: u8,
    ) -> Result<UnlockingScript, ScriptError> {
        let preimage_hash = sha256(preimage);

        let sig = self
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    protocol_id,
                    key_id: key_id.to_string(),
                    counterparty,
                    data: Some(preimage_hash.to_vec()),
                    hash_to_directly_sign: None,
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                self.originator.as_deref(),
            )
            .await
            .map_err(|e| {
                ScriptError::InvalidScript(format!("PushDrop unlock: createSignature: {e}"))
            })?;

        let mut sig_bytes = sig.signature;
        sig_bytes.push(sighash_type);

        let chunks = vec![ScriptChunk::new_raw(sig_bytes.len() as u8, Some(sig_bytes))];
        Ok(UnlockingScript::from_script(Script::from_chunks(chunks)))
    }

    /// The default sighash scope: `SIGHASH_ALL | SIGHASH_FORKID`.
    pub fn default_sighash_type() -> u8 {
        (SIGHASH_ALL | SIGHASH_FORKID) as u8
    }

    /// Estimate the byte length of the unlocking script (TS/Go both answer 73).
    pub fn estimate_unlock_length() -> usize {
        73
    }
}

/// Decode a PushDrop locking script in the default (`Before`) position.
///
/// A free function, mirroring Go's package-level `pushdrop.Decode`. Decoding does
/// not involve a wallet, so it must not be bound to the wallet-generic
/// [`PushDrop`] type — otherwise every call site needs a meaningless turbofish.
pub fn decode(script: &LockingScript) -> Result<PushDropData, ScriptError> {
    decode_with_position(script, LockPosition::Before)
}

/// Decode a PushDrop locking script, recovering pubkey + data fields.
pub fn decode_with_position(
    script: &LockingScript,
    position: LockPosition,
) -> Result<PushDropData, ScriptError> {
    let chunks = script.chunks();
    if chunks.len() < 3 {
        return Err(ScriptError::InvalidScript(
            "PushDrop::decode: script too short".into(),
        ));
    }

    match position {
        LockPosition::Before => decode_before(chunks),
        LockPosition::After => decode_after(chunks),
    }
}

impl PushDropData {
    /// Convenience alias for [`decode`].
    pub fn decode(script: &LockingScript) -> Result<PushDropData, ScriptError> {
        decode(script)
    }
}

/// Decode "before" layout: `<pubkey> OP_CHECKSIG <fields...> OP_2DROP...`
fn decode_before(chunks: &[ScriptChunk]) -> Result<PushDropData, ScriptError> {
    if chunks[0].data.is_none() || chunks[1].op != Op::OpCheckSig {
        return Err(ScriptError::InvalidScript(
            "PushDrop::decode(before): expected <pubkey> OP_CHECKSIG at start".into(),
        ));
    }
    let locking_public_key = PublicKey::from_der_bytes(chunks[0].data.as_ref().unwrap())
        .map_err(|e| ScriptError::InvalidScript(format!("PushDrop::decode: pubkey: {e}")))?;

    let mut fields = Vec::new();
    for i in 2..chunks.len() {
        let next_is_drop = chunks
            .get(i + 1)
            .is_some_and(|next| next.op == Op::OpDrop || next.op == Op::Op2Drop);

        if chunks[i].op == Op::OpDrop || chunks[i].op == Op::Op2Drop {
            break;
        }

        // Reconstruct opcode-encoded fields rather than skipping chunks with no
        // data payload — skipping them silently LOSES minimally-encoded fields.
        fields.push(decode_field(&chunks[i]));

        if next_is_drop {
            break;
        }
    }

    Ok(PushDropData {
        locking_public_key,
        fields,
    })
}

/// Decode "after" layout: `<fields...> OP_2DROP... <pubkey> OP_CHECKSIG`
fn decode_after(chunks: &[ScriptChunk]) -> Result<PushDropData, ScriptError> {
    let last = &chunks[chunks.len() - 1];
    if last.op != Op::OpCheckSig {
        return Err(ScriptError::InvalidScript(
            "PushDrop::decode(after): last opcode must be OP_CHECKSIG".into(),
        ));
    }
    let pubkey_chunk = &chunks[chunks.len() - 2];
    let pubkey_bytes = pubkey_chunk.data.as_ref().ok_or_else(|| {
        ScriptError::InvalidScript(
            "PushDrop::decode(after): expected pubkey before OP_CHECKSIG".into(),
        )
    })?;
    let locking_public_key = PublicKey::from_der_bytes(pubkey_bytes)
        .map_err(|e| ScriptError::InvalidScript(format!("PushDrop::decode: pubkey: {e}")))?;

    // Walk backwards from before the pubkey, counting the DROP tail.
    let mut drop_field_count = 0usize;
    let mut pos = chunks.len() - 3;
    loop {
        let chunk = &chunks[pos];
        if chunk.op == Op::Op2Drop {
            drop_field_count += 2;
        } else if chunk.op == Op::OpDrop {
            drop_field_count += 1;
        } else {
            break;
        }
        if pos == 0 {
            break;
        }
        pos -= 1;
    }

    if drop_field_count == 0 {
        return Err(ScriptError::InvalidScript(
            "PushDrop::decode(after): no OP_DROP/OP_2DROP found".into(),
        ));
    }
    if drop_field_count > chunks.len() {
        return Err(ScriptError::InvalidScript(
            "PushDrop::decode(after): drop count exceeds script length".into(),
        ));
    }

    // Reconstruct opcode-encoded fields. The previous code ERRORED on them
    // ("expected data push"), making TS/Go-minted tokens with a minimally
    // encoded field undecodable in this layout.
    let fields = chunks[0..drop_field_count]
        .iter()
        .map(decode_field)
        .collect();

    Ok(PushDropData {
        locking_public_key,
        fields,
    })
}

/// Byte-for-byte port of TS `createMinimallyEncodedScriptChunk` /
/// Go `CreateMinimallyEncodedScriptChunk`.
///
/// The minimal forms are NOT cosmetic: both reference SDKs emit a bare opcode
/// (no data payload) for `[]`, `[0]`, single bytes `1..=16`, and `[0x81]`. A
/// port that push-encodes those instead produces a different script — and a
/// decoder that only reads chunks carrying `data` silently loses the field.
/// See [`decode_field`], the inverse.
///
/// Quirk preserved deliberately for parity: both references map `[]` AND `[0]`
/// to `OP_0`, and decode `OP_0` back to `[0]` — so an empty field round-trips
/// to `[0]`. Bug-for-bug on purpose; diverging would desync the wire.
fn make_data_push(data: &[u8]) -> ScriptChunk {
    if data.is_empty() {
        return ScriptChunk::new_opcode(Op::Op0);
    }
    if data.len() == 1 {
        let b = data[0];
        if b == 0 {
            return ScriptChunk::new_opcode(Op::Op0);
        }
        if (1..=16).contains(&b) {
            // OP_1 ..= OP_16 == 0x51 ..= 0x60
            return ScriptChunk::new_raw(0x50 + b, None);
        }
        if b == 0x81 {
            return ScriptChunk::new_opcode(Op::Op1Negate);
        }
    }

    let len = data.len();
    if len < 0x4c {
        ScriptChunk::new_raw(len as u8, Some(data.to_vec()))
    } else if len < 256 {
        ScriptChunk::new_raw(Op::OpPushData1.to_byte(), Some(data.to_vec()))
    } else if len < 65536 {
        ScriptChunk::new_raw(Op::OpPushData2.to_byte(), Some(data.to_vec()))
    } else {
        ScriptChunk::new_raw(Op::OpPushData4.to_byte(), Some(data.to_vec()))
    }
}

/// Inverse of [`make_data_push`] — recover one field from a chunk,
/// reconstructing the minimally-encoded opcode forms.
///
/// # Follows the GO SDK, not the TS SDK — they disagree, and TS is wrong
///
/// TS `PushDrop.decode` gates on `op >= 80 && op <= 95` (`0x50..=0x5f`), which
/// EXCLUDES `OP_16` (`0x60`) — even though its own encoder emits `OP_16` for
/// `[16]`. So @bsv/sdk cannot round-trip a `[16]` field: it decodes to empty.
/// Verified against @bsv/sdk 2.0.13 — `lock([[16],[15]])` decodes to
/// `["", "0f"]`. That is silent data loss in the TS SDK.
///
/// go-sdk v1.2.24 gates on `Op1-1 ..= Op16` (`0x50..=0x60`) and round-trips
/// correctly. We match Go. The `0x50` low bound is shared by both references
/// (it maps `0x50` to `[0]`); our encoder never emits `0x50`, so it only
/// matters when decoding foreign scripts — and there we match.
fn decode_field(chunk: &ScriptChunk) -> Vec<u8> {
    if let Some(data) = &chunk.data {
        if !data.is_empty() {
            return data.clone();
        }
    }
    match chunk.op_byte {
        // 0x50 -> [0]; 0x51..=0x60 -> OP_1..=OP_16 -> [1..=16]
        0x50..=0x60 => vec![chunk.op_byte - 0x50],
        0x00 => vec![0],    // OP_0
        0x4f => vec![0x81], // OP_1NEGATE
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::proto_wallet::ProtoWallet;

    fn wallet() -> ProtoWallet {
        ProtoWallet::new(PrivateKey::from_bytes(&[0x55u8; 32]).unwrap())
    }

    fn protocol() -> Protocol {
        Protocol {
            security_level: 2,
            protocol: "did revocation".to_string(),
        }
    }

    fn cpty() -> Counterparty {
        Counterparty {
            counterparty_type: crate::wallet::types::CounterpartyType::Self_,
            public_key: None,
        }
    }

    #[tokio::test]
    async fn lock_derives_the_pubkey_from_the_wallet_not_the_raw_key() {
        let script = PushDrop::new(&wallet(), None)
            .lock(
                vec![b"hello".to_vec()],
                protocol(),
                "k",
                cpty(),
                false,
                false,
                LockPosition::Before,
            )
            .await
            .unwrap();

        let decoded = decode(&script).unwrap();
        let raw = PrivateKey::from_bytes(&[0x55u8; 32])
            .unwrap()
            .to_public_key();

        assert_ne!(
            decoded.locking_public_key.to_der_hex(),
            raw.to_der_hex(),
            "the locking key must be a BRC-42 DERIVED child, never the raw key"
        );
        assert_eq!(decoded.fields, vec![b"hello".to_vec()]);
    }

    /// `include_signature` (the TS/Go default) appends the signature AS A FIELD,
    /// so it changes both the field count and the OP_2DROP/OP_DROP tail.
    #[tokio::test]
    async fn include_signature_appends_the_signature_as_an_extra_field() {
        let fields = vec![b"a".to_vec(), b"b".to_vec()];

        let no_sig = PushDrop::new(&wallet(), None)
            .lock(
                fields.clone(),
                protocol(),
                "k",
                cpty(),
                false,
                false,
                LockPosition::Before,
            )
            .await
            .unwrap();
        let with_sig = PushDrop::new(&wallet(), None)
            .lock(
                fields.clone(),
                protocol(),
                "k",
                cpty(),
                false,
                true,
                LockPosition::Before,
            )
            .await
            .unwrap();

        let d_no = decode(&no_sig).unwrap();
        let d_with = decode(&with_sig).unwrap();

        assert_eq!(d_no.fields.len(), 2);
        assert_eq!(d_with.fields.len(), 3, "the signature is an extra field");
        assert_eq!(&d_with.fields[..2], &fields[..]);
        assert!(
            d_with.fields[2].starts_with(&[0x30]),
            "the appended field is a DER signature"
        );
    }

    /// Single bytes 1..=16 must use the minimal OP_1..OP_16 forms, and round-trip.
    #[tokio::test]
    async fn minimally_encoded_fields_round_trip() {
        let fields = vec![
            vec![0x01],
            vec![0x10],
            vec![0x81],
            vec![0x00],
            b"abc".to_vec(),
        ];
        let script = PushDrop::new(&wallet(), None)
            .lock(
                fields.clone(),
                protocol(),
                "k",
                cpty(),
                false,
                false,
                LockPosition::Before,
            )
            .await
            .unwrap();

        let hex = script.to_hex();
        assert!(hex.contains("51"), "[1] must encode as OP_1");
        assert!(hex.contains("60"), "[16] must encode as OP_16");
        assert!(hex.contains("4f"), "[0x81] must encode as OP_1NEGATE");

        let decoded = decode(&script).unwrap();
        assert_eq!(decoded.fields, fields);
    }

    #[tokio::test]
    async fn after_position_round_trips() {
        let fields = vec![b"x".to_vec(), b"y".to_vec()];
        let script = PushDrop::new(&wallet(), None)
            .lock(
                fields.clone(),
                protocol(),
                "k",
                cpty(),
                false,
                false,
                LockPosition::After,
            )
            .await
            .unwrap();

        let decoded = decode_with_position(&script, LockPosition::After).unwrap();
        assert_eq!(decoded.fields, fields);
    }

    #[tokio::test]
    async fn unlock_produces_a_der_signature_with_the_sighash_byte() {
        let sig = PushDrop::new(&wallet(), None)
            .unlock(
                b"preimage",
                protocol(),
                "k",
                cpty(),
                PushDrop::<ProtoWallet>::default_sighash_type(),
            )
            .await
            .unwrap();

        let chunks = sig.chunks();
        assert_eq!(chunks.len(), 1);
        let data = chunks[0].data.as_ref().unwrap();
        assert_eq!(data[0], 0x30, "DER sequence");
        assert_eq!(
            *data.last().unwrap(),
            PushDrop::<ProtoWallet>::default_sighash_type()
        );
    }

    #[test]
    fn decode_non_pushdrop_errors() {
        let script = LockingScript::from_hex("76a914").expect("parses as a script");
        assert!(decode(&script).is_err(), "a P2PKH prefix is not a PushDrop");
    }
}
