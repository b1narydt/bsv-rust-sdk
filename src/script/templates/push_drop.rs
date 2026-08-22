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
use crate::primitives::signature::Signature;
use crate::primitives::transaction_signature::{TransactionSignature, SIGHASH_ALL, SIGHASH_FORKID};
use crate::script::error::ScriptError;
use crate::script::locking_script::LockingScript;
use crate::script::op::Op;
use crate::script::script::Script;
use crate::script::script_chunk::ScriptChunk;
use async_trait::async_trait;

use crate::script::templates::ScriptTemplateUnlock;
use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::sighash_preimage::SighashPreimage;
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

    /// Return the deferred unlocker for a PushDrop output — **without signing**.
    ///
    /// Port of TS `PushDrop.unlock`, which returns `{ sign, estimateLength }` and
    /// signs nothing until the transaction machinery calls `sign`. Rust's
    /// equivalent of that pair is [`ScriptTemplateUnlock`], and the returned
    /// [`PushDropUnlock`] implements it.
    ///
    /// Deferral is not a style choice. A wallet with no local key — an MPC vault,
    /// an HSM — produces a signature by running a ceremony, once, for the WHOLE
    /// transaction. An `unlock` that signed on the spot would convene a second
    /// ceremony at the wrong moment.
    ///
    /// A caller that ALREADY holds the DER — because its ceremony ran once for
    /// the whole transaction — wants no unlocker at all: it calls
    /// [`push_drop_unlocking_script`] directly, which is the same function this
    /// unlocker ends at.
    /// The scope is NOT a parameter here. It is named once, at
    /// [`Transaction::sign`](crate::transaction::Transaction::sign), and arrives
    /// bound to the preimage it produced — see [`SighashPreimage`].
    ///
    /// TS takes `signOutputs: 'all'|'none'|'single'` and `anyoneCanPay: boolean`
    /// at this point and folds them into a scope inside `sign`. This port does not
    /// copy that pair, deliberately: taking it here would put a scope back on the
    /// template, which is the second opinion [`SighashPreimage`] exists to delete.
    /// The scope is a `u32` of the exported `SIGHASH_*` constants, as everywhere
    /// else in this SDK, and TS's defaults are
    /// [`PushDrop::default_sighash_type`] — the same `SIGHASH_ALL | SIGHASH_FORKID`
    /// value `signOutputs='all', anyoneCanPay=false` computes.
    pub fn unlock(
        &self,
        protocol_id: Protocol,
        key_id: &str,
        counterparty: Counterparty,
    ) -> PushDropUnlock<'a, W> {
        PushDropUnlock {
            wallet: self.wallet,
            originator: self.originator.clone(),
            protocol_id,
            key_id: key_id.to_string(),
            counterparty,
        }
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

/// The deferred unlocker returned by [`PushDrop::unlock`].
///
/// TS's `{ sign, estimateLength }`, as a type. `estimate_length` answers 73 like
/// every port; `sign` asks the wallet for a signature over the sighash and
/// assembles the one-push unlocking script.
pub struct PushDropUnlock<'a, W: WalletInterface + ?Sized> {
    /// The wallet that produces the signature.
    pub wallet: &'a W,
    /// Originator passed through on the wallet request.
    pub originator: Option<String>,
    /// Protocol the signing key is derived under.
    pub protocol_id: Protocol,
    /// Key ID the signing key is derived under.
    pub key_id: String,
    /// Counterparty the signing key is derived against.
    pub counterparty: Counterparty,
}

#[async_trait]
impl<W: WalletInterface + ?Sized> ScriptTemplateUnlock for PushDropUnlock<'_, W> {
    /// The wallet is handed `sha256(preimage)` as `data` and hashes once more
    /// internally, so the signed digest is `sha256d(preimage)` — the BSV sighash.
    /// (An older revision signed a SINGLE sha256 of the preimage, which is not a
    /// valid BSV sighash.)
    async fn sign(&self, preimage: &SighashPreimage) -> Result<UnlockingScript, ScriptError> {
        let preimage_hash = sha256(preimage.bytes());
        let bare_der = self
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    protocol_id: self.protocol_id.clone(),
                    key_id: self.key_id.clone(),
                    counterparty: self.counterparty.clone(),
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
            })?
            .signature;
        push_drop_unlocking_script(&bare_der, preimage.scope() as u8)
    }

    fn estimate_length(&self) -> Result<usize, ScriptError> {
        Ok(73)
    }
}

/// **The one place a PushDrop unlocking script is assembled.**
///
/// `bare_der` is the DER-encoded ECDSA signature; `sighash_type` is the scope
/// byte. The result is a single push of `DER ++ sighash`.
///
/// The DER is PARSED and RE-SERIALIZED, matching TS
/// (`Signature.fromDER(bare)` → `new TransactionSignature(r, s, scope)` →
/// `toChecksigFormat()`) rather than appending the scope byte to whatever the
/// signer returned. For canonical DER — which is what `createSignature` and the
/// MPC ceremony both produce — the bytes are identical; for anything else the
/// round trip either rejects it here, where the error names PushDrop, or emits
/// the canonical encoding instead of relaying a malformed script to the network.
/// It does NOT touch S: TS's `toChecksigFormat` does not force low-S either, so
/// a high-S signature stays high-S in both SDKs.
pub fn push_drop_unlocking_script(
    bare_der: &[u8],
    sighash_type: u8,
) -> Result<UnlockingScript, ScriptError> {
    let sig = Signature::from_der(bare_der).map_err(|e| {
        ScriptError::InvalidSignature(format!("PushDrop unlock: signature is not valid DER: {e}"))
    })?;
    let sig_bytes = TransactionSignature::new(sig, sighash_type as u32).to_checksig_format();

    let chunks = vec![ScriptChunk::new_raw(sig_bytes.len() as u8, Some(sig_bytes))];
    Ok(UnlockingScript::from_script(Script::from_chunks(chunks)))
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
    use crate::transaction::sighash_preimage::test_support::preimage_under;
    use crate::wallet::proto_wallet::ProtoWallet;

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

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

    // -----------------------------------------------------------------------
    // unlock: deferred — it returns an unlocker and signs NOTHING until asked
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unlock_produces_a_der_signature_with_the_sighash_byte() {
        let w = wallet();
        let sig = PushDrop::new(&w, None)
            .unlock(protocol(), "k", cpty())
            .sign(&preimage_under(SIGHASH_ALL | SIGHASH_FORKID))
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

    /// **The regression test for the split sighash scope.**
    ///
    /// Before [`SighashPreimage`], `Transaction::sign` computed the preimage under
    /// a `scope` argument while `PushDrop::unlock` captured a `sighash_type` of its
    /// own, and NOTHING bound the two. Signing under one scope while the template
    /// stamped another compiled, signed, and produced a script the network
    /// rejects. The template now holds no scope to disagree with.
    ///
    /// Both halves are checked against values derived OUTSIDE this module: the
    /// signing key straight from the deriver, the digest straight from the BSV
    /// rule (`hash256` of the preimage), the scope a non-default one so a
    /// hard-coded `0x41` cannot pass.
    #[tokio::test]
    async fn the_scope_reaches_both_halves_of_the_signature() {
        use crate::primitives::ecdsa::ecdsa_sign;
        use crate::primitives::hash::hash256;
        use crate::primitives::transaction_signature::SIGHASH_NONE;
        use crate::transaction::{Transaction, TransactionInput, TransactionOutput};
        use crate::wallet::key_deriver::KeyDeriver;

        let w = wallet();
        let pd = PushDrop::new(&w, None);
        let lock = pd
            .lock(
                vec![b"field".to_vec()],
                protocol(),
                "k",
                cpty(),
                false,
                false,
                LockPosition::Before,
            )
            .await
            .unwrap();

        // NOT the default scope: SIGHASH_NONE | SIGHASH_FORKID == 0x42.
        let scope = SIGHASH_NONE | SIGHASH_FORKID;
        assert_ne!(scope as u8, PushDrop::<ProtoWallet>::default_sighash_type());

        let mut tx = Transaction::new();
        tx.add_input(TransactionInput {
            source_transaction: None,
            source_txid: Some("cd".repeat(32)),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffff_ffff,
        });
        tx.add_output(TransactionOutput {
            satoshis: Some(900),
            locking_script: lock.clone(),
            change: false,
        });

        let unlocker = pd.unlock(protocol(), "k", cpty());
        tx.sign(0, &unlocker, scope, 1_000, &lock)
            .await
            .expect("signing should succeed");

        let script_sig = tx.inputs[0].unlocking_script.as_ref().unwrap().chunks()[0]
            .data
            .clone()
            .unwrap();
        let (der, sighash_byte) = script_sig.split_at(script_sig.len() - 1);

        // (a) the script advertises the scope the caller named.
        assert_eq!(
            sighash_byte[0], scope as u8,
            "the script's sighash byte must be the scope Transaction::sign was given"
        );

        // (b) the signature commits to the preimage computed under that SAME scope.
        let preimage = tx.sighash_preimage(0, scope, 1_000, &lock).unwrap();
        assert_eq!(
            preimage.scope(),
            scope,
            "the preimage reports its own scope"
        );
        let sk = KeyDeriver::new(PrivateKey::from_bytes(&[0x55u8; 32]).unwrap())
            .derive_private_key(&protocol(), "k", &cpty())
            .unwrap();
        let expected = ecdsa_sign(&hash256(preimage.bytes()), sk.bn(), true)
            .unwrap()
            .to_der();
        assert_eq!(
            der,
            &expected[..],
            "the signature must be over the preimage its own sighash byte names"
        );

        // ... and NOT over the preimage under the scope the template used to hold.
        let default_scope = tx
            .sighash_preimage(0, SIGHASH_ALL | SIGHASH_FORKID, 1_000, &lock)
            .unwrap();
        let wrong = ecdsa_sign(&hash256(default_scope.bytes()), sk.bn(), true)
            .unwrap()
            .to_der();
        assert_ne!(
            der,
            &wrong[..],
            "the two scopes must actually produce different signatures, or this proves nothing"
        );
    }

    /// **The digest is `sha256d(preimage)`, not `sha256(preimage)`.**
    ///
    /// The wallet is handed `sha256(preimage)` as `data` and hashes once more
    /// internally; get that wrong and the signature is over a digest OP_CHECKSIG
    /// never computes. The expected DER here is derived independently of this
    /// module — the signing key straight from the deriver, the digest straight
    /// from the BSV rule — so it cannot agree with a mistake by construction. The
    /// control at the end proves the two digests really do differ, i.e. that the
    /// assertion above has something to catch.
    #[tokio::test]
    async fn the_wallet_signs_the_double_hashed_preimage() {
        use crate::primitives::ecdsa::ecdsa_sign;
        use crate::primitives::hash::hash256;
        use crate::wallet::key_deriver::KeyDeriver;

        let w = wallet();
        let scope = PushDrop::<ProtoWallet>::default_sighash_type();
        let preimage = preimage_under(SIGHASH_ALL | SIGHASH_FORKID);

        let script = PushDrop::new(&w, None)
            .unlock(protocol(), "k", cpty())
            .sign(&preimage)
            .await
            .unwrap();

        let sk = KeyDeriver::new(PrivateKey::from_bytes(&[0x55u8; 32]).unwrap())
            .derive_private_key(&protocol(), "k", &cpty())
            .unwrap();
        let expected_der = ecdsa_sign(&hash256(preimage.bytes()), sk.bn(), true)
            .unwrap()
            .to_der();

        let mut expected = expected_der.clone();
        expected.push(scope);
        assert_eq!(
            script.chunks()[0].data.as_ref().unwrap(),
            &expected,
            "the script must be one push of DER-over-sha256d(preimage) ++ the sighash byte"
        );

        // Control: the single-hash digest yields a DIFFERENT signature, so the
        // assertion above is not satisfied by both.
        let single_hashed = ecdsa_sign(&sha256(preimage.bytes()), sk.bn(), true)
            .unwrap()
            .to_der();
        assert_ne!(expected_der, single_hashed);
    }

    /// **The assembly stamps the scope it is given, not a constant.**
    ///
    /// Every other test in this file signs under `SIGHASH_ALL | SIGHASH_FORKID`,
    /// so a `0x41` written into the assembly in place of the argument would pass
    /// all of them. The expected script is composed HERE from a fixed DER vector
    /// and the scope byte, for several scopes.
    #[test]
    fn assembly_stamps_the_scope_it_is_given_not_a_constant() {
        let der = hex_to_bytes(
            "30440220111111111111111111111111111111111111111111111111111111111111111102202222222222222222222222222222222222222222222222222222222222222222",
        );

        // ALL|FORKID, NONE|FORKID, SINGLE|FORKID, ALL|FORKID|ANYONECANPAY, and a
        // bare ALL with no FORKID bit.
        for scope in [0x41u8, 0x42, 0x43, 0xc1, 0x01] {
            let script = push_drop_unlocking_script(&der, scope).unwrap();
            assert_eq!(
                script.to_hex(),
                format!("47{}{scope:02x}", bytes_to_hex(&der)),
                "scope {scope:#04x} must reach the script"
            );
        }
    }

    /// Parity with TS: `Signature.fromDER` → `TransactionSignature.toChecksigFormat`.
    /// A fixed vector, so the assembly is pinned independently of any wallet.
    #[test]
    fn assembly_matches_the_ts_checksig_format_for_a_fixed_vector() {
        // A canonical low-S DER signature (r and s both 32 bytes, high bit clear).
        let der = hex_to_bytes(
            "3044             0220             1111111111111111111111111111111111111111111111111111111111111111             0220             2222222222222222222222222222222222222222222222222222222222222222",
        );
        let script = push_drop_unlocking_script(&der, 0x41).unwrap();
        let data = script.chunks()[0].data.as_ref().unwrap();

        let mut expected = der.clone();
        expected.push(0x41);
        assert_eq!(data, &expected);
        assert_eq!(
            script.to_hex(),
            format!("47{}41", bytes_to_hex(&der)),
            "one 0x47-byte push of DER ++ sighash"
        );
    }

    /// The normalisation TS performs and the old Rust append did not: garbage
    /// that is not DER is refused HERE, naming PushDrop, rather than relayed
    /// into a transaction.
    #[test]
    fn assembly_refuses_a_signature_that_is_not_der() {
        assert!(push_drop_unlocking_script(&[0xde, 0xad, 0xbe, 0xef], 0x41).is_err());
    }

    #[test]
    fn estimate_length_is_73_like_every_other_port() {
        let w = wallet();
        let unlocker = PushDrop::new(&w, None).unlock(protocol(), "k", cpty());
        assert_eq!(unlocker.estimate_length().unwrap(), 73);
        assert_eq!(PushDrop::<ProtoWallet>::estimate_unlock_length(), 73);
    }

    /// The point of the async trait: the wallet arm SIGNS through `sign()` —
    /// there is no second entry point and no runtime refusal. Before the trait
    /// was async this same call returned an error telling the caller to go use
    /// `sign_async` instead.
    #[tokio::test]
    async fn the_wallet_arm_signs_through_the_trait_method() {
        let w = wallet();
        let unlocker = PushDrop::new(&w, None).unlock(protocol(), "k", cpty());
        let script = unlocker
            .sign(&preimage_under(SIGHASH_ALL | SIGHASH_FORKID))
            .await
            .expect("wallet arm signs");
        let data = script.chunks()[0].data.as_ref().unwrap();
        assert_eq!(data[0], 0x30, "DER sequence");
        assert_eq!(*data.last().unwrap(), 0x41, "sighash byte");
    }

    /// The wallet arm is reachable through `&dyn ScriptTemplateUnlock` — the way
    /// `Transaction::sign` drives it — which a synchronous trait could not do.
    #[tokio::test]
    async fn the_wallet_arm_signs_through_a_trait_object() {
        let w = wallet();
        let unlocker = PushDrop::new(&w, None).unlock(protocol(), "k", cpty());
        let as_dyn: &dyn ScriptTemplateUnlock = &unlocker;
        assert!(as_dyn
            .sign(&preimage_under(SIGHASH_ALL | SIGHASH_FORKID))
            .await
            .is_ok());
        assert_eq!(as_dyn.estimate_length().unwrap(), 73);
    }

    #[test]
    fn decode_non_pushdrop_errors() {
        let script = LockingScript::from_hex("76a914").expect("parses as a script");
        assert!(decode(&script).is_err(), "a P2PKH prefix is not a PushDrop");
    }
}
