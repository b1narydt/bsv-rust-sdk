//! STAS-3 (canonical 2,899-byte engine) — token primitives.
//!
//! STAS-3 is a Bitcoin SV covenant template implementing fungible-token
//! semantics on top of bare script. The engine is a 2,899-byte block of
//! script bytecode that enforces — at unlock time — a set of rules over
//! every token operation: ownership transfer, multi-input merge, atomic
//! cross-token swap, freeze/unfreeze, confiscation, and one-shot
//! redemption back to the issuer.
//!
//! This module provides:
//! - Script primitives ([`build_locking_script`], [`decode_locking_script`])
//! - Operation factories ([`factory::build_transfer`],
//!   [`factory::build_split`], [`factory::build_merge`] (atomic 2-input;
//!   use [`factory::build_merge_chain`] for N>2 via chained binary-tree
//!   merges, mirroring the dxs reference SDK),
//!   [`factory::build_swap_mark`], [`factory::build_swap_cancel`],
//!   [`factory::build_swap_execute`], [`factory::build_freeze`],
//!   [`factory::build_unfreeze`], [`factory::build_confiscate`],
//!   [`factory::build_redeem`])
//! - A high-level wallet wrapper ([`Stas3Wallet`]) that owns Type-42
//!   key derivation and basket management
//! - Engine-side verification ([`verify_input`])
//! - The EAC schema overlay ([`build_eac_lock`], [`EacFields`]) and an
//!   EAC byte-template layout exporter ([`build_eac_template`])
//!
//! ## Type-42 key policy (spec §1A)
//!
//! Every key reference in this module flows through a [`KeyTriple`] —
//! `(protocolID, keyID, counterparty)` — resolved at sign / derive time
//! by a [`crate::wallet::interfaces::WalletInterface`] implementation.
//! The factories never see raw private keys. Pubkey hashes used in lock
//! scripts (owner_pkh, redemption_pkh, freeze authority, etc.) are
//! derived deterministically by the wallet from the triple.
//!
//! ## Quick start
//!
//! ```ignore
//! use bsv_sdk::script::templates::stas3::{
//!     Stas3Wallet, KeyTriple,
//!     factory::{TokenInput, FundingInput},
//! };
//! use bsv_sdk::wallet::proto_wallet::ProtoWallet;
//! use std::sync::Arc;
//!
//! # async fn example(wallet: Arc<ProtoWallet>) -> Result<(), Box<dyn std::error::Error>> {
//! let stas = Stas3Wallet::new(wallet);
//! let token: TokenInput = /* resolved via stas.find_token(outpoint).await? */
//! #     unimplemented!();
//! let funding: FundingInput = /* resolved via stas.pick_fuel(min_sats).await? */
//! #     unimplemented!();
//! let new_owner_pkh = [0u8; 20];
//! let change_pkh = [0u8; 20];
//! let tx = stas.transfer(token, funding, new_owner_pkh, change_pkh, 4_800, None).await?;
//! // broadcast, then:
//! // stas.internalize_stas_outputs(tx_bytes, vec![(0, new_owner_triple, None)], "stas3 transfer").await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Wire-format reference
//!
//! The locking-script layout, unlocking-script slot layout, and trailing
//! piece-array encoding (for merge / atomic-swap) match the canonical
//! `stas3-sdk` TypeScript reference at
//! `~/METAWATT/METAWATT-code/stas3-sdk/`. See `unlock::TrailingParams`
//! for the merge-section format and `factory::pieces` for the
//! source-tx-segmentation logic.

pub mod action_data;
pub mod constants;
pub mod decode;
pub mod eac;
pub mod error;
pub mod factory;
pub mod flags;
pub mod key_triple;
pub mod lock;
pub mod multisig;
pub mod owner_address;
pub mod eac_template;
pub mod sighash;
pub mod spend_type;
pub mod unlock;
pub mod verify;
pub mod wallet;

// ---------- Public API: import everything you need from one path ----------
//
// `use bsv_sdk::script::templates::stas3::*;` brings the high-level wallet
// wrapper, the lock/unlock builders, the action-data primitives, the EAC
// schema, and engine verification into scope. Lower-level factory request
// types live under `factory::` to keep the top namespace tidy.

pub use action_data::{ActionData, NextVar2, SwapDescriptor, SwapDescriptorError};
pub use decode::{decode_locking_script, DecodedLock};
pub use eac::{build_eac_lock, EacFields, EnergySource, EAC_SCHEMA_TAG_V1};
pub use error::Stas3Error;
pub use flags::{CONFISCATABLE, FREEZABLE};
pub use key_triple::KeyTriple;
pub use lock::{build_locking_script, LockParams};
pub use multisig::{
    p2mpkh_locking_script_bytes, MultisigScript, MAX_MULTISIG_KEYS, MIN_MULTISIG_KEYS,
};
pub use owner_address::OwnerAddress;
pub use eac_template::{build_eac_template, EacFieldSlot, EacTemplate};

// Deprecated re-exports under the old names for one-release backwards
// compatibility. The historical `runar` naming was misleading: the file
// only exposed an EAC byte-template layout, not an integration with the
// icellan/runar multi-language smart-contract compiler.
#[deprecated(
    since = "0.2.83",
    note = "renamed: see EacTemplate; runar.rs only exposed an EAC byte-template layout, not a Runar runtime integration"
)]
pub use eac_template::EacTemplate as EacRunarTemplate;
#[deprecated(
    since = "0.2.83",
    note = "renamed: see build_eac_template"
)]
pub use eac_template::build_eac_template as build_eac_runar_template;
pub use sighash::{build_preimage, STAS3_SIGHASH_SCOPE};
pub use spend_type::{SpendType, TxType};
pub use unlock::{
    build_transfer_unlocking, build_unlocking_script, AuthzWitness, ChangeWitness,
    FundingPointer, StasOutputWitness, TrailingParams, TransferUnlockParams, UnlockParams,
};
pub use verify::verify_input;
pub use wallet::{CustomInstructions, Stas3Wallet, Stas3WalletConfig};

// Factory request types — most callers will reach for `Stas3Wallet`
// methods, but the raw factory functions (and their request structs) are
// exported for advanced flows that need finer control.
pub use factory::{
    build_confiscate, build_freeze, build_merge, build_merge_chain, build_redeem,
    build_split, build_swap_cancel, build_swap_execute, build_swap_mark,
    build_transfer, build_unfreeze, ConfiscateRequest, FreezeRequest, FundingInput,
    MergeChainRequest, MergeRequest, RedeemRequest, SigningKey, SplitDestination,
    SplitRequest, SwapCancelRequest, SwapExecuteRequest, SwapMarkRequest, TokenInput,
    TransferRequest, UnfreezeRequest,
};

#[cfg(test)]
mod integration_tests {
    use super::action_data::ActionData;
    use super::constants;
    use super::lock::{build_locking_script, LockParams};
    use super::sighash::build_preimage;
    use super::unlock::{
        build_transfer_unlocking, ChangeWitness, FundingPointer, StasOutputWitness,
        TransferUnlockParams,
    };
    use super::verify::verify_input;
    use crate::primitives::hash::{hash160, hash256};
    use crate::primitives::private_key::PrivateKey;
    use crate::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
    use crate::script::locking_script::LockingScript;
    use crate::script::unlocking_script::UnlockingScript;
    use crate::transaction::transaction::Transaction;
    use crate::transaction::transaction_input::TransactionInput;
    use crate::transaction::transaction_output::TransactionOutput;
    use crate::wallet::interfaces::{
        CreateSignatureArgs, GetPublicKeyArgs, WalletInterface,
    };
    use crate::wallet::proto_wallet::ProtoWallet;
    use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

    async fn derive_pkh(wallet: &ProtoWallet, protocol: &str, key_id: &str) -> [u8; 20] {
        let pk = wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(Protocol {
                        security_level: 2,
                        protocol: protocol.to_string(),
                    }),
                    key_id: Some(key_id.to_string()),
                    counterparty: Some(Counterparty {
                        counterparty_type: CounterpartyType::Self_,
                        public_key: None,
                    }),
                    privileged: false,
                    privileged_reason: None,
                    for_self: Some(true),
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap();
        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&hash160(&pk.public_key.to_der()));
        pkh
    }

    /// Resolve a Type-42 triple to its `PublicKey`. Mirrors `derive_pkh`
    /// but returns the full public key (33-byte compressed) — used by
    /// the MPKH/multisig integration tests to assemble the redeem-script
    /// pubkey vector.
    async fn derive_pubkey(
        wallet: &ProtoWallet,
        protocol: &str,
        key_id: &str,
    ) -> crate::primitives::public_key::PublicKey {
        let pk = wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(Protocol {
                        security_level: 2,
                        protocol: protocol.to_string(),
                    }),
                    key_id: Some(key_id.to_string()),
                    counterparty: Some(Counterparty {
                        counterparty_type: CounterpartyType::Self_,
                        public_key: None,
                    }),
                    privileged: false,
                    privileged_reason: None,
                    for_self: Some(true),
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap();
        pk.public_key
    }

    fn make_p2pkh_lock(pkh: &[u8; 20]) -> LockingScript {
        let mut bytes = Vec::with_capacity(25);
        bytes.push(0x76); // OP_DUP
        bytes.push(0xa9); // OP_HASH160
        bytes.push(0x14); // PUSH20
        bytes.extend_from_slice(pkh);
        bytes.push(0x88); // OP_EQUALVERIFY
        bytes.push(0xac); // OP_CHECKSIG
        LockingScript::from_binary(&bytes)
    }

    /// End-to-end test: build a STAS-3 token; build a transfer tx that
    /// consumes it; sign with a Type-42 wallet-derived key; verify the
    /// engine accepts the spend.
    ///
    /// THIS IS THE PHASE 4 GATE.
    #[tokio::test]
    async fn test_transfer_engine_verifies() {
        // 1. Set up: derive Type-42 keys for owner + funding via ProtoWallet
        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let new_owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "2").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;

        // Arbitrary issuer identity for this test
        let redemption_pkh = [0xab; 20];

        // 2. Build the source tx — contains a STAS-3 UTXO at vout 0 and a
        //    P2PKH funding UTXO at vout 1.
        let stas_amount: u64 = 10_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        let funding_amount: u64 = 5_000;
        let funding_lock = make_p2pkh_lock(&funding_pkh);

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: funding_lock.clone(),
            change: false,
        });
        let source_txid_hex = source_tx
            .id()
            .expect("source tx id");

        // 3. Build the spending tx — STAS in (vout 0), funding in (vout 1)
        //                            STAS out at new owner, P2PKH change to funding owner
        let new_stas_lock = build_locking_script(&LockParams {
            owner_pkh: new_owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();
        let change_amount = funding_amount - 200; // leave 200 sats for fee
        let change_lock = make_p2pkh_lock(&funding_pkh);

        let mut spend_tx = Transaction::new();
        spend_tx.version = constants::STAS3_TX_VERSION; // 2 — relaxed mode
        spend_tx.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(source_txid_hex.clone()),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
        spend_tx.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(source_txid_hex.clone()),
            source_output_index: 1,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
        spend_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: new_stas_lock,
            change: false,
        });
        spend_tx.outputs.push(TransactionOutput {
            satoshis: Some(change_amount),
            locking_script: change_lock,
            change: false,
        });

        // 4. Build the BIP-143 preimage for the STAS input (input 0).
        let preimage = build_preimage(&spend_tx, 0, stas_amount, &stas_lock).unwrap();
        let preimage_hash = hash256(&preimage).to_vec();

        // 5. Sign the preimage_hash via the wallet (Type-42 derivation under
        //    "stas3owner"/"1", counterparty=Self).
        let sig_res = owner_wallet
            .create_signature(
                CreateSignatureArgs {
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: "stas3owner".to_string(),
                    },
                    key_id: "1".to_string(),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Self_,
                        public_key: None,
                    },
                    data: None,
                    hash_to_directly_sign: Some(preimage_hash),
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap();
        // Append SIGHASH byte (= STAS3_SIGHASH_SCOPE = 0x41).
        let mut sig_with_hash = sig_res.signature;
        sig_with_hash.push((SIGHASH_ALL | SIGHASH_FORKID) as u8);

        // Get pubkey for the same triple.
        let pk = owner_wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(Protocol {
                        security_level: 2,
                        protocol: "stas3owner".to_string(),
                    }),
                    key_id: Some("1".to_string()),
                    counterparty: Some(Counterparty {
                        counterparty_type: CounterpartyType::Self_,
                        public_key: None,
                    }),
                    privileged: false,
                    privileged_reason: None,
                    for_self: Some(true),
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap();
        let pubkey_bytes = pk.public_key.to_der(); // 33-byte compressed

        // Sanity: pubkey hash matches the owner_pkh on the locking script.
        let pkh_check: [u8; 20] = hash160(&pubkey_bytes);
        assert_eq!(
            pkh_check, owner_pkh,
            "derived pubkey doesn't hash to the owner_pkh embedded in the lock"
        );

        // Suppress unused-warning on funding_wallet; keep param for future P2PKH input sign.
        let _ = &funding_wallet;

        // 6. Funding tx pointer — the source tx that holds the funding UTXO.
        //    Source txid is in display/BE hex; we need LE bytes for the unlock slot.
        let txid_be_bytes = hex_be_to_bytes(&source_txid_hex);
        let mut txid_le = [0u8; 32];
        for (i, b) in txid_be_bytes.iter().rev().enumerate() {
            txid_le[i] = *b;
        }

        // 7. Build the unlocking script.
        let unlock_bytes = build_transfer_unlocking(&TransferUnlockParams {
            stas_output: StasOutputWitness {
                satoshis: stas_amount,
                owner_pkh: new_owner_pkh,
                var2_bytes: vec![],
            },
            change: Some(ChangeWitness {
                satoshis: change_amount,
                owner_pkh: funding_pkh,
            }),
            funding: Some(FundingPointer {
                vout: 1,
                txid_le,
            }),
            preimage: preimage.clone(),
            signature: sig_with_hash,
            pubkey: pubkey_bytes,
        })
        .unwrap();
        spend_tx.inputs[0].unlocking_script = Some(UnlockingScript::from_binary(&unlock_bytes));

        // 8. THE GATE: engine-verify the STAS input.
        let result = verify_input(&spend_tx, 0, &stas_lock, stas_amount);
        match &result {
            Ok(true) => { /* gate passed */ }
            Ok(false) => panic!(
                "engine rejected the STAS-3 transfer spend (Ok(false) — interpreter \
                 completed but result was falsy). \n\
                 Unlocking script ({} bytes): {}\n\
                 Owner pkh on lock: {:02x?}\n\
                 PKH from pubkey:   {:02x?}",
                unlock_bytes.len(),
                hex_dump(&unlock_bytes),
                owner_pkh,
                pkh_check,
            ),
            Err(e) => panic!(
                "engine errored on STAS-3 transfer spend: {e:?}\n\
                 Unlocking script ({} bytes): {}\n\
                 Owner pkh on lock: {:02x?}\n\
                 PKH from pubkey:   {:02x?}",
                unlock_bytes.len(),
                hex_dump(&unlock_bytes),
                owner_pkh,
                pkh_check,
            ),
        }
        assert!(result.unwrap());
    }

    /// Decode a BE-hex string to a Vec<u8>. Length must be even.
    fn hex_be_to_bytes(hex: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(hex.len() / 2);
        let bytes = hex.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn hex_dump(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// Phase 5a gate: build a transfer via the factory and engine-verify
    /// the STAS input. Mirrors `test_transfer_engine_verifies` but goes
    /// through `factory::build_transfer` instead of hand-assembling the tx.
    #[tokio::test]
    async fn test_factory_transfer_engine_verifies() {
        use super::factory::{build_transfer, FundingInput, TokenInput, TransferRequest};

        // 1. Derive Type-42 keys.
        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let new_owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "2").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        // 2. Build the source tx with the STAS UTXO at vout 0 and the
        //    funding UTXO at vout 1.
        let stas_amount: u64 = 10_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        // 3. Build the transfer via the factory.
        let req = TransferRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_input: TokenInput {
                txid_hex: source_txid_hex.clone(),
                vout: 0,
                satoshis: stas_amount,
                locking_script: stas_lock.clone(),
                signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: None,
            },
            funding_input: FundingInput {
                txid_hex: source_txid_hex.clone(),
                vout: 1,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            destination_owner_pkh: new_owner_pkh,
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
            note: None,
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_transfer(req).await.unwrap();

        // 4. THE GATE: engine-verify the STAS input on the factory-built tx.
        let valid = verify_input(&tx, 0, &stas_lock, stas_amount).unwrap();
        assert!(valid, "engine rejected the factory-built transfer spend");
    }

    /// Wave-2A.3 gate: MPKH/multisig owner signing across the factory
    /// pipeline. Mints STAS-3 tokens whose `owner_pkh` is the 20-byte
    /// `MPKH` of an `M`-of-`N` multisig redeem script (spec §10.2 P2MPKH
    /// path), transfers them via `SigningKey::Multi { triples, multisig }`,
    /// and engine-verifies the produced unlock against the lock.
    ///
    /// Three sub-shapes exercised by this single test (one assertion
    /// helper, three call sites — each tagged with the variant):
    ///   - 2-of-3 (canonical small-multisig case)
    ///   - 3-of-5 (max threshold, max keys per spec)
    ///   - 1-of-1 (collapses to a single-sig but still exercises the
    ///     P2MPKH wire format — useful as a structural sanity check
    ///     that the P2MPKH path's `OP_0 sig redeem` shape engine-verifies
    ///     for the trivial threshold).
    #[tokio::test]
    async fn test_factory_transfer_with_mpkh_owner_engine_verifies() {
        use super::factory::types::SigningKey;
        use super::factory::{build_transfer, FundingInput, TokenInput, TransferRequest};
        use super::multisig::MultisigScript;

        // Helper closure: mint a STAS-3 UTXO at `owner_mpkh`, then
        // transfer it via `signing_key`. Returns whether the engine
        // accepted the spend, plus the produced tx for further
        // assertions.
        async fn run_mpkh_transfer_case(
            owner_root: PrivateKey,
            funding_root: PrivateKey,
            triples: Vec<super::key_triple::KeyTriple>,
            multisig: MultisigScript,
            label: &'static str,
        ) {
            let owner_wallet = ProtoWallet::new(owner_root);
            let funding_wallet = ProtoWallet::new(funding_root);

            let owner_mpkh = multisig.mpkh();
            let new_owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "dest").await;
            let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
            let redemption_pkh = [0xab; 20];

            // Build the STAS lock with `owner_pkh = MPKH` per spec §10.2.
            let stas_amount: u64 = 10_000;
            let funding_amount: u64 = 5_000;
            let stas_lock = build_locking_script(&LockParams {
                owner_pkh: owner_mpkh,
                action_data: ActionData::Passive(vec![]),
                redemption_pkh,
                flags: 0,
                service_fields: vec![],
                optional_data: vec![],
            })
            .unwrap();

            // Source tx: STAS at vout 0, funding at vout 1.
            let mut source_tx = Transaction::new();
            source_tx.outputs.push(TransactionOutput {
                satoshis: Some(stas_amount),
                locking_script: stas_lock.clone(),
                change: false,
            });
            source_tx.outputs.push(TransactionOutput {
                satoshis: Some(funding_amount),
                locking_script: make_p2pkh_lock(&funding_pkh),
                change: false,
            });
            let source_txid_hex = source_tx.id().expect("source tx id");

            // Build the transfer with a `SigningKey::Multi` for the STAS
            // input. The factory signs with each triple in input order
            // and emits an `AuthzWitness::P2mpkh` (OP_0 sig...sig redeem).
            let req = TransferRequest {
                wallet: &owner_wallet,
                originator: None,
                stas_input: TokenInput {
                    txid_hex: source_txid_hex.clone(),
                    vout: 0,
                    satoshis: stas_amount,
                    locking_script: stas_lock.clone(),
                    signing_key: SigningKey::Multi {
                        triples,
                        multisig: multisig.clone(),
                    },
                    current_action_data: ActionData::Passive(vec![]),
                    source_tx_bytes: None,
                },
                funding_input: FundingInput {
                    txid_hex: source_txid_hex.clone(),
                    vout: 1,
                    satoshis: funding_amount,
                    locking_script: make_p2pkh_lock(&funding_pkh),
                    triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
                },
                destination_owner_pkh: new_owner_pkh,
                redemption_pkh,
                flags: 0,
                service_fields: vec![],
                optional_data: vec![],
                note: None,
                change_pkh: funding_pkh,
                change_satoshis: funding_amount - 200,
            };
            let tx = build_transfer(req).await.unwrap();

            // Engine-verify the STAS input.
            let result = verify_input(&tx, 0, &stas_lock, stas_amount);
            match &result {
                Ok(true) => {}
                Ok(false) => panic!(
                    "[{label}] engine rejected MPKH transfer (Ok(false))\n\
                     unlocking_script bytes: {}",
                    tx.inputs[0]
                        .unlocking_script
                        .as_ref()
                        .map(|s| hex_dump(&s.to_binary()))
                        .unwrap_or_default()
                ),
                Err(e) => panic!(
                    "[{label}] engine errored on MPKH transfer: {e:?}\n\
                     unlocking_script bytes: {}",
                    tx.inputs[0]
                        .unlocking_script
                        .as_ref()
                        .map(|s| hex_dump(&s.to_binary()))
                        .unwrap_or_default()
                ),
            }
            assert!(
                result.unwrap(),
                "[{label}] engine rejected the factory-built MPKH transfer spend"
            );
        }

        // ---- 2-of-3 (canonical small multisig) ----
        {
            let owner_root = PrivateKey::from_hex("01").unwrap();
            let owner_wallet = ProtoWallet::new(owner_root.clone());
            let pk_1 = derive_pubkey(&owner_wallet, "stas3owner", "ms-1").await;
            let pk_2 = derive_pubkey(&owner_wallet, "stas3owner", "ms-2").await;
            let pk_3 = derive_pubkey(&owner_wallet, "stas3owner", "ms-3").await;
            let multisig =
                MultisigScript::new(2, vec![pk_1, pk_2, pk_3]).expect("2-of-3 valid");
            // Threshold 2 → caller supplies 2 triples (positions 1, 2).
            let triples = vec![
                super::key_triple::KeyTriple::self_under("stas3owner", "ms-1"),
                super::key_triple::KeyTriple::self_under("stas3owner", "ms-2"),
            ];
            run_mpkh_transfer_case(
                owner_root,
                PrivateKey::from_hex("02").unwrap(),
                triples,
                multisig,
                "2-of-3",
            )
            .await;
        }

        // ---- 3-of-5 (max-spec multisig) ----
        {
            let owner_root = PrivateKey::from_hex("03").unwrap();
            let owner_wallet = ProtoWallet::new(owner_root.clone());
            let mut pks = Vec::with_capacity(5);
            for i in 1..=5 {
                pks.push(
                    derive_pubkey(&owner_wallet, "stas3owner", &format!("ms-3of5-{i}")).await,
                );
            }
            let multisig = MultisigScript::new(3, pks).expect("3-of-5 valid");
            // Threshold 3 → caller supplies 3 triples (positions 1, 2, 3).
            let triples = (1..=3)
                .map(|i| {
                    super::key_triple::KeyTriple::self_under(
                        "stas3owner",
                        format!("ms-3of5-{i}"),
                    )
                })
                .collect();
            run_mpkh_transfer_case(
                owner_root,
                PrivateKey::from_hex("04").unwrap(),
                triples,
                multisig,
                "3-of-5",
            )
            .await;
        }

        // ---- 1-of-1 (single-sig collapse via the P2MPKH path) ----
        // Per spec §10.2, the P2MPKH wire format works for all
        // 1 <= m <= n <= 5 — including the trivial 1-of-1 where the
        // redeem script holds a single pubkey. Useful as a structural
        // sanity check that the engine accepts the `OP_0 sig redeem`
        // form even when there's only one signature.
        {
            let owner_root = PrivateKey::from_hex("05").unwrap();
            let owner_wallet = ProtoWallet::new(owner_root.clone());
            let pk_1 = derive_pubkey(&owner_wallet, "stas3owner", "ms-1of1").await;
            let multisig = MultisigScript::new(1, vec![pk_1]).expect("1-of-1 valid");
            let triples = vec![super::key_triple::KeyTriple::self_under(
                "stas3owner",
                "ms-1of1",
            )];
            run_mpkh_transfer_case(
                owner_root,
                PrivateKey::from_hex("06").unwrap(),
                triples,
                multisig,
                "1-of-1",
            )
            .await;
        }
    }

    /// Phase 5b gate (split, 2-way): build a 1000-sat STAS UTXO and split it
    /// 600 + 400 to two distinct destination owners; engine-verify input.
    #[tokio::test]
    async fn test_factory_split_engine_verifies() {
        use super::factory::{build_split, FundingInput, SplitDestination, SplitRequest, TokenInput};

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let dest_a_pkh = derive_pkh(&owner_wallet, "stas3owner", "2").await;
        let dest_b_pkh = derive_pkh(&owner_wallet, "stas3owner", "3").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        let stas_amount: u64 = 1_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        let req = SplitRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_input: TokenInput {
                txid_hex: source_txid_hex.clone(),
                vout: 0,
                satoshis: stas_amount,
                locking_script: stas_lock.clone(),
                signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: None,
            },
            funding_input: FundingInput {
                txid_hex: source_txid_hex.clone(),
                vout: 1,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            destinations: vec![
                SplitDestination {
                    owner_pkh: dest_a_pkh,
                    satoshis: 600,
                },
                SplitDestination {
                    owner_pkh: dest_b_pkh,
                    satoshis: 400,
                },
            ],
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
            note: None,
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_split(req).await.unwrap();

        let valid = verify_input(&tx, 0, &stas_lock, stas_amount).unwrap();
        assert!(valid, "engine rejected the factory-built split spend");
    }

    /// Phase 5b gate (split, 3-way): exercise a 333 + 333 + 334 split to
    /// confirm that >2 destinations also engine-verify.
    #[tokio::test]
    async fn test_factory_split_3way_engine_verifies() {
        use super::factory::{build_split, FundingInput, SplitDestination, SplitRequest, TokenInput};

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let dest_a_pkh = derive_pkh(&owner_wallet, "stas3owner", "2").await;
        let dest_b_pkh = derive_pkh(&owner_wallet, "stas3owner", "3").await;
        let dest_c_pkh = derive_pkh(&owner_wallet, "stas3owner", "4").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        let stas_amount: u64 = 1_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        let req = SplitRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_input: TokenInput {
                txid_hex: source_txid_hex.clone(),
                vout: 0,
                satoshis: stas_amount,
                locking_script: stas_lock.clone(),
                signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: None,
            },
            funding_input: FundingInput {
                txid_hex: source_txid_hex.clone(),
                vout: 1,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            destinations: vec![
                SplitDestination {
                    owner_pkh: dest_a_pkh,
                    satoshis: 333,
                },
                SplitDestination {
                    owner_pkh: dest_b_pkh,
                    satoshis: 333,
                },
                SplitDestination {
                    owner_pkh: dest_c_pkh,
                    satoshis: 334,
                },
            ],
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
            note: None,
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_split(req).await.unwrap();

        let valid = verify_input(&tx, 0, &stas_lock, stas_amount).unwrap();
        assert!(valid, "engine rejected the factory-built 3-way split spend");
    }

    /// Phase 5b gate (redeem): build an issuer-owned (`owner == redemption_pkh`)
    /// STAS UTXO and redeem it to a P2PKH destination; engine-verify input.
    ///
    /// Setup: derive the issuer key under "stas3mint"/"1" and use that PKH
    /// as both owner_pkh AND redemption_pkh on the source STAS lock —
    /// satisfying the issuer-only invariant of spec §9.6.
    #[tokio::test]
    async fn test_factory_redeem_engine_verifies() {
        use super::factory::{build_redeem, FundingInput, RedeemRequest, TokenInput};

        let issuer_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let issuer_wallet = ProtoWallet::new(issuer_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        // Issuer PKH = both the owner and the protoID of the source STAS.
        let issuer_pkh = derive_pkh(&issuer_wallet, "stas3mint", "1").await;
        // The redemption-destination PKH (where the burned satoshis go).
        let dest_pkh = derive_pkh(&issuer_wallet, "stas3mint", "redeem-to").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;

        let stas_amount: u64 = 10_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh: issuer_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh: issuer_pkh, // owner == redemption_pkh per §9.6
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        let req = RedeemRequest {
            wallet: &issuer_wallet,
            originator: None,
            stas_input: TokenInput {
                txid_hex: source_txid_hex.clone(),
                vout: 0,
                satoshis: stas_amount,
                locking_script: stas_lock.clone(),
                signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3mint", "1")),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: None,
            },
            funding_input: FundingInput {
                txid_hex: source_txid_hex.clone(),
                vout: 1,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            redemption_destination_pkh: dest_pkh,
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_redeem(req).await.unwrap();

        // Suppress unused-warning on funding_wallet.
        let _ = &funding_wallet;

        // Canonical redeem shape (spec §10.2 / dxs `redeem_by_issuer_valid`):
        // output[0] is a 70-byte P2MPKH lock at `dest_pkh`.
        let out0_bytes = tx.outputs[0].locking_script.to_binary();
        assert_eq!(
            out0_bytes.len(),
            70,
            "redeem output[0] must be the canonical 70-byte P2MPKH lock; got {} bytes",
            out0_bytes.len()
        );
        assert_eq!(
            &out0_bytes[..3],
            &[0x76, 0xa9, 0x14],
            "redeem output[0] must start with P2MPKH prefix (OP_DUP OP_HASH160 PUSH20)"
        );
        assert_eq!(
            &out0_bytes[3..23],
            &dest_pkh,
            "redeem output[0] must contain the redemption-destination PKH at bytes 3..23"
        );
        // Canonical 47-byte P2MPKH suffix per spec §10.2.
        let expected_suffix: [u8; 47] = [
            0x88, 0x82, 0x01, 0x21, 0x87, 0x63, 0xac, 0x67,
            0x51, 0x7f, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
            0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
            0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
            0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
            0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
            0xae, 0x68,
        ];
        assert_eq!(
            &out0_bytes[23..70],
            &expected_suffix,
            "redeem output[0] must end with the canonical 47-byte P2MPKH suffix"
        );

        let valid = verify_input(&tx, 0, &stas_lock, stas_amount).unwrap();
        assert!(valid, "engine rejected the factory-built redeem spend");
    }

    /// Phase 5c gate (merge, 2-input): two STAS UTXOs at distinct owners,
    /// each from its own preceding tx (one STAS output per preceding tx →
    /// per-input piece count = 2 → per-input txType = Merge2). Merged into
    /// one STAS output at a third owner; engine-verifies BOTH STAS inputs.
    ///
    /// # Phase 5c-1 status (in progress)
    ///
    /// Two byte-level fixes have been applied to `unlock.rs::TrailingParams`:
    /// 1. The merge piece array is now emitted as a SINGLE push-data blob
    ///    `[count][len_0][p_0]...[len_{N-1}][p_{N-1}]` (was: per-piece
    ///    push), matching the canonical engine atom
    ///    `OP_1 OP_SPLIT OP_IFDUP OP_IF OP_SWAP OP_SPLIT OP_ENDIF`.
    /// 2. The blob is right-padded with `(5 - N)` zero bytes so the
    ///    engine's fixed-5 piece-iteration loop doesn't run off the end.
    ///
    /// These two changes move the failure mode from
    /// `InvalidStackOperation("split position out of range")` to
    /// `Script(CheckSigVerifyFailed)`. The remaining failure is the
    /// engine's preimage reconstruction (HASH256 of `head || asset_script
    /// || tail`) not matching the actual src_a hash committed in the
    /// outpoint — a downstream issue in either the piece order, the
    /// padding-shift's effect on subsequent stack indices, or the
    /// asset-script reassembly path.
    ///
    /// Bittoku's reference test (same code path) is also `#[ignore]`d
    /// with a related symptom — see
    /// `~/PARAGON/PARAGON-code/.ref/bsv-sdk-rust/crates/bsv-tokens/tests/stas3_engine_verify.rs`
    /// `engine_accepts_swap_swap_with_trailing_pieces` which calls out
    /// the signed-byte OP_SPLIT issue. Our pieces are < 127 bytes so
    /// that specific issue doesn't apply here, but the broader
    /// preimage-mismatch failure persists across reference impls.
    #[tokio::test]
    async fn test_factory_merge_2input_engine_verifies() {
        use super::factory::{build_merge, FundingInput, MergeRequest, TokenInput};

        // 1. Derive Type-42 keys for two distinct input owners + destination
        //    + funding owner.
        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        let pkh_a = derive_pkh(&owner_wallet, "stas3owner", "a").await;
        let pkh_b = derive_pkh(&owner_wallet, "stas3owner", "b").await;
        let pkh_c = derive_pkh(&owner_wallet, "stas3owner", "c").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        // 2. Build two source txs, each with exactly one STAS UTXO at vout 0.
        //    A separate funding source tx supplies the fee.
        let amt_a: u64 = 600;
        let amt_b: u64 = 400;
        let funding_amount: u64 = 5_000;

        let lock_a = build_locking_script(&LockParams {
            owner_pkh: pkh_a,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();
        let lock_b = build_locking_script(&LockParams {
            owner_pkh: pkh_b,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        // NB: source txs include a placeholder input — matches the TS
        // reference shape (and the on-chain shape of any spendable txn).
        let mut src_a = Transaction::new();
        src_a.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(
                "0000000000000000000000000000000000000000000000000000000000000040".into(),
            ),
            source_output_index: 0,
            unlocking_script: Some(UnlockingScript::from_binary(&[0x00])),
            sequence: 0xffff_ffff,
        });
        src_a.outputs.push(TransactionOutput {
            satoshis: Some(amt_a),
            locking_script: lock_a.clone(),
            change: false,
        });
        let src_a_bytes = src_a.to_bytes().expect("serialize src_a");
        let src_a_txid_hex = src_a.id().expect("src_a txid");

        let mut src_b = Transaction::new();
        src_b.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(
                "0000000000000000000000000000000000000000000000000000000000000041".into(),
            ),
            source_output_index: 0,
            unlocking_script: Some(UnlockingScript::from_binary(&[0x00])),
            sequence: 0xffff_ffff,
        });
        src_b.outputs.push(TransactionOutput {
            satoshis: Some(amt_b),
            locking_script: lock_b.clone(),
            change: false,
        });
        let src_b_bytes = src_b.to_bytes().expect("serialize src_b");
        let src_b_txid_hex = src_b.id().expect("src_b txid");

        let mut src_funding = Transaction::new();
        src_funding.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let src_funding_txid_hex = src_funding.id().expect("src_funding txid");

        // 3. Build the merge tx via the factory.
        let req = MergeRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_inputs: vec![
                TokenInput {
                    txid_hex: src_a_txid_hex.clone(),
                    vout: 0,
                    satoshis: amt_a,
                    locking_script: lock_a.clone(),
                    signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "a")),
                    current_action_data: ActionData::Passive(vec![]),
                    source_tx_bytes: Some(src_a_bytes),
                },
                TokenInput {
                    txid_hex: src_b_txid_hex.clone(),
                    vout: 0,
                    satoshis: amt_b,
                    locking_script: lock_b.clone(),
                    signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "b")),
                    current_action_data: ActionData::Passive(vec![]),
                    source_tx_bytes: Some(src_b_bytes),
                },
            ],
            funding_input: FundingInput {
                txid_hex: src_funding_txid_hex.clone(),
                vout: 0,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            destination_owner_pkh: pkh_c,
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
            note: None,
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_merge(req).await.unwrap();

        // Suppress unused-warning on funding_wallet.
        let _ = &funding_wallet;

        // 4. Engine-verify BOTH STAS inputs independently.
        let valid_a = verify_input(&tx, 0, &lock_a, amt_a);
        match &valid_a {
            Ok(true) => {}
            Ok(false) => panic!(
                "engine rejected merge input 0 (Ok(false))\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
            Err(e) => panic!("engine errored on merge input 0: {e:?}"),
        }
        assert!(valid_a.unwrap(), "engine rejected merge input 0");

        let valid_b = verify_input(&tx, 1, &lock_b, amt_b);
        match &valid_b {
            Ok(true) => {}
            Ok(false) => panic!(
                "engine rejected merge input 1 (Ok(false))\n\
                 unlocking_script bytes: {}",
                tx.inputs[1]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
            Err(e) => panic!("engine errored on merge input 1: {e:?}"),
        }
        assert!(valid_b.unwrap(), "engine rejected merge input 1");
    }

    /// Helper for the N-input merge tests below: builds N source txs (each
    /// containing exactly one STAS UTXO) plus a funding source, then
    /// invokes `build_merge` and returns the resulting tx + the per-input
    /// (locking_script, satoshis) pairs needed for engine-verification.
    ///
    /// `key_ids` MUST be N distinct labels (drives the Type-42 derivation
    /// for each input owner). Each input is given 100 satoshis for a
    /// stable, easily-summed token amount.
    async fn build_n_input_merge_for_test(
        n: usize,
        key_ids: &[&str],
    ) -> Result<
        (Transaction, Vec<(LockingScript, u64)>),
        super::error::Stas3Error,
    > {
        use super::factory::{build_merge, FundingInput, MergeRequest, TokenInput};

        assert_eq!(key_ids.len(), n, "test bug: key_ids must have len n");

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let dest_pkh = derive_pkh(&owner_wallet, "stas3owner", "dest").await;
        let redemption_pkh = [0xab; 20];

        let amt: u64 = 100;
        let funding_amount: u64 = 5_000;

        // Build N STAS source txs.
        let mut stas_inputs: Vec<TokenInput> = Vec::with_capacity(n);
        let mut verify_meta: Vec<(LockingScript, u64)> = Vec::with_capacity(n);
        for (i, kid) in key_ids.iter().enumerate() {
            let pkh = derive_pkh(&owner_wallet, "stas3owner", kid).await;
            let lock = build_locking_script(&LockParams {
                owner_pkh: pkh,
                action_data: ActionData::Passive(vec![]),
                redemption_pkh,
                flags: 0,
                service_fields: vec![],
                optional_data: vec![],
            })
            .unwrap();

            // Source tx — placeholder input; one STAS output at vout 0.
            let mut src = Transaction::new();
            // Use a unique placeholder source_txid per input so source-tx
            // bytes differ (otherwise engine cross-checks may collapse).
            let mut placeholder_txid =
                "00000000000000000000000000000000000000000000000000000000000000".to_string();
            placeholder_txid.push_str(&format!("{:02x}", 0x40 + i));
            src.inputs.push(TransactionInput {
                source_transaction: None,
                source_txid: Some(placeholder_txid),
                source_output_index: 0,
                unlocking_script: Some(UnlockingScript::from_binary(&[0x00])),
                sequence: 0xffff_ffff,
            });
            src.outputs.push(TransactionOutput {
                satoshis: Some(amt),
                locking_script: lock.clone(),
                change: false,
            });
            let src_bytes = src.to_bytes().expect("serialize src");
            let src_txid_hex = src.id().expect("src txid");

            stas_inputs.push(TokenInput {
                txid_hex: src_txid_hex,
                vout: 0,
                satoshis: amt,
                locking_script: lock.clone(),
                signing_key: super::factory::types::SigningKey::P2pkh(
                    super::key_triple::KeyTriple::self_under("stas3owner", *kid),
                ),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: Some(src_bytes),
            });
            verify_meta.push((lock, amt));
        }

        // Funding source tx.
        let mut src_funding = Transaction::new();
        src_funding.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let src_funding_txid_hex = src_funding.id().expect("src_funding txid");

        let req = MergeRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_inputs,
            funding_input: FundingInput {
                txid_hex: src_funding_txid_hex,
                vout: 0,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            destination_owner_pkh: dest_pkh,
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
            note: None,
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_merge(req).await?;
        // Suppress unused-warning on funding_wallet.
        let _ = &funding_wallet;
        Ok((tx, verify_meta))
    }

    /// `build_merge` MUST reject N=1 (below the atomic-merge minimum).
    #[tokio::test]
    async fn test_factory_merge_n_equals_1_rejected() {
        // build_n_input_merge_for_test asserts key_ids.len() == n, so we
        // construct a 1-input request inline by re-using its body for n=1
        // would assert; instead, build a minimal N=1 request directly.
        use super::factory::{build_merge, FundingInput, MergeRequest, TokenInput};

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);
        let pkh = derive_pkh(&owner_wallet, "stas3owner", "a").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        let lock = build_locking_script(&LockParams {
            owner_pkh: pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();
        let mut src = Transaction::new();
        src.outputs.push(TransactionOutput {
            satoshis: Some(100),
            locking_script: lock.clone(),
            change: false,
        });
        let src_bytes = src.to_bytes().unwrap();
        let src_txid_hex = src.id().unwrap();

        let req = MergeRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_inputs: vec![TokenInput {
                txid_hex: src_txid_hex,
                vout: 0,
                satoshis: 100,
                locking_script: lock,
                signing_key: super::factory::types::SigningKey::P2pkh(
                    super::key_triple::KeyTriple::self_under("stas3owner", "a"),
                ),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: Some(src_bytes),
            }],
            funding_input: FundingInput {
                txid_hex: "00".repeat(32),
                vout: 0,
                satoshis: 5_000,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            destination_owner_pkh: pkh,
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
            note: None,
            change_pkh: funding_pkh,
            change_satoshis: 4_800,
        };
        let _ = &funding_wallet;
        let result = build_merge(req).await;
        assert!(
            matches!(result, Err(super::error::Stas3Error::InvalidScript(_))),
            "merge with N=1 must be rejected as InvalidScript; got {:?}",
            result.as_ref().err()
        );
    }

    /// `build_merge` MUST reject N=3 (only N=2 is supported atomically;
    /// N>2 callers must use `build_merge_chain`).
    #[tokio::test]
    async fn test_factory_merge_n_equals_3_rejected() {
        let result =
            build_n_input_merge_for_test(3, &["a", "b", "c"]).await;
        assert!(
            matches!(result, Err(super::error::Stas3Error::InvalidScript(_))),
            "merge with N=3 must be rejected as InvalidScript; got {:?}",
            result.as_ref().err()
        );
    }

    /// Helper for `build_merge_chain` tests: returns the raw materials
    /// (N original STAS source UTXOs + N-1 funding UTXOs + per-merge
    /// destination metadata) plus a `sources` map keyed by txid that
    /// callers extend with chain txs to drive engine verification.
    async fn build_chain_test_setup(
        n: usize,
        key_ids: &[&str],
    ) -> (
        ProtoWallet,                                       // owner_wallet
        Vec<super::factory::TokenInput>,                   // n stas inputs
        Vec<super::factory::FundingInput>,                 // n-1 fundings
        [u8; 20],                                          // dest_pkh
        super::factory::SigningKey,                        // dest_signing_key
        Vec<[u8; 20]>,                                     // n-1 change_pkhs
        Vec<u64>,                                          // n-1 change_satoshis
        std::collections::HashMap<String, Transaction>,    // sources by txid
    ) {
        use super::factory::{FundingInput, SigningKey, TokenInput};

        assert!(n >= 2, "chain test requires n >= 2");
        assert_eq!(key_ids.len(), n, "key_ids must have len n");

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let dest_pkh = derive_pkh(&owner_wallet, "stas3owner", "dest").await;
        let dest_signing_key = SigningKey::P2pkh(
            super::key_triple::KeyTriple::self_under("stas3owner", "dest"),
        );
        let redemption_pkh = [0xab; 20];

        let amt: u64 = 100;
        let funding_amount: u64 = 5_000;

        let mut sources: std::collections::HashMap<String, Transaction> =
            std::collections::HashMap::new();
        let mut stas_inputs: Vec<TokenInput> = Vec::with_capacity(n);
        for (i, kid) in key_ids.iter().enumerate() {
            let pkh = derive_pkh(&owner_wallet, "stas3owner", kid).await;
            let lock = build_locking_script(&LockParams {
                owner_pkh: pkh,
                action_data: ActionData::Passive(vec![]),
                redemption_pkh,
                flags: 0,
                service_fields: vec![],
                optional_data: vec![],
            })
            .unwrap();

            let mut src = Transaction::new();
            let mut placeholder_txid =
                "00000000000000000000000000000000000000000000000000000000000000".to_string();
            placeholder_txid.push_str(&format!("{:02x}", 0x40 + i));
            src.inputs.push(TransactionInput {
                source_transaction: None,
                source_txid: Some(placeholder_txid),
                source_output_index: 0,
                unlocking_script: Some(UnlockingScript::from_binary(&[0x00])),
                sequence: 0xffff_ffff,
            });
            src.outputs.push(TransactionOutput {
                satoshis: Some(amt),
                locking_script: lock.clone(),
                change: false,
            });
            let src_bytes = src.to_bytes().expect("serialize src");
            let src_txid_hex = src.id().expect("src txid");

            stas_inputs.push(TokenInput {
                txid_hex: src_txid_hex.clone(),
                vout: 0,
                satoshis: amt,
                locking_script: lock.clone(),
                signing_key: SigningKey::P2pkh(
                    super::key_triple::KeyTriple::self_under("stas3owner", *kid),
                ),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: Some(src_bytes),
            });
            sources.insert(src_txid_hex, src);
        }

        // n-1 distinct funding source txs (distinct txids so each merge has
        // a real outpoint). All hold `funding_amount`; each merge consumes
        // one.
        let mut fundings: Vec<FundingInput> = Vec::with_capacity(n - 1);
        let mut change_pkhs: Vec<[u8; 20]> = Vec::with_capacity(n - 1);
        let mut change_satoshis: Vec<u64> = Vec::with_capacity(n - 1);
        for j in 0..(n - 1) {
            let mut src_funding = Transaction::new();
            let mut placeholder_txid =
                "00000000000000000000000000000000000000000000000000000000000000".to_string();
            placeholder_txid.push_str(&format!("{:02x}", 0x80 + j));
            src_funding.inputs.push(TransactionInput {
                source_transaction: None,
                source_txid: Some(placeholder_txid),
                source_output_index: 0,
                unlocking_script: Some(UnlockingScript::from_binary(&[0x00])),
                sequence: 0xffff_ffff,
            });
            src_funding.outputs.push(TransactionOutput {
                satoshis: Some(funding_amount),
                locking_script: make_p2pkh_lock(&funding_pkh),
                change: false,
            });
            let src_funding_txid_hex =
                src_funding.id().expect("src_funding txid");
            fundings.push(FundingInput {
                txid_hex: src_funding_txid_hex.clone(),
                vout: 0,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            });
            change_pkhs.push(funding_pkh);
            change_satoshis.push(funding_amount - 200);
            sources.insert(src_funding_txid_hex, src_funding);
        }

        let _ = &funding_wallet;
        (
            owner_wallet,
            stas_inputs,
            fundings,
            dest_pkh,
            dest_signing_key,
            change_pkhs,
            change_satoshis,
            sources,
        )
    }

    /// Engine-verify every STAS input of every tx in a `build_merge_chain`
    /// result by looking up each input's source tx (either an original or
    /// a prior chain tx) in `sources`.
    fn verify_chain(
        chain: &[Transaction],
        sources: &std::collections::HashMap<String, Transaction>,
    ) {
        for (tx_idx, tx) in chain.iter().enumerate() {
            // Layout: [stas_0, stas_1, funding]. Verify the 2 STAS inputs.
            for input_idx in 0..2 {
                let input = &tx.inputs[input_idx];
                let prev_txid = input
                    .source_txid
                    .as_ref()
                    .expect("chain tx input must have source_txid");
                let prev_vout = input.source_output_index as usize;
                let source_tx = sources
                    .get(prev_txid)
                    .unwrap_or_else(|| panic!(
                        "tx[{tx_idx}] input[{input_idx}] source_txid {prev_txid} \
                         not in sources map"
                    ));
                let source_output = &source_tx.outputs[prev_vout];
                let lock = source_output.locking_script.clone();
                let amount =
                    source_output.satoshis.expect("source output satoshis");
                let valid = verify_input(tx, input_idx, &lock, amount);
                match &valid {
                    Ok(true) => {}
                    Ok(false) => panic!(
                        "engine rejected chain tx[{tx_idx}] input[{input_idx}] \
                         (Ok(false))\nunlocking_script bytes: {}",
                        tx.inputs[input_idx]
                            .unlocking_script
                            .as_ref()
                            .map(|s| hex_dump(&s.to_binary()))
                            .unwrap_or_default()
                    ),
                    Err(e) => panic!(
                        "engine errored on chain tx[{tx_idx}] input[{input_idx}]: {e:?}"
                    ),
                }
            }
        }
    }

    /// 3-input merge via `build_merge_chain` — produces 2 transactions
    /// (binary-tree pairwise merges), each STAS input of each tx must
    /// engine-verify.
    #[tokio::test]
    async fn test_factory_merge_chain_3_inputs_engine_verifies() {
        use super::factory::{build_merge_chain, MergeChainRequest};

        let (
            owner_wallet,
            stas_inputs,
            fundings,
            dest_pkh,
            dest_signing_key,
            change_pkhs,
            change_satoshis,
            mut sources,
        ) = build_chain_test_setup(3, &["a", "b", "c"]).await;

        let chain = build_merge_chain(MergeChainRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_inputs,
            fundings,
            destination_owner_pkh: dest_pkh,
            destination_signing_key: dest_signing_key,
            redemption_pkh: [0xab; 20],
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
            note: None,
            change_pkhs,
            change_satoshis,
        })
        .await
        .unwrap();

        assert_eq!(chain.len(), 2, "n=3 chain must produce 2 txs");

        // Extend sources with chain txs so later txs' inputs resolve.
        for tx in &chain {
            sources.insert(tx.id().expect("chain tx id"), tx.clone());
        }
        verify_chain(&chain, &sources);
    }

    /// 4-input merge via `build_merge_chain` — produces 3 transactions.
    #[tokio::test]
    async fn test_factory_merge_chain_4_inputs_engine_verifies() {
        use super::factory::{build_merge_chain, MergeChainRequest};

        let (
            owner_wallet,
            stas_inputs,
            fundings,
            dest_pkh,
            dest_signing_key,
            change_pkhs,
            change_satoshis,
            mut sources,
        ) = build_chain_test_setup(4, &["a", "b", "c", "d"]).await;

        let chain = build_merge_chain(MergeChainRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_inputs,
            fundings,
            destination_owner_pkh: dest_pkh,
            destination_signing_key: dest_signing_key,
            redemption_pkh: [0xab; 20],
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
            note: None,
            change_pkhs,
            change_satoshis,
        })
        .await
        .unwrap();

        assert_eq!(chain.len(), 3, "n=4 chain must produce 3 txs");

        for tx in &chain {
            sources.insert(tx.id().expect("chain tx id"), tx.clone());
        }
        verify_chain(&chain, &sources);
    }

    /// `build_merge_chain` rejects N<2 with `InvalidScript`.
    #[tokio::test]
    async fn test_factory_merge_chain_n_below_2_rejected() {
        use super::factory::{build_merge_chain, MergeChainRequest, SigningKey};

        let owner_wallet = ProtoWallet::new(PrivateKey::from_hex("01").unwrap());
        let dest_pkh = derive_pkh(&owner_wallet, "stas3owner", "dest").await;

        let result = build_merge_chain(MergeChainRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_inputs: vec![],
            fundings: vec![],
            destination_owner_pkh: dest_pkh,
            destination_signing_key: SigningKey::P2pkh(
                super::key_triple::KeyTriple::self_under("stas3owner", "dest"),
            ),
            redemption_pkh: [0xab; 20],
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
            note: None,
            change_pkhs: vec![],
            change_satoshis: vec![],
        })
        .await;

        assert!(
            matches!(result, Err(super::error::Stas3Error::InvalidScript(_))),
            "merge_chain with N=0 must be rejected; got {:?}",
            result.as_ref().err()
        );
    }

    /// Phase 5d gate (freeze): build a FREEZABLE STAS UTXO with the freeze
    /// authority's PKH in service_fields[0]; spend it via the freeze
    /// authority key, transitioning var2 from Passive(empty) to
    /// Frozen(empty). Engine-verifies the STAS input.
    #[tokio::test]
    async fn test_factory_freeze_engine_verifies() {
        use super::factory::{build_freeze, FreezeRequest, FundingInput, TokenInput};
        use super::flags::FREEZABLE;

        // 1. Derive Type-42 keys.
        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let authority_root = PrivateKey::from_hex("03").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);
        let authority_wallet = ProtoWallet::new(authority_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let freeze_authority_pkh = derive_pkh(&authority_wallet, "stas3freeze", "1").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        // 2. Build the source tx — STAS UTXO with FREEZABLE flag and the
        //    freeze authority's PKH in service_fields[0].
        let stas_amount: u64 = 10_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: FREEZABLE,
            service_fields: vec![freeze_authority_pkh.to_vec()],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        // 3. Build the freeze tx via the factory.
        let req = FreezeRequest {
            wallet: &authority_wallet,
            originator: None,
            stas_input: TokenInput {
                txid_hex: source_txid_hex.clone(),
                vout: 0,
                satoshis: stas_amount,
                locking_script: stas_lock.clone(),
                signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: None,
            },
            funding_input: FundingInput {
                txid_hex: source_txid_hex.clone(),
                vout: 1,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            freeze_authority: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under(
                "stas3freeze",
                "1",
            )),
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_freeze(req).await.unwrap();

        // Suppress unused-warning on funding_wallet.
        let _ = &funding_wallet;

        // 4. THE GATE: engine-verify the STAS input.
        let result = verify_input(&tx, 0, &stas_lock, stas_amount);
        match &result {
            Ok(true) => {}
            Ok(false) => panic!(
                "engine rejected freeze (Ok(false))\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
            Err(e) => panic!(
                "engine errored on freeze: {e:?}\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
        }
        assert!(result.unwrap(), "engine rejected the factory-built freeze spend");
    }

    /// Phase 5d gate (unfreeze): build a FREEZABLE+Frozen STAS UTXO and
    /// unfreeze it via the freeze authority. Engine-verifies the STAS input.
    #[tokio::test]
    async fn test_factory_unfreeze_engine_verifies() {
        use super::factory::{build_unfreeze, FundingInput, TokenInput, UnfreezeRequest};
        use super::flags::FREEZABLE;

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let authority_root = PrivateKey::from_hex("03").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);
        let authority_wallet = ProtoWallet::new(authority_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let freeze_authority_pkh = derive_pkh(&authority_wallet, "stas3freeze", "1").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        // Source UTXO is FREEZABLE and currently FROZEN.
        let stas_amount: u64 = 10_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Frozen(vec![]),
            redemption_pkh,
            flags: FREEZABLE,
            service_fields: vec![freeze_authority_pkh.to_vec()],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        let req = UnfreezeRequest {
            wallet: &authority_wallet,
            originator: None,
            stas_input: TokenInput {
                txid_hex: source_txid_hex.clone(),
                vout: 0,
                satoshis: stas_amount,
                locking_script: stas_lock.clone(),
                signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
                current_action_data: ActionData::Frozen(vec![]),
                source_tx_bytes: None,
            },
            funding_input: FundingInput {
                txid_hex: source_txid_hex.clone(),
                vout: 1,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            freeze_authority: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under(
                "stas3freeze",
                "1",
            )),
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_unfreeze(req).await.unwrap();

        let _ = &funding_wallet;

        let result = verify_input(&tx, 0, &stas_lock, stas_amount);
        match &result {
            Ok(true) => {}
            Ok(false) => panic!(
                "engine rejected unfreeze (Ok(false))\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
            Err(e) => panic!(
                "engine errored on unfreeze: {e:?}\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
        }
        assert!(result.unwrap(), "engine rejected the factory-built unfreeze spend");
    }

    /// Phase 5d gate (confiscate): build a CONFISCATABLE STAS UTXO with the
    /// confiscation authority's PKH in service_fields[0]; spend it via the
    /// confiscation authority key, reassigning to a new owner.
    /// Engine-verifies the STAS input.
    #[tokio::test]
    async fn test_factory_confiscate_engine_verifies() {
        use super::factory::{build_confiscate, ConfiscateRequest, FundingInput, TokenInput};
        use super::flags::CONFISCATABLE;

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let authority_root = PrivateKey::from_hex("03").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);
        let authority_wallet = ProtoWallet::new(authority_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let destination_pkh = derive_pkh(&owner_wallet, "stas3owner", "regulator").await;
        let confiscation_authority_pkh =
            derive_pkh(&authority_wallet, "stas3confiscate", "1").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        // CONFISCATABLE only — service_fields[0] is the confiscation
        // authority PKH (no FREEZABLE flag, so no preceding service field).
        let stas_amount: u64 = 10_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: CONFISCATABLE,
            service_fields: vec![confiscation_authority_pkh.to_vec()],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        let req = ConfiscateRequest {
            wallet: &authority_wallet,
            originator: None,
            stas_input: TokenInput {
                txid_hex: source_txid_hex.clone(),
                vout: 0,
                satoshis: stas_amount,
                locking_script: stas_lock.clone(),
                signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: None,
            },
            funding_input: FundingInput {
                txid_hex: source_txid_hex.clone(),
                vout: 1,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            confiscation_authority: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under(
                "stas3confiscate",
                "1",
            )),
            destination_owner_pkh: destination_pkh,
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_confiscate(req).await.unwrap();

        let _ = &funding_wallet;

        let result = verify_input(&tx, 0, &stas_lock, stas_amount);
        match &result {
            Ok(true) => {}
            Ok(false) => panic!(
                "engine rejected confiscate (Ok(false))\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
            Err(e) => panic!(
                "engine errored on confiscate: {e:?}\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
        }
        assert!(result.unwrap(), "engine rejected the factory-built confiscate spend");
    }

    /// Phase 7 gate (swap-mark): build a Passive STAS UTXO and mark it for
    /// swap (var2 transitions to a SwapDescriptor). Engine-verifies the
    /// STAS input — structurally a regular owner spend.
    #[tokio::test]
    async fn test_factory_swap_mark_engine_verifies() {
        use super::action_data::SwapDescriptor;
        use super::factory::{build_swap_mark, FundingInput, SwapMarkRequest, TokenInput};

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let receive_addr = derive_pkh(&owner_wallet, "stas3swap", "receive-1").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        let stas_amount: u64 = 10_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        // Counterparty script hash — for this test it can be any 32 bytes;
        // engine doesn't validate the descriptor's content during the mark
        // step, only during execute (which this test doesn't reach).
        let descriptor = SwapDescriptor {
            requested_script_hash: [0x77; 32],
            receive_addr,
            rate_numerator: 1,
            rate_denominator: 1,
            next: None,
        };

        let req = SwapMarkRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_input: TokenInput {
                txid_hex: source_txid_hex.clone(),
                vout: 0,
                satoshis: stas_amount,
                locking_script: stas_lock.clone(),
                signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: None,
            },
            funding_input: FundingInput {
                txid_hex: source_txid_hex.clone(),
                vout: 1,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            descriptor,
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_swap_mark(req).await.unwrap();

        let _ = &funding_wallet;

        let result = verify_input(&tx, 0, &stas_lock, stas_amount);
        match &result {
            Ok(true) => {}
            Ok(false) => panic!(
                "engine rejected swap_mark (Ok(false))\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
            Err(e) => panic!(
                "engine errored on swap_mark: {e:?}\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
        }
        assert!(result.unwrap(), "engine rejected the factory-built swap_mark spend");
    }

    /// Phase 7 gate (swap-cancel): build a swap-marked STAS UTXO whose
    /// descriptor.receive_addr is a Type-42-derived PKH; cancel it via the
    /// receive_addr's triple. Engine-verifies the STAS input.
    #[tokio::test]
    async fn test_factory_swap_cancel_engine_verifies() {
        use super::action_data::SwapDescriptor;
        use super::factory::{build_swap_cancel, FundingInput, SwapCancelRequest, TokenInput};

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        // The receive_addr — derived under a triple we'll use to sign cancel.
        let receive_addr = derive_pkh(&owner_wallet, "stas3swap", "receive-1").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        let stas_amount: u64 = 10_000;
        let funding_amount: u64 = 5_000;

        // Build the swap-marked source UTXO directly (skip the swap_mark step
        // for unit isolation — that path is exercised in
        // test_factory_swap_mark_engine_verifies).
        let descriptor = SwapDescriptor {
            requested_script_hash: [0x77; 32],
            receive_addr,
            rate_numerator: 1,
            rate_denominator: 1,
            next: None,
        };
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Swap(descriptor.clone()),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        let req = SwapCancelRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_input: TokenInput {
                txid_hex: source_txid_hex.clone(),
                vout: 0,
                satoshis: stas_amount,
                locking_script: stas_lock.clone(),
                // The input's owner triple — not used for signing here, but
                // the type still requires it.
                signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
                current_action_data: ActionData::Swap(descriptor.clone()),
                source_tx_bytes: None,
            },
            funding_input: FundingInput {
                txid_hex: source_txid_hex.clone(),
                vout: 1,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            receive_addr_signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under(
                "stas3swap",
                "receive-1",
            )),
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_swap_cancel(req).await.unwrap();

        let _ = &funding_wallet;

        let result = verify_input(&tx, 0, &stas_lock, stas_amount);
        match &result {
            Ok(true) => {}
            Ok(false) => panic!(
                "engine rejected swap_cancel (Ok(false))\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
            Err(e) => panic!(
                "engine errored on swap_cancel: {e:?}\n\
                 unlocking_script bytes: {}",
                tx.inputs[0]
                    .unlocking_script
                    .as_ref()
                    .map(|s| hex_dump(&s.to_binary()))
                    .unwrap_or_default()
            ),
        }
        assert!(result.unwrap(), "engine rejected the factory-built swap_cancel spend");
    }

    /// Phase 7 gate (swap-execute): atomic exchange of two STAS-3 tokens
    /// with mutually-compatible swap descriptors.
    ///
    /// **Status (Phase 5c-2)**: the wire format is correct (matches the
    /// stas3-sdk TypeScript reference's `Stas3.ts::buildMergeSection` for
    /// the swap branch — `mergeVout, [reversed pieces], segCount,
    /// counterpartyScript, swap_indicator(1)` — and the merge-only test
    /// `test_factory_merge_2input_engine_verifies` PASSES with this same
    /// wire format), but the engine still rejects with `Script(VerifyFailed)`
    /// from a deeper engine-side cross-validation predicate that's specific
    /// to the swap path (likely the `requested_script_hash` validation:
    /// the engine SHA256s a re-templated form of the OUTPUT script and
    /// compares against the descriptor's commitment, with the OWNER PKH
    /// position blanked or replaced — exact rule not yet decoded from
    /// the 2,899-byte engine ASM).
    ///
    /// To reproduce the working TS swap-swap test in Rust requires
    /// faithfully replicating its descriptor + output assignment shape;
    /// our test does so structurally but the engine-validated
    /// re-templating predicate hasn't been pinned down. Track in:
    /// `~/wiki/projects/stas3-rust-sdk.md` (if present).
    #[tokio::test]
    async fn test_factory_swap_execute_engine_verifies() {
        use super::action_data::SwapDescriptor;
        use super::factory::{
            build_swap_execute, counterparty_script_from_lock, FundingInput, SwapExecuteRequest,
            TokenInput,
        };
        use crate::primitives::hash::sha256;

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);

        // Two distinct token owners (e.g. wind GC holder + solar GC holder)
        // and a funding owner.
        let owner_a_pkh = derive_pkh(&owner_wallet, "stas3owner", "a").await;
        let owner_b_pkh = derive_pkh(&owner_wallet, "stas3owner", "b").await;
        // Per the TS reference: each side's swap descriptor `receive_addr`
        // is set to that side's OWNER pkh (alice receives back into alice
        // address, bob into bob address). Distinct receive addresses are
        // allowed in principle but require descriptor-aware engine paths
        // not yet exercised by this gate test.
        let receive_a_pkh = owner_a_pkh;
        let receive_b_pkh = owner_b_pkh;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        // Two distinct token TYPES (different redemption pkhs) so that the
        // swap descriptors' `requested_script_hash` values differ — matches
        // the TS swap-swap test shape.
        let redemption_a_pkh = [0xa1; 20];
        let redemption_b_pkh = [0xb1; 20];

        let amt_a: u64 = 1_000;
        let amt_b: u64 = 1_000;
        let funding_amount: u64 = 5_000;

        // Build provisional locks WITHOUT swap descriptors so we can compute
        // each side's script hash for the OTHER side's `requested_script_hash`.
        // Mutually-compatible swap means: A's descriptor requests B's lock,
        // B's descriptor requests A's lock. We assemble in two passes.
        let provisional_a = build_locking_script(&LockParams {
            owner_pkh: owner_a_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh: redemption_a_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();
        let provisional_b = build_locking_script(&LockParams {
            owner_pkh: owner_b_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh: redemption_b_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        // Per spec §5.5 and TS reference (`computeRequestedScriptHash` in
        // stas3-sdk/src/Stas3Swap.ts): the descriptor's
        // `requested_script_hash` is SHA256 of the OTHER side's
        // counterparty script (everything after the leading
        // `[owner_pkh][var2]` pushes — i.e. covenant body + protoID +
        // flags + service + optional). The engine recomputes this from
        // the produced output by stripping the same leading two pushes
        // and SHA256ing the remainder, then compares.
        let cp_a = counterparty_script_from_lock(&provisional_a).unwrap();
        let cp_b = counterparty_script_from_lock(&provisional_b).unwrap();
        let hash_of_b: [u8; 32] = sha256(&cp_b);
        let hash_of_a: [u8; 32] = sha256(&cp_a);

        let descriptor_a = SwapDescriptor {
            requested_script_hash: hash_of_b,
            receive_addr: receive_a_pkh,
            rate_numerator: 1,
            rate_denominator: 1,
            next: None,
        };
        let descriptor_b = SwapDescriptor {
            requested_script_hash: hash_of_a,
            receive_addr: receive_b_pkh,
            rate_numerator: 1,
            rate_denominator: 1,
            next: None,
        };

        // The actual swap-marked locks.
        let lock_a = build_locking_script(&LockParams {
            owner_pkh: owner_a_pkh,
            action_data: ActionData::Swap(descriptor_a.clone()),
            redemption_pkh: redemption_a_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();
        let lock_b = build_locking_script(&LockParams {
            owner_pkh: owner_b_pkh,
            action_data: ActionData::Swap(descriptor_b.clone()),
            redemption_pkh: redemption_b_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        // Two source txs each containing exactly one STAS UTXO at vout 0
        // (so each input's piece array is just head + tail). Include a
        // placeholder input so the source-tx shape matches an on-chain tx.
        let mut src_a = Transaction::new();
        src_a.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(
                "0000000000000000000000000000000000000000000000000000000000000050".into(),
            ),
            source_output_index: 0,
            unlocking_script: Some(UnlockingScript::from_binary(&[0x00])),
            sequence: 0xffff_ffff,
        });
        src_a.outputs.push(TransactionOutput {
            satoshis: Some(amt_a),
            locking_script: lock_a.clone(),
            change: false,
        });
        let src_a_bytes = src_a.to_bytes().expect("serialize src_a");
        let src_a_txid_hex = src_a.id().expect("src_a txid");

        let mut src_b = Transaction::new();
        src_b.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(
                "0000000000000000000000000000000000000000000000000000000000000051".into(),
            ),
            source_output_index: 0,
            unlocking_script: Some(UnlockingScript::from_binary(&[0x00])),
            sequence: 0xffff_ffff,
        });
        src_b.outputs.push(TransactionOutput {
            satoshis: Some(amt_b),
            locking_script: lock_b.clone(),
            change: false,
        });
        let src_b_bytes = src_b.to_bytes().expect("serialize src_b");
        let src_b_txid_hex = src_b.id().expect("src_b txid");

        let mut src_funding = Transaction::new();
        src_funding.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let src_funding_txid_hex = src_funding.id().expect("src_funding txid");

        let req = SwapExecuteRequest {
            wallet: &owner_wallet,
            originator: None,
            stas_inputs: [
                TokenInput {
                    txid_hex: src_a_txid_hex.clone(),
                    vout: 0,
                    satoshis: amt_a,
                    locking_script: lock_a.clone(),
                    signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "a")),
                    current_action_data: ActionData::Swap(descriptor_a),
                    source_tx_bytes: Some(src_a_bytes),
                },
                TokenInput {
                    txid_hex: src_b_txid_hex.clone(),
                    vout: 0,
                    satoshis: amt_b,
                    locking_script: lock_b.clone(),
                    signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "b")),
                    current_action_data: ActionData::Swap(descriptor_b),
                    source_tx_bytes: Some(src_b_bytes),
                },
            ],
            funding_input: FundingInput {
                txid_hex: src_funding_txid_hex.clone(),
                vout: 0,
                satoshis: funding_amount,
                locking_script: make_p2pkh_lock(&funding_pkh),
                triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
            },
            change_pkh: funding_pkh,
            change_satoshis: funding_amount - 200,
        };
        let tx = build_swap_execute(req).await.unwrap();

        let _ = &funding_wallet;

        // Engine-verify BOTH STAS inputs.
        let valid_a = verify_input(&tx, 0, &lock_a, amt_a);
        match &valid_a {
            Ok(true) => {}
            Ok(false) => panic!("engine rejected swap_execute input 0 (Ok(false))"),
            Err(e) => panic!("engine errored on swap_execute input 0: {e:?}"),
        }
        assert!(valid_a.unwrap(), "engine rejected swap_execute input 0");

        let valid_b = verify_input(&tx, 1, &lock_b, amt_b);
        match &valid_b {
            Ok(true) => {}
            Ok(false) => panic!("engine rejected swap_execute input 1 (Ok(false))"),
            Err(e) => panic!("engine errored on swap_execute input 1: {e:?}"),
        }
        assert!(valid_b.unwrap(), "engine rejected swap_execute input 1");
    }

    /// Phase 9 gate (Stas3Wallet wrapper): construct a TokenInput +
    /// FundingInput by hand (since `ProtoWallet::list_outputs` returns
    /// NotImplemented) and drive `Stas3Wallet::transfer`. Engine-verifies
    /// the produced tx — proves the wrapper composes the same valid spend
    /// as a direct `build_transfer` call.
    ///
    /// Full basket-aware integration (`pick_fuel` against a real wallet
    /// store + `internalize_action` post-broadcast) needs a live
    /// wallet-toolbox instance and is out of scope for this crate's tests.
    #[tokio::test]
    async fn test_stas3_wallet_transfer_round_trip() {
        use super::factory::{FundingInput, TokenInput};
        use super::wallet::Stas3Wallet;
        use std::sync::Arc;

        // 1. Derive Type-42 keys via ProtoWallet.
        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = Arc::new(ProtoWallet::new(owner_root));
        let funding_wallet = ProtoWallet::new(funding_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let new_owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "2").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        // 2. Build a synthetic source tx.
        let stas_amount: u64 = 10_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        // 3. Build TokenInput + FundingInput by hand (basket lookup is the
        //    integration concern; the wrapper's *composition* is what we're
        //    testing here).
        let token = TokenInput {
            txid_hex: source_txid_hex.clone(),
            vout: 0,
            satoshis: stas_amount,
            locking_script: stas_lock.clone(),
            signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
            current_action_data: ActionData::Passive(vec![]),
            source_tx_bytes: None,
        };
        let funding = FundingInput {
            txid_hex: source_txid_hex.clone(),
            vout: 1,
            satoshis: funding_amount,
            locking_script: make_p2pkh_lock(&funding_pkh),
            triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
        };

        // 4. Drive the wrapper.
        let wrapper = Stas3Wallet::new(Arc::clone(&owner_wallet));
        let tx = wrapper
            .transfer(
                token,
                funding,
                new_owner_pkh,
                funding_pkh,
                funding_amount - 200,
                None,
            )
            .await
            .expect("wrapper transfer");

        // Suppress unused-warning on funding_wallet.
        let _ = &funding_wallet;

        // 5. THE GATE: engine-verify the STAS input on the wrapper-built tx.
        let valid = verify_input(&tx, 0, &stas_lock, stas_amount).unwrap();
        assert!(valid, "engine rejected the wrapper-built transfer spend");
    }

    /// Phase 9 gate (wallet wrapper, freeze): exercise the
    /// `Stas3Wallet::freeze` path end-to-end and engine-verify.
    #[tokio::test]
    async fn test_stas3_wallet_freeze_round_trip() {
        use super::factory::{FundingInput, TokenInput};
        use super::flags::FREEZABLE;
        use super::wallet::Stas3Wallet;
        use std::sync::Arc;

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let authority_root = PrivateKey::from_hex("03").unwrap();
        let owner_wallet = ProtoWallet::new(owner_root);
        let funding_wallet = ProtoWallet::new(funding_root);
        let authority_wallet = Arc::new(ProtoWallet::new(authority_root));

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let freeze_authority_pkh = derive_pkh(&authority_wallet, "stas3freeze", "1").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        let stas_amount: u64 = 10_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: FREEZABLE,
            service_fields: vec![freeze_authority_pkh.to_vec()],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        let token = TokenInput {
            txid_hex: source_txid_hex.clone(),
            vout: 0,
            satoshis: stas_amount,
            locking_script: stas_lock.clone(),
            signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
            current_action_data: ActionData::Passive(vec![]),
            source_tx_bytes: None,
        };
        let funding = FundingInput {
            txid_hex: source_txid_hex.clone(),
            vout: 1,
            satoshis: funding_amount,
            locking_script: make_p2pkh_lock(&funding_pkh),
            triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
        };

        let wrapper = Stas3Wallet::new(Arc::clone(&authority_wallet));
        let tx = wrapper
            .freeze(
                token,
                funding,
                super::key_triple::KeyTriple::self_under("stas3freeze", "1"),
                funding_pkh,
                funding_amount - 200,
            )
            .await
            .expect("wrapper freeze");

        let _ = &funding_wallet;

        let valid = verify_input(&tx, 0, &stas_lock, stas_amount).unwrap();
        assert!(valid, "engine rejected the wrapper-built freeze spend");
    }

    /// Phase 9 gate (wallet wrapper, swap_mark): exercise the
    /// `Stas3Wallet::swap_mark` path end-to-end and engine-verify.
    #[tokio::test]
    async fn test_stas3_wallet_swap_mark_round_trip() {
        use super::action_data::SwapDescriptor;
        use super::factory::{FundingInput, TokenInput};
        use super::wallet::Stas3Wallet;
        use std::sync::Arc;

        let owner_root = PrivateKey::from_hex("01").unwrap();
        let funding_root = PrivateKey::from_hex("02").unwrap();
        let owner_wallet = Arc::new(ProtoWallet::new(owner_root));
        let funding_wallet = ProtoWallet::new(funding_root);

        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let receive_addr = derive_pkh(&owner_wallet, "stas3swap", "receive-1").await;
        let funding_pkh = derive_pkh(&funding_wallet, "stas3fuel", "1").await;
        let redemption_pkh = [0xab; 20];

        let stas_amount: u64 = 10_000;
        let funding_amount: u64 = 5_000;
        let stas_lock = build_locking_script(&LockParams {
            owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
        })
        .unwrap();

        let mut source_tx = Transaction::new();
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(stas_amount),
            locking_script: stas_lock.clone(),
            change: false,
        });
        source_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: make_p2pkh_lock(&funding_pkh),
            change: false,
        });
        let source_txid_hex = source_tx.id().expect("source tx id");

        let descriptor = SwapDescriptor {
            requested_script_hash: [0x77; 32],
            receive_addr,
            rate_numerator: 1,
            rate_denominator: 1,
            next: None,
        };

        let token = TokenInput {
            txid_hex: source_txid_hex.clone(),
            vout: 0,
            satoshis: stas_amount,
            locking_script: stas_lock.clone(),
            signing_key: super::factory::types::SigningKey::P2pkh(super::key_triple::KeyTriple::self_under("stas3owner", "1")),
            current_action_data: ActionData::Passive(vec![]),
            source_tx_bytes: None,
        };
        let funding = FundingInput {
            txid_hex: source_txid_hex.clone(),
            vout: 1,
            satoshis: funding_amount,
            locking_script: make_p2pkh_lock(&funding_pkh),
            triple: super::key_triple::KeyTriple::self_under("stas3fuel", "1"),
        };

        let wrapper = Stas3Wallet::new(Arc::clone(&owner_wallet));
        let tx = wrapper
            .swap_mark(
                token,
                funding,
                descriptor,
                funding_pkh,
                funding_amount - 200,
            )
            .await
            .expect("wrapper swap_mark");

        let _ = &funding_wallet;

        let valid = verify_input(&tx, 0, &stas_lock, stas_amount).unwrap();
        assert!(valid, "engine rejected the wrapper-built swap_mark spend");
    }

    /// Phase 9 gate (pick_fuel): when the wallet's `list_outputs` returns
    /// `NotImplemented` (as ProtoWallet does), the wrapper surfaces it as
    /// `Stas3Error::InvalidScript` rather than panicking. This is the
    /// negative-path proof that the basket-aware path requires a real
    /// wallet-toolbox.
    #[tokio::test]
    async fn test_stas3_wallet_pick_fuel_proto_wallet_returns_error() {
        use super::wallet::Stas3Wallet;
        use std::sync::Arc;

        let wallet = Arc::new(ProtoWallet::new(PrivateKey::from_hex("01").unwrap()));
        let wrapper = Stas3Wallet::new(wallet);
        let result = wrapper.pick_fuel(1_000).await;
        assert!(result.is_err(), "expected pick_fuel to fail on ProtoWallet");
    }

    // ===================================================================
    // Wave 2A.1 — production 2-tx contract+issue (build_issue / mint_eac)
    // ===================================================================

    /// Wave 2A.1 gate: build_issue produces a (contract, issue) pair where
    /// the issue tx's outputs are STAS-3 locks honoring the caller-supplied
    /// destinations, and a freshly-issued lock can subsequently be spent
    /// (engine-verified) via the standard transfer factory.
    #[tokio::test]
    async fn test_factory_issue_two_destinations_engine_verifies() {
        use super::factory::issue::{
            build_issue, IssueDestination, IssueRequest,
        };
        use super::factory::types::{FundingInput, SigningKey};
        use super::factory::{build_transfer, TokenInput, TransferRequest};

        // 1. Set up the issuer + two destination keys + a funding key.
        //    The issuer's pkh will be the redemption_pkh; the issuer also
        //    owns the funding UTXO (production parity — the same key
        //    signs both the contract and issue txs).
        let issuer_root = PrivateKey::from_hex("11").unwrap();
        let owner_a_root = PrivateKey::from_hex("22").unwrap();
        let owner_b_root = PrivateKey::from_hex("33").unwrap();

        let issuer_wallet = ProtoWallet::new(issuer_root);
        let owner_a_wallet = ProtoWallet::new(owner_a_root);
        let owner_b_wallet = ProtoWallet::new(owner_b_root);

        let issuer_pkh = derive_pkh(&issuer_wallet, "stas3mint", "1").await;
        let owner_a_pkh = derive_pkh(&owner_a_wallet, "stas3owner", "a").await;
        let owner_b_pkh = derive_pkh(&owner_b_wallet, "stas3owner", "b").await;

        // 2. Build a synthetic funding UTXO owned by the issuer.
        //    (We manually construct a "previous tx" that holds a P2PKH
        //    UTXO at vout 0; the issuance contract tx will spend it.)
        let funding_amount: u64 = 100_000;
        let funding_lock = make_p2pkh_lock(&issuer_pkh);
        let mut prev_tx = Transaction::new();
        prev_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: funding_lock.clone(),
            change: false,
        });
        let prev_txid_hex = prev_tx.id().expect("prev tx id");

        let issuer_signing_key = SigningKey::P2pkh(
            super::key_triple::KeyTriple::self_under("stas3mint", "1"),
        );
        let funding_input = FundingInput {
            txid_hex: prev_txid_hex,
            vout: 0,
            satoshis: funding_amount,
            locking_script: funding_lock,
            triple: super::key_triple::KeyTriple::self_under("stas3mint", "1"),
        };

        // 3. Build the 2-tx issuance with two destinations.
        let dest_a_sats: u64 = 30_000;
        let dest_b_sats: u64 = 50_000;
        let req = IssueRequest {
            wallet: &issuer_wallet,
            originator: None,
            issuer_signing_key,
            redemption_pkh: issuer_pkh,
            flags: 0,
            service_fields: vec![],
            scheme_bytes: b"TEST_SCHEME_v1".to_vec(),
            funding_input,
            destinations: vec![
                IssueDestination {
                    owner_pkh: owner_a_pkh,
                    action_data: ActionData::Passive(vec![]),
                    satoshis: dest_a_sats,
                    optional_data: vec![],
                },
                IssueDestination {
                    owner_pkh: owner_b_pkh,
                    action_data: ActionData::Passive(vec![]),
                    satoshis: dest_b_sats,
                    optional_data: vec![],
                },
            ],
            fee_rate_sat_per_kb: 500,
        };
        let result = build_issue(req).await.expect("build_issue ok");

        // Sanity: contract tx has 1 input, 2 outputs; issue tx has 2
        // inputs, 3 outputs (2 stas + 1 change).
        assert_eq!(result.contract_tx.inputs.len(), 1);
        assert_eq!(result.contract_tx.outputs.len(), 2);
        assert_eq!(result.issue_tx.inputs.len(), 2);
        assert_eq!(result.issue_tx.outputs.len(), 3);

        // 4. Take the issue tx output 0 (owner A's STAS-3 token) and
        //    transfer it via the existing factory — engine-verify the
        //    transfer to confirm the freshly-minted lock is valid.
        let stas_lock = result.issue_tx.outputs[0].locking_script.clone();
        let stas_satoshis = result.issue_tx.outputs[0].satoshis.unwrap();
        assert_eq!(stas_satoshis, dest_a_sats);
        let issue_tx_id = result.issue_tx.id().expect("issue tx id");

        // For the transfer's funding, we need a fresh P2PKH UTXO. Use
        // the issue tx's change output (output index 2).
        let funding_for_transfer_amount = result.issue_tx.outputs[2].satoshis.unwrap();
        let funding_for_transfer_lock = result.issue_tx.outputs[2].locking_script.clone();

        let new_owner_pkh = derive_pkh(&owner_a_wallet, "stas3owner", "a-next").await;

        let transfer_req = TransferRequest {
            wallet: &owner_a_wallet,
            originator: None,
            stas_input: TokenInput {
                txid_hex: issue_tx_id.clone(),
                vout: 0,
                satoshis: stas_satoshis,
                locking_script: stas_lock.clone(),
                signing_key: super::factory::types::SigningKey::P2pkh(
                    super::key_triple::KeyTriple::self_under("stas3owner", "a"),
                ),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: None,
            },
            funding_input: super::factory::FundingInput {
                txid_hex: issue_tx_id,
                vout: 2,
                satoshis: funding_for_transfer_amount,
                locking_script: funding_for_transfer_lock,
                triple: super::key_triple::KeyTriple::self_under("stas3mint", "1"),
            },
            destination_owner_pkh: new_owner_pkh,
            redemption_pkh: issuer_pkh,
            flags: 0,
            service_fields: vec![],
            optional_data: vec![],
            note: None,
            change_pkh: issuer_pkh,
            change_satoshis: funding_for_transfer_amount.saturating_sub(500),
        };
        let transfer_tx = build_transfer(transfer_req).await.expect("build_transfer ok");
        let valid = verify_input(&transfer_tx, 0, &stas_lock, stas_satoshis)
            .expect("verify_input no error");
        assert!(valid, "engine rejected transfer of freshly-issued lock");
    }

    /// Wave 2A.1: build_issue with FREEZABLE flag; service_fields[0] is
    /// the freeze authority pkh, and the produced lock decodes back to
    /// that authority.
    #[tokio::test]
    async fn test_factory_issue_with_freezable_flag() {
        use super::decode::decode_locking_script;
        use super::factory::issue::{
            build_issue, IssueDestination, IssueRequest,
        };
        use super::factory::types::{FundingInput, SigningKey};
        use super::flags::FREEZABLE;

        let issuer_root = PrivateKey::from_hex("44").unwrap();
        let owner_root = PrivateKey::from_hex("55").unwrap();
        let issuer_wallet = ProtoWallet::new(issuer_root);
        let owner_wallet = ProtoWallet::new(owner_root);

        let issuer_pkh = derive_pkh(&issuer_wallet, "stas3mint", "1").await;
        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;
        let freeze_auth_pkh = [0x77u8; 20];

        let funding_amount: u64 = 50_000;
        let funding_lock = make_p2pkh_lock(&issuer_pkh);
        let mut prev_tx = Transaction::new();
        prev_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: funding_lock.clone(),
            change: false,
        });
        let prev_txid_hex = prev_tx.id().expect("prev tx id");

        let req = IssueRequest {
            wallet: &issuer_wallet,
            originator: None,
            issuer_signing_key: SigningKey::P2pkh(
                super::key_triple::KeyTriple::self_under("stas3mint", "1"),
            ),
            redemption_pkh: issuer_pkh,
            flags: FREEZABLE,
            service_fields: vec![freeze_auth_pkh.to_vec()],
            scheme_bytes: b"FREEZABLE_TEST".to_vec(),
            funding_input: FundingInput {
                txid_hex: prev_txid_hex,
                vout: 0,
                satoshis: funding_amount,
                locking_script: funding_lock,
                triple: super::key_triple::KeyTriple::self_under("stas3mint", "1"),
            },
            destinations: vec![IssueDestination {
                owner_pkh,
                action_data: ActionData::Passive(vec![]),
                satoshis: 10_000,
                optional_data: vec![],
            }],
            fee_rate_sat_per_kb: 500,
        };
        let result = build_issue(req).await.expect("build_issue ok");

        // Decode the destination lock and verify the freeze authority.
        let decoded = decode_locking_script(&result.issue_tx.outputs[0].locking_script)
            .expect("decode lock ok");
        assert_eq!(decoded.flags, FREEZABLE);
        assert_eq!(
            decoded.service_fields.len(),
            1,
            "FREEZABLE-only mints should have exactly 1 service field"
        );
        assert_eq!(
            decoded.service_fields[0],
            freeze_auth_pkh.to_vec(),
            "service_fields[0] should be the freeze authority pkh"
        );
    }

    /// Wave 2A.1: round-trip via Stas3Wallet::mint_eac with EAC fields,
    /// then decode the EAC fields off the produced lock and verify
    /// equality.
    #[tokio::test]
    async fn test_mint_eac_wallet_helper() {
        use super::eac::{EacFields, EnergySource};
        use super::factory::types::{FundingInput, SigningKey};
        use super::wallet::Stas3Wallet;
        use std::sync::Arc;

        let issuer_root = PrivateKey::from_hex("66").unwrap();
        let owner_root = PrivateKey::from_hex("77").unwrap();
        let issuer_wallet = Arc::new(ProtoWallet::new(issuer_root));
        let owner_wallet = ProtoWallet::new(owner_root);

        let issuer_pkh = derive_pkh(&issuer_wallet, "stas3mint", "1").await;
        let owner_pkh = derive_pkh(&owner_wallet, "stas3owner", "1").await;

        let funding_amount: u64 = 60_000;
        let funding_lock = make_p2pkh_lock(&issuer_pkh);
        let mut prev_tx = Transaction::new();
        prev_tx.outputs.push(TransactionOutput {
            satoshis: Some(funding_amount),
            locking_script: funding_lock.clone(),
            change: false,
        });
        let prev_txid_hex = prev_tx.id().expect("prev tx id");

        let fields = EacFields {
            quantity_wh: 1_500_000,
            interval_start: 1_700_000_000,
            interval_end: 1_700_003_600,
            energy_source: EnergySource::Solar,
            country: *b"US",
            device_id: [0x42; 32],
            id_range: (1, 100),
            issue_date: 1_700_004_000,
            storage_tag: 0,
        };

        let stas = Stas3Wallet::new(issuer_wallet.clone());
        let result = stas
            .mint_eac(
                None,
                SigningKey::P2pkh(
                    super::key_triple::KeyTriple::self_under("stas3mint", "1"),
                ),
                FundingInput {
                    txid_hex: prev_txid_hex,
                    vout: 0,
                    satoshis: funding_amount,
                    locking_script: funding_lock,
                    triple: super::key_triple::KeyTriple::self_under("stas3mint", "1"),
                },
                0,
                None,
                None,
                vec![(owner_pkh, 5_000, fields.clone())],
                b"EAC_v1_metadata".to_vec(),
                500,
            )
            .await
            .expect("mint_eac ok");

        // Decode the lock and round-trip the EAC fields.
        let decoded = super::decode::decode_locking_script(
            &result.issue_tx.outputs[0].locking_script,
        )
        .expect("decode ok");
        let parsed = EacFields::from_optional_data(&decoded.optional_data)
            .expect("EacFields round-trip ok");
        assert_eq!(parsed, fields, "EAC fields should round-trip exactly");
        assert_eq!(decoded.owner_pkh, owner_pkh);
        assert_eq!(decoded.redemption_pkh, issuer_pkh);
    }
}
