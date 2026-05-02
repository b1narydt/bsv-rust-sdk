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
//!   [`factory::build_split`], [`factory::build_merge`],
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
    build_confiscate, build_freeze, build_merge, build_redeem, build_split,
    build_swap_cancel, build_swap_execute, build_swap_mark, build_transfer,
    build_unfreeze, ConfiscateRequest, FreezeRequest, FundingInput, MergeRequest,
    RedeemRequest, SplitDestination, SplitRequest, SwapCancelRequest,
    SwapExecuteRequest, SwapMarkRequest, TokenInput, TransferRequest,
    UnfreezeRequest,
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
                triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
                triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
                triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
                triple: super::key_triple::KeyTriple::self_under("stas3mint", "1"),
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
                    triple: super::key_triple::KeyTriple::self_under("stas3owner", "a"),
                    current_action_data: ActionData::Passive(vec![]),
                    source_tx_bytes: Some(src_a_bytes),
                },
                TokenInput {
                    txid_hex: src_b_txid_hex.clone(),
                    vout: 0,
                    satoshis: amt_b,
                    locking_script: lock_b.clone(),
                    triple: super::key_triple::KeyTriple::self_under("stas3owner", "b"),
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
                triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
            freeze_authority_triple: super::key_triple::KeyTriple::self_under(
                "stas3freeze",
                "1",
            ),
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
                triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
            freeze_authority_triple: super::key_triple::KeyTriple::self_under(
                "stas3freeze",
                "1",
            ),
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
                triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
            confiscation_authority_triple: super::key_triple::KeyTriple::self_under(
                "stas3confiscate",
                "1",
            ),
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
                triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
                triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
            receive_addr_triple: super::key_triple::KeyTriple::self_under(
                "stas3swap",
                "receive-1",
            ),
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
                    triple: super::key_triple::KeyTriple::self_under("stas3owner", "a"),
                    current_action_data: ActionData::Swap(descriptor_a),
                    source_tx_bytes: Some(src_a_bytes),
                },
                TokenInput {
                    txid_hex: src_b_txid_hex.clone(),
                    vout: 0,
                    satoshis: amt_b,
                    locking_script: lock_b.clone(),
                    triple: super::key_triple::KeyTriple::self_under("stas3owner", "b"),
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
            triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
            triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
            triple: super::key_triple::KeyTriple::self_under("stas3owner", "1"),
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
}
