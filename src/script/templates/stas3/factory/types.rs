//! Common helper types for STAS-3 factories.
//!
//! `TokenInput` references a STAS-3 UTXO being consumed; `FundingInput`
//! references a P2PKH funding UTXO that pays the spend's fee and supplies
//! the satoshis for the inline change output.

use crate::script::locking_script::LockingScript;

use super::super::action_data::ActionData;
use super::super::key_triple::KeyTriple;

/// A STAS-3 UTXO being consumed in a spend. The factory needs:
/// - the previous outpoint (`txid_hex` BE + `vout`)
/// - the previous satoshis (for BIP-143 preimage)
/// - the previous locking script (for BIP-143 preimage)
/// - the Type-42 triple identifying the owner key
/// - the current var2 form (so operations like freeze/unfreeze can derive
///   the next var2 form; transfer carries it forward unchanged)
/// - (merge only) the raw bytes of the preceding transaction, so the factory
///   can build the trailing piece array per spec §9.5 by excising the asset
///   locking script. Pass `None` for non-merge spends.
#[derive(Clone, Debug)]
pub struct TokenInput {
    pub txid_hex: String,
    pub vout: u32,
    pub satoshis: u64,
    pub locking_script: LockingScript,
    pub triple: KeyTriple,
    /// var2 form on the input UTXO. Used to derive var2 form on the output
    /// (operations like freeze/unfreeze transform; transfer carries forward).
    pub current_action_data: ActionData,
    /// Raw bytes of the preceding transaction that produced this UTXO.
    /// Required for merge (the factory excises this input's asset locking
    /// script from the preceding tx to build the trailing piece array per
    /// spec §9.5). Set to `None` for transfer/split/redeem.
    pub source_tx_bytes: Option<Vec<u8>>,
}

/// A P2PKH funding UTXO. Caller is responsible for signing input 1 of the
/// resulting transaction (the factory leaves it unsigned).
#[derive(Clone, Debug)]
pub struct FundingInput {
    pub txid_hex: String,
    pub vout: u32,
    pub satoshis: u64,
    /// Standard 25-byte P2PKH locking script.
    pub locking_script: LockingScript,
    pub triple: KeyTriple,
}
