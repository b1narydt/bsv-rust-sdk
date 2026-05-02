//! Common helper types for STAS-3 factories.
//!
//! `TokenInput` references a STAS-3 UTXO being consumed; `FundingInput`
//! references a P2PKH funding UTXO that pays the spend's fee and supplies
//! the satoshis for the inline change output.
//!
//! `SigningKey` is the union over the two STAS-3 ownership shapes
//! (P2PKH and P2MPKH/multisig). Every input that needs to produce an
//! `AuthzWitness` carries a `SigningKey` rather than a bare `KeyTriple`,
//! so the same factories cover both single-sig and m-of-n token owners
//! transparently per spec §10.2.

use crate::script::locking_script::LockingScript;

use super::super::action_data::ActionData;
use super::super::error::Stas3Error;
use super::super::key_triple::KeyTriple;
use super::super::multisig::MultisigScript;

/// Either a P2PKH owner (single Type-42 triple) or a P2MPKH multisig
/// owner (M triples + the full M-of-N multisig descriptor). Used by
/// every STAS-3 factory in place of a bare `KeyTriple` so multisig
/// (spec §10.2 P2MPKH) and single-sig owners share the same code path.
///
/// For `Multi`, `triples.len()` MUST equal `multisig.threshold()` —
/// each triple derives one of the M signing keys, in the same relative
/// order as the corresponding public key appears in
/// `multisig.public_keys()`. (The factory does not re-order; the
/// caller is responsible for presenting the triples in the order that
/// matches the redeem-script pubkey ordering, just as
/// `OP_CHECKMULTISIG` requires.)
#[derive(Clone, Debug)]
pub enum SigningKey {
    /// Standard single-sig P2PKH owner — one Type-42 triple.
    P2pkh(KeyTriple),
    /// M-of-N multisig (P2MPKH) owner — M triples + the full N-key
    /// redeem-script descriptor.
    Multi {
        /// M triples, one per signature required. `triples.len()` MUST
        /// equal `multisig.threshold()`.
        triples: Vec<KeyTriple>,
        /// The full M-of-N descriptor.
        multisig: MultisigScript,
    },
}

impl SigningKey {
    /// `true` if this is a multisig signing key.
    pub fn is_multi(&self) -> bool {
        matches!(self, Self::Multi { .. })
    }

    /// For the multisig arm: the 20-byte `MPKH` of the full redeem
    /// script. `None` for `P2pkh` (single-sig PKH derivation requires a
    /// wallet round-trip, so it's exposed on the wallet wrapper instead).
    pub fn mpkh(&self) -> Option<[u8; 20]> {
        match self {
            Self::Multi { multisig, .. } => Some(multisig.mpkh()),
            Self::P2pkh(_) => None,
        }
    }

    /// Validate internal invariants:
    /// - `Multi` must have `triples.len() == multisig.threshold()`.
    ///
    /// Used by [`super::common::sign_with_signing_key`] before
    /// dispatching to the wallet, so caller mistakes surface as
    /// `Stas3Error::InvalidScript` rather than confusing wallet errors.
    pub fn validate(&self) -> Result<(), Stas3Error> {
        match self {
            Self::P2pkh(_) => Ok(()),
            Self::Multi { triples, multisig } => {
                let m = multisig.threshold() as usize;
                if triples.len() != m {
                    return Err(Stas3Error::InvalidScript(format!(
                        "SigningKey::Multi: expected {m} triples for {m}-of-{} multisig, got {}",
                        multisig.n(),
                        triples.len()
                    )));
                }
                Ok(())
            }
        }
    }
}

impl From<KeyTriple> for SigningKey {
    fn from(t: KeyTriple) -> Self {
        Self::P2pkh(t)
    }
}

/// A STAS-3 UTXO being consumed in a spend. The factory needs:
/// - the previous outpoint (`txid_hex` BE + `vout`)
/// - the previous satoshis (for BIP-143 preimage)
/// - the previous locking script (for BIP-143 preimage)
/// - the signing-key shape (P2PKH or M-of-N multisig) authorizing the
///   spend
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
    /// Owner authorization: P2PKH (single triple) or P2MPKH (M triples
    /// plus full M-of-N redeem script). Build via
    /// `SigningKey::P2pkh(triple)` (or `triple.into()`) for the
    /// single-sig case, or `SigningKey::Multi { triples, multisig }`
    /// for multisig per spec §10.2.
    pub signing_key: SigningKey,
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
///
/// The funding input is held by a P2PKH owner only — multisig funding
/// is not supported (and per the fuel-basket pattern, the sole purpose
/// of these UTXOs is to pay tx fees, where multisig adds no value).
#[derive(Clone, Debug)]
pub struct FundingInput {
    pub txid_hex: String,
    pub vout: u32,
    pub satoshis: u64,
    /// Standard 25-byte P2PKH locking script.
    pub locking_script: LockingScript,
    pub triple: KeyTriple,
}
