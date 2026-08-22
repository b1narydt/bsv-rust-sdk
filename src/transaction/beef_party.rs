//! BeefParty: multi-party BEEF transaction sharing.
//!
//! Extends Beef for scenarios where transaction validity data is exchanged
//! between more than one external party. Tracks which txids each party
//! already knows to reduce re-transmission of large transactions.

use std::collections::HashMap;

use crate::transaction::beef::Beef;
use crate::transaction::error::TransactionError;

/// A multi-party BEEF container that tracks which transactions
/// each party already has validity proof for.
#[derive(Debug, Clone)]
pub struct BeefParty {
    /// The underlying Beef containing all transactions and bumps.
    pub beef: Beef,
    /// Maps party identifier -> set of txids known to that party.
    pub known_to: HashMap<String, HashMap<String, bool>>,
}

impl BeefParty {
    /// Create a new BeefParty with initial party identifiers.
    ///
    /// Accepts any iterator of string-like items (e.g., `&["alice", "bob"]`,
    /// `vec!["charlie".to_string()]`, or an empty `&[]`).
    pub fn new(parties: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        let mut bp = BeefParty {
            beef: Beef::new(crate::transaction::beef::BEEF_V2),
            known_to: HashMap::new(),
        };
        for party in parties {
            bp.known_to
                .insert(party.as_ref().to_string(), HashMap::new());
        }
        bp
    }

    /// Create a BeefParty from an existing Beef.
    pub fn from_beef(beef: Beef) -> Self {
        BeefParty {
            beef,
            known_to: HashMap::new(),
        }
    }

    /// Check if a party has been added.
    pub fn is_party(&self, party: &str) -> bool {
        self.known_to.contains_key(party)
    }

    /// Add a new unique party identifier.
    pub fn add_party(&mut self, party: &str) -> Result<(), TransactionError> {
        if self.is_party(party) {
            return Err(TransactionError::BeefError(format!(
                "Party {party} already exists."
            )));
        }
        self.known_to.insert(party.to_string(), HashMap::new());
        Ok(())
    }

    /// Get the list of txids known to a party.
    pub fn get_known_txids_for_party(&self, party: &str) -> Result<Vec<String>, TransactionError> {
        let known = self
            .known_to
            .get(party)
            .ok_or_else(|| TransactionError::BeefError(format!("Party {party} is unknown.")))?;
        Ok(known.keys().cloned().collect())
    }

    /// Record additional txids as known to a party (adding the party if new).
    ///
    /// Each txid is also merged into the beef as a txid-only entry so the
    /// beef's dependency graph can resolve against it; an entry that an
    /// existing bump already proves picks up that proof (TS `mergeTxidOnly`).
    pub fn add_known_txids_for_party(&mut self, party: &str, txids: &[String]) {
        let known = self.known_to.entry(party.to_string()).or_default();
        for txid in txids {
            known.insert(txid.clone(), true);
            self.beef.merge_txid_only(txid);
        }
    }

    /// Get a Beef trimmed of what `party` already knows.
    ///
    /// Only txid-only entries the party knows are removed — a full
    /// transaction stays even if the party knows its txid, because a
    /// full transaction is validity data the beef still depends on
    /// (TS `trimKnownTxids` removes `isTxidOnly` entries only). Bumps no
    /// longer referenced after the trim are pruned and re-indexed.
    pub fn get_trimmed_beef_for_party(&self, party: &str) -> Result<Beef, TransactionError> {
        let known_txids = self.get_known_txids_for_party(party)?;
        let mut pruned = self.beef.clone();
        pruned.trim_known_txids(&known_txids)?;
        Ok(pruned)
    }

    /// Merge another Beef into this BeefParty's beef.
    ///
    /// Routes through `Beef::merge_beef`, so bumps dedupe by (height, root)
    /// and every merged transaction's `bump_index` is re-derived against
    /// this beef's bumps array. Copying `other`'s entries verbatim would
    /// carry `bump_index` values that point into `other`'s array, not ours.
    pub fn merge(&mut self, other: &Beef) -> Result<(), TransactionError> {
        self.beef.merge_beef(other)
    }

    /// Merge a beef received from `party`, recording every transaction the
    /// beef proves (or chains to a proof) as known to that party.
    pub fn merge_beef_from_party(
        &mut self,
        party: &str,
        other: &Beef,
    ) -> Result<(), TransactionError> {
        let known_txids = other.get_valid_txids();
        self.beef.merge_beef(other)?;
        let known = self.known_to.entry(party.to_string()).or_default();
        for txid in known_txids {
            known.insert(txid, true);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beef_party_new_with_str_slices() {
        let bp = BeefParty::new(["alice", "bob"]);
        assert!(bp.is_party("alice"));
        assert!(bp.is_party("bob"));
        assert!(!bp.is_party("charlie"));
    }

    #[test]
    fn test_beef_party_new_empty() {
        let empty: &[&str] = &[];
        let bp = BeefParty::new(empty);
        assert!(bp.known_to.is_empty());
    }

    #[test]
    fn test_beef_party_new_with_owned_strings() {
        let bp = BeefParty::new(vec!["charlie".to_string()]);
        assert!(bp.is_party("charlie"));
        assert_eq!(bp.known_to.len(), 1);
    }
}
