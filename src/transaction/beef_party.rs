//! BeefParty: multi-party BEEF transaction sharing.
//!
//! Extends Beef for scenarios where transaction validity data is exchanged
//! between more than one external party. Tracks which txids each party
//! already knows to reduce re-transmission of large transactions.

use std::collections::HashMap;

use crate::transaction::beef::Beef;
use crate::transaction::beef_tx::BeefTx;
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

    /// Record additional txids as known to a party.
    pub fn add_known_txids_for_party(&mut self, party: &str, txids: &[String]) {
        let known = self.known_to.entry(party.to_string()).or_default();
        for txid in txids {
            known.insert(txid.clone(), true);
            // Also add as txid-only to the beef if not already present
            if !self.beef.txs.iter().any(|t| t.txid == *txid) {
                self.beef.txs.push(BeefTx::from_txid(txid.clone()));
            }
        }
    }

    /// Get a trimmed Beef for a specific party, excluding txids they already know.
    pub fn get_trimmed_beef_for_party(&self, party: &str) -> Result<Beef, TransactionError> {
        let known_txids = self.get_known_txids_for_party(party)?;
        let mut trimmed = self.beef.clone();
        trimmed.txs.retain(|tx| !known_txids.contains(&tx.txid));
        Ok(trimmed)
    }

    /// Merge another Beef into this BeefParty.
    pub fn merge(&mut self, other: &Beef) -> Result<(), TransactionError> {
        // Merge bumps, deduplicating by block height and root
        for bump in &other.bumps {
            let already_exists = self.beef.bumps.iter().any(|b| {
                b.block_height == bump.block_height
                    && b.compute_root(None).ok() == bump.compute_root(None).ok()
            });
            if !already_exists {
                self.beef.bumps.push(bump.clone());
            }
        }

        // Merge transactions, deduplicating by txid
        for tx in &other.txs {
            if !self.beef.txs.iter().any(|t| t.txid == tx.txid) {
                self.beef.txs.push(tx.clone());
            }
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
