//! Historian for traversing transaction ancestry chains.
//!
//! Translates the TS SDK Historian.ts. Builds chronological history by
//! recursively traversing input.source_transaction chains and interpreting
//! each transaction's outputs with a provided callback.

use std::collections::{HashMap, HashSet};

use crate::transaction::Transaction;

/// Interpreter function type: given a transaction and output index,
/// optionally returns a typed value for that output.
///
/// Return None to indicate this output does not contribute to history.
pub type InterpreterFn<T, C> =
    Box<dyn Fn(&Transaction, usize, Option<&C>) -> Option<T> + Send + Sync>;

/// Historian traverses transaction input ancestry chains and interprets
/// each output to build a chronological value history.
///
/// Generic parameters:
/// - T: The interpreted value type produced for matching outputs.
/// - C: Context type passed through to the interpreter.
pub struct Historian<T, C> {
    interpreter: InterpreterFn<T, C>,
    cache: Option<HashMap<String, Vec<T>>>,
}

impl<T: Clone, C> Historian<T, C> {
    /// Create a new Historian with the given interpreter function.
    pub fn new(interpreter: InterpreterFn<T, C>) -> Self {
        Historian {
            interpreter,
            cache: None,
        }
    }

    /// Create a new Historian with result caching enabled.
    pub fn with_cache(interpreter: InterpreterFn<T, C>) -> Self {
        Historian {
            interpreter,
            cache: Some(HashMap::new()),
        }
    }

    /// Build a chronological history (oldest first) by traversing the
    /// transaction's input ancestry chain.
    ///
    /// Each transaction's outputs are passed to the interpreter. Non-None
    /// results are collected. The traversal follows input.source_transaction
    /// recursively (depth-first), visiting each transaction at most once.
    pub fn build_history(&mut self, start_tx: &Transaction, context: Option<&C>) -> Vec<T> {
        let cache_key = start_tx.id().unwrap_or_default();

        // Check cache.
        if let Some(ref cache) = self.cache {
            if let Some(cached) = cache.get(&cache_key) {
                return cached.clone();
            }
        }

        let mut history = Vec::new();
        let mut visited = HashSet::new();
        let txid_index = start_tx.source_transaction_index().unwrap_or_default();

        self.traverse(start_tx, context, &mut history, &mut visited, &txid_index);

        // History is collected in traversal order (depth-first from tip),
        // reverse to get chronological order (oldest first).
        history.reverse();

        // Cache the result.
        if let Some(ref mut cache) = self.cache {
            cache.insert(cache_key, history.clone());
        }

        history
    }

    fn traverse(
        &self,
        tx: &Transaction,
        context: Option<&C>,
        history: &mut Vec<T>,
        visited: &mut HashSet<String>,
        txid_index: &HashMap<String, &Transaction>,
    ) {
        let txid = tx.id().unwrap_or_default();
        if visited.contains(&txid) {
            return;
        }
        visited.insert(txid);
        let tx = txid_index
            .get(&tx.id().unwrap_or_default())
            .copied()
            .unwrap_or(tx);

        // Interpret outputs of this transaction.
        for output_index in 0..tx.outputs.len() {
            if let Some(value) = (self.interpreter)(tx, output_index, context) {
                history.push(value);
            }
        }

        // Recursively traverse input source transactions.
        for input in &tx.inputs {
            let source_tx = if let Some(source) = input.source_transaction.as_deref() {
                txid_index
                    .get(&source.id().unwrap_or_default())
                    .copied()
                    .unwrap_or(source)
            } else if let Some(source_txid) = input.source_txid.as_deref() {
                let Some(source) = txid_index.get(source_txid).copied() else {
                    continue;
                };
                source
            } else {
                continue;
            };
            self.traverse(source_tx, context, history, visited, txid_index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;

    #[test]
    fn test_empty_transaction_returns_empty_history() {
        let tx = Transaction::new();
        let mut historian: Historian<String, ()> = Historian::new(Box::new(|_tx, _idx, _ctx| None));
        let history = historian.build_history(&tx, None);
        assert!(history.is_empty());
    }

    #[test]
    fn test_interpreter_called_for_each_output() {
        use crate::transaction::TransactionOutput;

        let mut tx = Transaction::new();
        tx.outputs.push(TransactionOutput {
            satoshis: Some(100),
            ..Default::default()
        });
        tx.outputs.push(TransactionOutput {
            satoshis: Some(200),
            ..Default::default()
        });
        tx.outputs.push(TransactionOutput {
            satoshis: Some(300),
            ..Default::default()
        });

        let mut historian: Historian<u64, ()> =
            Historian::new(Box::new(|tx, idx, _ctx| tx.outputs[idx].satoshis));

        let history = historian.build_history(&tx, None);
        assert_eq!(history.len(), 3);
        // Reversed: 300, 200, 100
        assert_eq!(history, vec![300, 200, 100]);
    }

    #[test]
    fn test_caching_returns_same_result() {
        let tx = Transaction::new();
        let mut historian: Historian<String, ()> =
            Historian::with_cache(Box::new(|_tx, _idx, _ctx| None));
        let h1 = historian.build_history(&tx, None);
        let h2 = historian.build_history(&tx, None);
        assert_eq!(h1, h2);
    }
}
