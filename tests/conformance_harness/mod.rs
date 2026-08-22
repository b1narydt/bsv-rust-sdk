#![allow(dead_code)]

use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Deserialize)]
pub struct VectorFile {
    #[serde(default)]
    pub id: Option<String>,
    pub vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
pub struct Vector {
    pub id: String,
    pub input: Value,
    pub expected: Value,
    #[serde(default)]
    pub skip: bool,
    #[serde(default)]
    pub skip_reason: Option<String>,
}

#[derive(Clone, Copy)]
pub struct Corpus<'a> {
    pub category: &'a str,
    pub json: &'a str,
    pub expected_count: usize,
}

#[derive(Clone, Copy)]
pub struct KnownDivergence<'a> {
    pub id: &'a str,
    pub reason: &'a str,
    pub evidence: &'a str,
}

pub fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

pub fn bool_value(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

pub fn number(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

pub fn usize_value(value: &Value, key: &str) -> usize {
    value.get(key).and_then(Value::as_u64).unwrap_or(0) as usize
}

pub fn bytes(hex: &str) -> Result<Vec<u8>, String> {
    let padded;
    let hex = if hex.len().is_multiple_of(2) {
        hex
    } else {
        padded = format!("0{hex}");
        &padded
    };
    hex::decode(hex).map_err(|error| format!("invalid hex {hex:?}: {error}"))
}

pub fn bytes32(hex: &str) -> Result<[u8; 32], String> {
    let raw = bytes(hex)?;
    if raw.len() > 32 {
        return Err(format!("value is {} bytes, expected at most 32", raw.len()));
    }
    let mut out = [0u8; 32];
    out[32 - raw.len()..].copy_from_slice(&raw);
    Ok(out)
}

pub fn hex_string(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}

pub fn ensure(condition: bool, message: impl FnOnce() -> String) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message())
    }
}

/// Execute every non-governed vector and enforce an exact divergence ledger.
/// A pinned finding must continue failing with its named evidence, while an
/// unpinned failure or a newly passing pin fails the test.
pub fn run_corpora(
    corpora: &[Corpus<'_>],
    governed_skips: &[&str],
    known: &[KnownDivergence<'_>],
    dispatch: impl Fn(&str, &Vector) -> Result<(), String>,
) {
    let skip_ids: BTreeSet<&str> = governed_skips.iter().copied().collect();
    let known_by_id: BTreeMap<&str, KnownDivergence<'_>> =
        known.iter().map(|entry| (entry.id, *entry)).collect();
    assert_eq!(
        skip_ids.len(),
        governed_skips.len(),
        "duplicate governed skip"
    );
    assert_eq!(known_by_id.len(), known.len(), "duplicate divergence pin");

    let mut loaded = 0usize;
    let mut asserted = 0usize;
    let mut skipped = BTreeSet::new();
    let mut observed_findings = BTreeSet::new();
    let mut failures = Vec::new();

    for corpus in corpora {
        let file: VectorFile = serde_json::from_str(corpus.json)
            .unwrap_or_else(|error| panic!("{} corpus JSON: {error}", corpus.category));
        assert_eq!(
            file.vectors.len(),
            corpus.expected_count,
            "{} vector count changed on refresh",
            corpus.category
        );
        loaded += file.vectors.len();

        for vector in &file.vectors {
            if vector.skip {
                skipped.insert(vector.id.clone());
                if !skip_ids.contains(vector.id.as_str()) {
                    failures.push(format!(
                        "{}: unledgered governed skip: {}",
                        vector.id,
                        vector.skip_reason.as_deref().unwrap_or("missing reason")
                    ));
                }
                continue;
            }

            asserted += 1;
            let outcome = dispatch(corpus.category, vector)
                .map_err(|error| format!("{}: {error}", vector.id));
            match (outcome, known_by_id.get(vector.id.as_str())) {
                (Ok(()), None) => {}
                (Ok(()), Some(pin)) => failures.push(format!(
                    "{}: pinned divergence unexpectedly passed ({})",
                    vector.id, pin.reason
                )),
                (Err(error), None) => failures.push(error),
                (Err(error), Some(pin)) => {
                    observed_findings.insert(vector.id.clone());
                    if !error.contains(pin.evidence) {
                        failures.push(format!(
                            "{}: divergence changed shape; expected evidence {:?}, got {error:?}",
                            vector.id, pin.evidence
                        ));
                    }
                }
            }
        }
    }

    let expected_skips: BTreeSet<String> =
        governed_skips.iter().map(|id| (*id).to_string()).collect();
    assert_eq!(skipped, expected_skips, "governed skip ledger drifted");
    let expected_findings: BTreeSet<String> =
        known.iter().map(|entry| entry.id.to_string()).collect();
    assert_eq!(
        observed_findings, expected_findings,
        "known-divergence ledger drifted"
    );
    assert_eq!(loaded, asserted + skipped.len());
    assert!(
        failures.is_empty(),
        "{} conformance failures across {loaded} loaded / {asserted} asserted / {} skipped:\n{}",
        failures.len(),
        skipped.len(),
        failures.join("\n")
    );
}
