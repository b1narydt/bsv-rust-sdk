//! Bitcoin transaction type with wire format and EF format serialization.

use std::io::{Cursor, Read, Write};

use std::collections::{HashMap, HashSet};

use crate::primitives::hash::hash256;
use crate::primitives::transaction_signature::{
    SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
};
use crate::script::locking_script::LockingScript;
use crate::script::templates::ScriptTemplateUnlock;
use crate::transaction::beef::BEEF_V1;
use crate::transaction::error::TransactionError;
use crate::transaction::merkle_path::MerklePath;
use crate::transaction::transaction_input::TransactionInput;
use crate::transaction::transaction_output::TransactionOutput;
use crate::transaction::{
    read_u32_le, read_u64_le, read_varint, write_u32_le, write_u64_le, write_varint,
};

/// EF format marker bytes: [0x00, 0x00, 0x00, 0x00, 0x00, 0xEF]
const EF_MARKER: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0xEF];

/// A Bitcoin transaction with inputs, outputs, and optional merkle proof.
///
/// Supports standard binary and Extended Format (EF) serialization,
/// BEEF/Atomic BEEF packaging, and BIP-143 sighash preimage computation
/// for signing. Translates the TS SDK Transaction.ts.
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction version number.
    pub version: u32,
    /// Transaction inputs.
    pub inputs: Vec<TransactionInput>,
    /// Transaction outputs.
    pub outputs: Vec<TransactionOutput>,
    /// Lock time.
    pub lock_time: u32,
    /// Merkle path for SPV verification (populated from BEEF).
    pub merkle_path: Option<MerklePath>,
}

impl Transaction {
    /// Create a new empty transaction with default values.
    pub fn new() -> Self {
        Self {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            merkle_path: None,
        }
    }

    /// Deserialize a transaction from binary wire format.
    pub fn from_binary(reader: &mut impl Read) -> Result<Self, TransactionError> {
        let version = read_u32_le(reader)?;

        let input_count = read_varint(reader)? as usize;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(TransactionInput::from_binary(reader)?);
        }

        let output_count = read_varint(reader)? as usize;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(TransactionOutput::from_binary(reader)?);
        }

        let lock_time = read_u32_le(reader)?;

        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time,
            merkle_path: None,
        })
    }

    /// Deserialize a transaction from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, TransactionError> {
        let bytes = hex_to_bytes(hex)
            .map_err(|e| TransactionError::InvalidFormat(format!("invalid hex: {}", e)))?;
        let mut cursor = Cursor::new(bytes);
        Self::from_binary(&mut cursor)
    }

    /// Parse a transaction from a BEEF hex string, returning the subject transaction.
    ///
    /// Decodes the hex to bytes, parses the BEEF structure, and extracts the
    /// subject transaction (the last tx, or the atomic txid target).
    pub fn from_beef(beef_hex: &str) -> Result<Self, TransactionError> {
        let beef = crate::transaction::beef::Beef::from_hex(beef_hex)?;
        beef.into_transaction()
    }

    /// Serialize a transaction to binary wire format.
    pub fn to_binary(&self, writer: &mut impl Write) -> Result<(), TransactionError> {
        write_u32_le(writer, self.version)?;

        write_varint(writer, self.inputs.len() as u64)?;
        for input in &self.inputs {
            input.to_binary(writer)?;
        }

        write_varint(writer, self.outputs.len() as u64)?;
        for output in &self.outputs {
            output.to_binary(writer)?;
        }

        write_u32_le(writer, self.lock_time)?;
        Ok(())
    }

    /// Serialize a transaction to a hex string.
    pub fn to_hex(&self) -> Result<String, TransactionError> {
        let bytes = self.to_bytes()?;
        Ok(bytes_to_hex(&bytes))
    }

    /// Serialize a transaction to a byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let mut buf = Vec::new();
        self.to_binary(&mut buf)?;
        Ok(buf)
    }

    /// Serialize this transaction and its input chain to BEEF (BRC-62) format.
    ///
    /// Walks the `source_transaction` tree recursively to collect all ancestor
    /// transactions and their merkle paths, then serializes as BEEF V1.
    /// Matches the TS SDK's `Transaction.toBEEF()`.
    pub fn to_beef(&self) -> Result<Vec<u8>, TransactionError> {
        let mut bumps: Vec<MerklePath> = Vec::new();
        // Map from (blockHeight, computedRoot) → bump index for deduplication.
        let mut bump_index_by_root: HashMap<String, usize> = HashMap::new();
        let mut txs: Vec<(&Transaction, Option<usize>)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        fn get_bump_index(
            mp: &MerklePath,
            bumps: &mut Vec<MerklePath>,
            bump_index_by_root: &mut HashMap<String, usize>,
        ) -> Result<usize, TransactionError> {
            let root = mp.compute_root(None)?;
            let key = format!("{}:{}", mp.block_height, root);
            if let Some(&idx) = bump_index_by_root.get(&key) {
                bumps[idx].combine(mp)?;
                return Ok(idx);
            }
            let idx = bumps.len();
            bumps.push(mp.clone());
            bump_index_by_root.insert(key, idx);
            Ok(idx)
        }

        fn collect<'a>(
            tx: &'a Transaction,
            bumps: &mut Vec<MerklePath>,
            bump_index_by_root: &mut HashMap<String, usize>,
            txs: &mut Vec<(&'a Transaction, Option<usize>)>,
            seen: &mut HashSet<String>,
        ) -> Result<(), TransactionError> {
            let txid = tx.id()?;
            if seen.contains(&txid) {
                return Ok(());
            }

            let path_index = if let Some(ref mp) = tx.merkle_path {
                Some(get_bump_index(mp, bumps, bump_index_by_root)?)
            } else {
                // No proof — recurse into source transactions.
                for input in tx.inputs.iter().rev() {
                    if let Some(ref source_tx) = input.source_transaction {
                        collect(source_tx, bumps, bump_index_by_root, txs, seen)?;
                    }
                }
                None
            };

            seen.insert(txid);
            txs.push((tx, path_index));
            Ok(())
        }

        collect(self, &mut bumps, &mut bump_index_by_root, &mut txs, &mut seen)?;

        // Serialize BEEF V1.
        let mut buf = Vec::new();
        write_u32_le(&mut buf, BEEF_V1)?;

        // BUMPs
        write_varint(&mut buf, bumps.len() as u64)?;
        for bump in &bumps {
            bump.to_binary(&mut buf)?;
        }

        // Transactions
        write_varint(&mut buf, txs.len() as u64)?;
        for (tx, path_index) in &txs {
            tx.to_binary(&mut buf)?;
            if let Some(idx) = path_index {
                buf.push(1u8); // has_bump = true
                write_varint(&mut buf, *idx as u64)?;
            } else {
                buf.push(0u8); // has_bump = false
            }
        }

        Ok(buf)
    }

    /// Compute the transaction hash (double SHA-256).
    ///
    /// Returns the hash in internal byte order (LE).
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let bytes = self.to_bytes()?;
        Ok(hash256(&bytes))
    }

    /// Compute the transaction ID (hash reversed, hex-encoded).
    ///
    /// Returns the txid in display format (BE hex).
    pub fn id(&self) -> Result<String, TransactionError> {
        let mut h = self.hash()?;
        h.reverse();
        Ok(bytes_to_hex(&h))
    }

    /// Add an input to the transaction.
    pub fn add_input(&mut self, input: TransactionInput) {
        self.inputs.push(input);
    }

    /// Add an output to the transaction.
    pub fn add_output(&mut self, output: TransactionOutput) {
        self.outputs.push(output);
    }

    /// Deserialize a transaction from EF format (BRC-30).
    ///
    /// EF format: version(4) + EF_MARKER(6) + inputs_with_source_info + outputs + locktime(4)
    /// Each input additionally includes source satoshis (u64 LE) and source locking script.
    pub fn from_ef(reader: &mut impl Read) -> Result<Self, TransactionError> {
        let version = read_u32_le(reader)?;

        // Read and verify the 6-byte EF marker
        let mut marker = [0u8; 6];
        reader.read_exact(&mut marker)?;
        if marker != EF_MARKER {
            return Err(TransactionError::InvalidFormat(
                "invalid EF marker".to_string(),
            ));
        }

        let input_count = read_varint(reader)? as usize;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            // Read standard input fields
            let mut input = TransactionInput::from_binary(reader)?;

            // Read source satoshis (u64 LE)
            let source_satoshis = read_u64_le(reader)?;

            // Read source locking script (varint + bytes)
            let script_len = read_varint(reader)? as usize;
            let mut script_bytes = vec![0u8; script_len];
            if script_len > 0 {
                reader.read_exact(&mut script_bytes)?;
            }
            let source_locking_script = LockingScript::from_binary(&script_bytes);

            // Create a minimal source transaction with one output at the referenced index
            let mut source_tx = Transaction::new();
            // Pad outputs up to the referenced index
            for _ in 0..input.source_output_index {
                source_tx.outputs.push(TransactionOutput::default());
            }
            source_tx.outputs.push(TransactionOutput {
                satoshis: Some(source_satoshis),
                locking_script: source_locking_script,
                change: false,
            });
            input.source_transaction = Some(Box::new(source_tx));

            inputs.push(input);
        }

        let output_count = read_varint(reader)? as usize;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(TransactionOutput::from_binary(reader)?);
        }

        let lock_time = read_u32_le(reader)?;

        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time,
            merkle_path: None,
        })
    }

    /// Deserialize a transaction from an EF format hex string.
    pub fn from_hex_ef(hex: &str) -> Result<Self, TransactionError> {
        let bytes = hex_to_bytes(hex)
            .map_err(|e| TransactionError::InvalidFormat(format!("invalid hex: {}", e)))?;
        let mut cursor = Cursor::new(bytes);
        Self::from_ef(&mut cursor)
    }

    /// Serialize a transaction to EF format (BRC-30).
    pub fn to_ef(&self, writer: &mut impl Write) -> Result<(), TransactionError> {
        write_u32_le(writer, self.version)?;

        // Write EF marker
        writer.write_all(&EF_MARKER)?;

        write_varint(writer, self.inputs.len() as u64)?;
        for input in &self.inputs {
            // Write standard input fields
            input.to_binary(writer)?;

            // Write source satoshis and locking script from source transaction
            if let Some(ref source_tx) = input.source_transaction {
                let idx = input.source_output_index as usize;
                if idx < source_tx.outputs.len() {
                    let source_output = &source_tx.outputs[idx];
                    write_u64_le(writer, source_output.satoshis.unwrap_or(0))?;
                    let script_bin = source_output.locking_script.to_binary();
                    write_varint(writer, script_bin.len() as u64)?;
                    writer.write_all(&script_bin)?;
                } else {
                    return Err(TransactionError::MissingSourceTransaction);
                }
            } else {
                return Err(TransactionError::MissingSourceTransaction);
            }
        }

        write_varint(writer, self.outputs.len() as u64)?;
        for output in &self.outputs {
            output.to_binary(writer)?;
        }

        write_u32_le(writer, self.lock_time)?;
        Ok(())
    }

    /// Serialize a transaction to an EF format hex string.
    pub fn to_hex_ef(&self) -> Result<String, TransactionError> {
        let mut buf = Vec::new();
        self.to_ef(&mut buf)?;
        Ok(bytes_to_hex(&buf))
    }

    // -- Sighash preimage computation -----------------------------------------

    /// Resolve the txid bytes (internal/LE byte order) for the input at `input_index`.
    fn resolve_input_txid_bytes(&self, input_index: usize) -> Result<[u8; 32], TransactionError> {
        let input = &self.inputs[input_index];
        if let Some(ref txid) = input.source_txid {
            let mut bytes = hex_to_bytes(txid)
                .map_err(|e| TransactionError::InvalidFormat(format!("invalid txid hex: {}", e)))?;
            bytes.reverse(); // display (BE) -> internal (LE)
            let mut arr = [0u8; 32];
            if bytes.len() == 32 {
                arr.copy_from_slice(&bytes);
            }
            Ok(arr)
        } else if let Some(ref source_tx) = input.source_transaction {
            source_tx.hash()
        } else {
            Err(TransactionError::InvalidFormat(
                "input has neither source_txid nor source_transaction".to_string(),
            ))
        }
    }

    /// Compute the BIP143/ForkID sighash preimage for the input at `input_index`.
    ///
    /// This is the standard BSV post-fork sighash format. The `scope` flags
    /// should include SIGHASH_FORKID for normal BSV transactions.
    ///
    /// Parameters:
    /// - `input_index`: index of the input being signed
    /// - `scope`: sighash flags (e.g., SIGHASH_ALL | SIGHASH_FORKID)
    /// - `source_satoshis`: value of the UTXO being spent
    /// - `source_locking_script`: locking script of the UTXO being spent
    pub fn sighash_preimage(
        &self,
        input_index: usize,
        scope: u32,
        source_satoshis: u64,
        source_locking_script: &LockingScript,
    ) -> Result<Vec<u8>, TransactionError> {
        if input_index >= self.inputs.len() {
            return Err(TransactionError::InvalidSighash(format!(
                "input_index {} out of range (tx has {} inputs)",
                input_index,
                self.inputs.len()
            )));
        }

        let base_type = scope & 0x1f;
        let anyone_can_pay = (scope & SIGHASH_ANYONECANPAY) != 0;

        let mut preimage = Vec::with_capacity(256);

        // 1. nVersion (4 bytes LE)
        preimage.extend_from_slice(&self.version.to_le_bytes());

        // 2. hashPrevouts
        if !anyone_can_pay {
            let mut prevouts = Vec::new();
            for (i, input) in self.inputs.iter().enumerate() {
                let txid_bytes = self.resolve_input_txid_bytes(i)?;
                prevouts.extend_from_slice(&txid_bytes);
                prevouts.extend_from_slice(&input.source_output_index.to_le_bytes());
            }
            preimage.extend_from_slice(&hash256(&prevouts));
        } else {
            preimage.extend_from_slice(&[0u8; 32]);
        }

        // 3. hashSequence
        if !anyone_can_pay && base_type != SIGHASH_NONE && base_type != SIGHASH_SINGLE {
            let mut sequences = Vec::new();
            for input in &self.inputs {
                sequences.extend_from_slice(&input.sequence.to_le_bytes());
            }
            preimage.extend_from_slice(&hash256(&sequences));
        } else {
            preimage.extend_from_slice(&[0u8; 32]);
        }

        // 4. outpoint: this input's txid (LE) + output_index (4 bytes LE)
        let this_txid = self.resolve_input_txid_bytes(input_index)?;
        preimage.extend_from_slice(&this_txid);
        preimage.extend_from_slice(&self.inputs[input_index].source_output_index.to_le_bytes());

        // 5. scriptCode: varint-prefixed source_locking_script bytes
        let script_bytes = source_locking_script.to_binary();
        write_varint_to_vec(&mut preimage, script_bytes.len() as u64);
        preimage.extend_from_slice(&script_bytes);

        // 6. value: source_satoshis (8 bytes LE)
        preimage.extend_from_slice(&source_satoshis.to_le_bytes());

        // 7. nSequence: this input's sequence (4 bytes LE)
        preimage.extend_from_slice(&self.inputs[input_index].sequence.to_le_bytes());

        // 8. hashOutputs
        if base_type != SIGHASH_NONE && base_type != SIGHASH_SINGLE {
            // ALL: hash of all outputs serialized
            let mut outputs_data = Vec::new();
            for output in &self.outputs {
                outputs_data.extend_from_slice(&output.satoshis.unwrap_or(0).to_le_bytes());
                let script_bytes = output.locking_script.to_binary();
                write_varint_to_vec(&mut outputs_data, script_bytes.len() as u64);
                outputs_data.extend_from_slice(&script_bytes);
            }
            preimage.extend_from_slice(&hash256(&outputs_data));
        } else if base_type == SIGHASH_SINGLE && input_index < self.outputs.len() {
            // SINGLE: hash of the output at input_index
            let output = &self.outputs[input_index];
            let mut out_data = Vec::new();
            out_data.extend_from_slice(&output.satoshis.unwrap_or(0).to_le_bytes());
            let script_bytes = output.locking_script.to_binary();
            write_varint_to_vec(&mut out_data, script_bytes.len() as u64);
            out_data.extend_from_slice(&script_bytes);
            preimage.extend_from_slice(&hash256(&out_data));
        } else {
            // NONE or SINGLE out-of-range: 32 zero bytes
            preimage.extend_from_slice(&[0u8; 32]);
        }

        // 9. nLockTime (4 bytes LE)
        preimage.extend_from_slice(&self.lock_time.to_le_bytes());

        // 10. sighash type (4 bytes LE) -- scope with FORKID bit
        preimage.extend_from_slice(&(scope | SIGHASH_FORKID).to_le_bytes());

        Ok(preimage)
    }

    /// Compute the legacy OTDA sighash preimage for the input at `input_index`.
    ///
    /// Used when SIGHASH_FORKID is NOT set (pre-fork transactions or Chronicle mode).
    /// This is the original Bitcoin sighash algorithm.
    ///
    /// The `sub_script` is the scriptCode bytes. OP_CODESEPARATOR opcodes will be
    /// stripped automatically before inclusion in the preimage.
    pub fn sighash_preimage_legacy(
        &self,
        input_index: usize,
        scope: u32,
        sub_script: &[u8],
    ) -> Result<Vec<u8>, TransactionError> {
        if input_index >= self.inputs.len() {
            return Err(TransactionError::InvalidSighash(format!(
                "input_index {} out of range (tx has {} inputs)",
                input_index,
                self.inputs.len()
            )));
        }

        // Strip OP_CODESEPARATOR (0xab) opcodes from the script.
        // Must parse properly to avoid removing 0xab bytes that appear as push data.
        let sub_script = strip_codeseparator(sub_script);

        let base_type = scope & 0x1f;
        let anyone_can_pay = (scope & SIGHASH_ANYONECANPAY) != 0;
        let is_none = base_type == SIGHASH_NONE;
        let is_single = base_type == SIGHASH_SINGLE;

        // SIGHASH_SINGLE bug: if input_index >= outputs, return [1, 0, 0, ..., 0]
        if is_single && input_index >= self.outputs.len() {
            let mut result = vec![0u8; 32];
            result[0] = 1;
            return Ok(result);
        }

        let empty_script: Vec<u8> = Vec::new();

        let mut preimage = Vec::with_capacity(512);

        // Version
        preimage.extend_from_slice(&self.version.to_le_bytes());

        // Inputs
        if anyone_can_pay {
            // Only the current input
            write_varint_to_vec(&mut preimage, 1);
            let txid_bytes = self.resolve_input_txid_bytes(input_index)?;
            preimage.extend_from_slice(&txid_bytes);
            preimage.extend_from_slice(&self.inputs[input_index].source_output_index.to_le_bytes());
            write_varint_to_vec(&mut preimage, sub_script.len() as u64);
            preimage.extend_from_slice(&sub_script);
            preimage.extend_from_slice(&self.inputs[input_index].sequence.to_le_bytes());
        } else {
            write_varint_to_vec(&mut preimage, self.inputs.len() as u64);
            for (i, input) in self.inputs.iter().enumerate() {
                let txid_bytes = self.resolve_input_txid_bytes(i)?;
                preimage.extend_from_slice(&txid_bytes);
                preimage.extend_from_slice(&input.source_output_index.to_le_bytes());

                // Script: only include sub_script for the input being signed
                if i == input_index {
                    write_varint_to_vec(&mut preimage, sub_script.len() as u64);
                    preimage.extend_from_slice(&sub_script);
                } else {
                    write_varint_to_vec(&mut preimage, empty_script.len() as u64);
                }

                // Sequence: for SINGLE and NONE, zero out other inputs' sequences
                if i == input_index || (!is_single && !is_none) {
                    preimage.extend_from_slice(&input.sequence.to_le_bytes());
                } else {
                    preimage.extend_from_slice(&0u32.to_le_bytes());
                }
            }
        }

        // Outputs
        if is_none {
            write_varint_to_vec(&mut preimage, 0);
        } else if is_single {
            write_varint_to_vec(&mut preimage, (input_index + 1) as u64);
            for i in 0..input_index {
                // Blank outputs before the matching one: satoshis = -1 (0xFFFFFFFFFFFFFFFF), empty script
                preimage.extend_from_slice(&u64::MAX.to_le_bytes());
                write_varint_to_vec(&mut preimage, 0);
                let _ = i;
            }
            // The output at input_index
            let output = &self.outputs[input_index];
            preimage.extend_from_slice(&output.satoshis.unwrap_or(0).to_le_bytes());
            let script_bytes = output.locking_script.to_binary();
            write_varint_to_vec(&mut preimage, script_bytes.len() as u64);
            preimage.extend_from_slice(&script_bytes);
        } else {
            // ALL: serialize all outputs
            write_varint_to_vec(&mut preimage, self.outputs.len() as u64);
            for output in &self.outputs {
                preimage.extend_from_slice(&output.satoshis.unwrap_or(0).to_le_bytes());
                let script_bytes = output.locking_script.to_binary();
                write_varint_to_vec(&mut preimage, script_bytes.len() as u64);
                preimage.extend_from_slice(&script_bytes);
            }
        }

        // Locktime
        preimage.extend_from_slice(&self.lock_time.to_le_bytes());

        // Sighash type (4 bytes LE)
        preimage.extend_from_slice(&scope.to_le_bytes());

        Ok(preimage)
    }

    // -- Transaction signing --------------------------------------------------

    /// Sign the input at `input_index` using a ScriptTemplateUnlock implementation.
    ///
    /// Computes the sighash preimage (BIP143/ForkID format) and passes it to the
    /// template's sign() method, then sets the resulting unlocking script on the input.
    pub fn sign(
        &mut self,
        input_index: usize,
        template: &dyn ScriptTemplateUnlock,
        scope: u32,
        source_satoshis: u64,
        source_locking_script: &LockingScript,
    ) -> Result<(), TransactionError> {
        let preimage =
            self.sighash_preimage(input_index, scope, source_satoshis, source_locking_script)?;
        let unlocking_script = template
            .sign(&preimage)
            .map_err(|e| TransactionError::SigningFailed(format!("{}", e)))?;
        self.inputs[input_index].unlocking_script = Some(unlocking_script);
        Ok(())
    }

    /// Sign all unsigned inputs using the same template.
    ///
    /// A convenience method that reduces the per-input signing loop. For each
    /// input that has no `unlocking_script` yet, this resolves `source_satoshis`
    /// and `source_locking_script` from the input's `source_transaction` and
    /// signs with the given template and sighash scope.
    ///
    /// Inputs that already have an unlocking script are skipped.
    ///
    /// Each input must have its `source_transaction` set so that the source
    /// output's satoshis and locking script can be resolved. If you need
    /// different templates or scopes per input, use the single-input `sign()`.
    pub fn sign_all_inputs(
        &mut self,
        template: &dyn ScriptTemplateUnlock,
        scope: u32,
    ) -> Result<(), TransactionError> {
        let num_inputs = self.inputs.len();

        for i in 0..num_inputs {
            // Skip inputs that already have an unlocking script
            if self.inputs[i].unlocking_script.is_some() {
                continue;
            }

            // Resolve source satoshis and locking script from source_transaction
            let (source_satoshis, source_locking_script) = {
                let source_tx = self.inputs[i].source_transaction.as_ref().ok_or_else(|| {
                    TransactionError::SigningFailed(format!(
                        "input {}: source_transaction required for sign_all_inputs()",
                        i
                    ))
                })?;
                let out_idx = self.inputs[i].source_output_index as usize;
                let output = source_tx.outputs.get(out_idx).ok_or_else(|| {
                    TransactionError::SigningFailed(format!(
                        "input {}: source transaction has no output at index {}",
                        i, out_idx
                    ))
                })?;
                let satoshis = output.satoshis.ok_or_else(|| {
                    TransactionError::SigningFailed(format!(
                        "input {}: source output {} has no satoshis",
                        i, out_idx
                    ))
                })?;
                (satoshis, output.locking_script.clone())
            };

            let preimage =
                self.sighash_preimage(i, scope, source_satoshis, &source_locking_script)?;
            let unlocking_script = template
                .sign(&preimage)
                .map_err(|e| TransactionError::SigningFailed(format!("input {}: {}", i, e)))?;
            self.inputs[i].unlocking_script = Some(unlocking_script);
        }

        Ok(())
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a byte slice to a lowercase hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Strip OP_CODESEPARATOR (0xab) opcodes from a raw script byte array.
///
/// Properly parses the script to avoid removing 0xab bytes that appear
/// as data within push operations.
fn strip_codeseparator(script: &[u8]) -> Vec<u8> {
    const OP_CODESEPARATOR: u8 = 0xab;

    let mut result = Vec::with_capacity(script.len());
    let mut i = 0;
    while i < script.len() {
        let opcode = script[i];
        if opcode == OP_CODESEPARATOR {
            // Skip this opcode
            i += 1;
            continue;
        }

        if opcode > 0 && opcode < 76 {
            // Direct push: opcode is the number of bytes to push
            let push_len = opcode as usize;
            let end = std::cmp::min(i + 1 + push_len, script.len());
            result.extend_from_slice(&script[i..end]);
            i = end;
        } else if opcode == 76 {
            // OP_PUSHDATA1: next byte is length
            if i + 1 < script.len() {
                let push_len = script[i + 1] as usize;
                let end = std::cmp::min(i + 2 + push_len, script.len());
                result.extend_from_slice(&script[i..end]);
                i = end;
            } else {
                result.push(opcode);
                i += 1;
            }
        } else if opcode == 77 {
            // OP_PUSHDATA2: next 2 bytes are length (LE)
            if i + 2 < script.len() {
                let push_len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                let end = std::cmp::min(i + 3 + push_len, script.len());
                result.extend_from_slice(&script[i..end]);
                i = end;
            } else {
                result.extend_from_slice(&script[i..]);
                break;
            }
        } else if opcode == 78 {
            // OP_PUSHDATA4: next 4 bytes are length (LE)
            if i + 4 < script.len() {
                let push_len = u32::from_le_bytes([
                    script[i + 1],
                    script[i + 2],
                    script[i + 3],
                    script[i + 4],
                ]) as usize;
                let end = std::cmp::min(i + 5 + push_len, script.len());
                result.extend_from_slice(&script[i..end]);
                i = end;
            } else {
                result.extend_from_slice(&script[i..]);
                break;
            }
        } else {
            // Regular opcode (0x00, or 0x4f..0xff except 0xab)
            result.push(opcode);
            i += 1;
        }
    }
    result
}

/// Write a Bitcoin-style varint directly to a Vec<u8> (no io::Write needed).
fn write_varint_to_vec(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Convert a hex string to bytes.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd length hex string".to_string());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("invalid hex at position {}: {}", i, e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::private_key::PrivateKey;
    use crate::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
    use crate::script::templates::p2pkh::P2PKH;
    use crate::script::templates::ScriptTemplateLock;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct TestVector {
        description: String,
        hex: String,
        txid: String,
        version: u32,
        inputs: usize,
        outputs: usize,
        locktime: u32,
    }

    fn load_test_vectors() -> Vec<TestVector> {
        let json = include_str!("../../test-vectors/transaction_valid.json");
        serde_json::from_str(json).expect("failed to parse transaction_valid.json")
    }

    #[test]
    fn test_from_binary_round_trip() {
        let vectors = load_test_vectors();
        for v in &vectors {
            let tx = Transaction::from_hex(&v.hex)
                .unwrap_or_else(|e| panic!("failed to parse '{}': {}", v.description, e));
            let result_hex = tx
                .to_hex()
                .unwrap_or_else(|e| panic!("failed to serialize '{}': {}", v.description, e));
            assert_eq!(
                result_hex, v.hex,
                "round-trip failed for '{}'",
                v.description
            );
        }
    }

    #[test]
    fn test_txid() {
        let vectors = load_test_vectors();
        for v in &vectors {
            let tx = Transaction::from_hex(&v.hex)
                .unwrap_or_else(|e| panic!("failed to parse '{}': {}", v.description, e));
            let txid = tx
                .id()
                .unwrap_or_else(|e| panic!("failed to compute id for '{}': {}", v.description, e));
            assert_eq!(txid, v.txid, "txid mismatch for '{}'", v.description);
        }
    }

    #[test]
    fn test_input_output_counts() {
        let vectors = load_test_vectors();
        for v in &vectors {
            let tx = Transaction::from_hex(&v.hex)
                .unwrap_or_else(|e| panic!("failed to parse '{}': {}", v.description, e));
            assert_eq!(
                tx.inputs.len(),
                v.inputs,
                "input count mismatch for '{}'",
                v.description
            );
            assert_eq!(
                tx.outputs.len(),
                v.outputs,
                "output count mismatch for '{}'",
                v.description
            );
            assert_eq!(
                tx.version, v.version,
                "version mismatch for '{}'",
                v.description
            );
            assert_eq!(
                tx.lock_time, v.locktime,
                "locktime mismatch for '{}'",
                v.description
            );
        }
    }

    #[test]
    fn test_empty_transaction() {
        let tx = Transaction::new();
        assert_eq!(tx.version, 1);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
        assert_eq!(tx.lock_time, 0);
        assert!(tx.merkle_path.is_none());
    }

    #[test]
    fn test_add_input_output() {
        let mut tx = Transaction::new();
        assert_eq!(tx.inputs.len(), 0);
        assert_eq!(tx.outputs.len(), 0);

        tx.add_input(TransactionInput::default());
        assert_eq!(tx.inputs.len(), 1);

        tx.add_output(TransactionOutput::default());
        assert_eq!(tx.outputs.len(), 1);
    }

    #[test]
    fn test_ef_round_trip() {
        // EF format vector from TS SDK test
        let ef_hex = "010000000000000000ef01ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff3e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac00000000";

        let tx = Transaction::from_hex_ef(ef_hex).expect("failed to parse EF hex");
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);

        // Verify source transaction info was captured
        let input = &tx.inputs[0];
        assert!(input.source_transaction.is_some());
        let source_tx = input.source_transaction.as_ref().unwrap();
        let source_output = &source_tx.outputs[input.source_output_index as usize];
        assert_eq!(source_output.satoshis, Some(0x663e)); // 26174 satoshis

        // Round-trip: serialize back to EF hex
        let result_hex = tx.to_hex_ef().expect("failed to serialize to EF");
        assert_eq!(result_hex, ef_hex);
    }

    #[test]
    fn test_hash_and_id_consistency() {
        // tx2 from the TS SDK test
        let tx2hex = "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f000000008c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2ffffffffa3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f020000008b48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff02206b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88acf0ca0100000000001976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000";
        let tx2idhex = "8c9aa966d35bfeaf031409e0001b90ccdafd8d859799eb945a3c515b8260bcf2";

        let tx = Transaction::from_hex(tx2hex).unwrap();
        let id = tx.id().unwrap();
        assert_eq!(id, tx2idhex);

        // Verify hash is the reverse of id
        let hash = tx.hash().unwrap();
        let mut reversed_hash = hash;
        reversed_hash.reverse();
        let reversed_hex = bytes_to_hex(&reversed_hash);
        assert_eq!(reversed_hex, tx2idhex);
    }

    // -- Sighash preimage tests -----------------------------------------------

    /// OTDA sighash test vectors from TS SDK sighashTestData.ts
    /// Format: (raw_tx_hex, script_hex, input_index, hash_type_unsigned, expected_otda_hash_display)
    fn otda_test_vectors() -> Vec<(&'static str, &'static str, usize, u32, &'static str)> {
        vec![
            ("0122769903cfc6fedb9c63fe76930fed0c87b44be46f5032a534fa05861548616a5b99034701000000040063656ac864c70228b3f6ebaf97be065b2180ece52fae4f9039c7bf932e567625d7d89582abe1340100000008ac6363650063ab65ffffffff587125b913706705dc799454ab0343ee8aa59a2f2d538f75e12c0deeb40aa741030000000027b3a02003d21f34040000000000fa7f2c0300000000016387213b0300000000056aabacacab00000000", "", 1, 902085315, "49fdc84c5f88a590c5c65e17de58da7d1028133b74ad2d56a8b15ba317ac98f6"),
            ("7e8c3f7902634018b6e1db2ca591816dff64a6cff74643de7455323ebfc560500aad9eee8c0100000001519c2d146d06fdca2c2e5fa3a2559812df66b6b5e40a3c57b2f7071ae6fe3863c74ab0952d0100000001000bf6638c013c5f6503000000000351ac63cbbf66be", "acab", 0, 2433331782, "f6261bacaed3a70d504cd70d3c0623e3593f6d197cd47316e56cea79ceabe095"),
            ("459499bb032fdcc39d3c6cf819dcaa0a0165d97578446aa87ab745fb9fdcd3e6177b4cba3d0000000005006a6a5265ffffffff10e5929ebe065273c112cab15f6a1f6d9a8a517c288311b048b16663b3d406dc030000000700535263655151ffffffff981d73a7f3d477ab055398bcf9a7d349db1a8e6362055e20f4207ad1b775bac301000000066a6363ac6552ffffffff0403342603000000000165c4390004000000000965ac52006565006365373ce8010000000005520000516aba5a9404000000000351655300000000", "6a5352", 0, 3544391288, "738b7dcb86260e6fe3fad331ff342429c157730bbcb90c205b9e08568557cd94"),
            ("cb3b8d30043ccd81c3bda7f594cca60e2eef170c67ffe8a1eb1f1a994dc40a0a5cf89fa9690100000009ab536a52acab5300653bea9324983da711ccb6eaff060930e6f55cf6df75e5abdda91a8d5fc25c3b9b28d0e7370200000003ab51522f86cdbd8aa19b6b8536efb6ca8cc23ebccef585ad00a78b5956d803908482bb44b25c550000000007abab65530051ac8177a2acebc517db1d5b5be14f91ab40e811ec0316cf029ce657a4b06f04f30698f0a0e50000000007516aac636a6351ffffffff02ccbefa02000000000252ab3e297f0100000000060052525163521acc3e2b", "6aac636a63535153", 0, 3406487088, "3568dfad7e968afd3492bd146c8b0e3255f90e5b642a4ec10105693e8b029132"),
        ]
    }

    #[test]
    fn test_sighash_preimage_legacy_vectors() {
        let vectors = otda_test_vectors();
        let mut passed = 0;

        for (i, (raw_tx_hex, script_hex, input_index, hash_type, expected_hash)) in
            vectors.iter().enumerate()
        {
            let tx = Transaction::from_hex(raw_tx_hex)
                .unwrap_or_else(|e| panic!("vector {}: failed to parse tx: {}", i, e));

            let sub_script = if script_hex.is_empty() {
                vec![]
            } else {
                hex_to_bytes(script_hex).unwrap()
            };

            let preimage = tx
                .sighash_preimage_legacy(*input_index, *hash_type, &sub_script)
                .unwrap_or_else(|e| panic!("vector {}: sighash error: {}", i, e));

            // The expected hash is in display (BE/reversed) format
            let mut hash_bytes = hash256(&preimage);
            hash_bytes.reverse();
            let computed_hash = bytes_to_hex(&hash_bytes);

            if computed_hash == *expected_hash {
                passed += 1;
            } else {
                println!(
                    "MISMATCH vector {}: expected={}, got={}",
                    i, expected_hash, computed_hash
                );
            }
        }

        println!(
            "sighash legacy OTDA vectors: {}/{} passed",
            passed,
            vectors.len()
        );
        assert_eq!(
            passed,
            vectors.len(),
            "all sighash OTDA vectors should pass"
        );
    }

    #[test]
    fn test_sighash_preimage_bip143() {
        // Test vector from Go SDK: "1 Input 2 Outputs - SIGHASH_ALL (FORKID)"
        let unsigned_tx_hex = "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000";
        let source_script_hex = "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac";
        let source_satoshis: u64 = 100_000_000;
        let expected_preimage_hex = "010000007ced5b2e5cf3ea407b005d8b18c393b6256ea2429b6ff409983e10adc61d0ae83bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e7066504493a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac00e1f50500000000ffffffff87841ab2b7a4133af2c58256edb7c3c9edca765a852ebe2d0dc962604a30f1030000000041000000";

        let tx = Transaction::from_hex(unsigned_tx_hex).unwrap();
        let source_script_bytes = hex_to_bytes(source_script_hex).unwrap();
        let source_locking_script = LockingScript::from_binary(&source_script_bytes);

        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        let preimage = tx
            .sighash_preimage(0, scope, source_satoshis, &source_locking_script)
            .unwrap();
        let preimage_hex = bytes_to_hex(&preimage);

        assert_eq!(
            preimage_hex, expected_preimage_hex,
            "BIP143 preimage should match Go SDK test vector"
        );
    }

    // -- Transaction signing tests --------------------------------------------

    #[test]
    fn test_sign_p2pkh() {
        let key = PrivateKey::from_hex("1").unwrap();
        let p2pkh_lock = P2PKH::from_private_key(key.clone());
        let p2pkh_unlock = P2PKH::from_private_key(key.clone());

        let lock_script = p2pkh_lock.lock().unwrap();

        // Build a transaction with one input and one output
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput {
            source_transaction: None,
            source_txid: Some("00".repeat(32)),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
        tx.add_output(TransactionOutput {
            satoshis: Some(50000),
            locking_script: lock_script.clone(),
            change: false,
        });

        // Sign the input
        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        tx.sign(0, &p2pkh_unlock, scope, 100000, &lock_script)
            .expect("signing should succeed");

        // Verify unlocking script is set
        let unlock = tx.inputs[0].unlocking_script.as_ref().unwrap();
        let chunks = unlock.chunks();
        assert_eq!(
            chunks.len(),
            2,
            "P2PKH unlock should have 2 chunks (sig + pubkey)"
        );

        // First chunk: signature (DER + sighash byte)
        let sig_data = chunks[0].data.as_ref().unwrap();
        assert!(
            sig_data.len() >= 70 && sig_data.len() <= 74,
            "signature length {} should be 70-74",
            sig_data.len()
        );
        assert_eq!(
            *sig_data.last().unwrap(),
            (SIGHASH_ALL | SIGHASH_FORKID) as u8,
            "last byte should be sighash type"
        );

        // Second chunk: compressed public key (33 bytes)
        let pubkey_data = chunks[1].data.as_ref().unwrap();
        assert_eq!(pubkey_data.len(), 33);
    }

    #[test]
    fn test_sign_and_verify_round_trip() {
        use crate::script::spend::{Spend, SpendParams};

        let key = PrivateKey::from_hex("abcdef01").unwrap();
        let p2pkh = P2PKH::from_private_key(key.clone());
        let lock_script = p2pkh.lock().unwrap();

        // Build and sign a transaction
        let mut tx = Transaction::new();
        let source_satoshis = 100_000u64;

        tx.add_input(TransactionInput {
            source_transaction: None,
            source_txid: Some("aa".repeat(32)),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
        tx.add_output(TransactionOutput {
            satoshis: Some(90_000),
            locking_script: lock_script.clone(),
            change: false,
        });

        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        tx.sign(0, &p2pkh, scope, source_satoshis, &lock_script)
            .expect("signing should succeed");

        // Now verify with Spend
        let unlock_script = tx.inputs[0].unlocking_script.clone().unwrap();

        let mut spend = Spend::new(SpendParams {
            locking_script: lock_script.clone(),
            unlocking_script: unlock_script,
            source_txid: "aa".repeat(32),
            source_output_index: 0,
            source_satoshis,
            transaction_version: tx.version,
            transaction_lock_time: tx.lock_time,
            transaction_sequence: tx.inputs[0].sequence,
            other_inputs: vec![],
            other_outputs: tx.outputs.clone(),
            input_index: 0,
        });

        let valid = spend.validate().expect("spend validation should not error");
        assert!(valid, "signed transaction should verify successfully");
    }

    #[test]
    fn test_to_beef_round_trip() {
        // Parse a known valid BEEF, re-serialize with to_beef(), parse again,
        // and verify the round-trip produces the same subject transaction.
        let vectors_json = std::fs::read_to_string("test-vectors/beef_valid.json").unwrap();
        let vectors: Vec<serde_json::Value> = serde_json::from_str(&vectors_json).unwrap();
        let original_hex = vectors[0]["hex"].as_str().unwrap();
        let expected_txid = vectors[0]["txid"].as_str().unwrap();

        // Parse BEEF → Transaction (populates source_transaction + merkle_path)
        let tx = Transaction::from_beef(original_hex).expect("from_beef should succeed");
        assert_eq!(tx.id().unwrap(), expected_txid);

        // Re-serialize to BEEF via to_beef()
        let beef_bytes = tx.to_beef().expect("to_beef should succeed");

        // Verify BEEF V1 header (0x0100BEEF in LE)
        assert_eq!(&beef_bytes[0..4], &[0x01, 0x00, 0xBE, 0xEF]);

        // Parse the re-serialized BEEF and verify same txid
        let re_hex: String = beef_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let re_parsed = Transaction::from_beef(&re_hex).expect("round-trip from_beef should succeed");
        assert_eq!(re_parsed.id().unwrap(), expected_txid);
        assert_eq!(re_parsed.outputs.len(), tx.outputs.len());
    }
}
