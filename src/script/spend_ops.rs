//! Opcode dispatch and implementation for the Spend interpreter.
//!
//! This module implements all ~80 BSV opcodes as a single dispatch method
//! on Spend. Organized by category: constants, flow control, stack, splice,
//! bitwise, arithmetic, crypto.

use crate::primitives::big_number::BigNumber;
use crate::script::error::ScriptError;
use crate::script::op::Op;
use crate::script::script_chunk::ScriptChunk;
use crate::script::spend::Spend;

impl Spend {
    /// Dispatch and execute a single opcode.
    pub(crate) fn execute_opcode(
        &mut self,
        op: Op,
        chunk: &ScriptChunk,
    ) -> Result<(), ScriptError> {
        match op {
            // -- Constants / Push -----------------------------------------------
            Op::Op0 => {
                self.push_stack(vec![])?;
            }

            Op::Op1Negate => {
                let n = BigNumber::from_number(-1);
                self.push_stack(n.to_script_num())?;
            }

            Op::Op1 => self.push_stack(vec![1])?,
            Op::Op2 => self.push_stack(vec![2])?,
            Op::Op3 => self.push_stack(vec![3])?,
            Op::Op4 => self.push_stack(vec![4])?,
            Op::Op5 => self.push_stack(vec![5])?,
            Op::Op6 => self.push_stack(vec![6])?,
            Op::Op7 => self.push_stack(vec![7])?,
            Op::Op8 => self.push_stack(vec![8])?,
            Op::Op9 => self.push_stack(vec![9])?,
            Op::Op10 => self.push_stack(vec![10])?,
            Op::Op11 => self.push_stack(vec![11])?,
            Op::Op12 => self.push_stack(vec![12])?,
            Op::Op13 => self.push_stack(vec![13])?,
            Op::Op14 => self.push_stack(vec![14])?,
            Op::Op15 => self.push_stack(vec![15])?,
            Op::Op16 => self.push_stack(vec![16])?,

            // Push data opcodes (direct push 0x01..=0x4b, PUSHDATA1/2/4)
            Op::OpPushData1 | Op::OpPushData2 | Op::OpPushData4 => {
                let data = chunk.data.clone().unwrap_or_default();
                self.push_stack(data)?;
            }

            // Direct push (OpInvalidOpcode means op_byte is 0x01..0x4b)
            Op::OpInvalidOpcode if chunk.op_byte >= 0x01 && chunk.op_byte <= 0x4b => {
                let data = chunk.data.clone().unwrap_or_default();
                self.push_stack(data)?;
            }

            // -- Flow Control ---------------------------------------------------
            Op::OpNop | Op::OpNop1 | Op::OpNop2 | Op::OpNop3 | Op::OpNop9 | Op::OpNop10 => {
                // No operation
            }

            Op::OpIf => {
                let val = self.pop_stack()?;
                let cond = Self::stack_to_bool(&val);
                self.if_stack.push(cond);
            }

            Op::OpNotIf => {
                let val = self.pop_stack()?;
                let cond = !Self::stack_to_bool(&val);
                self.if_stack.push(cond);
            }

            Op::OpVerIf => {
                // BSV-specific: compare top of stack to transactionVersion
                let val = self.pop_stack()?;
                let num = BigNumber::from_script_num(&val, false, None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let ver = BigNumber::from_number(self.transaction_version as i64);
                let cond = num.cmp(&ver) == 0;
                self.if_stack.push(cond);
            }

            Op::OpVerNotIf => {
                let val = self.pop_stack()?;
                let num = BigNumber::from_script_num(&val, false, None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let ver = BigNumber::from_number(self.transaction_version as i64);
                let cond = num.cmp(&ver) != 0;
                self.if_stack.push(cond);
            }

            Op::OpElse => {
                if let Some(last) = self.if_stack.last_mut() {
                    *last = !*last;
                } else {
                    return Err(ScriptError::InvalidScript(
                        "OP_ELSE without OP_IF".to_string(),
                    ));
                }
            }

            Op::OpEndIf => {
                if self.if_stack.pop().is_none() {
                    return Err(ScriptError::InvalidScript(
                        "OP_ENDIF without OP_IF".to_string(),
                    ));
                }
            }

            Op::OpVerify => {
                let val = self.pop_stack()?;
                if !Self::stack_to_bool(&val) {
                    return Err(ScriptError::VerifyFailed);
                }
            }

            Op::OpReturn => {
                // Post-Genesis BSV semantics: OP_RETURN at top level is a
                // successful early termination. Used by covenant scripts
                // (e.g. STAS-3) that end with OP_RETURN as a success marker.
                // The parser truncates everything after this point into the
                // OP_RETURN chunk's data, so we jump to end-of-script and let
                // the caller inspect the stack — if the script left a falsy
                // top, validate() will still return false. This is the
                // unconditional behavior matching the dxs production engine
                // and the canonical 2,899-byte STAS-3 body which terminates
                // with OP_RETURN regardless of tx version.
                let chunks_len = match self.context {
                    crate::script::spend::ScriptContext::Unlocking => {
                        self.unlocking_script.chunks().len()
                    }
                    crate::script::spend::ScriptContext::Locking => {
                        self.locking_script.chunks().len()
                    }
                };
                self.program_counter = chunks_len;
                return Ok(());
            }

            Op::OpVer => {
                // Push transactionVersion as script number
                let ver = BigNumber::from_number(self.transaction_version as i64);
                self.push_stack(ver.to_script_num())?;
            }

            Op::OpReserved | Op::OpReserved1 | Op::OpReserved2 => {
                return Err(ScriptError::InvalidOpcode(chunk.op_byte));
            }

            // -- Stack Operations -----------------------------------------------
            Op::OpToAltStack => {
                let val = self.pop_stack()?;
                self.push_alt_stack(val)?;
            }

            Op::OpFromAltStack => {
                let val = self.pop_alt_stack()?;
                self.push_stack(val)?;
            }

            Op::Op2Drop => {
                self.pop_stack()?;
                self.pop_stack()?;
            }

            Op::Op2Dup => {
                let a = self.stack_top(1)?.clone();
                let b = self.stack_top(0)?.clone();
                self.push_stack(a)?;
                self.push_stack(b)?;
            }

            Op::Op3Dup => {
                let a = self.stack_top(2)?.clone();
                let b = self.stack_top(1)?.clone();
                let c = self.stack_top(0)?.clone();
                self.push_stack(a)?;
                self.push_stack(b)?;
                self.push_stack(c)?;
            }

            Op::Op2Over => {
                let a = self.stack_top(3)?.clone();
                let b = self.stack_top(2)?.clone();
                self.push_stack(a)?;
                self.push_stack(b)?;
            }

            Op::Op2Rot => {
                let len = self.stack.len();
                if len < 6 {
                    return Err(ScriptError::StackUnderflow);
                }
                let a = self.stack.remove(len - 6);
                let b = self.stack.remove(len - 6); // after first remove, index shifted
                                                    // mem unchanged, just rearranged
                self.stack.push(a);
                self.stack.push(b);
            }

            Op::Op2Swap => {
                let len = self.stack.len();
                if len < 4 {
                    return Err(ScriptError::StackUnderflow);
                }
                self.stack.swap(len - 4, len - 2);
                self.stack.swap(len - 3, len - 1);
            }

            Op::OpIfDup => {
                let top = self.stack_top(0)?.clone();
                if Self::stack_to_bool(&top) {
                    self.push_stack(top)?;
                }
            }

            Op::OpDepth => {
                let depth = BigNumber::from_number(self.stack.len() as i64);
                self.push_stack(depth.to_script_num())?;
            }

            Op::OpDrop => {
                self.pop_stack()?;
            }

            Op::OpDup => {
                let top = self.stack_top(0)?.clone();
                self.push_stack(top)?;
            }

            Op::OpNip => {
                let len = self.stack.len();
                if len < 2 {
                    return Err(ScriptError::StackUnderflow);
                }
                let removed = self.stack.remove(len - 2);
                self.stack_mem = self.stack_mem.saturating_sub(removed.len());
            }

            Op::OpOver => {
                let item = self.stack_top(1)?.clone();
                self.push_stack(item)?;
            }

            Op::OpPick => {
                let n_bytes = self.pop_stack()?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let n_val = n.to_number().unwrap_or(0) as isize;
                if n_val < 0 {
                    return Err(ScriptError::InvalidStackOperation(
                        "negative pick".to_string(),
                    ));
                }
                let item = self.stack_top(n_val)?.clone();
                self.push_stack(item)?;
            }

            Op::OpRoll => {
                let n_bytes = self.pop_stack()?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let n_val = n.to_number().unwrap_or(0) as usize;
                let len = self.stack.len();
                if n_val >= len {
                    return Err(ScriptError::StackUnderflow);
                }
                let idx = len - 1 - n_val;
                let item = self.stack.remove(idx);
                // Memory unchanged (moved, not added/removed)
                self.stack.push(item);
            }

            Op::OpRot => {
                let len = self.stack.len();
                if len < 3 {
                    return Err(ScriptError::StackUnderflow);
                }
                let item = self.stack.remove(len - 3);
                self.stack.push(item);
            }

            Op::OpSwap => {
                let len = self.stack.len();
                if len < 2 {
                    return Err(ScriptError::StackUnderflow);
                }
                self.stack.swap(len - 2, len - 1);
            }

            Op::OpTuck => {
                let len = self.stack.len();
                if len < 2 {
                    return Err(ScriptError::StackUnderflow);
                }
                let top = self.stack[len - 1].clone();
                self.ensure_stack_mem(top.len())?;
                self.stack_mem += top.len();
                self.stack.insert(len - 2, top);
            }

            // -- Splice Operations (BSV-restored) --------------------------------
            Op::OpCat => {
                let b = self.pop_stack()?;
                let a = self.pop_stack()?;
                let mut result = a;
                result.extend_from_slice(&b);
                self.push_stack(result)?;
            }

            Op::OpSplit => {
                let n_bytes = self.pop_stack()?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let pos = n.to_number().unwrap_or(0) as usize;
                let data = self.pop_stack()?;
                if pos > data.len() {
                    return Err(ScriptError::InvalidStackOperation(
                        "split position out of range".to_string(),
                    ));
                }
                let left = data[..pos].to_vec();
                let right = data[pos..].to_vec();
                self.push_stack(left)?;
                self.push_stack(right)?;
            }

            Op::OpNum2Bin => {
                let size_bytes = self.pop_stack()?;
                let size = BigNumber::from_script_num(&size_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let size_val = size.to_number().unwrap_or(0) as usize;
                let num_bytes = self.pop_stack()?;
                let num = BigNumber::from_script_num(&num_bytes, false, None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let mut result = num.to_script_num();

                if result.len() > size_val {
                    return Err(ScriptError::InvalidStackOperation(
                        "num2bin: number too large for target size".to_string(),
                    ));
                }

                // Sign-extend to target size
                if !result.is_empty() {
                    // SAFETY: guarded by is_empty() check above
                    let sign_byte = result.last().unwrap() & 0x80;
                    let last_idx = result.len() - 1;
                    result[last_idx] &= 0x7f; // clear sign bit
                    while result.len() < size_val {
                        result.push(0x00);
                    }
                    if size_val > 0 {
                        let last = result.len() - 1;
                        result[last] |= sign_byte; // restore sign
                    }
                } else {
                    result.resize(size_val, 0x00);
                }

                self.push_stack(result)?;
            }

            Op::OpBin2Num => {
                let data = self.pop_stack()?;
                let num = BigNumber::from_script_num(&data, false, None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                self.push_stack(num.to_script_num())?;
            }

            Op::OpSize => {
                let top = self.stack_top(0)?;
                let size = BigNumber::from_number(top.len() as i64);
                self.push_stack(size.to_script_num())?;
            }

            // -- Bitwise Operations ---------------------------------------------
            Op::OpInvert => {
                let a = self.pop_stack()?;
                let result: Vec<u8> = a.iter().map(|b| !b).collect();
                self.push_stack(result)?;
            }

            Op::OpAnd => {
                let b = self.pop_stack()?;
                let a = self.pop_stack()?;
                if a.len() != b.len() {
                    return Err(ScriptError::InvalidStackOperation(
                        "OP_AND: operands must have same length".to_string(),
                    ));
                }
                let result: Vec<u8> = a.iter().zip(b.iter()).map(|(x, y)| x & y).collect();
                self.push_stack(result)?;
            }

            Op::OpOr => {
                let b = self.pop_stack()?;
                let a = self.pop_stack()?;
                if a.len() != b.len() {
                    return Err(ScriptError::InvalidStackOperation(
                        "OP_OR: operands must have same length".to_string(),
                    ));
                }
                let result: Vec<u8> = a.iter().zip(b.iter()).map(|(x, y)| x | y).collect();
                self.push_stack(result)?;
            }

            Op::OpXor => {
                let b = self.pop_stack()?;
                let a = self.pop_stack()?;
                if a.len() != b.len() {
                    return Err(ScriptError::InvalidStackOperation(
                        "OP_XOR: operands must have same length".to_string(),
                    ));
                }
                let result: Vec<u8> = a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
                self.push_stack(result)?;
            }

            Op::OpEqual => {
                let b = self.pop_stack()?;
                let a = self.pop_stack()?;
                let equal = a == b;
                self.push_stack(Self::bool_to_stack(equal))?;
            }

            Op::OpEqualVerify => {
                let b = self.pop_stack()?;
                let a = self.pop_stack()?;
                if a != b {
                    return Err(ScriptError::EqualVerifyFailed);
                }
            }

            // -- Arithmetic Operations ------------------------------------------
            Op::Op1Add => {
                self.unary_arith_op(|a| a.add(&BigNumber::from_number(1)))?;
            }

            Op::Op1Sub => {
                self.unary_arith_op(|a| a.sub(&BigNumber::from_number(1)))?;
            }

            Op::OpNegate => {
                self.unary_arith_op(|a| a.neg())?;
            }

            Op::OpAbs => {
                self.unary_arith_op(|a| if a.is_negative() { a.neg() } else { a })?;
            }

            Op::OpNot => {
                let val = self.pop_stack()?;
                let num = BigNumber::from_script_num(&val, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let result = if num.is_zero() {
                    BigNumber::from_number(1)
                } else {
                    BigNumber::from_number(0)
                };
                self.push_stack(result.to_script_num())?;
            }

            Op::Op0NotEqual => {
                let val = self.pop_stack()?;
                let num = BigNumber::from_script_num(&val, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let result = if num.is_zero() {
                    BigNumber::from_number(0)
                } else {
                    BigNumber::from_number(1)
                };
                self.push_stack(result.to_script_num())?;
            }

            Op::OpAdd => {
                self.binary_arith_op(|a, b| a.add(&b))?;
            }

            Op::OpSub => {
                self.binary_arith_op(|a, b| a.sub(&b))?;
            }

            Op::OpMul => {
                self.binary_arith_op(|a, b| a.mul(&b))?;
            }

            Op::OpDiv => {
                let b_bytes = self.pop_stack()?;
                let a_bytes = self.pop_stack()?;
                let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let b = BigNumber::from_script_num(&b_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                if b.is_zero() {
                    return Err(ScriptError::DivisionByZero);
                }
                let (result, _) = a
                    .div_mod(&b)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                self.push_stack(result.to_script_num())?;
            }

            Op::OpMod => {
                let b_bytes = self.pop_stack()?;
                let a_bytes = self.pop_stack()?;
                let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let b = BigNumber::from_script_num(&b_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                if b.is_zero() {
                    return Err(ScriptError::DivisionByZero);
                }
                let (_, result) = a
                    .div_mod(&b)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                self.push_stack(result.to_script_num())?;
            }

            Op::OpBoolAnd => {
                let b_bytes = self.pop_stack()?;
                let a_bytes = self.pop_stack()?;
                let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let b = BigNumber::from_script_num(&b_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let result = if !a.is_zero() && !b.is_zero() {
                    BigNumber::from_number(1)
                } else {
                    BigNumber::from_number(0)
                };
                self.push_stack(result.to_script_num())?;
            }

            Op::OpBoolOr => {
                let b_bytes = self.pop_stack()?;
                let a_bytes = self.pop_stack()?;
                let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let b = BigNumber::from_script_num(&b_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let result = if !a.is_zero() || !b.is_zero() {
                    BigNumber::from_number(1)
                } else {
                    BigNumber::from_number(0)
                };
                self.push_stack(result.to_script_num())?;
            }

            Op::OpNumEqual => {
                self.binary_cmp_op(|a, b| a.cmp(b) == 0)?;
            }

            Op::OpNumEqualVerify => {
                let b_bytes = self.pop_stack()?;
                let a_bytes = self.pop_stack()?;
                let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let b = BigNumber::from_script_num(&b_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                if a.cmp(&b) != 0 {
                    return Err(ScriptError::NumEqualVerifyFailed);
                }
            }

            Op::OpNumNotEqual => {
                self.binary_cmp_op(|a, b| a.cmp(b) != 0)?;
            }

            Op::OpLessThan => {
                self.binary_cmp_op(|a, b| a.cmp(b) < 0)?;
            }

            Op::OpGreaterThan => {
                self.binary_cmp_op(|a, b| a.cmp(b) > 0)?;
            }

            Op::OpLessThanOrEqual => {
                self.binary_cmp_op(|a, b| a.cmp(b) <= 0)?;
            }

            Op::OpGreaterThanOrEqual => {
                self.binary_cmp_op(|a, b| a.cmp(b) >= 0)?;
            }

            Op::OpMin => {
                self.binary_arith_op(|a, b| if a.cmp(&b) < 0 { a } else { b })?;
            }

            Op::OpMax => {
                self.binary_arith_op(|a, b| if a.cmp(&b) > 0 { a } else { b })?;
            }

            Op::OpWithin => {
                let max_bytes = self.pop_stack()?;
                let min_bytes = self.pop_stack()?;
                let x_bytes = self.pop_stack()?;
                let x = BigNumber::from_script_num(&x_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let min = BigNumber::from_script_num(&min_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let max = BigNumber::from_script_num(&max_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let result = x.cmp(&min) >= 0 && x.cmp(&max) < 0;
                self.push_stack(Self::bool_to_stack(result))?;
            }

            // -- Shift Operations (BSV-restored) --------------------------------
            Op::OpLShift => {
                let n_bytes = self.pop_stack()?;
                let data = self.pop_stack()?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let shift = n.to_number().unwrap_or(0);
                if shift < 0 {
                    return Err(ScriptError::InvalidStackOperation(
                        "negative shift".to_string(),
                    ));
                }
                let result = byte_lshift(&data, shift as usize);
                self.push_stack(result)?;
            }

            Op::OpRShift => {
                let n_bytes = self.pop_stack()?;
                let data = self.pop_stack()?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let shift = n.to_number().unwrap_or(0);
                if shift < 0 {
                    return Err(ScriptError::InvalidStackOperation(
                        "negative shift".to_string(),
                    ));
                }
                let result = byte_rshift(&data, shift as usize);
                self.push_stack(result)?;
            }

            // -- Crypto Operations ----------------------------------------------
            Op::OpRipemd160 => {
                let data = self.pop_stack()?;
                let hash = crate::primitives::hash::ripemd160(&data);
                self.push_stack(hash.to_vec())?;
            }

            Op::OpSha1 => {
                let data = self.pop_stack()?;
                let hash = crate::primitives::hash::sha1(&data);
                self.push_stack(hash.to_vec())?;
            }

            Op::OpSha256 => {
                let data = self.pop_stack()?;
                let hash = crate::primitives::hash::sha256(&data);
                self.push_stack(hash.to_vec())?;
            }

            Op::OpHash160 => {
                let data = self.pop_stack()?;
                let hash = crate::primitives::hash::hash160(&data);
                self.push_stack(hash.to_vec())?;
            }

            Op::OpHash256 => {
                let data = self.pop_stack()?;
                let hash = crate::primitives::hash::hash256(&data);
                self.push_stack(hash.to_vec())?;
            }

            Op::OpCodeSeparator => {
                self.last_code_separator = Some(self.program_counter);
            }

            Op::OpCheckSig => {
                self.op_checksig()?;
            }

            Op::OpCheckSigVerify => {
                self.op_checksig()?;
                let val = self.pop_stack()?;
                if !Self::stack_to_bool(&val) {
                    return Err(ScriptError::CheckSigVerifyFailed);
                }
            }

            Op::OpCheckMultiSig => {
                self.op_checkmultisig()?;
            }

            Op::OpCheckMultiSigVerify => {
                self.op_checkmultisig()?;
                let val = self.pop_stack()?;
                if !Self::stack_to_bool(&val) {
                    return Err(ScriptError::CheckMultiSigVerifyFailed);
                }
            }

            // OP_CHECKLOCKTIMEVERIFY (OP_NOP2 / OP_CLTV)
            // In standard BSV this is NOP2 -- we handle it as NOP for now.
            // The verify behavior requires transaction locktime comparison.

            // OP_CHECKSEQUENCEVERIFY (OP_NOP3 / OP_CSV)
            // Similar -- NOP in BSV.

            // -- Chronicle 2026 Opcodes -----------------------------------------
            Op::OpSubstr => {
                // stack: data, begin, length -> substring
                let len_bytes = self.pop_stack()?;
                let begin_bytes = self.pop_stack()?;
                let data = self.pop_stack()?;
                let begin = BigNumber::from_script_num(&begin_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let len = BigNumber::from_script_num(&len_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let begin_val = begin.to_number().unwrap_or(0) as usize;
                let len_val = len.to_number().unwrap_or(0) as usize;
                if begin_val + len_val > data.len() {
                    return Err(ScriptError::InvalidStackOperation(
                        "OP_SUBSTR: range out of bounds".to_string(),
                    ));
                }
                let result = data[begin_val..begin_val + len_val].to_vec();
                self.push_stack(result)?;
            }

            Op::OpLeft => {
                let n_bytes = self.pop_stack()?;
                let data = self.pop_stack()?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let n_val = n.to_number().unwrap_or(0) as usize;
                if n_val > data.len() {
                    return Err(ScriptError::InvalidStackOperation(
                        "OP_LEFT: position out of range".to_string(),
                    ));
                }
                self.push_stack(data[..n_val].to_vec())?;
            }

            Op::OpRight => {
                let n_bytes = self.pop_stack()?;
                let data = self.pop_stack()?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let n_val = n.to_number().unwrap_or(0) as usize;
                if n_val > data.len() {
                    return Err(ScriptError::InvalidStackOperation(
                        "OP_RIGHT: position out of range".to_string(),
                    ));
                }
                self.push_stack(data[data.len() - n_val..].to_vec())?;
            }

            Op::OpLShiftNum => {
                let n_bytes = self.pop_stack()?;
                let a_bytes = self.pop_stack()?;
                let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let shift = n.to_number().unwrap_or(0);
                if shift < 0 {
                    return Err(ScriptError::InvalidStackOperation(
                        "negative shift".to_string(),
                    ));
                }
                let mut result = a;
                result.iushln(shift as usize);
                self.push_stack(result.to_script_num())?;
            }

            Op::OpRShiftNum => {
                let n_bytes = self.pop_stack()?;
                let a_bytes = self.pop_stack()?;
                let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let shift = n.to_number().unwrap_or(0);
                if shift < 0 {
                    return Err(ScriptError::InvalidStackOperation(
                        "negative shift".to_string(),
                    ));
                }
                let mut result = a;
                result.iushrn(shift as usize);
                self.push_stack(result.to_script_num())?;
            }

            // -- Disabled Opcodes -----------------------------------------------
            Op::Op2Mul => {
                return Err(ScriptError::DisabledOpcode("OP_2MUL".to_string()));
            }

            Op::Op2Div => {
                return Err(ScriptError::DisabledOpcode("OP_2DIV".to_string()));
            }

            // -- All NOPs (NOP11..NOP77 etc) ------------------------------------
            _ => {
                // Any remaining opcode that is a NOP variant is a no-op.
                // Check if it's in the NOP range (0xba..=0xf8) or other known NOP.
                let byte = chunk.op_byte;
                if (0xba..=0xf8).contains(&byte) {
                    // NOP variant -- no operation
                } else {
                    return Err(ScriptError::InvalidOpcode(byte));
                }
            }
        }

        Ok(())
    }

    // -- Arithmetic helpers ---------------------------------------------------

    /// Pop one value, apply unary function, push result.
    fn unary_arith_op<F>(&mut self, f: F) -> Result<(), ScriptError>
    where
        F: FnOnce(BigNumber) -> BigNumber,
    {
        let a_bytes = self.pop_stack()?;
        let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
            .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
        let result = f(a);
        self.push_stack(result.to_script_num())?;
        Ok(())
    }

    /// Pop two values, apply binary function, push result.
    fn binary_arith_op<F>(&mut self, f: F) -> Result<(), ScriptError>
    where
        F: FnOnce(BigNumber, BigNumber) -> BigNumber,
    {
        let b_bytes = self.pop_stack()?;
        let a_bytes = self.pop_stack()?;
        let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
            .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
        let b = BigNumber::from_script_num(&b_bytes, !self.is_relaxed(), None)
            .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
        let result = f(a, b);
        self.push_stack(result.to_script_num())?;
        Ok(())
    }

    /// Pop two values, apply comparison, push bool result.
    fn binary_cmp_op<F>(&mut self, f: F) -> Result<(), ScriptError>
    where
        F: FnOnce(&BigNumber, &BigNumber) -> bool,
    {
        let b_bytes = self.pop_stack()?;
        let a_bytes = self.pop_stack()?;
        let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
            .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
        let b = BigNumber::from_script_num(&b_bytes, !self.is_relaxed(), None)
            .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
        let result = f(&a, &b);
        self.push_stack(Self::bool_to_stack(result))?;
        Ok(())
    }

    // -- Crypto helpers -------------------------------------------------------

    /// OP_CHECKSIG implementation.
    fn op_checksig(&mut self) -> Result<(), ScriptError> {
        use crate::primitives::ecdsa::ecdsa_verify;
        use crate::primitives::point::Point;
        use crate::primitives::signature::Signature;

        let pubkey_bytes = self.pop_stack()?;
        let sig_bytes = self.pop_stack()?;

        if sig_bytes.is_empty() {
            // Empty signature always fails
            self.push_stack(Self::bool_to_stack(false))?;
            return Ok(());
        }

        // SAFETY: guarded by is_empty() check above which returns early
        let sighash_type = *sig_bytes.last().unwrap() as u32;
        let der_sig = &sig_bytes[..sig_bytes.len() - 1];

        // Parse DER signature
        let signature = match Signature::from_der(der_sig) {
            Ok(s) => s,
            Err(_) => {
                self.push_stack(Self::bool_to_stack(false))?;
                return Ok(());
            }
        };

        // In non-relaxed mode, require low-S
        if !self.is_relaxed() && !signature.has_low_s() {
            self.push_stack(Self::bool_to_stack(false))?;
            return Ok(());
        }

        // Parse public key
        let pubkey = match Point::from_der(&pubkey_bytes) {
            Ok(p) => p,
            Err(_) => {
                self.push_stack(Self::bool_to_stack(false))?;
                return Ok(());
            }
        };

        // Compute sighash
        let sub_script = self.get_subscript();
        let preimage = self.sighash_preimage(&sub_script, sighash_type);
        let sighash = crate::primitives::hash::hash256(&preimage);

        // Verify
        let valid = ecdsa_verify(&sighash, &signature, &pubkey);
        self.push_stack(Self::bool_to_stack(valid))?;
        Ok(())
    }

    /// OP_CHECKMULTISIG implementation.
    fn op_checkmultisig(&mut self) -> Result<(), ScriptError> {
        use crate::primitives::ecdsa::ecdsa_verify;
        use crate::primitives::point::Point;
        use crate::primitives::signature::Signature;

        // Pop n (number of public keys)
        let n_bytes = self.pop_stack()?;
        let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
            .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
        let n_val = n.to_number().unwrap_or(0) as usize;

        if n_val > 20 {
            return Err(ScriptError::InvalidScript(
                "too many public keys".to_string(),
            ));
        }

        // Pop n pubkeys
        let mut pubkeys = Vec::with_capacity(n_val);
        for _ in 0..n_val {
            pubkeys.push(self.pop_stack()?);
        }

        // Pop m (number of signatures required)
        let m_bytes = self.pop_stack()?;
        let m = BigNumber::from_script_num(&m_bytes, !self.is_relaxed(), None)
            .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
        let m_val = m.to_number().unwrap_or(0) as usize;

        if m_val > n_val {
            return Err(ScriptError::InvalidScript(
                "m > n in CHECKMULTISIG".to_string(),
            ));
        }

        // Pop m signatures
        let mut signatures = Vec::with_capacity(m_val);
        for _ in 0..m_val {
            signatures.push(self.pop_stack()?);
        }

        // Pop the dummy element (BIP 147: NULLDUMMY)
        let dummy = self.pop_stack()?;
        if !self.is_relaxed() && !dummy.is_empty() {
            return Err(ScriptError::NullDummyViolation);
        }

        // Verify m signatures against n pubkeys in order
        let sub_script = self.get_subscript();
        let mut pk_idx = 0;
        let mut sig_idx = 0;
        let mut success = true;

        while sig_idx < m_val && pk_idx < n_val {
            let sig_bytes = &signatures[sig_idx];

            if sig_bytes.is_empty() {
                sig_idx += 1;
                continue;
            }

            // SAFETY: guarded by is_empty() check above which continues
            let sighash_type = *sig_bytes.last().unwrap() as u32;
            let der_sig = &sig_bytes[..sig_bytes.len() - 1];

            let signature = match Signature::from_der(der_sig) {
                Ok(s) => s,
                Err(_) => {
                    success = false;
                    break;
                }
            };

            if !self.is_relaxed() && !signature.has_low_s() {
                success = false;
                break;
            }

            let pubkey = match Point::from_der(&pubkeys[pk_idx]) {
                Ok(p) => p,
                Err(_) => {
                    pk_idx += 1;
                    continue;
                }
            };

            let preimage = self.sighash_preimage(&sub_script, sighash_type);
            let sighash = crate::primitives::hash::hash256(&preimage);

            if ecdsa_verify(&sighash, &signature, &pubkey) {
                sig_idx += 1;
            }
            pk_idx += 1;

            // Check if enough pubkeys remain to verify remaining signatures
            if n_val - pk_idx < m_val - sig_idx {
                success = false;
                break;
            }
        }

        if sig_idx < m_val {
            success = false;
        }

        self.push_stack(Self::bool_to_stack(success))?;
        Ok(())
    }

    /// Get the subscript for signature verification.
    ///
    /// Returns the locking script from the last OP_CODESEPARATOR position
    /// (or the full locking script if no CODESEPARATOR was encountered).
    fn get_subscript(&self) -> crate::script::script::Script {
        use crate::script::script::Script;

        let chunks = self.locking_script.chunks();
        let start = match self.last_code_separator {
            Some(pos) => pos + 1,
            None => 0,
        };

        if start >= chunks.len() {
            return Script::new();
        }

        Script::from_chunks(chunks[start..].to_vec())
    }

    /// Compute the BIP143/forkid sighash preimage.
    ///
    /// BSV uses the BIP143-style sighash for all transactions (FORKID flag 0x40).
    pub(crate) fn sighash_preimage(
        &self,
        sub_script: &crate::script::script::Script,
        sighash_type: u32,
    ) -> Vec<u8> {
        use crate::primitives::hash::hash256;

        // Sighash type flags
        let sighash_forkid: u32 = 0x40;
        let sighash_anyonecanpay: u32 = 0x80;
        let base_type = sighash_type & 0x1f;

        let _sighash_all: u32 = 1;
        let sighash_none: u32 = 2;
        let sighash_single: u32 = 3;

        let anyone_can_pay = (sighash_type & sighash_anyonecanpay) != 0;

        let mut preimage = Vec::new();

        // 1. version (4 bytes LE)
        preimage.extend_from_slice(&self.transaction_version.to_le_bytes());

        // 2. hashPrevouts
        //
        // BIP-143 hashPrevouts is the double-SHA256 of the serialized outpoints
        // of ALL inputs, in their original transaction order. `other_inputs`
        // holds the OTHER N-1 inputs (excluding the current one) in tx order;
        // splice the current input back in at position `input_index`.
        if !anyone_can_pay {
            let mut prevouts = Vec::new();
            let total_inputs = self.other_inputs.len() + 1;
            let mut others = self.other_inputs.iter();
            for i in 0..total_inputs {
                if i == self.input_index {
                    prevouts.extend_from_slice(&txid_to_bytes(&self.source_txid));
                    prevouts.extend_from_slice(&(self.source_output_index as u32).to_le_bytes());
                } else if let Some(input) = others.next() {
                    let default_txid = "00".repeat(32);
                    let txid = input.source_txid.as_deref().unwrap_or(&default_txid);
                    prevouts.extend_from_slice(&txid_to_bytes(txid));
                    prevouts.extend_from_slice(&input.source_output_index.to_le_bytes());
                }
            }
            preimage.extend_from_slice(&hash256(&prevouts));
        } else {
            preimage.extend_from_slice(&[0u8; 32]);
        }

        // 3. hashSequence — same ordering rule as hashPrevouts.
        if !anyone_can_pay && base_type != sighash_none && base_type != sighash_single {
            let mut sequences = Vec::new();
            let total_inputs = self.other_inputs.len() + 1;
            let mut others = self.other_inputs.iter();
            for i in 0..total_inputs {
                if i == self.input_index {
                    sequences.extend_from_slice(&self.transaction_sequence.to_le_bytes());
                } else if let Some(input) = others.next() {
                    sequences.extend_from_slice(&input.sequence.to_le_bytes());
                }
            }
            preimage.extend_from_slice(&hash256(&sequences));
        } else {
            preimage.extend_from_slice(&[0u8; 32]);
        }

        // 4. outpoint (txid + index, 36 bytes)
        preimage.extend_from_slice(&txid_to_bytes(&self.source_txid));
        preimage.extend_from_slice(&(self.source_output_index as u32).to_le_bytes());

        // 5. scriptCode (varint length + serialized sub_script)
        let script_bytes = sub_script.to_binary();
        write_varint(&mut preimage, script_bytes.len() as u64);
        preimage.extend_from_slice(&script_bytes);

        // 6. value (8 bytes LE)
        preimage.extend_from_slice(&self.source_satoshis.to_le_bytes());

        // 7. sequence (4 bytes LE)
        preimage.extend_from_slice(&self.transaction_sequence.to_le_bytes());

        // 8. hashOutputs
        if base_type != sighash_none && base_type != sighash_single {
            let mut outputs = Vec::new();
            for output in &self.other_outputs {
                outputs.extend_from_slice(&output.satoshis.unwrap_or(0).to_le_bytes());
                let script_bytes = output.locking_script.to_binary();
                write_varint(&mut outputs, script_bytes.len() as u64);
                outputs.extend_from_slice(&script_bytes);
            }
            preimage.extend_from_slice(&hash256(&outputs));
        } else if base_type == sighash_single && self.input_index < self.other_outputs.len() {
            let output = &self.other_outputs[self.input_index];
            let mut out_data = Vec::new();
            out_data.extend_from_slice(&output.satoshis.unwrap_or(0).to_le_bytes());
            let script_bytes = output.locking_script.to_binary();
            write_varint(&mut out_data, script_bytes.len() as u64);
            out_data.extend_from_slice(&script_bytes);
            preimage.extend_from_slice(&hash256(&out_data));
        } else {
            preimage.extend_from_slice(&[0u8; 32]);
        }

        // 9. locktime (4 bytes LE)
        preimage.extend_from_slice(&self.transaction_lock_time.to_le_bytes());

        // 10. sighash type (4 bytes LE, including FORKID flag)
        preimage.extend_from_slice(&(sighash_type | sighash_forkid).to_le_bytes());

        preimage
    }
}

// -- Utility functions --------------------------------------------------------

/// Left-shift a byte array by n bits (unsigned, preserving length).
#[allow(clippy::needless_range_loop)]
fn byte_lshift(data: &[u8], n: usize) -> Vec<u8> {
    if data.is_empty() || n >= data.len() * 8 {
        return vec![0; data.len()];
    }

    let byte_shift = n / 8;
    let bit_shift = n % 8;
    let len = data.len();
    let mut result = vec![0u8; len];

    for i in 0..len {
        let src = i + byte_shift;
        if src < len {
            result[i] = data[src] << bit_shift;
            if bit_shift > 0 && src + 1 < len {
                result[i] |= data[src + 1] >> (8 - bit_shift);
            }
        }
    }
    result
}

/// Right-shift a byte array by n bits (unsigned, preserving length).
fn byte_rshift(data: &[u8], n: usize) -> Vec<u8> {
    if data.is_empty() || n >= data.len() * 8 {
        return vec![0; data.len()];
    }

    let byte_shift = n / 8;
    let bit_shift = n % 8;
    let len = data.len();
    let mut result = vec![0u8; len];

    for i in (0..len).rev() {
        if i >= byte_shift {
            let src = i - byte_shift;
            result[i] = data[src] >> bit_shift;
            if bit_shift > 0 && src > 0 {
                result[i] |= data[src - 1] << (8 - bit_shift);
            }
        }
    }
    result
}

/// Convert a hex txid string to bytes (reversed, since txids are displayed in reverse byte order).
fn txid_to_bytes(txid: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    for i in (0..txid.len()).step_by(2) {
        if let Ok(b) = u8::from_str_radix(&txid[i..i + 2], 16) {
            bytes.push(b);
        }
    }
    // Txids are displayed in reverse byte order
    bytes.reverse();
    // Ensure exactly 32 bytes
    bytes.resize(32, 0);
    bytes
}

/// Write a Bitcoin-style varint to a buffer.
fn write_varint(buf: &mut Vec<u8>, val: u64) {
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
