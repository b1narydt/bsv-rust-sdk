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
                // Post-Genesis BSV semantics. With no open OP_IF, OP_RETURN
                // is a successful early termination — jump to end-of-script
                // and let the caller inspect the stack. With an open OP_IF,
                // termination is deferred until the matching OP_ENDIF: until
                // then, only structural ops execute (the
                // `returning_from_conditional` gate in `step()` handles this).
                //
                // Matches ts-sdk Spend.ts:902-913 and go-sdk
                // operations.go:583-598.
                //
                // TODO(divergence vs ts-sdk Spend.ts:903-905): TS errors with
                // "OP_RETURN is invalid before Genesis" when
                // `hasExplicitFlags() && !isAfterGenesis()`. Rust matches
                // go-sdk's post-Genesis-only behavior and assumes Genesis is
                // active (true for all live BSV networks since 2020-02-04).
                // Add explicit_flags / is_after_genesis plumbing if pre-Genesis
                // conformance vectors are ever needed.
                if !self.if_stack.is_empty() {
                    self.returning_from_conditional = true;
                    return Ok(());
                }
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
                // Node v1.2.0 (and ts-sdk Spend): the tx version as 4 little-endian bytes, not a script number
                self.push_stack(self.transaction_version.to_le_bytes().to_vec())?;
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
                let n_val = match Self::stack_index(&n, self.stack.len()) {
                    Some(i) => i as isize,
                    None => {
                        return Err(ScriptError::InvalidStackOperation(
                            "OP_PICK requires the top stack element to be 0 or a positive number less than the current size of the stack.".to_string(),
                        ))
                    }
                };
                let item = self.stack_top(n_val)?.clone();
                self.push_stack(item)?;
            }

            Op::OpRoll => {
                let n_bytes = self.pop_stack()?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let len = self.stack.len();
                let n_val = match Self::stack_index(&n, len) {
                    Some(i) => i,
                    None => return Err(ScriptError::StackUnderflow),
                };
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
                let data = self.pop_stack()?;
                let pos = match n.to_number() {
                    Some(p) if !n.is_neg() && (p as u64) <= data.len() as u64 => p as usize,
                    _ => usize::MAX,
                };
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
                // A negative or oversized size is refused (ts-sdk: "not currently possible to push ...").
                let size_val = match size.to_number() {
                    Some(v)
                        if !size.is_neg()
                            && v <= 0x7fff_ffff
                            && (v as usize) <= self.memory_limit =>
                    {
                        v as usize
                    }
                    _ => {
                        return Err(ScriptError::InvalidStackOperation(
                            "OP_NUM2BIN size is negative or larger than can be pushed".to_string(),
                        ))
                    }
                };
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
                if n.is_neg() {
                    return Err(ScriptError::InvalidStackOperation(
                        "OP_LSHIFT requires the top item on the stack not to be negative."
                            .to_string(),
                    ));
                }
                // A count past every bit shifts everything out (zeros of the input's width, as ts-sdk).
                let shift = n.to_number().map_or(usize::MAX, |v| v as usize);
                let result = if shift >= data.len().saturating_mul(8) {
                    vec![0u8; data.len()]
                } else {
                    byte_lshift(&data, shift)
                };
                self.push_stack(result)?;
            }

            Op::OpRShift => {
                let n_bytes = self.pop_stack()?;
                let data = self.pop_stack()?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                if n.is_neg() {
                    return Err(ScriptError::InvalidStackOperation(
                        "OP_RSHIFT requires the top item on the stack not to be negative."
                            .to_string(),
                    ));
                }
                // A count past every bit shifts everything out (zeros of the input's width, as ts-sdk).
                let shift = n.to_number().map_or(usize::MAX, |v| v as usize);
                let result = if shift >= data.len().saturating_mul(8) {
                    vec![0u8; data.len()]
                } else {
                    byte_rshift(&data, shift)
                };
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
                // ts-sdk Spend: stack data, offset, length -> data[offset .. offset + length]
                let len = self.splice_operand()?;
                let offset = self.splice_operand()?;
                let data = self.pop_stack()?;
                let size = data.len() as i64;
                if offset < 0 || offset >= size || len < 0 || len > size - offset {
                    return Err(ScriptError::InvalidStackOperation(format!(
                        "OP_SUBSTR offset ({offset}) must be in range [0, {size}) and length ({len}) must be in range [0, {}]",
                        size - offset
                    )));
                }
                self.push_stack(data[offset as usize..(offset + len) as usize].to_vec())?;
            }

            Op::OpLeft => {
                let len = self.splice_operand()?;
                let data = self.pop_stack()?;
                let size = data.len() as i64;
                if len < 0 || len > size {
                    return Err(ScriptError::InvalidStackOperation(format!(
                        "OP_LEFT length ({len}) must be in range [0, {size}]"
                    )));
                }
                self.push_stack(data[..len as usize].to_vec())?;
            }

            Op::OpRight => {
                let len = self.splice_operand()?;
                let data = self.pop_stack()?;
                let size = data.len() as i64;
                if len < 0 || len > size {
                    return Err(ScriptError::InvalidStackOperation(format!(
                        "OP_RIGHT length ({len}) must be in range [0, {size}]"
                    )));
                }
                self.push_stack(data[(size - len) as usize..].to_vec())?;
            }

            Op::OpLShiftNum => {
                let n_bytes = self.pop_stack()?;
                let a_bytes = self.pop_stack()?;
                let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let shift = Self::shift_count(&n, "OP_LSHIFTNUM")?;
                // A non-zero value shifted past the memory limit cannot be held: refuse it before allocating it
                // (ts-sdk's BigInt fails the same way; the stack's memory limit would refuse the result anyway).
                if !a.is_zero()
                    && a.bit_length().saturating_add(shift) > self.memory_limit.saturating_mul(8)
                {
                    return Err(ScriptError::MemoryLimitExceeded);
                }
                let mut result = a;
                if !result.is_zero() {
                    result.iushln(shift);
                }
                self.push_stack(result.to_script_num())?;
            }

            Op::OpRShiftNum => {
                let n_bytes = self.pop_stack()?;
                let a_bytes = self.pop_stack()?;
                let a = BigNumber::from_script_num(&a_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
                    .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
                let shift = Self::shift_count(&n, "OP_RSHIFTNUM")?;
                let mut result = a;
                if shift >= result.bit_length() {
                    result = BigNumber::from_number(0);
                } else {
                    result.iushrn(shift);
                }
                self.push_stack(result.to_script_num())?;
            }

            // -- OP_2MUL / OP_2DIV (re-enabled by Chronicle) ----------------------
            // ts-sdk `Spend` (with no explicit verify flags) executes both: the top number times 2, and the top
            // number divided by 2 (truncated toward zero).
            Op::Op2Mul => {
                self.unary_arith_op(|a| a.mul(&BigNumber::from_number(2)))?;
            }

            Op::Op2Div => {
                self.unary_arith_op(|a| a.div(&BigNumber::from_number(2)).expect("division by 2"))?;
            }

            // -- All NOPs (NOP11..NOP77 etc) ------------------------------------
            _ => {
                // Every other opcode is invalid when executed: OP_NOP1, OP_NOP9 and OP_NOP10 (and OP_NOP2/3 as
                // CHECKLOCKTIMEVERIFY / CHECKSEQUENCEVERIFY) are the only upgrade-NOP slots of node v1.2.0, and every
                // value above 0xb9 is FIRST_UNDEFINED_OP_VALUE (ts-sdk Spend, go-sdk). An unexecuted branch skips them.
                return Err(ScriptError::InvalidOpcode(chunk.op_byte));
            }
        }

        Ok(())
    }

    // -- Arithmetic helpers ---------------------------------------------------

    /// ts-sdk `Spend` #checkSignatureEncoding without explicit flags: an empty signature passes; otherwise strict
    /// DER, a defined hash type, the Chronicle bit only after Chronicle, and low S when not relaxed.
    pub(crate) fn check_signature_encoding(&self, buf: &[u8]) -> Result<(), ScriptError> {
        use crate::primitives::transaction_signature::TransactionSignature;
        if buf.is_empty() {
            return Ok(());
        }
        let bad = || ScriptError::InvalidScript("The signature format is invalid.".to_string());
        if !is_checksig_format(buf) {
            return Err(bad());
        }
        let sig = TransactionSignature::from_checksig_format(buf, false).map_err(|_| bad())?;
        let scope = buf[buf.len() - 1] as u32;
        let base = scope & 0x1f;
        if !(1..=3).contains(&base) {
            return Err(ScriptError::InvalidScript(
                "The signature hash type is invalid.".to_string(),
            ));
        }
        if scope & 0x20 != 0 && !self.is_relaxed() {
            return Err(ScriptError::InvalidScript(
                "The signature hash type is invalid before Chronicle.".to_string(),
            ));
        }
        if !self.is_relaxed() && !sig.has_low_s() {
            return Err(ScriptError::InvalidScript(
                "The signature must have a low S value.".to_string(),
            ));
        }
        Ok(())
    }

    /// ts-sdk `Spend` #checkPublicKeyEncoding (strict encoding, on without explicit flags).
    pub(crate) fn check_public_key_encoding(&self, buf: &[u8]) -> Result<(), ScriptError> {
        let err = |m: &str| Err(ScriptError::InvalidScript(m.to_string()));
        if buf.is_empty() {
            return err("Public key is empty.");
        }
        if buf.len() < 33 {
            return err("The public key is too short, it must be at least 33 bytes.");
        }
        match buf[0] {
            0x04 if buf.len() != 65 => {
                return err("The non-compressed public key must be 65 bytes.")
            }
            0x02 | 0x03 if buf.len() != 33 => {
                return err("The compressed public key must be 33 bytes.")
            }
            0x02..=0x04 => {}
            _ => return err("The public key is in an unknown format."),
        }
        if crate::primitives::point::Point::from_der(buf).is_err() {
            return err("The public key is in an unknown format.");
        }
        Ok(())
    }

    /// `n` as an index into a stack of `len` items (0 = top): None when negative or past the bottom.
    fn stack_index(n: &BigNumber, len: usize) -> Option<usize> {
        if n.is_neg() {
            return None;
        }
        match n.to_number() {
            Some(v) if (v as u64) < len as u64 => Some(v as usize),
            _ => None,
        }
    }

    /// A splice operand (OP_SUBSTR / OP_LEFT / OP_RIGHT), as ts-sdk `Spend` reads it: a script number (minimally
    /// encoded when not relaxed); more than 8 bytes reads the first 8 as a two's-complement i64; clamped to the
    /// 32-bit range.
    fn splice_operand(&mut self) -> Result<i64, ScriptError> {
        let b = self.pop_stack()?;
        let n = BigNumber::from_script_num(&b, !self.is_relaxed(), None)
            .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
        let v: i64 = if b.len() > 8 {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[..8]);
            i64::from_le_bytes(a)
        } else {
            n.to_number().unwrap_or(0)
        };
        Ok(v.clamp(-0x8000_0000, 0x7fff_ffff))
    }

    /// The bit count of OP_LSHIFTNUM / OP_RSHIFTNUM, as ts-sdk `Spend` checks it: not negative, at most INT_MAX.
    fn shift_count(n: &BigNumber, op: &str) -> Result<usize, ScriptError> {
        if n.is_neg() {
            return Err(ScriptError::InvalidStackOperation(format!(
                "{op} bits to shift must not be negative."
            )));
        }
        match n.to_number() {
            Some(s) if s <= 0x7fff_ffff => Ok(s as usize),
            _ => Err(ScriptError::InvalidStackOperation(format!(
                "{op} shift count exceeds INT_MAX."
            ))),
        }
    }

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
        use crate::primitives::transaction_signature::TransactionSignature;

        let pubkey_bytes = self.pop_stack()?;
        let sig_bytes = self.pop_stack()?;
        self.check_signature_encoding(&sig_bytes)?;
        self.check_public_key_encoding(&pubkey_bytes)?;

        if sig_bytes.is_empty() {
            // Empty signature always fails
            self.push_stack(Self::bool_to_stack(false))?;
            return Ok(());
        }

        // Parse the complete checksig value (DER signature + sighash byte).
        let transaction_signature =
            match TransactionSignature::from_checksig_format(&sig_bytes, false) {
                Ok(signature) => signature,
                Err(_) => {
                    self.push_stack(Self::bool_to_stack(false))?;
                    return Ok(());
                }
            };

        // In non-relaxed mode, require low-S
        if !self.is_relaxed() && !transaction_signature.has_low_s() {
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
        let sub_script = self.get_subscript(true);
        let preimage = self.sighash_preimage(&sub_script, transaction_signature.scope());
        let sighash = crate::primitives::hash::hash256(&preimage);

        // Verify
        let valid =
            ecdsa_verify(&sighash, transaction_signature.signature(), &pubkey).unwrap_or(false);
        self.push_stack(Self::bool_to_stack(valid))?;
        Ok(())
    }

    /// OP_CHECKMULTISIG implementation.
    fn op_checkmultisig(&mut self) -> Result<(), ScriptError> {
        use crate::primitives::ecdsa::ecdsa_verify;
        use crate::primitives::point::Point;
        use crate::primitives::transaction_signature::TransactionSignature;

        // Pop n (number of public keys)
        let n_bytes = self.pop_stack()?;
        let n = BigNumber::from_script_num(&n_bytes, !self.is_relaxed(), None)
            .map_err(|e| ScriptError::InvalidScript(e.to_string()))?;
        // The whole number is range-checked (a count wider than an i64 is out of range, not 0). As in ts-sdk Spend,
        // the limit is INT_MAX, and the stack must hold the keys before anything is allocated for them.
        let n_val = match n.to_number() {
            Some(v) if !n.is_neg() && v <= 0x7fff_ffff => v as usize,
            _ => {
                return Err(ScriptError::InvalidScript(
                    "OP_CHECKMULTISIG requires a key count between 0 and 2147483647.".to_string(),
                ))
            }
        };
        if self.stack.len() < n_val {
            return Err(ScriptError::InvalidStackOperation(
                "OP_CHECKMULTISIG stack too small for nKeys and keys.".to_string(),
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
        let m_val = match m.to_number() {
            Some(v) if !m.is_neg() && v <= n_val as i64 => v as usize,
            _ => usize::MAX,
        };

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
        let sub_script = self.get_subscript(false);
        let mut pk_idx = 0;
        let mut sig_idx = 0;
        let mut success = true;

        while sig_idx < m_val && pk_idx < n_val {
            let sig_bytes = &signatures[sig_idx];

            if sig_bytes.is_empty() {
                sig_idx += 1;
                continue;
            }
            self.check_signature_encoding(sig_bytes)?;
            self.check_public_key_encoding(&pubkeys[pk_idx])?;

            let transaction_signature =
                match TransactionSignature::from_checksig_format(sig_bytes, false) {
                    Ok(signature) => signature,
                    Err(_) => {
                        success = false;
                        break;
                    }
                };

            if !self.is_relaxed() && !transaction_signature.has_low_s() {
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

            let preimage = self.sighash_preimage(&sub_script, transaction_signature.scope());
            let sighash = crate::primitives::hash::hash256(&preimage);

            if ecdsa_verify(&sighash, transaction_signature.signature(), &pubkey).unwrap_or(false) {
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
    ///
    /// The subscript is taken from the script being executed (the unlocking
    /// script while it runs, else the locking script). With `cross_boundary`
    /// (OP_CHECKSIG / OP_CHECKSIGVERIFY), a subscript taken while the unlocking
    /// script runs continues into the full locking script, as ts-sdk
    /// `Spend` and go-sdk `thread.subScript` (after Chronicle) do; OP_PUSH_TX
    /// style contracts sign over that combined subscript.
    fn get_subscript(&self, cross_boundary: bool) -> crate::script::script::Script {
        use crate::script::script::Script;
        use crate::script::spend::ScriptContext;

        let in_unlocking = matches!(self.context, ScriptContext::Unlocking);
        let chunks = if in_unlocking {
            self.unlocking_script.chunks()
        } else {
            self.locking_script.chunks()
        };
        let start = match self.last_code_separator {
            Some(pos) => pos + 1,
            None => 0,
        };

        let mut out = if start >= chunks.len() {
            Vec::new()
        } else {
            chunks[start..].to_vec()
        };
        if cross_boundary && in_unlocking {
            out.extend(self.locking_script.chunks().iter().cloned());
        }
        Script::from_chunks(out)
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

        // Precondition: `input_index` must address one of the N inputs (the
        // signed input or one of `other_inputs`). Out-of-range silently drops
        // the current input from the splice loops below, producing a hash
        // that disagrees with TS/Go canonical and yields a syntactically-
        // valid but invalid signature.
        //
        // `assert!` (not `debug_assert!`) so release builds enforce the
        // invariant — this is signing-correctness, not a dev-only guard.
        assert!(
            self.input_index <= self.other_inputs.len(),
            "input_index {} exceeds total inputs {}",
            self.input_index,
            self.other_inputs.len() + 1
        );

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
        //
        // Pre-fix this concatenated [current_input, ...others] which is only
        // correct for input_index == 0. Multi-input spends signing input >0
        // (e.g. STAS-3 covenant + funding input pattern) produced invalid
        // signatures.
        //
        // Matches bsv-blockchain/ts-sdk src/primitives/TransactionSignature.ts:150
        // (filter+splice) and bsv-blockchain/go-sdk transaction/txinput.go:52-78
        // (iterate-all-in-order).
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

/// ts-sdk isChecksigFormatHelper: the strict DER shape of a checksig-format signature (DER + hash type).
fn is_checksig_format(buf: &[u8]) -> bool {
    if buf.len() < 9 || buf.len() > 73 || buf[0] != 0x30 || buf[1] as usize != buf.len() - 3 {
        return false;
    }
    let r_len = buf[3] as usize;
    if buf[2] != 0x02 || r_len == 0 || 5 + r_len >= buf.len() {
        return false;
    }
    let s_marker = 4 + r_len;
    let s_len = buf[s_marker + 1] as usize;
    if buf[s_marker] != 0x02 || s_len == 0 {
        return false;
    }
    if buf[4] & 0x80 != 0 || (r_len > 1 && buf[4] == 0 && buf[5] & 0x80 == 0) {
        return false;
    }
    let s_val = s_marker + 2;
    if s_val >= buf.len()
        || buf[s_val] & 0x80 != 0
        || (s_len > 1 && buf[s_val] == 0 && buf.get(s_val + 1).is_some_and(|b| b & 0x80 == 0))
    {
        return false;
    }
    r_len + s_len + 7 == buf.len()
}
