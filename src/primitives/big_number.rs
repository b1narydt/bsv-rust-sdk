//! Arbitrary-precision integer type for cryptographic operations.
//!
//! BigNumber provides arbitrary-precision arithmetic with 64-bit limbs and
//! a small-vec optimization that keeps values up to 256 bits on the stack.
//! This is the Rust-native counterpart to the TS SDK's BigNumber class.

use crate::primitives::error::PrimitivesError;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// SmallLimbs: inline storage for <= 4 u64 limbs (256 bits), heap for larger
// ---------------------------------------------------------------------------

/// Storage strategy for BigNumber limbs.
/// Values fitting in 4 u64 limbs (256 bits) are stored inline on the stack.
/// Larger values spill to the heap via Vec.
#[derive(Clone, Debug)]
pub enum SmallLimbs {
    /// Inline storage for up to 4 limbs (256 bits).
    Inline { data: [u64; 4], len: u8 },
    /// Heap storage for values exceeding 256 bits.
    Heap(Vec<u64>),
}

impl SmallLimbs {
    /// Create a SmallLimbs representing zero.
    fn zero() -> Self {
        SmallLimbs::Inline {
            data: [0; 4],
            len: 0,
        }
    }

    /// Create SmallLimbs from a slice of limbs.
    fn from_limbs(limbs: &[u64]) -> Self {
        let stripped = strip_leading_zeros(limbs);
        if stripped.len() <= 4 {
            let mut data = [0u64; 4];
            for (i, &v) in stripped.iter().enumerate() {
                data[i] = v;
            }
            SmallLimbs::Inline {
                data,
                len: stripped.len() as u8,
            }
        } else {
            SmallLimbs::Heap(stripped.to_vec())
        }
    }

    /// Return a slice of the active limbs (least-significant first).
    fn as_slice(&self) -> &[u64] {
        match self {
            SmallLimbs::Inline { data, len } => &data[..*len as usize],
            SmallLimbs::Heap(v) => v.as_slice(),
        }
    }

    /// Number of active limbs.
    fn len(&self) -> usize {
        match self {
            SmallLimbs::Inline { len, .. } => *len as usize,
            SmallLimbs::Heap(v) => v.len(),
        }
    }

    /// Whether there are no limbs (value is zero).
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this is using inline storage.
    pub fn is_inline(&self) -> bool {
        matches!(self, SmallLimbs::Inline { .. })
    }

    /// Get a mutable vec of limbs for modification. After modification,
    /// call `from_limbs` on the result to re-canonicalize.
    fn to_vec(&self) -> Vec<u64> {
        self.as_slice().to_vec()
    }

    /// Get limb at index, or 0 if out of bounds.
    fn get(&self, index: usize) -> u64 {
        let s = self.as_slice();
        if index < s.len() {
            s[index]
        } else {
            0
        }
    }
}

/// Strip leading zero limbs from a slice.
fn strip_leading_zeros(limbs: &[u64]) -> &[u64] {
    let mut end = limbs.len();
    while end > 0 && limbs[end - 1] == 0 {
        end -= 1;
    }
    &limbs[..end]
}

// ---------------------------------------------------------------------------
// Endian
// ---------------------------------------------------------------------------

/// Byte order for array conversions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    /// Big-endian (most significant byte first).
    Big,
    /// Little-endian (least significant byte first).
    Little,
}

// ---------------------------------------------------------------------------
// BigNumber
// ---------------------------------------------------------------------------

/// Arbitrary-precision big number with 64-bit limb representation.
///
/// Limbs are stored in little-endian order (least significant limb first).
/// Values up to 256 bits (4 limbs) use inline stack storage; larger values
/// are heap-allocated.
#[derive(Clone, Debug)]
pub struct BigNumber {
    /// The magnitude limbs (unsigned, little-endian limb order).
    limbs: SmallLimbs,
    /// Whether the number is negative.
    negative: bool,
    /// Optional reduction context for modular arithmetic.
    pub red: Option<Arc<ReductionContext>>,
}

// Forward declaration -- full ReductionContext is defined in reduction_context.rs
// but we need a reference here for the `red` field.
pub use crate::primitives::reduction_context::ReductionContext;

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

impl BigNumber {
    // -- Core constructors --------------------------------------------------

    /// Create a BigNumber from zero.
    pub fn zero() -> Self {
        BigNumber {
            limbs: SmallLimbs::zero(),
            negative: false,
            red: None,
        }
    }

    /// Create a BigNumber from an i64.
    pub fn from_number(n: i64) -> Self {
        if n == 0 {
            return Self::zero();
        }
        let negative = n < 0;
        let mag = (n as i128).unsigned_abs() as u64;
        BigNumber {
            limbs: SmallLimbs::from_limbs(&[mag]),
            negative,
            red: None,
        }
    }

    /// Create a BigNumber with value 1.
    pub fn one() -> Self {
        Self::from_number(1)
    }

    /// Create a BigNumber from a hexadecimal string (no "0x" prefix).
    /// Leading zeros in the hex string are ignored.
    pub fn from_hex(hex: &str) -> Result<Self, PrimitivesError> {
        if hex.is_empty() {
            return Ok(Self::zero());
        }

        // Handle optional sign
        let (hex_str, negative) = if let Some(rest) = hex.strip_prefix('-') {
            (rest, true)
        } else {
            (hex, false)
        };

        if hex_str.is_empty() {
            return Ok(Self::zero());
        }

        // Strip leading zeros
        let hex_str = hex_str.trim_start_matches('0');
        if hex_str.is_empty() {
            return Ok(Self::zero());
        }

        // Validate characters
        for c in hex_str.chars() {
            if !c.is_ascii_hexdigit() {
                return Err(PrimitivesError::InvalidHex(format!(
                    "invalid hex character: {c}"
                )));
            }
        }

        // Parse into u64 limbs, 16 hex chars = 64 bits per limb, from the right
        let mut limbs = Vec::new();
        let bytes = hex_str.as_bytes();
        let mut pos = bytes.len();

        while pos > 0 {
            let start = pos.saturating_sub(16);
            let chunk = &hex_str[start..pos];
            let val = u64::from_str_radix(chunk, 16).map_err(|e| {
                PrimitivesError::InvalidHex(format!("failed to parse hex chunk: {e}"))
            })?;
            limbs.push(val);
            pos = start;
        }

        Ok(BigNumber {
            limbs: SmallLimbs::from_limbs(&limbs),
            negative: negative && !limbs.is_empty(),
            red: None,
        })
    }

    /// Create a BigNumber from a byte array with the specified endianness.
    pub fn from_bytes(bytes: &[u8], endian: Endian) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }

        // Convert to big-endian for processing
        let be_bytes: Vec<u8> = match endian {
            Endian::Big => bytes.to_vec(),
            Endian::Little => {
                let mut v = bytes.to_vec();
                v.reverse();
                v
            }
        };

        // Strip leading zeros
        let start = be_bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(be_bytes.len());
        if start == be_bytes.len() {
            return Self::zero();
        }
        let be_bytes = &be_bytes[start..];

        // Parse into u64 limbs (little-endian limb order)
        let mut limbs = Vec::new();
        let mut pos = be_bytes.len();
        while pos > 0 {
            let chunk_start = pos.saturating_sub(8);
            let chunk = &be_bytes[chunk_start..pos];
            let mut val: u64 = 0;
            for &b in chunk {
                val = (val << 8) | (b as u64);
            }
            limbs.push(val);
            pos = chunk_start;
        }

        BigNumber {
            limbs: SmallLimbs::from_limbs(&limbs),
            negative: false,
            red: None,
        }
    }

    /// Alias for `from_bytes` with big-endian.
    pub fn from_array(bytes: &[u8], endian: Endian) -> Self {
        Self::from_bytes(bytes, endian)
    }

    // -- Conversion methods -------------------------------------------------

    /// Convert to a hexadecimal string (lowercase, no "0x" prefix, minimal length).
    /// Zero is represented as "0".
    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }

        let prefix = if self.negative { "-" } else { "" };
        let limbs = self.limbs.as_slice();
        let mut hex = String::new();

        // Process from most significant limb
        for (i, &limb) in limbs.iter().rev().enumerate() {
            if i == 0 {
                // First (most significant) limb: no leading zeros
                hex.push_str(&format!("{limb:x}"));
            } else {
                // Subsequent limbs: pad to 16 hex chars
                hex.push_str(&format!("{limb:016x}"));
            }
        }

        format!("{prefix}{hex}")
    }

    /// Convert to a byte array with the specified endianness.
    /// If `length` is Some, the output is zero-padded or truncated to that length.
    /// If `length` is None, produces the minimal representation.
    pub fn to_array(&self, endian: Endian, length: Option<usize>) -> Vec<u8> {
        if self.is_zero() {
            let len = length.unwrap_or(0);
            return vec![0u8; len];
        }

        // First produce big-endian bytes (natural order)
        let mut be_bytes = Vec::new();
        let limbs = self.limbs.as_slice();

        for &limb in limbs.iter().rev() {
            be_bytes.extend_from_slice(&limb.to_be_bytes());
        }

        // Strip leading zeros
        let start = be_bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(be_bytes.len());
        let be_bytes = &be_bytes[start..];

        let actual_len = be_bytes.len();
        let target_len = length.unwrap_or(actual_len);

        // Build output at target_len in big-endian
        let mut result = vec![0u8; target_len];
        let copy_len = actual_len.min(target_len);
        // Right-align in big-endian
        let offset = target_len.saturating_sub(actual_len);
        result[offset..offset + copy_len].copy_from_slice(&be_bytes[..copy_len]);

        match endian {
            Endian::Big => result,
            Endian::Little => {
                result.reverse();
                result
            }
        }
    }

    /// Convert to bytes (alias for to_array with Big endian, no padding).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_array(Endian::Big, None)
    }

    // -- Comparison methods -------------------------------------------------

    /// Compare two BigNumbers.
    /// Returns -1 if self < other, 0 if equal, 1 if self > other.
    #[allow(clippy::should_implement_trait)]
    pub fn cmp(&self, other: &BigNumber) -> i32 {
        // Handle sign differences
        if self.negative && !other.negative {
            if self.is_zero() && other.is_zero() {
                return 0;
            }
            return -1;
        }
        if !self.negative && other.negative {
            if self.is_zero() && other.is_zero() {
                return 0;
            }
            return 1;
        }

        // Same sign: compare magnitudes
        let mag_cmp = self.ucmp(other);
        if self.negative {
            -mag_cmp // Negative numbers: larger magnitude means smaller value
        } else {
            mag_cmp
        }
    }

    /// Compare unsigned magnitudes.
    /// Returns -1 if |self| < |other|, 0 if equal, 1 if |self| > |other|.
    pub fn ucmp(&self, other: &BigNumber) -> i32 {
        let a = self.limbs.as_slice();
        let b = other.limbs.as_slice();

        if a.len() != b.len() {
            return if a.len() < b.len() { -1 } else { 1 };
        }

        // Same number of limbs: compare from most significant
        for i in (0..a.len()).rev() {
            if a[i] < b[i] {
                return -1;
            }
            if a[i] > b[i] {
                return 1;
            }
        }
        0
    }

    /// Compare with a small number.
    pub fn cmpn(&self, n: i64) -> i32 {
        let other = BigNumber::from_number(n);
        self.cmp(&other)
    }

    /// Compare greater than with small number.
    pub fn gtn(&self, n: i64) -> bool {
        self.cmpn(n) > 0
    }

    /// Compare less than with small number.
    pub fn ltn(&self, n: i64) -> bool {
        self.cmpn(n) < 0
    }

    /// Check equality with small number.
    pub fn eqn(&self, n: i64) -> bool {
        self.cmpn(n) == 0
    }

    // -- Property methods ---------------------------------------------------

    /// Returns true if this BigNumber represents zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// Returns true if this BigNumber is odd.
    pub fn is_odd(&self) -> bool {
        if self.is_zero() {
            return false;
        }
        (self.limbs.get(0) & 1) == 1
    }

    /// Returns true if this BigNumber is even.
    pub fn is_even(&self) -> bool {
        !self.is_odd()
    }

    /// Returns true if this BigNumber is negative.
    pub fn is_negative(&self) -> bool {
        self.negative && !self.is_zero()
    }

    /// Returns true if this BigNumber is negative (alias for is_negative).
    pub fn is_neg(&self) -> bool {
        self.is_negative()
    }

    /// Returns true if this BigNumber equals 1.
    pub fn is_one(&self) -> bool {
        !self.negative && self.limbs.len() == 1 && self.limbs.get(0) == 1
    }

    /// Number of bits needed to represent the magnitude.
    pub fn bit_length(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let limbs = self.limbs.as_slice();
        let top_limb = limbs[limbs.len() - 1];
        let top_bits = 64 - top_limb.leading_zeros() as usize;
        (limbs.len() - 1) * 64 + top_bits
    }

    /// Number of bytes needed to represent the magnitude.
    pub fn byte_length(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        self.bit_length().div_ceil(8)
    }

    /// Return the low bits masked by `mask` (mask is a bit count).
    /// Returns the value of (self & ((1 << mask) - 1)) as a u32.
    pub fn andln(&self, mask: u32) -> u32 {
        if self.is_zero() || mask == 0 {
            return 0;
        }
        let low = self.limbs.get(0);
        let m = if mask >= 32 {
            u32::MAX
        } else {
            (1u32 << mask) - 1
        };
        (low as u32) & m
    }

    /// Test whether bit at position `bit` is set.
    pub fn testn(&self, bit: usize) -> bool {
        if self.is_zero() {
            return false;
        }
        let limb_index = bit / 64;
        let bit_index = bit % 64;
        let limb = self.limbs.get(limb_index);
        (limb >> bit_index) & 1 == 1
    }

    /// Returns the number of trailing zero bits.
    pub fn zero_bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let limbs = self.limbs.as_slice();
        let mut count = 0;
        for &limb in limbs {
            if limb == 0 {
                count += 64;
            } else {
                count += limb.trailing_zeros() as usize;
                break;
            }
        }
        count
    }

    /// Whether SmallLimbs is using inline storage (for testing).
    pub fn is_inline(&self) -> bool {
        self.limbs.is_inline()
    }

    /// Get a reference to the internal limbs as a slice (little-endian).
    /// Used by sibling modules for optimized operations on raw limb data.
    pub fn get_limbs(&self) -> &[u64] {
        self.limbs.as_slice()
    }

    /// Construct a BigNumber from a slice of u64 limbs (little-endian, unsigned).
    /// Used by sibling modules for optimized operations that produce limb arrays.
    pub fn from_raw_limbs(limbs: &[u64]) -> BigNumber {
        BigNumber {
            limbs: SmallLimbs::from_limbs(limbs),
            negative: false,
            red: None,
        }
    }

    // -- Sign manipulation --------------------------------------------------

    /// Negate this BigNumber (return new).
    pub fn neg(&self) -> BigNumber {
        let mut r = self.clone();
        if !r.is_zero() {
            r.negative = !r.negative;
        }
        r
    }

    /// In-place negation.
    pub fn ineg(&mut self) -> &mut Self {
        if !self.is_zero() {
            self.negative = !self.negative;
        }
        self
    }

    /// Absolute value (return new).
    pub fn abs(&self) -> BigNumber {
        let mut r = self.clone();
        r.negative = false;
        r
    }

    // -- Conversion to number -----------------------------------------------

    /// Convert to i64 if the value fits. Returns None otherwise.
    pub fn to_number(&self) -> Option<i64> {
        if self.is_zero() {
            return Some(0);
        }
        if self.limbs.len() > 1 {
            return None;
        }
        let val = self.limbs.get(0);
        if self.negative {
            // i64::MIN magnitude is 2^63 which fits in u64
            if val > (i64::MAX as u64) + 1 {
                None
            } else {
                Some(-(val as i64))
            }
        } else if val > i64::MAX as u64 {
            None
        } else {
            Some(val as i64)
        }
    }

    // -- Script number encoding/decoding ------------------------------------

    /// Encode this BigNumber as a Bitcoin script number (signed-magnitude
    /// little-endian encoding).
    ///
    /// Zero encodes as an empty byte vector.
    /// Positive values use little-endian; if the MSB of the last byte is >= 0x80
    /// an extra 0x00 byte is appended to distinguish from negative.
    /// Negative values set the MSB of the last byte to 0x80.
    pub fn to_script_num(&self) -> Vec<u8> {
        if self.is_zero() {
            return Vec::new();
        }

        // Get the absolute value as big-endian bytes, then reverse to little-endian
        let abs_val = self.abs();
        let be_bytes = abs_val.to_array(Endian::Big, None);
        let mut le_bytes: Vec<u8> = be_bytes.into_iter().rev().collect();

        // If the MSB of the last byte has bit 0x80 set, we need an extra byte
        // for the sign.
        if let Some(&last) = le_bytes.last() {
            if last & 0x80 != 0 {
                // Append sign byte
                if self.negative {
                    le_bytes.push(0x80);
                } else {
                    le_bytes.push(0x00);
                }
            } else if self.negative {
                // Set the sign bit on the last byte
                let len = le_bytes.len();
                le_bytes[len - 1] |= 0x80;
            }
        }

        le_bytes
    }

    /// Decode a Bitcoin script number (signed-magnitude little-endian) into a
    /// BigNumber.
    ///
    /// - Empty bytes decode to zero.
    /// - If `require_minimal` is true, non-minimally-encoded values are rejected
    ///   (leading zero bytes that are not sign extension, or negative zero).
    /// - If `max_len` is provided, rejects inputs longer than that.
    pub fn from_script_num(
        bytes: &[u8],
        require_minimal: bool,
        max_len: Option<usize>,
    ) -> Result<BigNumber, PrimitivesError> {
        if let Some(max) = max_len {
            if bytes.len() > max {
                return Err(PrimitivesError::InvalidLength(format!(
                    "script number too long: {} > {}",
                    bytes.len(),
                    max
                )));
            }
        }

        if bytes.is_empty() {
            return Ok(BigNumber::zero());
        }

        if require_minimal {
            // Check for negative zero: single byte 0x80
            // or more generally, the last byte is 0x80 and all preceding bytes
            // are zero (that would be negative zero).
            let last = bytes[bytes.len() - 1];
            if last == 0x80 && bytes[..bytes.len() - 1].iter().all(|&b| b == 0) {
                return Err(PrimitivesError::InvalidFormat(
                    "non-minimal script number: negative zero".to_string(),
                ));
            }
            // Check for non-minimal encoding: if the last byte is 0x00 or 0x80,
            // and the second-to-last byte does NOT have the 0x80 bit set,
            // then the encoding is non-minimal (unnecessary sign extension byte).
            if bytes.len() > 1 {
                let last = bytes[bytes.len() - 1];
                let second_last = bytes[bytes.len() - 2];
                if (last == 0x00 || last == 0x80) && (second_last & 0x80 == 0) {
                    return Err(PrimitivesError::InvalidFormat(
                        "non-minimal script number encoding".to_string(),
                    ));
                }
            }
        }

        // Determine sign from MSB of last byte
        let last = bytes[bytes.len() - 1];
        let is_negative = last & 0x80 != 0;

        // Strip sign bit and convert to magnitude
        let mut le_bytes = bytes.to_vec();
        let len = le_bytes.len();
        le_bytes[len - 1] &= 0x7f;

        // Convert from little-endian to BigNumber
        // Reverse to get big-endian
        le_bytes.reverse();

        // Strip leading zeros
        let start = le_bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(le_bytes.len());

        if start == le_bytes.len() {
            return Ok(BigNumber::zero());
        }

        let mut result = BigNumber::from_bytes(&le_bytes[start..], Endian::Big);
        result.negative = is_negative;
        Ok(result)
    }

    // -- Strip helper -------------------------------------------------------

    /// Re-canonicalize limbs (strip leading zeros).
    pub fn strip(&mut self) -> &mut Self {
        let limbs_vec = self.limbs.to_vec();
        self.limbs = SmallLimbs::from_limbs(&limbs_vec);
        if self.is_zero() {
            self.negative = false;
        }
        self
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl std::fmt::Display for BigNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl PartialEq for BigNumber {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == 0
    }
}

impl Eq for BigNumber {}

impl PartialOrd for BigNumber {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for BigNumber {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cmp_ord(other)
    }
}

impl BigNumber {
    fn cmp_ord(&self, other: &Self) -> std::cmp::Ordering {
        match BigNumber::cmp(self, other) {
            -1 => std::cmp::Ordering::Less,
            0 => std::cmp::Ordering::Equal,
            _ => std::cmp::Ordering::Greater,
        }
    }
}

// ---------------------------------------------------------------------------
// Arithmetic operations
// ---------------------------------------------------------------------------

impl BigNumber {
    // -- Addition -----------------------------------------------------------

    /// Add two BigNumbers, returning a new BigNumber.
    pub fn add(&self, other: &BigNumber) -> BigNumber {
        // If signs differ, this is actually subtraction
        if self.negative != other.negative {
            if self.negative {
                // -a + b = b - a
                let a_abs = self.abs();
                return other.sub_unsigned(&a_abs, other.ucmp(&a_abs));
            } else {
                // a + (-b) = a - b
                let b_abs = other.abs();
                return self.sub_unsigned(&b_abs, self.ucmp(&b_abs));
            }
        }

        // Same sign: add magnitudes
        let result_limbs = add_magnitudes(self.limbs.as_slice(), other.limbs.as_slice());
        BigNumber {
            limbs: SmallLimbs::from_limbs(&result_limbs),
            negative: self.negative, // both have same sign
            red: None,
        }
    }

    /// In-place add.
    pub fn iadd(&mut self, other: &BigNumber) -> &mut Self {
        let result = self.add(other);
        self.limbs = result.limbs;
        self.negative = result.negative;
        self
    }

    /// Add a small number.
    pub fn addn(&self, n: i64) -> BigNumber {
        let other = BigNumber::from_number(n);
        self.add(&other)
    }

    /// In-place add small number.
    pub fn iaddn(&mut self, n: i64) -> &mut Self {
        let other = BigNumber::from_number(n);
        let result = self.add(&other);
        self.limbs = result.limbs;
        self.negative = result.negative;
        self
    }

    // -- Subtraction --------------------------------------------------------

    /// Subtract other from self, returning a new BigNumber.
    pub fn sub(&self, other: &BigNumber) -> BigNumber {
        // a - b = a + (-b)
        let neg_other = other.neg();
        self.add(&neg_other)
    }

    /// In-place subtraction.
    pub fn isub(&mut self, other: &BigNumber) -> &mut Self {
        let result = self.sub(other);
        self.limbs = result.limbs;
        self.negative = result.negative;
        self
    }

    /// Subtract a small number.
    pub fn subn(&self, n: i64) -> BigNumber {
        let other = BigNumber::from_number(n);
        self.sub(&other)
    }

    /// In-place subtract small number.
    pub fn isubn(&mut self, n: i64) -> &mut Self {
        let other = BigNumber::from_number(n);
        let result = self.sub(&other);
        self.limbs = result.limbs;
        self.negative = result.negative;
        self
    }

    /// Helper: subtract magnitudes. `cmp_result` is ucmp(self, other).
    fn sub_unsigned(&self, other: &BigNumber, cmp_result: i32) -> BigNumber {
        if cmp_result == 0 {
            return BigNumber::zero();
        }

        let (larger, smaller, neg) = if cmp_result > 0 {
            (self.limbs.as_slice(), other.limbs.as_slice(), self.negative)
        } else {
            (
                other.limbs.as_slice(),
                self.limbs.as_slice(),
                !self.negative,
            )
        };

        let result_limbs = sub_magnitudes(larger, smaller);
        let mut result = BigNumber {
            limbs: SmallLimbs::from_limbs(&result_limbs),
            negative: neg,
            red: None,
        };
        if result.is_zero() {
            result.negative = false;
        }
        result
    }

    // -- Multiplication -----------------------------------------------------

    /// Multiply two BigNumbers, returning a new BigNumber.
    pub fn mul(&self, other: &BigNumber) -> BigNumber {
        if self.is_zero() || other.is_zero() {
            return BigNumber::zero();
        }

        let result_limbs = mul_magnitudes(self.limbs.as_slice(), other.limbs.as_slice());
        let negative = self.negative != other.negative;

        BigNumber {
            limbs: SmallLimbs::from_limbs(&result_limbs),
            negative,
            red: None,
        }
    }

    /// In-place multiplication.
    pub fn imul(&mut self, other: &BigNumber) -> &mut Self {
        let result = self.mul(other);
        self.limbs = result.limbs;
        self.negative = result.negative;
        self.red = None;
        self
    }

    /// Multiply by a small number in-place.
    pub fn imuln(&mut self, n: i64) -> &mut Self {
        let other = BigNumber::from_number(n);
        let result = self.mul(&other);
        self.limbs = result.limbs;
        self.negative = result.negative;
        self
    }

    /// Multiply by a small number.
    pub fn muln(&self, n: i64) -> BigNumber {
        let mut r = self.clone();
        r.imuln(n);
        r
    }

    /// Square (self * self).
    /// Uses dedicated sqr_4x4 for 4-limb inputs to exploit symmetry.
    pub fn sqr(&self) -> BigNumber {
        let limbs = self.limbs.as_slice();
        if limbs.len() == 4 {
            let a4: [u64; 4] = [limbs[0], limbs[1], limbs[2], limbs[3]];
            let result_limbs = sqr_4x4(&a4);
            return BigNumber {
                limbs: SmallLimbs::from_limbs(&result_limbs),
                negative: false, // square is always positive
                red: None,
            };
        }
        self.mul(self)
    }

    /// In-place square.
    pub fn isqr(&mut self) -> &mut Self {
        let sq = self.sqr();
        self.limbs = sq.limbs;
        self.negative = sq.negative;
        self.red = None;
        self
    }

    /// Exponentiation: self^exp.
    pub fn pow(&self, exp: &BigNumber) -> BigNumber {
        if exp.is_zero() {
            return BigNumber::one();
        }
        if self.is_zero() {
            return BigNumber::zero();
        }

        let mut result = BigNumber::one();
        let mut base = self.abs();
        let base_neg = self.is_neg();
        let exp_odd = exp.is_odd();
        let mut e = exp.clone();

        while !e.is_zero() {
            if e.is_odd() {
                result = result.mul(&base);
            }
            base = base.sqr();
            e.iushrn(1);
        }

        if base_neg && exp_odd {
            result.negative = true;
        }
        result
    }

    // -- Division and modulo ------------------------------------------------

    /// Divide self by other, returning (quotient, remainder).
    /// Both operands are treated as unsigned for the division.
    /// Signs are handled separately.
    pub fn div_mod(&self, other: &BigNumber) -> Result<(BigNumber, BigNumber), PrimitivesError> {
        if other.is_zero() {
            return Err(PrimitivesError::DivisionByZero);
        }

        if self.is_zero() {
            return Ok((BigNumber::zero(), BigNumber::zero()));
        }

        let cmp = self.ucmp(other);
        if cmp < 0 {
            // |self| < |other|: quotient=0, remainder=self (with sign)
            return Ok((BigNumber::zero(), self.abs()));
        }
        if cmp == 0 {
            let mut q = BigNumber::one();
            q.negative = self.negative != other.negative;
            if q.negative && q.is_zero() {
                q.negative = false;
            }
            return Ok((q, BigNumber::zero()));
        }

        // Long division
        let (q, r) = div_mod_unsigned(self.limbs.as_slice(), other.limbs.as_slice());

        let mut quotient = BigNumber {
            limbs: SmallLimbs::from_limbs(&q),
            negative: self.negative != other.negative,
            red: None,
        };
        let remainder = BigNumber {
            limbs: SmallLimbs::from_limbs(&r),
            negative: false,
            red: None,
        };

        if quotient.is_zero() {
            quotient.negative = false;
        }

        Ok((quotient, remainder))
    }

    /// Division (truncated toward zero).
    pub fn div(&self, other: &BigNumber) -> Result<BigNumber, PrimitivesError> {
        let (q, _) = self.div_mod(other)?;
        Ok(q)
    }

    /// Unsigned modulo (always returns non-negative result).
    pub fn umod(&self, other: &BigNumber) -> Result<BigNumber, PrimitivesError> {
        let (_, mut r) = self.div_mod(other)?;
        if self.negative && !r.is_zero() {
            r = other.abs().sub(&r);
        }
        r.negative = false;
        Ok(r)
    }

    /// Alias for umod.
    pub fn r#mod(&self, other: &BigNumber) -> Result<BigNumber, PrimitivesError> {
        self.umod(other)
    }

    // -- Shift operations ---------------------------------------------------

    /// Unsigned shift left by `bits` positions.
    pub fn ushln(&self, bits: usize) -> BigNumber {
        if self.is_zero() || bits == 0 {
            return self.clone();
        }

        let limb_shift = bits / 64;
        let bit_shift = bits % 64;

        let old_limbs = self.limbs.as_slice();
        let new_len = old_limbs.len() + limb_shift + if bit_shift > 0 { 1 } else { 0 };
        let mut new_limbs = vec![0u64; new_len];

        if bit_shift == 0 {
            for (i, &v) in old_limbs.iter().enumerate() {
                new_limbs[i + limb_shift] = v;
            }
        } else {
            let mut carry = 0u64;
            for (i, &v) in old_limbs.iter().enumerate() {
                new_limbs[i + limb_shift] = (v << bit_shift) | carry;
                carry = v >> (64 - bit_shift);
            }
            if carry > 0 {
                new_limbs[old_limbs.len() + limb_shift] = carry;
            }
        }

        BigNumber {
            limbs: SmallLimbs::from_limbs(&new_limbs),
            negative: self.negative,
            red: None,
        }
    }

    /// In-place unsigned shift left.
    pub fn iushln(&mut self, bits: usize) -> &mut Self {
        let result = self.ushln(bits);
        self.limbs = result.limbs;
        self
    }

    /// Unsigned shift right by `bits` positions.
    pub fn ushrn(&self, bits: usize) -> BigNumber {
        if self.is_zero() || bits == 0 {
            return self.clone();
        }

        let limb_shift = bits / 64;
        let bit_shift = bits % 64;

        let old_limbs = self.limbs.as_slice();
        if limb_shift >= old_limbs.len() {
            return BigNumber::zero();
        }

        let new_len = old_limbs.len() - limb_shift;
        let mut new_limbs = vec![0u64; new_len];

        if bit_shift == 0 {
            new_limbs[..new_len].copy_from_slice(&old_limbs[limb_shift..(new_len + limb_shift)]);
        } else {
            for i in 0..new_len {
                let current = old_limbs[i + limb_shift] >> bit_shift;
                let next = if i + limb_shift + 1 < old_limbs.len() {
                    old_limbs[i + limb_shift + 1] << (64 - bit_shift)
                } else {
                    0
                };
                new_limbs[i] = current | next;
            }
        }

        let mut result = BigNumber {
            limbs: SmallLimbs::from_limbs(&new_limbs),
            negative: self.negative,
            red: None,
        };
        if result.is_zero() {
            result.negative = false;
        }
        result
    }

    /// In-place unsigned shift right.
    pub fn iushrn(&mut self, bits: usize) -> &mut Self {
        let result = self.ushrn(bits);
        self.limbs = result.limbs;
        self.negative = result.negative;
        self
    }

    /// Unsigned shift right with remainder output.
    /// Returns the bits that were shifted out as a separate BigNumber.
    pub fn iushrn_with_remainder(&mut self, bits: usize) -> BigNumber {
        // Extract the low `bits` before shifting
        let remainder = self.maskn(bits);
        self.iushrn(bits);
        remainder
    }

    // -- Bitwise operations -------------------------------------------------

    /// Retain only the bottom `n` bits.
    pub fn maskn(&self, n: usize) -> BigNumber {
        if self.is_zero() || n == 0 {
            return BigNumber::zero();
        }

        if n >= self.bit_length() {
            return self.clone();
        }

        let limb_count = n.div_ceil(64);
        let bit_remainder = n % 64;
        let old_limbs = self.limbs.as_slice();

        let mut new_limbs = vec![0u64; limb_count];
        let copy_len = limb_count.min(old_limbs.len());
        new_limbs[..copy_len].copy_from_slice(&old_limbs[..copy_len]);

        // Mask the top limb
        if bit_remainder > 0 && limb_count > 0 {
            new_limbs[limb_count - 1] &= (1u64 << bit_remainder) - 1;
        }

        BigNumber {
            limbs: SmallLimbs::from_limbs(&new_limbs),
            negative: false,
            red: None,
        }
    }

    /// In-place maskn.
    pub fn imaskn(&mut self, n: usize) -> &mut Self {
        let result = self.maskn(n);
        self.limbs = result.limbs;
        self.negative = false;
        self
    }

    // -- GCD and modular inverse --------------------------------------------

    /// Greatest common divisor.
    pub fn gcd(&self, other: &BigNumber) -> BigNumber {
        let mut a = self.abs();
        let mut b = other.abs();

        if a.is_zero() {
            return b;
        }
        if b.is_zero() {
            return a;
        }

        // Binary GCD algorithm
        let shift_a = a.zero_bits();
        let shift_b = b.zero_bits();
        let shift = shift_a.min(shift_b);

        a.iushrn(shift_a);
        b.iushrn(shift_b);

        loop {
            // Both are odd now
            let c = a.ucmp(&b);
            if c == 0 {
                return a.ushln(shift);
            }

            if c < 0 {
                std::mem::swap(&mut a, &mut b);
            }

            a = a.sub(&b);
            a.iushrn(a.zero_bits());
        }
    }

    /// Extended GCD: returns (gcd, x, y) such that a*x + b*y = gcd.
    pub fn egcd(&self, other: &BigNumber) -> (BigNumber, BigNumber, BigNumber) {
        let a = self.abs();
        let b = other.abs();

        if a.is_zero() {
            return (b, BigNumber::zero(), BigNumber::one());
        }
        if b.is_zero() {
            return (a, BigNumber::one(), BigNumber::zero());
        }

        // Extended Euclidean algorithm
        let mut old_r = a;
        let mut r = b;
        let mut old_s = BigNumber::one();
        let mut s = BigNumber::zero();
        let mut old_t = BigNumber::zero();
        let mut t = BigNumber::one();

        while !r.is_zero() {
            let q = old_r.div(&r).unwrap_or_else(|_| BigNumber::zero());
            let new_r = old_r.sub(&q.mul(&r));
            old_r = r;
            r = new_r;

            let new_s = old_s.sub(&q.mul(&s));
            old_s = s;
            s = new_s;

            let new_t = old_t.sub(&q.mul(&t));
            old_t = t;
            t = new_t;
        }

        (old_r, old_s, old_t)
    }

    /// Modular multiplicative inverse: find x such that self * x === 1 (mod m).
    pub fn invm(&self, m: &BigNumber) -> Result<BigNumber, PrimitivesError> {
        if m.is_zero() || m.is_one() {
            return Err(PrimitivesError::ArithmeticError(
                "modulus must be greater than 1".to_string(),
            ));
        }

        let a = self.umod(m)?;
        if a.is_zero() {
            return Err(PrimitivesError::ArithmeticError(
                "no inverse for zero".to_string(),
            ));
        }

        // Extended Euclidean on a and m
        let (gcd, x, _) = a.egcd(m);
        if !gcd.is_one() {
            return Err(PrimitivesError::ArithmeticError(
                "no modular inverse exists (gcd != 1)".to_string(),
            ));
        }

        // x might be negative; normalize to [0, m)
        let result = x.umod(m)?;
        Ok(result)
    }

    /// Modular multiplicative inverse using binary method (_invmp in TS).
    pub fn _invmp(&self, m: &BigNumber) -> Result<BigNumber, PrimitivesError> {
        self.invm(m)
    }

    // -- Reduction context operations ---------------------------------------

    /// Enter a reduction context.
    pub fn to_red(&self, ctx: Arc<ReductionContext>) -> BigNumber {
        let reduced = ctx.convert_to(self);
        let mut r = reduced;
        r.red = Some(ctx);
        r
    }

    /// Force entry into a reduction context (skip reduction).
    pub fn force_red(&self, ctx: Arc<ReductionContext>) -> BigNumber {
        let mut r = self.clone();
        r.red = Some(ctx);
        r
    }

    /// Exit reduction context.
    pub fn from_red(&self) -> BigNumber {
        let mut r = self.clone();
        r.red = None;
        r
    }

    // Red-mode arithmetic helpers
    pub fn red_add(&self, other: &BigNumber) -> Result<BigNumber, PrimitivesError> {
        let ctx = self.red.as_ref().ok_or_else(|| {
            PrimitivesError::ArithmeticError("red_add requires reduction context".to_string())
        })?;
        Ok(ctx.add(self, other))
    }

    pub fn red_iadd(&mut self, other: &BigNumber) -> Result<&mut Self, PrimitivesError> {
        let ctx = self
            .red
            .as_ref()
            .ok_or_else(|| {
                PrimitivesError::ArithmeticError("red_iadd requires reduction context".to_string())
            })?
            .clone();
        let result = ctx.add(self, other);
        self.limbs = result.limbs;
        self.negative = result.negative;
        Ok(self)
    }

    pub fn red_sub(&self, other: &BigNumber) -> Result<BigNumber, PrimitivesError> {
        let ctx = self.red.as_ref().ok_or_else(|| {
            PrimitivesError::ArithmeticError("red_sub requires reduction context".to_string())
        })?;
        Ok(ctx.sub(self, other))
    }

    pub fn red_mul(&self, other: &BigNumber) -> Result<BigNumber, PrimitivesError> {
        let ctx = self.red.as_ref().ok_or_else(|| {
            PrimitivesError::ArithmeticError("red_mul requires reduction context".to_string())
        })?;
        Ok(ctx.mul(self, other))
    }

    pub fn red_sqr(&self) -> Result<BigNumber, PrimitivesError> {
        let ctx = self.red.as_ref().ok_or_else(|| {
            PrimitivesError::ArithmeticError("red_sqr requires reduction context".to_string())
        })?;
        Ok(ctx.sqr(self))
    }

    pub fn red_neg(&self) -> Result<BigNumber, PrimitivesError> {
        let ctx = self.red.as_ref().ok_or_else(|| {
            PrimitivesError::ArithmeticError("red_neg requires reduction context".to_string())
        })?;
        Ok(ctx.neg(self))
    }

    pub fn red_invm(&self) -> Result<BigNumber, PrimitivesError> {
        let ctx = self.red.as_ref().ok_or_else(|| {
            PrimitivesError::ArithmeticError("red_invm requires reduction context".to_string())
        })?;
        Ok(ctx.invm(self))
    }

    pub fn red_pow(&self, exp: &BigNumber) -> Result<BigNumber, PrimitivesError> {
        let ctx = self.red.as_ref().ok_or_else(|| {
            PrimitivesError::ArithmeticError("red_pow requires reduction context".to_string())
        })?;
        Ok(ctx.pow(self, exp))
    }

    pub fn red_sqrt(&self) -> Result<BigNumber, PrimitivesError> {
        let ctx = self.red.as_ref().ok_or_else(|| {
            PrimitivesError::ArithmeticError("red_sqrt requires reduction context".to_string())
        })?;
        Ok(ctx.sqrt(self))
    }

    /// Copy values from src into self.
    pub fn copy_from(&mut self, src: &BigNumber) {
        self.limbs = src.limbs.clone();
        self.negative = src.negative;
        self.red = src.red.clone();
    }

    /// Move values from src into dest (static version).
    pub fn move_to(dest: &mut BigNumber, src: &BigNumber) {
        dest.copy_from(src);
    }

    /// Set a specific bit.
    pub fn setn(&mut self, bit: usize, val: bool) -> &mut Self {
        let limb_index = bit / 64;
        let bit_index = bit % 64;

        // Ensure we have enough limbs
        let mut limbs_vec = self.limbs.to_vec();
        while limbs_vec.len() <= limb_index {
            limbs_vec.push(0);
        }

        if val {
            limbs_vec[limb_index] |= 1u64 << bit_index;
        } else {
            limbs_vec[limb_index] &= !(1u64 << bit_index);
        }

        self.limbs = SmallLimbs::from_limbs(&limbs_vec);
        self
    }

    /// Bitwise NOT for `width` bits.
    pub fn notn(&self, width: usize) -> BigNumber {
        let mut r = self.clone();
        r.inotn(width);
        r
    }

    /// In-place bitwise NOT for `width` bits.
    pub fn inotn(&mut self, width: usize) -> &mut Self {
        if width == 0 {
            self.limbs = SmallLimbs::zero();
            self.negative = false;
            return self;
        }

        let full_limbs = width / 64;
        let remaining_bits = width % 64;
        let total_limbs = full_limbs + if remaining_bits > 0 { 1 } else { 0 };

        let mut limbs_vec = self.limbs.to_vec();
        while limbs_vec.len() < total_limbs {
            limbs_vec.push(0);
        }

        for limb in limbs_vec.iter_mut().take(full_limbs) {
            *limb = !*limb;
        }
        if remaining_bits > 0 {
            let mask = (1u64 << remaining_bits) - 1;
            limbs_vec[full_limbs] = (!limbs_vec[full_limbs]) & mask;
        }
        // Zero out any limbs beyond width
        for limb in limbs_vec.iter_mut().skip(total_limbs) {
            *limb = 0;
        }

        self.limbs = SmallLimbs::from_limbs(&limbs_vec);
        self.negative = false;
        self
    }

    /// Expand nominal word length (no-op in Rust, but needed for API compat).
    pub fn expand(&mut self, _size: usize) -> &mut Self {
        self
    }

    /// Convert to two's complement representation.
    pub fn to_twos(&self, width: usize) -> BigNumber {
        if !self.is_neg() {
            return self.maskn(width);
        }
        // For negative: 2^width + self
        let mut pow_val = BigNumber::one();
        pow_val.iushln(width);
        pow_val.iadd(self);
        pow_val.maskn(width)
    }

    /// Convert from two's complement.
    pub fn from_twos(&self, width: usize) -> BigNumber {
        if width == 0 {
            return self.clone();
        }
        if !self.testn(width - 1) {
            return self.clone();
        }
        // Negative: self - 2^width
        let mut pow_val = BigNumber::one();
        pow_val.iushln(width);
        self.sub(&pow_val)
    }
}

// ---------------------------------------------------------------------------
// Low-level magnitude arithmetic (unsigned, limb-level)
// ---------------------------------------------------------------------------

/// Add two unsigned magnitude arrays (little-endian limb order).
fn add_magnitudes(a: &[u64], b: &[u64]) -> Vec<u64> {
    let max_len = a.len().max(b.len());
    let mut result = Vec::with_capacity(max_len + 1);
    let mut carry: u64 = 0;

    for i in 0..max_len {
        let av = if i < a.len() { a[i] } else { 0 };
        let bv = if i < b.len() { b[i] } else { 0 };
        let (sum1, c1) = av.overflowing_add(bv);
        let (sum2, c2) = sum1.overflowing_add(carry);
        result.push(sum2);
        carry = (c1 as u64) + (c2 as u64);
    }

    if carry > 0 {
        result.push(carry);
    }

    result
}

/// Subtract smaller magnitude from larger (|a| >= |b|).
fn sub_magnitudes(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut result = Vec::with_capacity(a.len());
    let mut borrow: u64 = 0;

    for i in 0..a.len() {
        let av = a[i];
        let bv = if i < b.len() { b[i] } else { 0 };
        let (diff1, c1) = av.overflowing_sub(bv);
        let (diff2, c2) = diff1.overflowing_sub(borrow);
        result.push(diff2);
        borrow = (c1 as u64) + (c2 as u64);
    }

    result
}

/// Schoolbook 2x2 multiplication: two 2-limb values -> 4-limb result.
/// All values are little-endian (least-significant limb first).
/// Uses standard schoolbook with accumulator to avoid u128 overflow.
#[inline(always)]
fn mul_2x2(a: &[u64; 2], b: &[u64; 2]) -> [u64; 4] {
    let mut result = [0u64; 4];
    for i in 0..2 {
        let mut carry: u128 = 0;
        for j in 0..2 {
            let prod = (a[i] as u128) * (b[j] as u128) + (result[i + j] as u128) + carry;
            result[i + j] = prod as u64;
            carry = prod >> 64;
        }
        result[i + 2] = carry as u64;
    }
    result
}

/// Karatsuba 4x4 multiplication: two 4-limb values -> 8-limb result on the stack.
/// Splits each 4-limb input into two 2-limb halves and uses Karatsuba's identity:
/// z0 = lo_a * lo_b, z2 = hi_a * hi_b, z1 = (lo_a + hi_a)(lo_b + hi_b) - z0 - z2
#[inline]
pub(crate) fn mul_4x4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let a_lo = [a[0], a[1]];
    let a_hi = [a[2], a[3]];
    let b_lo = [b[0], b[1]];
    let b_hi = [b[2], b[3]];

    let z0 = mul_2x2(&a_lo, &b_lo); // 4 limbs
    let z2 = mul_2x2(&a_hi, &b_hi); // 4 limbs

    // (a_lo + a_hi) and (b_lo + b_hi) -- each sum can be up to 3 limbs (65 bits max per position)
    let a_sum_0 = (a_lo[0] as u128) + (a_hi[0] as u128);
    let a_sum_1 = (a_lo[1] as u128) + (a_hi[1] as u128) + (a_sum_0 >> 64);
    let a_sum_2 = a_sum_1 >> 64;
    let a_sum = [a_sum_0 as u64, a_sum_1 as u64, a_sum_2 as u64];

    let b_sum_0 = (b_lo[0] as u128) + (b_hi[0] as u128);
    let b_sum_1 = (b_lo[1] as u128) + (b_hi[1] as u128) + (b_sum_0 >> 64);
    let b_sum_2 = b_sum_1 >> 64;
    let b_sum = [b_sum_0 as u64, b_sum_1 as u64, b_sum_2 as u64];

    // z1_full = a_sum * b_sum (3x3 schoolbook -> 6 limbs max)
    let mut z1_full = [0u64; 6];
    for i in 0..3 {
        let mut carry: u128 = 0;
        for j in 0..3 {
            let prod = (a_sum[i] as u128) * (b_sum[j] as u128) + (z1_full[i + j] as u128) + carry;
            z1_full[i + j] = prod as u64;
            carry = prod >> 64;
        }
        z1_full[i + 3] = carry as u64;
    }

    // z1 = z1_full - z0 - z2 (can go through signed intermediates, but in practice stays positive)
    // Subtract z0 from z1_full
    let mut borrow: u128 = 0;
    for i in 0..4 {
        let a_val = z1_full[i] as u128;
        let b_val = (z0[i] as u128) + borrow;
        if a_val >= b_val {
            z1_full[i] = (a_val - b_val) as u64;
            borrow = 0;
        } else {
            z1_full[i] = (a_val + (1u128 << 64) - b_val) as u64;
            borrow = 1;
        }
    }
    for item in z1_full.iter_mut().skip(4) {
        let a_val = *item as u128;
        if a_val >= borrow {
            *item = (a_val - borrow) as u64;
            borrow = 0;
        } else {
            *item = (a_val + (1u128 << 64) - borrow) as u64;
            borrow = 1;
        }
    }

    // Subtract z2 from z1_full
    borrow = 0;
    for i in 0..4 {
        let a_val = z1_full[i] as u128;
        let b_val = (z2[i] as u128) + borrow;
        if a_val >= b_val {
            z1_full[i] = (a_val - b_val) as u64;
            borrow = 0;
        } else {
            z1_full[i] = (a_val + (1u128 << 64) - b_val) as u64;
            borrow = 1;
        }
    }
    for item in z1_full.iter_mut().skip(4) {
        let a_val = *item as u128;
        if a_val >= borrow {
            *item = (a_val - borrow) as u64;
            borrow = 0;
        } else {
            *item = (a_val + (1u128 << 64) - borrow) as u64;
            borrow = 1;
        }
    }

    // result = z0 + z1 << 128 + z2 << 256
    let mut result = [0u64; 8];

    // Add z0 (limbs 0..3)
    result[0] = z0[0];
    result[1] = z0[1];
    result[2] = z0[2];
    result[3] = z0[3];

    // Add z1 << 128 (shifted by 2 limbs)
    let mut carry: u128 = 0;
    for i in 0..6 {
        let sum = (result[i + 2] as u128) + (z1_full[i] as u128) + carry;
        result[i + 2] = sum as u64;
        carry = sum >> 64;
    }

    // Add z2 << 256 (shifted by 4 limbs)
    carry = 0;
    for i in 0..4 {
        let sum = (result[i + 4] as u128) + (z2[i] as u128) + carry;
        result[i + 4] = sum as u64;
        carry = sum >> 64;
    }

    result
}

/// Dedicated 4-limb squaring: dispatches to mul_4x4(a, a).
/// The Karatsuba mul_4x4 already handles the common path efficiently.
#[inline]
fn sqr_4x4(a: &[u64; 4]) -> [u64; 8] {
    mul_4x4(a, a)
}

/// Multiplication of two magnitude arrays.
/// Dispatches to Karatsuba mul_4x4 for the common 4-limb (256-bit) case.
fn mul_magnitudes(a: &[u64], b: &[u64]) -> Vec<u64> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }

    // Fast path for 4-limb * 4-limb (256-bit operands -- the common case)
    if a.len() == 4 && b.len() == 4 {
        let a4: [u64; 4] = [a[0], a[1], a[2], a[3]];
        let b4: [u64; 4] = [b[0], b[1], b[2], b[3]];
        return mul_4x4(&a4, &b4).to_vec();
    }

    // Use recursive Karatsuba for large numbers, schoolbook for small
    let n = a.len().max(b.len());
    if n <= 32 {
        return schoolbook_mul(a, b);
    }

    karatsuba_mul(a, b)
}

/// Schoolbook O(n*m) multiplication for small operands.
fn schoolbook_mul(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut result = vec![0u64; a.len() + b.len()];
    for i in 0..a.len() {
        let mut carry: u128 = 0;
        for j in 0..b.len() {
            let prod = (a[i] as u128) * (b[j] as u128) + (result[i + j] as u128) + carry;
            result[i + j] = prod as u64;
            carry = prod >> 64;
        }
        if carry > 0 {
            result[i + b.len()] += carry as u64;
        }
    }
    result
}

/// Add slice `b` to slice `a` starting at offset, propagating carry.
/// `a` must be large enough to hold the result.
fn add_at(a: &mut [u64], b: &[u64], offset: usize) {
    let mut carry: u64 = 0;
    for (i, &b_val) in b.iter().enumerate() {
        let pos = offset + i;
        let (sum1, c1) = a[pos].overflowing_add(b_val);
        let (sum2, c2) = sum1.overflowing_add(carry);
        a[pos] = sum2;
        carry = (c1 as u64) + (c2 as u64);
    }
    // Propagate remaining carry
    let mut pos = offset + b.len();
    while carry > 0 && pos < a.len() {
        let (sum, c) = a[pos].overflowing_add(carry);
        a[pos] = sum;
        carry = c as u64;
        pos += 1;
    }
}

/// Subtract slice `b` from slice `a` starting at offset, propagating borrow.
/// Assumes a >= b at that offset (no underflow past MSB).
#[allow(dead_code)]
fn sub_at(a: &mut [u64], b: &[u64], offset: usize) {
    let mut borrow: u64 = 0;
    for (i, &b_val) in b.iter().enumerate() {
        let pos = offset + i;
        let (diff1, b1) = a[pos].overflowing_sub(b_val);
        let (diff2, b2) = diff1.overflowing_sub(borrow);
        a[pos] = diff2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    // Propagate remaining borrow
    let mut pos = offset + b.len();
    while borrow > 0 && pos < a.len() {
        let (diff, b1) = a[pos].overflowing_sub(borrow);
        a[pos] = diff;
        borrow = b1 as u64;
        pos += 1;
    }
}

/// Recursive Karatsuba multiplication.
/// For a and b with n = max(len(a), len(b)):
///   Split at n/2: a = a1*B + a0, b = b1*B + b0
///   z0 = a0 * b0
///   z2 = a1 * b1
///   z1 = (a0+a1)*(b0+b1) - z0 - z2
///   result = z2*B^2 + z1*B + z0
fn karatsuba_mul(a: &[u64], b: &[u64]) -> Vec<u64> {
    let n = a.len().max(b.len());

    // Base case: use schoolbook for small inputs
    if n <= 32 {
        return schoolbook_mul(a, b);
    }

    let half = n / 2;

    // Split a into a0 (low) and a1 (high)
    let (a0, a1) = if a.len() <= half {
        (a, &[][..])
    } else {
        (&a[..half], &a[half..])
    };

    // Split b into b0 (low) and b1 (high)
    let (b0, b1) = if b.len() <= half {
        (b, &[][..])
    } else {
        (&b[..half], &b[half..])
    };

    // z0 = a0 * b0
    let z0 = karatsuba_mul(a0, b0);

    // z2 = a1 * b1
    let z2 = if a1.is_empty() || b1.is_empty() {
        vec![]
    } else {
        karatsuba_mul(a1, b1)
    };

    // sum_a = a0 + a1, sum_b = b0 + b1
    let sum_a = limb_add(a0, a1);
    let sum_b = limb_add(b0, b1);

    // z1_full = sum_a * sum_b
    let z1_full = karatsuba_mul(&sum_a, &sum_b);

    // z1 = z1_full - z0 - z2
    let mut z1 = z1_full;
    limb_sub_inplace(&mut z1, &z0);
    limb_sub_inplace(&mut z1, &z2);

    // result = z2 * B^(2*half) + z1 * B^half + z0
    let result_len = a.len() + b.len();
    let mut result = vec![0u64; result_len];

    // Add z0 at offset 0
    add_at(&mut result, &z0, 0);

    // Add z1 at offset half
    add_at(&mut result, &z1, half);

    // Add z2 at offset 2*half
    if !z2.is_empty() {
        add_at(&mut result, &z2, 2 * half);
    }

    result
}

/// Add two limb slices, returning a new vector.
fn limb_add(a: &[u64], b: &[u64]) -> Vec<u64> {
    let max_len = a.len().max(b.len());
    let mut result = vec![0u64; max_len + 1];
    let mut carry: u64 = 0;
    for i in 0..max_len {
        let av = if i < a.len() { a[i] } else { 0 };
        let bv = if i < b.len() { b[i] } else { 0 };
        let (s1, c1) = av.overflowing_add(bv);
        let (s2, c2) = s1.overflowing_add(carry);
        result[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    if carry > 0 {
        result[max_len] = carry;
    } else {
        result.pop();
    }
    result
}

/// Subtract b from a in place (a must be >= b in unsigned magnitude).
fn limb_sub_inplace(a: &mut [u64], b: &[u64]) {
    let mut borrow: u64 = 0;
    for i in 0..b.len() {
        if i >= a.len() {
            break;
        }
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    let mut pos = b.len();
    while borrow > 0 && pos < a.len() {
        let (d, b1) = a[pos].overflowing_sub(borrow);
        a[pos] = d;
        borrow = b1 as u64;
        pos += 1;
    }
}

/// Long division: returns (quotient, remainder) for unsigned magnitudes.
/// Both arrays are in little-endian limb order.
fn div_mod_unsigned(numerator: &[u64], denominator: &[u64]) -> (Vec<u64>, Vec<u64>) {
    let n_bits = {
        let mut bits = 0;
        for (i, &limb) in numerator.iter().enumerate() {
            if limb != 0 {
                bits = i * 64 + (64 - limb.leading_zeros() as usize);
            }
        }
        bits
    };

    let d_bits = {
        let mut bits = 0;
        for (i, &limb) in denominator.iter().enumerate() {
            if limb != 0 {
                bits = i * 64 + (64 - limb.leading_zeros() as usize);
            }
        }
        bits
    };

    if d_bits == 0 {
        return (vec![], vec![]);
    }

    if n_bits < d_bits {
        return (vec![], numerator.to_vec());
    }

    // Single-limb denominator: fast path
    if denominator.len() == 1 && denominator[0] != 0 {
        let d = denominator[0] as u128;
        let mut quotient = vec![0u64; numerator.len()];
        let mut remainder: u128 = 0;

        for i in (0..numerator.len()).rev() {
            let cur = (remainder << 64) | (numerator[i] as u128);
            quotient[i] = (cur / d) as u64;
            remainder = cur % d;
        }

        return (quotient, vec![remainder as u64]);
    }

    // Multi-limb division: shift-and-subtract (binary long division)
    let shift = n_bits - d_bits;
    let mut remainder = numerator.to_vec();
    let q_limbs = shift / 64 + 1;
    let mut quotient = vec![0u64; q_limbs];

    for i in (0..=shift).rev() {
        let limb_shift = i / 64;
        let bit_shift = i % 64;

        let can_sub = can_subtract_shifted(&remainder, denominator, limb_shift, bit_shift);

        if can_sub {
            quotient[i / 64] |= 1u64 << (i % 64);
            subtract_shifted(&mut remainder, denominator, limb_shift, bit_shift);
        }
    }

    (quotient, remainder)
}

/// Check if `a >= b << shift` where shift = limb_shift * 64 + bit_shift.
fn can_subtract_shifted(a: &[u64], b: &[u64], limb_shift: usize, bit_shift: usize) -> bool {
    let shifted_len = b.len() + limb_shift + 1;

    for i in (0..shifted_len.max(a.len())).rev() {
        let a_val = if i < a.len() { a[i] } else { 0 };
        let b_val = get_shifted_limb(b, limb_shift, bit_shift, i);

        if a_val > b_val {
            return true;
        }
        if a_val < b_val {
            return false;
        }
    }
    true // equal
}

/// Get the limb at position `i` of `b << (limb_shift * 64 + bit_shift)`.
fn get_shifted_limb(b: &[u64], limb_shift: usize, bit_shift: usize, i: usize) -> u64 {
    if i < limb_shift {
        return 0;
    }
    let src_idx = i - limb_shift;
    if bit_shift == 0 {
        if src_idx < b.len() {
            b[src_idx]
        } else {
            0
        }
    } else {
        let lo = if src_idx < b.len() {
            b[src_idx] << bit_shift
        } else {
            0
        };
        let hi = if src_idx > 0 && (src_idx - 1) < b.len() {
            b[src_idx - 1] >> (64 - bit_shift)
        } else {
            0
        };
        lo | hi
    }
}

/// Subtract `b << (limb_shift * 64 + bit_shift)` from `a` in-place.
fn subtract_shifted(a: &mut Vec<u64>, b: &[u64], limb_shift: usize, bit_shift: usize) {
    let shifted_len = b.len() + limb_shift + 1;
    while a.len() < shifted_len {
        a.push(0);
    }

    let mut borrow: u64 = 0;
    for (i, limb) in a.iter_mut().enumerate() {
        let b_val = get_shifted_limb(b, limb_shift, bit_shift, i);
        let (diff1, c1) = limb.overflowing_sub(b_val);
        let (diff2, c2) = diff1.overflowing_sub(borrow);
        *limb = diff2;
        borrow = (c1 as u64) + (c2 as u64);
    }

    // Strip trailing zeros
    while a.len() > 1 && a[a.len() - 1] == 0 {
        a.pop();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Test vector loading ----

    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct ConversionVector {
        hex: String,
        #[serde(default)]
        value: Option<i64>,
        #[serde(default)]
        bytes_be: Option<Vec<u8>>,
        #[serde(default)]
        bytes_le: Option<Vec<u8>>,
        #[serde(default)]
        bytes_be_32: Option<Vec<u8>>,
        bit_length: usize,
        byte_length: usize,
        is_zero: bool,
        is_odd: bool,
        #[serde(default)]
        note: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct ArithmeticVector {
        op: String,
        #[serde(default)]
        a: Option<String>,
        #[serde(default)]
        b: Option<String>,
        #[serde(default)]
        m: Option<String>,
        expected: String,
        #[serde(default)]
        note: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct TestVectors {
        conversions: Vec<ConversionVector>,
        arithmetic: Vec<ArithmeticVector>,
    }

    fn load_test_vectors() -> TestVectors {
        let json = include_str!("../../test-vectors/big_number.json");
        serde_json::from_str(json).expect("failed to parse big_number.json")
    }

    // ---- Conversion tests ----

    #[test]
    fn test_from_hex_zero() {
        let n = BigNumber::from_hex("0").unwrap();
        assert!(n.is_zero());
        assert!(!n.is_negative());
        assert_eq!(n.to_hex(), "0");
    }

    #[test]
    fn test_from_hex_ff() {
        let n = BigNumber::from_hex("ff").unwrap();
        assert!(!n.is_zero());
        assert_eq!(n.to_hex(), "ff");
        assert_eq!(n.to_number(), Some(255));
    }

    #[test]
    fn test_from_hex_secp256k1_p() {
        let hex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
        let n = BigNumber::from_hex(hex).unwrap();
        assert!(!n.is_zero());
        assert!(n.is_odd());
        assert_eq!(n.bit_length(), 256);
        assert_eq!(n.to_hex(), hex);
        // Should fit in 4 u64 limbs (inline)
        assert!(n.is_inline());
    }

    #[test]
    fn test_from_number() {
        let z = BigNumber::from_number(0);
        assert!(z.is_zero());

        let neg = BigNumber::from_number(-1);
        assert!(neg.is_negative());
        assert_eq!(neg.to_number(), Some(-1));

        let pos = BigNumber::from_number(42);
        assert_eq!(pos.to_number(), Some(42));
    }

    #[test]
    fn test_hex_roundtrip_vectors() {
        let vectors = load_test_vectors();
        for v in &vectors.conversions {
            let n = BigNumber::from_hex(&v.hex).unwrap();
            let hex_out = n.to_hex();
            // from_hex strips leading zeros, so we compare stripped versions
            let expected = v.hex.trim_start_matches('0');
            let expected = if expected.is_empty() { "0" } else { expected };
            assert_eq!(hex_out, expected, "hex roundtrip failed for {:?}", v.note);
        }
    }

    #[test]
    fn test_properties_from_vectors() {
        let vectors = load_test_vectors();
        for v in &vectors.conversions {
            let n = BigNumber::from_hex(&v.hex).unwrap();
            assert_eq!(
                n.bit_length(),
                v.bit_length,
                "bit_length mismatch for {:?}",
                v.note
            );
            assert_eq!(
                n.byte_length(),
                v.byte_length,
                "byte_length mismatch for {:?}",
                v.note
            );
            assert_eq!(n.is_zero(), v.is_zero, "is_zero mismatch for {:?}", v.note);
            assert_eq!(n.is_odd(), v.is_odd, "is_odd mismatch for {:?}", v.note);
        }
    }

    #[test]
    fn test_to_array_big_endian_32() {
        let hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let n = BigNumber::from_hex(hex).unwrap();
        let arr = n.to_array(Endian::Big, Some(32));
        assert_eq!(arr.len(), 32);
        assert!(arr.iter().all(|&b| b == 255));
    }

    #[test]
    fn test_to_array_little_endian_minimal() {
        let n = BigNumber::from_hex("ff").unwrap();
        let arr = n.to_array(Endian::Little, None);
        assert_eq!(arr, vec![255]);
    }

    #[test]
    fn test_to_array_big_endian_padded() {
        let n = BigNumber::from_hex("ff").unwrap();
        let arr = n.to_array(Endian::Big, Some(4));
        assert_eq!(arr, vec![0, 0, 0, 255]);
    }

    #[test]
    fn test_to_array_vectors() {
        let vectors = load_test_vectors();
        for v in &vectors.conversions {
            let n = BigNumber::from_hex(&v.hex).unwrap();

            if let Some(ref be) = v.bytes_be {
                let arr = n.to_array(Endian::Big, None);
                assert_eq!(arr, *be, "to_array(Big) mismatch for {:?}", v.note);
            }

            if let Some(ref le) = v.bytes_le {
                let arr = n.to_array(Endian::Little, None);
                assert_eq!(arr, *le, "to_array(Little) mismatch for {:?}", v.note);
            }

            if let Some(ref be32) = v.bytes_be_32 {
                let arr = n.to_array(Endian::Big, Some(32));
                assert_eq!(arr, *be32, "to_array(Big, 32) mismatch for {:?}", v.note);
            }
        }
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let hex = "deadbeef";
        let n = BigNumber::from_hex(hex).unwrap();
        let bytes = n.to_array(Endian::Big, None);
        let n2 = BigNumber::from_bytes(&bytes, Endian::Big);
        assert_eq!(n2.to_hex(), hex);

        // Little-endian roundtrip
        let le_bytes = n.to_array(Endian::Little, None);
        let n3 = BigNumber::from_bytes(&le_bytes, Endian::Little);
        assert_eq!(n3.to_hex(), hex);
    }

    #[test]
    fn test_cmp() {
        let a = BigNumber::from_number(5);
        let b = BigNumber::from_number(3);
        assert_eq!(BigNumber::cmp(&a, &b), 1);
        assert_eq!(BigNumber::cmp(&b, &a), -1);
        assert_eq!(BigNumber::cmp(&a, &a), 0);

        let neg = BigNumber::from_number(-1);
        assert_eq!(BigNumber::cmp(&neg, &a), -1);
        assert_eq!(BigNumber::cmp(&a, &neg), 1);
    }

    #[test]
    fn test_is_odd() {
        assert!(BigNumber::from_number(1).is_odd());
        assert!(!BigNumber::from_number(2).is_odd());
        assert!(!BigNumber::from_number(0).is_odd());
    }

    #[test]
    fn test_bit_length() {
        assert_eq!(BigNumber::from_number(0).bit_length(), 0);
        assert_eq!(BigNumber::from_number(1).bit_length(), 1);
        assert_eq!(BigNumber::from_number(255).bit_length(), 8);
        assert_eq!(BigNumber::from_number(256).bit_length(), 9);
    }

    #[test]
    fn test_byte_length() {
        assert_eq!(BigNumber::from_number(0).byte_length(), 0);
        assert_eq!(BigNumber::from_number(255).byte_length(), 1);
        assert_eq!(BigNumber::from_number(256).byte_length(), 2);
    }

    #[test]
    fn test_clone_independence() {
        let a = BigNumber::from_number(42);
        let mut b = a.clone();
        b.iadd(&BigNumber::from_number(1));
        assert_eq!(a.to_number(), Some(42));
        assert_eq!(b.to_number(), Some(43));
    }

    #[test]
    fn test_small_limbs_inline() {
        // 256-bit value should use inline storage
        let n =
            BigNumber::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        assert!(n.is_inline());

        // 512-bit value should use heap
        let big = BigNumber::from_hex(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap();
        assert!(!big.is_inline());
    }

    #[test]
    fn test_andln() {
        let n = BigNumber::from_hex("ff").unwrap();
        assert_eq!(n.andln(4), 0xf); // bottom 4 bits of 0xff
        assert_eq!(n.andln(1), 1); // bottom 1 bit
        assert_eq!(n.andln(8), 0xff); // bottom 8 bits

        let z = BigNumber::zero();
        assert_eq!(z.andln(4), 0);
    }

    #[test]
    fn test_from_array_endians() {
        let be_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let n_be = BigNumber::from_array(&be_bytes, Endian::Big);
        assert_eq!(n_be.to_hex(), "deadbeef");

        let le_bytes = vec![0xef, 0xbe, 0xad, 0xde];
        let n_le = BigNumber::from_array(&le_bytes, Endian::Little);
        assert_eq!(n_le.to_hex(), "deadbeef");
    }

    #[test]
    fn test_zero_to_array() {
        let z = BigNumber::zero();
        let arr = z.to_array(Endian::Big, Some(32));
        assert_eq!(arr.len(), 32);
        assert!(arr.iter().all(|&b| b == 0));

        let arr_none = z.to_array(Endian::Big, None);
        assert_eq!(arr_none.len(), 0);
    }

    #[test]
    fn test_testn() {
        let n = BigNumber::from_number(5); // binary: 101
        assert!(n.testn(0)); // bit 0 = 1
        assert!(!n.testn(1)); // bit 1 = 0
        assert!(n.testn(2)); // bit 2 = 1
        assert!(!n.testn(3)); // bit 3 = 0
    }

    #[test]
    fn test_neg_and_abs() {
        let n = BigNumber::from_number(42);
        let neg = n.neg();
        assert!(neg.is_negative());
        assert_eq!(neg.to_number(), Some(-42));

        let abs_val = neg.abs();
        assert!(!abs_val.is_negative());
        assert_eq!(abs_val.to_number(), Some(42));
    }

    // ---- Arithmetic tests (Task 2) ----

    #[test]
    fn test_add_basic() {
        // 0 + 0 = 0
        assert!(BigNumber::zero().add(&BigNumber::zero()).is_zero());
        // 1 + 1 = 2
        assert_eq!(
            BigNumber::from_number(1)
                .add(&BigNumber::from_number(1))
                .to_number(),
            Some(2)
        );
        // ff + 1 = 100
        let ff = BigNumber::from_hex("ff").unwrap();
        let one = BigNumber::from_number(1);
        assert_eq!(ff.add(&one).to_hex(), "100");
    }

    #[test]
    fn test_add_256bit_overflow() {
        // max 256-bit + 1 overflows to 257 bits (heap)
        let max256 =
            BigNumber::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        let one = BigNumber::from_number(1);
        let result = max256.add(&one);
        assert_eq!(result.bit_length(), 257);
        assert!(!result.is_inline()); // Should spill to heap (5 limbs)
    }

    #[test]
    fn test_add_negative_positive() {
        // -5 + 3 = -2
        let neg5 = BigNumber::from_number(-5);
        let pos3 = BigNumber::from_number(3);
        assert_eq!(neg5.add(&pos3).to_number(), Some(-2));

        // 3 + (-5) = -2
        assert_eq!(pos3.add(&neg5).to_number(), Some(-2));
    }

    #[test]
    fn test_sub_basic() {
        assert_eq!(
            BigNumber::from_number(5)
                .sub(&BigNumber::from_number(3))
                .to_number(),
            Some(2)
        );
        assert_eq!(
            BigNumber::from_number(3)
                .sub(&BigNumber::from_number(5))
                .to_number(),
            Some(-2)
        );
        assert_eq!(
            BigNumber::from_number(0)
                .sub(&BigNumber::from_number(1))
                .to_number(),
            Some(-1)
        );
    }

    #[test]
    fn test_mul_basic() {
        assert_eq!(
            BigNumber::from_number(2)
                .mul(&BigNumber::from_number(3))
                .to_number(),
            Some(6)
        );
        assert!(BigNumber::from_number(0)
            .mul(&BigNumber::from_number(100))
            .is_zero());
    }

    #[test]
    fn test_mul_large() {
        let ff = BigNumber::from_hex("ff").unwrap();
        let result = ff.mul(&ff);
        assert_eq!(result.to_hex(), "fe01"); // 255 * 255 = 65025
    }

    #[test]
    fn test_sqr() {
        let n = BigNumber::from_number(5);
        assert_eq!(n.sqr().to_number(), Some(25));
        // Verify sqr matches mul
        assert_eq!(n.sqr().to_hex(), n.mul(&n).to_hex());
    }

    #[test]
    fn test_div_basic() {
        assert_eq!(
            BigNumber::from_number(10)
                .div(&BigNumber::from_number(3))
                .unwrap()
                .to_number(),
            Some(3)
        );
        assert_eq!(
            BigNumber::from_number(10)
                .div(&BigNumber::from_number(2))
                .unwrap()
                .to_number(),
            Some(5)
        );
    }

    #[test]
    fn test_div_by_zero() {
        let result = BigNumber::from_number(10).div(&BigNumber::zero());
        assert!(result.is_err());
    }

    #[test]
    fn test_umod_basic() {
        assert_eq!(
            BigNumber::from_number(10)
                .umod(&BigNumber::from_number(3))
                .unwrap()
                .to_number(),
            Some(1)
        );
        assert_eq!(
            BigNumber::from_hex("ff")
                .unwrap()
                .umod(&BigNumber::from_number(16))
                .unwrap()
                .to_number(),
            Some(15)
        );
    }

    #[test]
    fn test_ushln() {
        let n = BigNumber::from_number(1);
        // Shift left by 1 = double
        assert_eq!(n.ushln(1).to_number(), Some(2));
        // Shift left by 64 = move to next limb
        let shifted = n.ushln(64);
        assert_eq!(shifted.bit_length(), 65);
    }

    #[test]
    fn test_ushrn() {
        let n = BigNumber::from_number(256);
        assert_eq!(n.ushrn(1).to_number(), Some(128));
        // Shift right by 64
        let big = BigNumber::from_number(1).ushln(64);
        assert_eq!(big.ushrn(64).to_number(), Some(1));
    }

    #[test]
    fn test_iushrn_in_place() {
        let mut n = BigNumber::from_number(8);
        n.iushrn(1);
        assert_eq!(n.to_number(), Some(4));
        n.iushrn(1);
        assert_eq!(n.to_number(), Some(2));
        n.iushrn(1);
        assert_eq!(n.to_number(), Some(1));
    }

    #[test]
    fn test_maskn() {
        let n = BigNumber::from_hex("ff").unwrap();
        assert_eq!(n.maskn(4).to_number(), Some(15)); // Bottom 4 bits of 0xff
        assert_eq!(n.maskn(8).to_number(), Some(255)); // Bottom 8 bits of 0xff
    }

    #[test]
    fn test_gcd() {
        assert_eq!(
            BigNumber::from_number(12)
                .gcd(&BigNumber::from_number(8))
                .to_number(),
            Some(4)
        );
        assert_eq!(
            BigNumber::from_number(17)
                .gcd(&BigNumber::from_number(13))
                .to_number(),
            Some(1)
        );
    }

    #[test]
    fn test_egcd() {
        let a = BigNumber::from_number(12);
        let b = BigNumber::from_number(8);
        let (gcd, x, y) = a.egcd(&b);
        assert_eq!(gcd.to_number(), Some(4));
        // Verify: a*x + b*y = gcd
        let check = a.mul(&x).add(&b.mul(&y));
        assert_eq!(check.to_number(), gcd.to_number());
    }

    #[test]
    fn test_invm_small() {
        // 3^-1 mod 11 = 4 (because 3*4 = 12, 12 mod 11 = 1)
        let a = BigNumber::from_number(3);
        let m = BigNumber::from_number(11);
        let inv = a.invm(&m).unwrap();
        assert_eq!(inv.to_number(), Some(4));
        // Verify: a * inv mod m = 1
        let check = a.mul(&inv).umod(&m).unwrap();
        assert_eq!(check.to_number(), Some(1));
    }

    #[test]
    fn test_invm_secp256k1() {
        // 7^-1 mod secp256k1_n
        let a = BigNumber::from_number(7);
        let m =
            BigNumber::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .unwrap();
        let inv = a.invm(&m).unwrap();
        // Verify: 7 * inv mod m = 1
        let check = a.mul(&inv).umod(&m).unwrap();
        assert!(check.is_one(), "7 * 7^-1 mod n should be 1");
    }

    #[test]
    fn test_arithmetic_vectors() {
        let vectors = load_test_vectors();
        for v in &vectors.arithmetic {
            match v.op.as_str() {
                "add" => {
                    let a = BigNumber::from_hex(v.a.as_ref().unwrap()).unwrap();
                    let b = BigNumber::from_hex(v.b.as_ref().unwrap()).unwrap();
                    let result = a.add(&b);
                    assert_eq!(
                        result.to_hex(),
                        v.expected,
                        "add({}, {}) failed",
                        v.a.as_ref().unwrap(),
                        v.b.as_ref().unwrap()
                    );
                }
                "sub" => {
                    let a = BigNumber::from_hex(v.a.as_ref().unwrap()).unwrap();
                    let b = BigNumber::from_hex(v.b.as_ref().unwrap()).unwrap();
                    let result = a.sub(&b);
                    assert_eq!(
                        result.to_hex(),
                        v.expected,
                        "sub({}, {}) failed",
                        v.a.as_ref().unwrap(),
                        v.b.as_ref().unwrap()
                    );
                }
                "mul" => {
                    let a = BigNumber::from_hex(v.a.as_ref().unwrap()).unwrap();
                    let b = BigNumber::from_hex(v.b.as_ref().unwrap()).unwrap();
                    let result = a.mul(&b);
                    assert_eq!(
                        result.to_hex(),
                        v.expected,
                        "mul({}, {}) failed",
                        v.a.as_ref().unwrap(),
                        v.b.as_ref().unwrap()
                    );
                }
                "div" => {
                    let a = BigNumber::from_hex(v.a.as_ref().unwrap()).unwrap();
                    let b = BigNumber::from_hex(v.b.as_ref().unwrap()).unwrap();
                    let result = a.div(&b).unwrap();
                    assert_eq!(
                        result.to_hex(),
                        v.expected,
                        "div({}, {}) failed",
                        v.a.as_ref().unwrap(),
                        v.b.as_ref().unwrap()
                    );
                }
                "mod" => {
                    let a = BigNumber::from_hex(v.a.as_ref().unwrap()).unwrap();
                    let b = BigNumber::from_hex(v.b.as_ref().unwrap()).unwrap();
                    let result = a.umod(&b).unwrap();
                    assert_eq!(
                        result.to_hex(),
                        v.expected,
                        "mod({}, {}) failed",
                        v.a.as_ref().unwrap(),
                        v.b.as_ref().unwrap()
                    );
                }
                "gcd" => {
                    let a = BigNumber::from_hex(v.a.as_ref().unwrap()).unwrap();
                    let b = BigNumber::from_hex(v.b.as_ref().unwrap()).unwrap();
                    let result = a.gcd(&b);
                    assert_eq!(
                        result.to_hex(),
                        v.expected,
                        "gcd({}, {}) failed",
                        v.a.as_ref().unwrap(),
                        v.b.as_ref().unwrap()
                    );
                }
                "invm" => {
                    let a = BigNumber::from_hex(v.a.as_ref().unwrap()).unwrap();
                    let m = BigNumber::from_hex(v.m.as_ref().unwrap()).unwrap();
                    let result = a.invm(&m).unwrap();
                    assert_eq!(
                        result.to_hex(),
                        v.expected,
                        "invm({}, {}) failed: {:?}",
                        v.a.as_ref().unwrap(),
                        v.m.as_ref().unwrap(),
                        v.note
                    );
                    // Double check: a * result mod m == 1
                    let check = a.mul(&result).umod(&m).unwrap();
                    assert!(check.is_one(), "invm verification failed for {:?}", v.note);
                }
                _ => {} // skip unknown ops
            }
        }
    }

    #[test]
    fn test_to_red_from_red() {
        let ctx =
            crate::primitives::reduction_context::ReductionContext::new(BigNumber::from_number(7));
        let a = BigNumber::from_number(10);
        let a_red = a.to_red(ctx.clone());
        assert!(a_red.red.is_some());
        assert_eq!(a_red.to_number(), Some(3)); // 10 mod 7

        let a_back = a_red.from_red();
        assert!(a_back.red.is_none());
        assert_eq!(a_back.to_number(), Some(3));
    }

    #[test]
    fn test_pow() {
        // 2^10 = 1024
        let base = BigNumber::from_number(2);
        let exp = BigNumber::from_number(10);
        assert_eq!(base.pow(&exp).to_number(), Some(1024));

        // Anything^0 = 1
        assert!(BigNumber::from_number(42).pow(&BigNumber::zero()).is_one());
    }

    #[test]
    fn test_negative_arithmetic() {
        // -3 * -4 = 12
        let neg3 = BigNumber::from_number(-3);
        let neg4 = BigNumber::from_number(-4);
        assert_eq!(neg3.mul(&neg4).to_number(), Some(12));

        // -3 * 4 = -12
        let pos4 = BigNumber::from_number(4);
        assert_eq!(neg3.mul(&pos4).to_number(), Some(-12));
    }

    #[test]
    fn test_large_values_heap() {
        // Multiply two 256-bit values to get a 512-bit result (heap)
        let a =
            BigNumber::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        let result = a.mul(&a);
        assert!(!result.is_inline()); // Should be on heap
        assert!(result.bit_length() > 256);
    }

    // -- Script number encoding/decoding tests --

    #[test]
    fn test_script_num_zero() {
        let zero = BigNumber::zero();
        let encoded = zero.to_script_num();
        assert!(encoded.is_empty(), "zero should encode to empty vec");
        let decoded = BigNumber::from_script_num(&encoded, true, None).unwrap();
        assert!(decoded.is_zero());
    }

    #[test]
    fn test_script_num_positive_small() {
        // 1 -> [0x01]
        let one = BigNumber::from_number(1);
        assert_eq!(one.to_script_num(), vec![0x01]);
        let rt = BigNumber::from_script_num(&[0x01], false, None).unwrap();
        assert_eq!(rt.to_number(), Some(1));

        // 127 -> [0x7f]
        let n = BigNumber::from_number(127);
        assert_eq!(n.to_script_num(), vec![0x7f]);
        let rt = BigNumber::from_script_num(&[0x7f], false, None).unwrap();
        assert_eq!(rt.to_number(), Some(127));
    }

    #[test]
    fn test_script_num_128() {
        // 128 -> [0x80, 0x00] (MSB of 0x80 set, need sign-extension byte)
        let n = BigNumber::from_number(128);
        assert_eq!(n.to_script_num(), vec![0x80, 0x00]);
        let rt = BigNumber::from_script_num(&[0x80, 0x00], false, None).unwrap();
        assert_eq!(rt.to_number(), Some(128));
    }

    #[test]
    fn test_script_num_255() {
        // 255 -> [0xff, 0x00]
        let n = BigNumber::from_number(255);
        assert_eq!(n.to_script_num(), vec![0xff, 0x00]);
        let rt = BigNumber::from_script_num(&[0xff, 0x00], false, None).unwrap();
        assert_eq!(rt.to_number(), Some(255));
    }

    #[test]
    fn test_script_num_256() {
        // 256 -> [0x00, 0x01]
        let n = BigNumber::from_number(256);
        assert_eq!(n.to_script_num(), vec![0x00, 0x01]);
        let rt = BigNumber::from_script_num(&[0x00, 0x01], false, None).unwrap();
        assert_eq!(rt.to_number(), Some(256));
    }

    #[test]
    fn test_script_num_negative() {
        // -1 -> [0x81]
        let n = BigNumber::from_number(-1);
        assert_eq!(n.to_script_num(), vec![0x81]);
        let rt = BigNumber::from_script_num(&[0x81], false, None).unwrap();
        assert_eq!(rt.to_number(), Some(-1));

        // -128 -> [0x80, 0x80]
        let n = BigNumber::from_number(-128);
        assert_eq!(n.to_script_num(), vec![0x80, 0x80]);
        let rt = BigNumber::from_script_num(&[0x80, 0x80], false, None).unwrap();
        assert_eq!(rt.to_number(), Some(-128));

        // -256 -> [0x00, 0x81]
        let n = BigNumber::from_number(-256);
        assert_eq!(n.to_script_num(), vec![0x00, 0x81]);
        let rt = BigNumber::from_script_num(&[0x00, 0x81], false, None).unwrap();
        assert_eq!(rt.to_number(), Some(-256));
    }

    #[test]
    fn test_script_num_roundtrip_comprehensive() {
        let values: Vec<i64> = vec![
            0, 1, -1, 2, -2, 127, -127, 128, -128, 255, -255, 256, -256, 1000, -1000, 32767,
            -32767, 32768, -32768, 65535, -65535, 65536, -65536,
        ];
        for val in values {
            let bn = BigNumber::from_number(val);
            let encoded = bn.to_script_num();
            let decoded = BigNumber::from_script_num(&encoded, false, None).unwrap();
            assert_eq!(
                decoded.to_number(),
                Some(val),
                "round-trip failed for {val}"
            );
        }
    }

    #[test]
    fn test_script_num_minimal_encoding_check() {
        // Non-minimal: [0x00, 0x00] should be rejected (zero with extra byte)
        let result = BigNumber::from_script_num(&[0x00, 0x00], true, None);
        assert!(result.is_err(), "non-minimal encoding should be rejected");

        // Non-minimal: negative zero [0x80] should be rejected
        let result = BigNumber::from_script_num(&[0x80], true, None);
        assert!(
            result.is_err(),
            "negative zero should be rejected as non-minimal"
        );

        // Non-minimal: [0x01, 0x00] when 0x01 would suffice
        let result = BigNumber::from_script_num(&[0x01, 0x00], true, None);
        assert!(
            result.is_err(),
            "unnecessary zero extension should be rejected"
        );
    }

    #[test]
    fn test_script_num_max_len() {
        let result = BigNumber::from_script_num(&[0x01, 0x02, 0x03, 0x04, 0x05], true, Some(4));
        assert!(result.is_err(), "should reject inputs exceeding max_len");
    }
}
