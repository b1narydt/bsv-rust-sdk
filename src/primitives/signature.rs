//! ECDSA signature type with DER encoding support.
//!
//! Signature represents an ECDSA signature as (r, s) BigNumber values.
//! Supports DER encoding/decoding per Bitcoin consensus rules,
//! compact (fixed-width) encoding, and low-S normalization.

use crate::primitives::base_point::BasePoint;
use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::curve::Curve;
use crate::primitives::error::PrimitivesError;
use crate::primitives::point::Point;
use crate::primitives::public_key::PublicKey;

/// An ECDSA signature consisting of (r, s) values.
///
/// The signature pair (r, s) corresponds to the raw ECDSA signature.
/// Signatures are often serialized in DER encoding for transmission
/// and storage in Bitcoin transactions.
#[derive(Clone, Debug)]
pub struct Signature {
    /// The r component of the signature.
    r: BigNumber,
    /// The s component of the signature.
    s: BigNumber,
}

impl Signature {
    /// Create a new Signature from r and s BigNumber values.
    pub fn new(r: BigNumber, s: BigNumber) -> Self {
        Signature { r, s }
    }

    /// Get the r component.
    pub fn r(&self) -> &BigNumber {
        &self.r
    }

    /// Get the s component.
    pub fn s(&self) -> &BigNumber {
        &self.s
    }

    // -----------------------------------------------------------------------
    // DER encoding/decoding
    // -----------------------------------------------------------------------

    /// Parse a signature from DER-encoded bytes.
    ///
    /// DER format: 0x30 || total_len || 0x02 || r_len || r_bytes || 0x02 || s_len || s_bytes
    pub fn from_der(data: &[u8]) -> Result<Self, PrimitivesError> {
        if data.is_empty() {
            return Err(PrimitivesError::InvalidSignature(
                "empty DER data".to_string(),
            ));
        }

        let mut pos = 0;

        // Check sequence tag
        if data[pos] != 0x30 {
            return Err(PrimitivesError::InvalidSignature(
                "DER signature must start with 0x30".to_string(),
            ));
        }
        pos += 1;

        // Total length
        let total_len = Self::read_der_length(data, &mut pos)?;
        if total_len + pos != data.len() {
            return Err(PrimitivesError::InvalidSignature(
                "DER signature length mismatch".to_string(),
            ));
        }

        // Parse r
        if pos >= data.len() || data[pos] != 0x02 {
            return Err(PrimitivesError::InvalidSignature(
                "DER signature invalid: expected 0x02 for r".to_string(),
            ));
        }
        pos += 1;

        let r_len = Self::read_der_length(data, &mut pos)?;
        if pos + r_len > data.len() {
            return Err(PrimitivesError::InvalidSignature(
                "DER signature truncated at r".to_string(),
            ));
        }
        let mut r_bytes = &data[pos..pos + r_len];
        pos += r_len;

        // Parse s
        if pos >= data.len() || data[pos] != 0x02 {
            return Err(PrimitivesError::InvalidSignature(
                "DER signature invalid: expected 0x02 for s".to_string(),
            ));
        }
        pos += 1;

        let s_len = Self::read_der_length(data, &mut pos)?;
        if data.len() != s_len + pos {
            return Err(PrimitivesError::InvalidSignature(
                "DER signature has trailing data".to_string(),
            ));
        }
        let mut s_bytes = &data[pos..pos + s_len];

        // Strip leading zero padding (used for positive integer encoding)
        if !r_bytes.is_empty() && r_bytes[0] == 0 {
            if r_bytes.len() > 1 && (r_bytes[1] & 0x80) != 0 {
                r_bytes = &r_bytes[1..];
            } else if r_bytes.len() > 1 {
                return Err(PrimitivesError::InvalidSignature(
                    "invalid R-value in DER: unnecessary leading zero".to_string(),
                ));
            }
        }
        if !s_bytes.is_empty() && s_bytes[0] == 0 {
            if s_bytes.len() > 1 && (s_bytes[1] & 0x80) != 0 {
                s_bytes = &s_bytes[1..];
            } else if s_bytes.len() > 1 {
                return Err(PrimitivesError::InvalidSignature(
                    "invalid S-value in DER: unnecessary leading zero".to_string(),
                ));
            }
        }

        let r = BigNumber::from_bytes(r_bytes, Endian::Big);
        let s = BigNumber::from_bytes(s_bytes, Endian::Big);

        Ok(Signature { r, s })
    }

    /// Parse a signature from a hex-encoded DER string.
    pub fn from_hex(hex: &str) -> Result<Self, PrimitivesError> {
        let bytes = hex_to_bytes(hex)?;
        Self::from_der(&bytes)
    }

    /// Encode this signature to DER format.
    ///
    /// DER format: 0x30 || total_len || 0x02 || r_len || r_bytes || 0x02 || s_len || s_bytes
    pub fn to_der(&self) -> Vec<u8> {
        let r_bytes = self.canonicalize_int(&self.r);
        let s_bytes = self.canonicalize_int(&self.s);

        let inner_len = 2 + r_bytes.len() + 2 + s_bytes.len();

        let mut result = Vec::with_capacity(inner_len + 2);
        result.push(0x30);
        Self::write_der_length(&mut result, inner_len);
        result.push(0x02);
        Self::write_der_length(&mut result, r_bytes.len());
        result.extend_from_slice(&r_bytes);
        result.push(0x02);
        Self::write_der_length(&mut result, s_bytes.len());
        result.extend_from_slice(&s_bytes);

        result
    }

    /// Encode to DER and return as hex string.
    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.to_der())
    }

    /// Canonicalize an integer for DER encoding.
    /// - Remove unnecessary leading zeros
    /// - Add 0x00 prefix if high bit is set (to keep it positive)
    fn canonicalize_int(&self, num: &BigNumber) -> Vec<u8> {
        let mut bytes = num.to_array(Endian::Big, None);

        if bytes.is_empty() {
            return vec![0x00];
        }

        // Remove leading zeros, but keep at least one byte
        // and keep zeros needed for positive encoding
        let mut start = 0;
        while start < bytes.len() - 1 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0 {
            start += 1;
        }
        bytes = bytes[start..].to_vec();

        // Add 0x00 prefix if high bit is set (DER positive integer)
        if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
            let mut padded = Vec::with_capacity(bytes.len() + 1);
            padded.push(0x00);
            padded.extend_from_slice(&bytes);
            return padded;
        }

        bytes
    }

    /// Read a DER length byte. Only supports short form (< 0x80).
    fn read_der_length(data: &[u8], pos: &mut usize) -> Result<usize, PrimitivesError> {
        if *pos >= data.len() {
            return Err(PrimitivesError::InvalidSignature(
                "DER length truncated".to_string(),
            ));
        }
        let initial = data[*pos];
        *pos += 1;
        if (initial & 0x80) != 0 {
            return Err(PrimitivesError::InvalidSignature(
                "DER entity length must be < 0x80".to_string(),
            ));
        }
        Ok(initial as usize)
    }

    /// Write a DER length byte.
    fn write_der_length(buf: &mut Vec<u8>, len: usize) {
        assert!(len < 0x80, "DER length must be < 0x80");
        buf.push(len as u8);
    }

    // -----------------------------------------------------------------------
    // Compact encoding (fixed-width 64 bytes: 32-byte r || 32-byte s)
    // -----------------------------------------------------------------------

    /// Parse from a 64-byte compact encoding (r || s, each 32 bytes).
    pub fn from_compact(data: &[u8]) -> Result<Self, PrimitivesError> {
        if data.len() != 64 {
            return Err(PrimitivesError::InvalidSignature(format!(
                "compact signature must be 64 bytes, got {}",
                data.len()
            )));
        }

        let r = BigNumber::from_bytes(&data[0..32], Endian::Big);
        let s = BigNumber::from_bytes(&data[32..64], Endian::Big);

        Ok(Signature { r, s })
    }

    /// Encode to 64-byte compact format (32-byte r || 32-byte s).
    pub fn to_compact(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(64);
        result.extend_from_slice(&self.r.to_array(Endian::Big, Some(32)));
        result.extend_from_slice(&self.s.to_array(Endian::Big, Some(32)));
        result
    }

    // -----------------------------------------------------------------------
    // Low-S normalization
    // -----------------------------------------------------------------------

    /// Check if this signature has a low S value (S <= N/2).
    ///
    /// Bitcoin requires low-S for transaction malleability prevention.
    pub fn has_low_s(&self) -> bool {
        let curve = Curve::secp256k1();
        self.s.cmp(&curve.half_n) <= 0
    }

    /// Return a signature with low-S normalization.
    /// If S > N/2, replace S with N - S.
    pub fn to_low_s(&self) -> Signature {
        if self.has_low_s() {
            return self.clone();
        }
        let curve = Curve::secp256k1();
        let new_s = curve.n.sub(&self.s);
        Signature {
            r: self.r.clone(),
            s: new_s,
        }
    }

    // -----------------------------------------------------------------------
    // Compact BSM signature encoding (65 bytes with recovery byte)
    // -----------------------------------------------------------------------

    /// Encode to BSM-format compact signature (65 bytes).
    ///
    /// Format: [27 + recovery + (4 if compressed), r(32 BE), s(32 BE)]
    /// The first byte encodes the recovery factor and compression flag.
    pub fn to_compact_bsm(&self, recovery: u8, compressed: bool) -> Vec<u8> {
        let mut compact_byte = 27 + recovery;
        if compressed {
            compact_byte += 4;
        }
        let mut result = Vec::with_capacity(65);
        result.push(compact_byte);
        result.extend_from_slice(&self.r.to_array(Endian::Big, Some(32)));
        result.extend_from_slice(&self.s.to_array(Endian::Big, Some(32)));
        result
    }

    /// Parse a BSM-format compact signature (65 bytes).
    ///
    /// Returns (Signature, recovery_factor, compressed).
    pub fn from_compact_bsm(data: &[u8]) -> Result<(Self, u8, bool), PrimitivesError> {
        if data.len() != 65 {
            return Err(PrimitivesError::InvalidSignature(
                "compact BSM signature must be 65 bytes".to_string(),
            ));
        }
        let compact_byte = data[0];
        if !(27..35).contains(&compact_byte) {
            return Err(PrimitivesError::InvalidSignature(
                "invalid compact byte (must be 27-34)".to_string(),
            ));
        }
        let compressed = compact_byte >= 31;
        let recovery = if compressed {
            compact_byte - 31
        } else {
            compact_byte - 27
        };
        let r = BigNumber::from_bytes(&data[1..33], Endian::Big);
        let s = BigNumber::from_bytes(&data[33..65], Endian::Big);
        Ok((Signature::new(r, s), recovery, compressed))
    }

    // -----------------------------------------------------------------------
    // Public key recovery from signature
    // -----------------------------------------------------------------------

    /// Recover a public key from this signature, a recovery factor, and a message hash.
    ///
    /// Implements ECDSA public key recovery:
    /// x = r + (recovery >> 1) * n
    /// R = Point::from_x(x, recovery & 1)
    /// Q = r^-1 * (s*R - e*G)
    pub fn recover_public_key(
        &self,
        recovery: u8,
        message_hash: &BigNumber,
    ) -> Result<PublicKey, PrimitivesError> {
        let curve = Curve::secp256k1();
        let n = &curve.n;

        let is_y_odd = (recovery & 1) != 0;
        let is_second_key = (recovery >> 1) != 0;

        // x = r + j*n (j = is_second_key ? 1 : 0)
        let x = if is_second_key {
            self.r.add(n)
        } else {
            self.r.clone()
        };
        let r_point = Point::from_x(&x, is_y_odd)?;

        // Verify nR is at infinity
        let n_r = r_point.mul(n);
        if !n_r.is_infinity() {
            return Err(PrimitivesError::InvalidSignature(
                "nR is not at infinity".to_string(),
            ));
        }

        // Q = r^-1 * (s*R - e*G)
        let e_neg = message_hash
            .neg()
            .umod(n)
            .map_err(|e| PrimitivesError::InvalidSignature(format!("umod failed: {e}")))?;
        let r_inv = self
            .r
            .invm(n)
            .map_err(|e| PrimitivesError::InvalidSignature(format!("invm failed: {e}")))?;

        let sr = r_point.mul(&self.s);
        let eg = BasePoint::instance().mul(&e_neg);
        let q = sr.add(&eg).mul(&r_inv);

        if q.is_infinity() {
            return Err(PrimitivesError::InvalidSignature(
                "recovered point is at infinity".to_string(),
            ));
        }

        Ok(PublicKey::from_point(q))
    }

    /// Calculate the recovery factor for a given public key and message hash.
    ///
    /// Tries recovery factors 0-3 and returns the first one that recovers
    /// the matching public key.
    pub fn calculate_recovery_factor(
        &self,
        pubkey: &PublicKey,
        message_hash: &BigNumber,
    ) -> Result<u8, PrimitivesError> {
        for recovery in 0..4u8 {
            if let Ok(recovered) = self.recover_public_key(recovery, message_hash) {
                if pubkey == &recovered {
                    return Ok(recovery);
                }
            }
        }
        Err(PrimitivesError::InvalidSignature(
            "unable to find valid recovery factor".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, PrimitivesError> {
    if hex.len() & 1 != 0 {
        return Err(PrimitivesError::InvalidHex(
            "odd-length hex string".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| PrimitivesError::InvalidHex(e.to_string()))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_new() {
        let r = BigNumber::one();
        let s = BigNumber::one();
        let sig = Signature::new(r.clone(), s.clone());
        assert_eq!(sig.r().cmp(&r), 0);
        assert_eq!(sig.s().cmp(&s), 0);
    }

    // -- DER encoding tests --

    #[test]
    fn test_der_encode_r1_s1() {
        let sig = Signature::new(BigNumber::one(), BigNumber::one());
        let der = sig.to_der();
        assert_eq!(bytes_to_hex(&der), "3006020101020101");
    }

    #[test]
    fn test_der_encode_high_bit_r_s() {
        let r = BigNumber::from_hex("ff").unwrap();
        let s = BigNumber::from_hex("ff").unwrap();
        let sig = Signature::new(r, s);
        let der = sig.to_der();
        assert_eq!(bytes_to_hex(&der), "3008020200ff020200ff");
    }

    #[test]
    fn test_der_encode_real_bitcoin_sig() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09")
                .unwrap();
        let sig = Signature::new(r, s);
        let der_hex = sig.to_hex();
        assert_eq!(
            der_hex,
            "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"
        );
    }

    #[test]
    fn test_der_encode_r_with_high_bit() {
        let r =
            BigNumber::from_hex("813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365")
                .unwrap();
        let s =
            BigNumber::from_hex("6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba")
                .unwrap();
        let sig = Signature::new(r, s);
        let der_hex = sig.to_hex();
        assert_eq!(
            der_hex,
            "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"
        );
    }

    #[test]
    fn test_der_encode_both_high_bits() {
        let r =
            BigNumber::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
                .unwrap();
        let s =
            BigNumber::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
                .unwrap();
        let sig = Signature::new(r, s);
        let der_hex = sig.to_hex();
        assert_eq!(
            der_hex,
            "3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        );
    }

    // -- DER round-trip tests --

    #[test]
    fn test_der_round_trip_r1_s1() {
        let sig = Signature::new(BigNumber::one(), BigNumber::one());
        let der = sig.to_der();
        let recovered = Signature::from_der(&der).unwrap();
        assert_eq!(recovered.r().cmp(sig.r()), 0);
        assert_eq!(recovered.s().cmp(sig.s()), 0);
    }

    #[test]
    fn test_der_round_trip_real_sig() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09")
                .unwrap();
        let sig = Signature::new(r, s);
        let der = sig.to_der();
        let recovered = Signature::from_der(&der).unwrap();
        assert_eq!(recovered.r().cmp(sig.r()), 0);
        assert_eq!(recovered.s().cmp(sig.s()), 0);
    }

    #[test]
    fn test_der_round_trip_high_bits() {
        let r =
            BigNumber::from_hex("813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365")
                .unwrap();
        let s =
            BigNumber::from_hex("6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba")
                .unwrap();
        let sig = Signature::new(r, s);
        let der = sig.to_der();
        let recovered = Signature::from_der(&der).unwrap();
        assert_eq!(recovered.r().cmp(sig.r()), 0);
        assert_eq!(recovered.s().cmp(sig.s()), 0);
    }

    #[test]
    fn test_der_from_hex() {
        let sig = Signature::from_hex(
            "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
        ).unwrap();
        assert_eq!(
            sig.r().to_hex(),
            "4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41"
        );
        assert_eq!(
            sig.s().to_hex(),
            "181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"
        );
    }

    // -- DER error cases --

    #[test]
    fn test_der_invalid_tag() {
        let result = Signature::from_der(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_invalid_length() {
        let result = Signature::from_der(&[0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_empty() {
        let result = Signature::from_der(&[]);
        assert!(result.is_err());
    }

    // -- Compact encoding tests --

    #[test]
    fn test_compact_round_trip() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09")
                .unwrap();
        let sig = Signature::new(r, s);

        let compact = sig.to_compact();
        assert_eq!(compact.len(), 64);

        let recovered = Signature::from_compact(&compact).unwrap();
        assert_eq!(recovered.r().cmp(sig.r()), 0);
        assert_eq!(recovered.s().cmp(sig.s()), 0);
    }

    #[test]
    fn test_compact_encoding_hex() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09")
                .unwrap();
        let sig = Signature::new(r, s);
        let compact = sig.to_compact();
        let hex = bytes_to_hex(&compact);
        assert_eq!(
            hex,
            "4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"
        );
    }

    #[test]
    fn test_compact_invalid_length() {
        let result = Signature::from_compact(&[0; 63]);
        assert!(result.is_err());
        let result = Signature::from_compact(&[0; 65]);
        assert!(result.is_err());
    }

    // -- Low-S normalization tests --

    #[test]
    fn test_low_s_already_low() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09")
                .unwrap();
        let sig = Signature::new(r, s);
        assert!(sig.has_low_s());

        let normalized = sig.to_low_s();
        assert_eq!(normalized.s().cmp(sig.s()), 0);
    }

    #[test]
    fn test_low_s_needs_normalization() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("e7eadd137135f821b79f5b5322ed6f6137921779f39c5a19b7b03ce459a92438")
                .unwrap();
        let sig = Signature::new(r, s);
        assert!(!sig.has_low_s());

        let normalized = sig.to_low_s();
        assert!(normalized.has_low_s());
        assert_eq!(
            normalized.s().to_hex(),
            "181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"
        );
    }

    #[test]
    fn test_low_s_boundary() {
        // S exactly at N/2 should be considered low
        let curve = Curve::secp256k1();
        let sig = Signature::new(BigNumber::one(), curve.half_n.clone());
        assert!(sig.has_low_s());
    }

    #[test]
    fn test_low_s_boundary_plus_one() {
        // S = N/2 + 1 should be considered high
        let curve = Curve::secp256k1();
        let s = curve.half_n.addn(1);
        let sig = Signature::new(BigNumber::one(), s);
        assert!(!sig.has_low_s());
    }

    // -- Compact BSM encoding tests --

    #[test]
    fn test_compact_bsm_round_trip_compressed() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09")
                .unwrap();
        let sig = Signature::new(r, s);

        let compact = sig.to_compact_bsm(0, true);
        assert_eq!(compact.len(), 65);
        assert_eq!(compact[0], 31); // 27 + 0 + 4 (compressed)

        let (recovered_sig, recovery, compressed) = Signature::from_compact_bsm(&compact).unwrap();
        assert_eq!(recovery, 0);
        assert!(compressed);
        assert_eq!(recovered_sig.r().cmp(sig.r()), 0);
        assert_eq!(recovered_sig.s().cmp(sig.s()), 0);
    }

    #[test]
    fn test_compact_bsm_round_trip_uncompressed() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09")
                .unwrap();
        let sig = Signature::new(r, s);

        let compact = sig.to_compact_bsm(1, false);
        assert_eq!(compact.len(), 65);
        assert_eq!(compact[0], 28); // 27 + 1 + 0 (uncompressed)

        let (recovered_sig, recovery, compressed) = Signature::from_compact_bsm(&compact).unwrap();
        assert_eq!(recovery, 1);
        assert!(!compressed);
        assert_eq!(recovered_sig.r().cmp(sig.r()), 0);
        assert_eq!(recovered_sig.s().cmp(sig.s()), 0);
    }

    #[test]
    fn test_compact_bsm_all_recovery_values() {
        let sig = Signature::new(BigNumber::one(), BigNumber::one());
        for rec in 0..4u8 {
            for &comp in &[true, false] {
                let compact = sig.to_compact_bsm(rec, comp);
                let (_, got_rec, got_comp) = Signature::from_compact_bsm(&compact).unwrap();
                assert_eq!(got_rec, rec, "recovery mismatch for rec={rec} comp={comp}");
                assert_eq!(
                    got_comp, comp,
                    "compressed mismatch for rec={rec} comp={comp}"
                );
            }
        }
    }

    #[test]
    fn test_compact_bsm_invalid_length() {
        assert!(Signature::from_compact_bsm(&[0; 64]).is_err());
        assert!(Signature::from_compact_bsm(&[0; 66]).is_err());
    }

    #[test]
    fn test_compact_bsm_invalid_compact_byte() {
        let mut data = [0u8; 65];
        data[0] = 26; // too low
        assert!(Signature::from_compact_bsm(&data).is_err());
        data[0] = 35; // too high
        assert!(Signature::from_compact_bsm(&data).is_err());
    }

    // -- Public key recovery tests --

    #[test]
    fn test_recover_public_key() {
        use crate::primitives::hash::sha256;
        use crate::primitives::private_key::PrivateKey;

        let priv_key = PrivateKey::from_hex("1").unwrap();
        let pub_key = PublicKey::from_private_key(&priv_key);

        let message = b"test message for recovery";
        let msg_hash = sha256(message);
        let msg_bn = BigNumber::from_bytes(&msg_hash, Endian::Big);

        let sig = priv_key.sign(message, true).unwrap();

        let recovery = sig.calculate_recovery_factor(&pub_key, &msg_bn).unwrap();
        let recovered = sig.recover_public_key(recovery, &msg_bn).unwrap();
        assert_eq!(pub_key, recovered, "recovered key should match original");
    }

    #[test]
    fn test_recover_public_key_multiple_keys() {
        use crate::primitives::hash::sha256;
        use crate::primitives::private_key::PrivateKey;

        // Use 32-byte messages to avoid triggering a pre-existing truncation
        // edge case in ecdsa.rs with short message hashes.
        let keys = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "00000000000000000000000000000000000000000000000000000000000000ff",
            "00000000000000000000000000000000000000000000000000000000000003e8",
            "00000000000000000000000000000000000000000000000000000000deadbeef",
        ];
        for (i, key_hex) in keys.iter().enumerate() {
            let priv_key = PrivateKey::from_hex(key_hex).unwrap();
            let pub_key = PublicKey::from_private_key(&priv_key);

            let message = format!("test message for recovery key {i}");
            let msg_hash = sha256(message.as_bytes());
            let msg_bn = BigNumber::from_bytes(&msg_hash, Endian::Big);

            let sig = priv_key.sign(message.as_bytes(), true).unwrap();

            let recovery = sig.calculate_recovery_factor(&pub_key, &msg_bn).unwrap();
            let recovered = sig.recover_public_key(recovery, &msg_bn).unwrap();
            assert_eq!(
                pub_key, recovered,
                "recovered key should match for key {key_hex}"
            );
        }
    }

    #[test]
    fn test_calculate_recovery_factor_fails_with_wrong_key() {
        use crate::primitives::hash::sha256;
        use crate::primitives::private_key::PrivateKey;

        let priv_key1 = PrivateKey::from_hex("1").unwrap();
        let priv_key2 = PrivateKey::from_hex("2").unwrap();
        let wrong_pub_key = PublicKey::from_private_key(&priv_key2);

        let message = b"test message";
        let msg_hash = sha256(message);
        let msg_bn = BigNumber::from_bytes(&msg_hash, Endian::Big);

        let sig = priv_key1.sign(message, true).unwrap();

        let result = sig.calculate_recovery_factor(&wrong_pub_key, &msg_bn);
        assert!(result.is_err(), "should fail with wrong public key");
    }

    // -- DER + compact consistency test --

    #[test]
    fn test_der_compact_same_values() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09")
                .unwrap();
        let sig = Signature::new(r, s);

        // Both encodings should decode to the same values
        let from_der = Signature::from_der(&sig.to_der()).unwrap();
        let from_compact = Signature::from_compact(&sig.to_compact()).unwrap();

        assert_eq!(from_der.r().cmp(from_compact.r()), 0);
        assert_eq!(from_der.s().cmp(from_compact.s()), 0);
    }

    // -- Test vector validation --

    #[test]
    fn test_all_der_vectors() {
        let vectors: Vec<(&str, &str, &str)> = vec![
            ("01", "01", "3006020101020101"),
            ("ff", "ff", "3008020200ff020200ff"),
            (
                "4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41",
                "181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
                "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
            ),
            (
                "813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365",
                "6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba",
                "3045022100813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc983236502206ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba",
            ),
        ];

        for (r_hex, s_hex, expected_der) in vectors {
            let r = BigNumber::from_hex(r_hex).unwrap();
            let s = BigNumber::from_hex(s_hex).unwrap();
            let sig = Signature::new(r, s);

            // Test encoding
            let der_hex = sig.to_hex();
            assert_eq!(der_hex, expected_der, "DER encoding mismatch for r={r_hex}");

            // Test round-trip
            let recovered = Signature::from_der(&sig.to_der()).unwrap();
            assert_eq!(
                recovered.r().cmp(sig.r()),
                0,
                "round-trip r mismatch for r={r_hex}"
            );
            assert_eq!(
                recovered.s().cmp(sig.s()),
                0,
                "round-trip s mismatch for r={r_hex}"
            );
        }
    }
}
