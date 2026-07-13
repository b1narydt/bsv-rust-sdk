//! Affine point representation on the secp256k1 curve.
//!
//! Point provides the public-facing API for elliptic curve point operations
//! including addition, scalar multiplication, compression/decompression, and
//! DER encoding. Internally delegates heavy arithmetic to JacobianPoint for
//! efficiency.

use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::curve::Curve;
use crate::primitives::error::PrimitivesError;
use crate::primitives::jacobian_point::JacobianPoint;

/// A point on the secp256k1 curve in affine coordinates (x, y).
///
/// The point at infinity is represented by `inf == true` (x and y are zero).
#[derive(Clone, Debug)]
pub struct Point {
    /// The x-coordinate.
    pub x: BigNumber,
    /// The y-coordinate.
    pub y: BigNumber,
    /// Whether this is the point at infinity.
    pub inf: bool,
}

impl Point {
    /// Create a new point from x, y coordinates.
    pub fn new(x: BigNumber, y: BigNumber) -> Self {
        Point { x, y, inf: false }
    }

    /// Create the point at infinity (identity element).
    pub fn infinity() -> Self {
        Point {
            x: BigNumber::zero(),
            y: BigNumber::zero(),
            inf: true,
        }
    }

    /// Check if this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.inf
    }

    /// Validate that this point lies on the secp256k1 curve.
    /// Returns true if y^2 = x^3 + 7 (mod p).
    pub fn validate(&self) -> bool {
        if self.inf {
            return false;
        }

        let curve = Curve::secp256k1();
        let red = &curve.red;

        let x_red = self.x.to_red(red.clone());
        let y_red = self.y.to_red(red.clone());

        // lhs = y^2 mod p
        let y2 = red.sqr(&y_red);

        // rhs = x^3 + 7 mod p
        let x2 = red.sqr(&x_red);
        let x3 = red.mul(&x_red, &x2);
        let seven = BigNumber::from_number(7).to_red(red.clone());
        let rhs = red.add(&x3, &seven);

        y2.from_red().cmp(&rhs.from_red()) == 0
    }

    /// Recover a point from its x coordinate and y-parity.
    /// `odd` = true means y should be odd.
    pub fn from_x(x: &BigNumber, odd: bool) -> Result<Self, PrimitivesError> {
        let curve = Curve::secp256k1();
        let red = &curve.red;

        let x_red = x.to_red(red.clone());

        // y^2 = x^3 + 7 mod p
        let x2 = red.sqr(&x_red);
        let x3 = red.mul(&x_red, &x2);
        let seven = BigNumber::from_number(7).to_red(red.clone());
        let y2 = red.add(&x3, &seven);

        // sqrt(y^2) mod p
        // For secp256k1, p % 4 == 3, so sqrt(a) = a^((p+1)/4)
        let y_red = red.sqrt(&y2);

        // Verify the square root is valid
        let y_check = red.sqr(&y_red);
        if y_check.from_red().cmp(&y2.from_red()) != 0 {
            return Err(PrimitivesError::PointNotOnCurve);
        }

        let mut y_val = y_red.from_red();

        // Adjust parity
        if y_val.is_odd() != odd {
            y_val = curve.p.sub(&y_val);
        }

        let point = Point::new(x.clone(), y_val);
        if !point.validate() {
            return Err(PrimitivesError::PointNotOnCurve);
        }
        Ok(point)
    }

    /// Parse a point from DER-encoded bytes (compressed or uncompressed).
    ///
    /// Compressed format: 0x02/0x03 || x (33 bytes total)
    /// Uncompressed format: 0x04 || x || y (65 bytes total)
    pub fn from_der(bytes: &[u8]) -> Result<Self, PrimitivesError> {
        if bytes.is_empty() {
            return Err(PrimitivesError::InvalidDer("empty input".to_string()));
        }

        let prefix = bytes[0];

        match prefix {
            0x04 | 0x06 | 0x07 => {
                // Uncompressed or hybrid format
                if bytes.len() != 65 {
                    return Err(PrimitivesError::InvalidDer(format!(
                        "uncompressed point must be 65 bytes, got {}",
                        bytes.len()
                    )));
                }

                // Validate hybrid format parity
                if prefix == 0x06 {
                    if bytes[64] & 1 != 0 {
                        return Err(PrimitivesError::InvalidDer(
                            "hybrid point parity mismatch (expected even y)".to_string(),
                        ));
                    }
                } else if prefix == 0x07 && bytes[64] & 1 == 0 {
                    return Err(PrimitivesError::InvalidDer(
                        "hybrid point parity mismatch (expected odd y)".to_string(),
                    ));
                }

                let x = BigNumber::from_bytes(&bytes[1..33], Endian::Big);
                let y = BigNumber::from_bytes(&bytes[33..65], Endian::Big);

                let point = Point::new(x, y);
                if !point.validate() {
                    return Err(PrimitivesError::PointNotOnCurve);
                }
                Ok(point)
            }
            0x02 | 0x03 => {
                // Compressed format
                if bytes.len() != 33 {
                    return Err(PrimitivesError::InvalidDer(format!(
                        "compressed point must be 33 bytes, got {}",
                        bytes.len()
                    )));
                }

                let x = BigNumber::from_bytes(&bytes[1..33], Endian::Big);
                let odd = prefix == 0x03;
                Point::from_x(&x, odd)
            }
            _ => Err(PrimitivesError::InvalidDer(format!(
                "unknown point format prefix: 0x{prefix:02x}"
            ))),
        }
    }

    /// Parse a point from a hex string (DER encoded).
    pub fn from_string(hex: &str) -> Result<Self, PrimitivesError> {
        let bytes = hex_to_bytes(hex)?;
        Self::from_der(&bytes)
    }

    /// Encode this point to DER format.
    ///
    /// Compressed (33 bytes): 0x02/0x03 || x
    /// Uncompressed (65 bytes): 0x04 || x || y
    pub fn to_der(&self, compressed: bool) -> Vec<u8> {
        if self.inf {
            return vec![0x00];
        }

        let x_bytes = self.x.to_array(Endian::Big, Some(32));

        if compressed {
            let prefix = if self.y.is_even() { 0x02 } else { 0x03 };
            let mut result = Vec::with_capacity(33);
            result.push(prefix);
            result.extend_from_slice(&x_bytes);
            result
        } else {
            let y_bytes = self.y.to_array(Endian::Big, Some(32));
            let mut result = Vec::with_capacity(65);
            result.push(0x04);
            result.extend_from_slice(&x_bytes);
            result.extend_from_slice(&y_bytes);
            result
        }
    }

    /// Encode to hex string (compressed DER).
    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.to_der(true))
    }

    /// Add two points.
    pub fn add(&self, other: &Point) -> Point {
        if self.inf {
            return other.clone();
        }
        if other.inf {
            return self.clone();
        }

        // Use Jacobian arithmetic for efficiency
        let jp1 = JacobianPoint::from_affine(&self.x, &self.y);
        let jp2 = JacobianPoint::from_affine(&other.x, &other.y);
        let result = jp1.add(&jp2);

        if result.is_infinity() {
            return Point::infinity();
        }

        let (x, y) = result.to_affine();
        Point::new(x, y)
    }

    /// Scalar multiplication: self * k.
    pub fn mul(&self, k: &BigNumber) -> Point {
        if k.is_zero() || self.inf {
            return Point::infinity();
        }

        let is_neg = k.is_neg();
        let k_abs = if is_neg { k.neg() } else { k.clone() };

        // Reduce k mod n
        let curve = Curve::secp256k1();
        let k_mod = k_abs.umod(&curve.n).unwrap_or(k_abs);

        if k_mod.is_zero() {
            return Point::infinity();
        }

        let jp = JacobianPoint::from_affine(&self.x, &self.y);
        let result = jp.mul_wnaf(&k_mod);

        if result.is_infinity() {
            return Point::infinity();
        }

        let (x, y) = result.to_affine();
        let point = Point::new(x, y);

        if is_neg {
            point.negate()
        } else {
            point
        }
    }

    /// Negate a point (same x, y = p - y).
    pub fn negate(&self) -> Point {
        if self.inf {
            return self.clone();
        }
        let curve = Curve::secp256k1();
        let neg_y = curve.p.sub(&self.y);
        Point::new(self.x.clone(), neg_y)
    }

    /// Check equality of two points.
    #[allow(clippy::should_implement_trait)]
    pub fn eq(&self, other: &Point) -> bool {
        if self.inf && other.inf {
            return true;
        }
        if self.inf != other.inf {
            return false;
        }
        self.x.cmp(&other.x) == 0 && self.y.cmp(&other.y) == 0
    }

    /// Double this point (P + P = 2P).
    pub fn dbl(&self) -> Point {
        if self.inf {
            return self.clone();
        }
        let jp = JacobianPoint::from_affine(&self.x, &self.y);
        let result = jp.dbl();
        if result.is_infinity() {
            return Point::infinity();
        }
        let (x, y) = result.to_affine();
        Point::new(x, y)
    }

    /// Get x coordinate (clone).
    pub fn get_x(&self) -> BigNumber {
        self.x.clone()
    }

    /// Get y coordinate (clone).
    pub fn get_y(&self) -> BigNumber {
        self.y.clone()
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

    fn g() -> Point {
        let curve = Curve::secp256k1();
        curve.generator()
    }

    #[test]
    fn test_point_infinity() {
        let inf = Point::infinity();
        assert!(inf.is_infinity());
    }

    #[test]
    fn test_point_g_on_curve() {
        let g = g();
        assert!(g.validate());
    }

    #[test]
    fn test_point_infinity_not_on_curve() {
        let inf = Point::infinity();
        assert!(!inf.validate());
    }

    #[test]
    fn test_point_add_g_plus_g() {
        let g = g();
        let two_g = g.add(&g);
        assert_eq!(
            two_g.x.to_hex(),
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );
        assert_eq!(
            two_g.y.to_hex(),
            "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
        );
    }

    #[test]
    fn test_point_add_identity() {
        let g = g();
        let inf = Point::infinity();

        let r1 = g.add(&inf);
        assert!(r1.eq(&g));

        let r2 = inf.add(&g);
        assert!(r2.eq(&g));
    }

    #[test]
    fn test_point_mul_1() {
        let g = g();
        let k = BigNumber::one();
        let result = g.mul(&k);
        assert!(result.eq(&g));
    }

    #[test]
    fn test_point_mul_2_equals_add() {
        let g = g();
        let k = BigNumber::from_number(2);
        let mul_result = g.mul(&k);
        let add_result = g.add(&g);
        assert!(mul_result.eq(&add_result));
    }

    #[test]
    fn test_point_mul_n_is_infinity() {
        let g = g();
        let curve = Curve::secp256k1();
        let result = g.mul(&curve.n);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_point_mul_n_minus_1() {
        let g = g();
        let curve = Curve::secp256k1();
        let n_minus_1 = curve.n.subn(1);
        let result = g.mul(&n_minus_1);
        // (n-1)*G should have same x as G but negated y (= p - G.y)
        assert_eq!(result.x.cmp(&g.x), 0);
        let neg_y = curve.p.sub(&g.y);
        assert_eq!(result.y.cmp(&neg_y), 0);
    }

    #[test]
    fn test_point_negate() {
        let g = g();
        let neg_g = g.negate();
        assert_eq!(neg_g.x.cmp(&g.x), 0);
        let curve = Curve::secp256k1();
        let expected_y = curve.p.sub(&g.y);
        assert_eq!(neg_g.y.cmp(&expected_y), 0);
    }

    #[test]
    fn test_point_negate_add_is_infinity() {
        let g = g();
        let neg_g = g.negate();
        let result = g.add(&neg_g);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_point_compressed_even_y() {
        let g = g();
        let der = g.to_der(true);
        assert_eq!(der.len(), 33);
        // G has even y, so prefix should be 0x02
        assert_eq!(der[0], 0x02);
    }

    #[test]
    fn test_point_uncompressed() {
        let g = g();
        let der = g.to_der(false);
        assert_eq!(der.len(), 65);
        assert_eq!(der[0], 0x04);
    }

    #[test]
    fn test_point_from_der_compressed() {
        let g = g();
        let der = g.to_der(true);
        let recovered = Point::from_der(&der).unwrap();
        assert!(recovered.eq(&g));
    }

    #[test]
    fn test_point_from_der_uncompressed() {
        let g = g();
        let der = g.to_der(false);
        let recovered = Point::from_der(&der).unwrap();
        assert!(recovered.eq(&g));
    }

    #[test]
    fn test_point_from_der_round_trip_compressed() {
        let g = g();
        for k in 1..=10 {
            let p = g.mul(&BigNumber::from_number(k));
            if p.is_infinity() {
                continue;
            }
            let der = p.to_der(true);
            let recovered = Point::from_der(&der).unwrap();
            assert!(recovered.eq(&p), "round-trip failed for k={k}");
        }
    }

    #[test]
    fn test_point_from_der_round_trip_uncompressed() {
        let g = g();
        for k in 1..=10 {
            let p = g.mul(&BigNumber::from_number(k));
            if p.is_infinity() {
                continue;
            }
            let der = p.to_der(false);
            let recovered = Point::from_der(&der).unwrap();
            assert!(recovered.eq(&p), "round-trip failed for k={k}");
        }
    }

    #[test]
    fn test_point_invalid_not_on_curve() {
        // Random bytes that are not on the curve
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(&[0x01; 32]); // x = 1
        bytes.extend_from_slice(&[0x01; 32]); // y = 1
        let result = Point::from_der(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_point_from_string() {
        let g = g();
        let hex = g.to_hex();
        let recovered = Point::from_string(&hex).unwrap();
        assert!(recovered.eq(&g));
    }

    #[test]
    fn test_point_mul_known_multiples() {
        let g = g();
        let expected = vec![
            (
                2,
                "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
            ),
            (
                3,
                "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672",
            ),
            (
                5,
                "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
                "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6",
            ),
            (
                10,
                "a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
                "893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7",
            ),
        ];

        for (k, ex, ey) in expected {
            let result = g.mul(&BigNumber::from_number(k));
            assert_eq!(result.x.to_hex(), ex, "x mismatch for k={k}");
            assert_eq!(result.y.to_hex(), ey, "y mismatch for k={k}");
        }
    }

    #[test]
    fn test_point_dbl() {
        let g = g();
        let dbl = g.dbl();
        let add = g.add(&g);
        assert!(dbl.eq(&add));
    }

    #[test]
    fn test_point_from_x() {
        let curve = Curve::secp256k1();
        // Recover G from its x coordinate
        let p = Point::from_x(&curve.g_x, false).unwrap();
        assert_eq!(p.x.cmp(&curve.g_x), 0);
        assert_eq!(p.y.cmp(&curve.g_y), 0);
    }

    #[test]
    fn test_point_from_x_odd() {
        let curve = Curve::secp256k1();
        // G.y is even, so asking for odd should give p - G.y
        let p = Point::from_x(&curve.g_x, true).unwrap();
        let neg_y = curve.p.sub(&curve.g_y);
        assert_eq!(p.y.cmp(&neg_y), 0);
    }
}
