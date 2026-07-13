//! Polynomial operations for threshold cryptography (Shamir's Secret Sharing).
//!
//! Implements polynomial representation using (x, y) points in GF(p) where p
//! is the secp256k1 field prime, and Lagrange interpolation for secret recovery.
//! Follows the TS SDK Polynomial.ts implementation exactly.

use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::curve::Curve;
use crate::primitives::error::PrimitivesError;
use crate::primitives::utils::{base58_decode, base58_encode};

/// A point in GF(p) representing (x, y) coordinates for polynomial evaluation.
///
/// All arithmetic is performed mod p (the secp256k1 field prime).
/// This matches the TS SDK's PointInFiniteField class.
#[derive(Clone, Debug)]
pub struct PointInFiniteField {
    pub x: BigNumber,
    pub y: BigNumber,
}

impl PointInFiniteField {
    /// Create a new point, reducing coordinates mod p.
    pub fn new(x: BigNumber, y: BigNumber) -> Self {
        let curve = Curve::secp256k1();
        let x_mod = x.umod(&curve.p).unwrap_or(x);
        let y_mod = y.umod(&curve.p).unwrap_or(y);
        PointInFiniteField { x: x_mod, y: y_mod }
    }

    /// Serialize this point as "base58(x).base58(y)".
    pub fn to_string_repr(&self) -> String {
        let x_bytes = self.x.to_array(Endian::Big, None);
        let y_bytes = self.y.to_array(Endian::Big, None);
        format!("{}.{}", base58_encode(&x_bytes), base58_encode(&y_bytes))
    }

    /// Parse a point from "base58(x).base58(y)" format.
    pub fn from_string_repr(s: &str) -> Result<Self, PrimitivesError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(PrimitivesError::InvalidFormat(format!(
                "Expected 'x.y' format, got: {s}"
            )));
        }
        let x_bytes = base58_decode(parts[0])?;
        let y_bytes = base58_decode(parts[1])?;
        let x = BigNumber::from_bytes(&x_bytes, Endian::Big);
        let y = BigNumber::from_bytes(&y_bytes, Endian::Big);
        Ok(PointInFiniteField::new(x, y))
    }
}

/// Polynomial over GF(p) represented by its evaluation points.
///
/// Used for Lagrange interpolation in Shamir's Secret Sharing.
/// The polynomial passes through the stored points and can be evaluated
/// at any x value using Lagrange interpolation.
pub struct Polynomial {
    pub points: Vec<PointInFiniteField>,
    pub threshold: usize,
}

impl Polynomial {
    /// Create a new polynomial from points with optional threshold.
    ///
    /// If threshold is not specified, it defaults to the number of points.
    pub fn new(points: Vec<PointInFiniteField>, threshold: Option<usize>) -> Self {
        let t = threshold.unwrap_or(points.len());
        Polynomial {
            points,
            threshold: t,
        }
    }

    /// Create a polynomial from a private key for Shamir's Secret Sharing.
    ///
    /// The private key value is the y-intercept (x=0, y=key).
    /// Additional (threshold - 1) random points are generated.
    pub fn from_private_key(key_bytes: &[u8], threshold: usize) -> Self {
        let curve = Curve::secp256k1();
        let key_bn = BigNumber::from_bytes(key_bytes, Endian::Big);

        // The key is the y-intercept: point at x=0
        let mut points = vec![PointInFiniteField::new(BigNumber::zero(), key_bn)];

        // Generate (threshold - 1) random points
        for _ in 1..threshold {
            let random_x_bytes = crate::primitives::random::random_bytes(32);
            let random_y_bytes = crate::primitives::random::random_bytes(32);
            let random_x = BigNumber::from_bytes(&random_x_bytes, Endian::Big)
                .umod(&curve.p)
                .unwrap_or(BigNumber::one());
            let random_y = BigNumber::from_bytes(&random_y_bytes, Endian::Big)
                .umod(&curve.p)
                .unwrap_or(BigNumber::one());
            points.push(PointInFiniteField::new(random_x, random_y));
        }

        Polynomial::new(points, Some(threshold))
    }

    /// Evaluate the polynomial at x using Lagrange interpolation.
    ///
    /// Uses the stored points and Lagrange basis polynomials to compute
    /// the polynomial's value at the given x coordinate. All arithmetic
    /// is performed mod p (secp256k1 field prime).
    pub fn value_at(&self, x: &BigNumber) -> BigNumber {
        let curve = Curve::secp256k1();
        let p = &curve.p;

        let mut y = BigNumber::zero();

        for i in 0..self.threshold {
            let mut term = self.points[i].y.clone();

            for j in 0..self.threshold {
                if i != j {
                    let xj = &self.points[j].x;
                    let xi = &self.points[i].x;

                    // numerator = (x - xj) mod p
                    let numerator = x.sub(xj).umod(p).unwrap_or(BigNumber::zero());

                    // denominator = (xi - xj) mod p
                    let denominator = xi.sub(xj).umod(p).unwrap_or(BigNumber::zero());

                    // denominator_inverse = denominator^(-1) mod p
                    let denominator_inverse = denominator.invm(p).unwrap_or(BigNumber::zero());

                    // fraction = numerator * denominator_inverse mod p
                    let fraction = numerator
                        .mul(&denominator_inverse)
                        .umod(p)
                        .unwrap_or(BigNumber::zero());

                    // term = term * fraction mod p
                    term = term.mul(&fraction).umod(p).unwrap_or(BigNumber::zero());
                }
            }

            y = y.add(&term).umod(p).unwrap_or(BigNumber::zero());
        }

        y
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_in_finite_field_new() {
        let p = PointInFiniteField::new(BigNumber::from_number(5), BigNumber::from_number(10));
        assert_eq!(p.x.cmp(&BigNumber::from_number(5)), 0);
        assert_eq!(p.y.cmp(&BigNumber::from_number(10)), 0);
    }

    #[test]
    fn test_point_in_finite_field_mod_p() {
        let curve = Curve::secp256k1();
        // Value larger than p should be reduced
        let large = curve.p.add(&BigNumber::from_number(1));
        let p = PointInFiniteField::new(large, BigNumber::from_number(5));
        assert_eq!(p.x.cmp(&BigNumber::from_number(1)), 0);
    }

    #[test]
    fn test_point_in_finite_field_string_roundtrip() {
        let p =
            PointInFiniteField::new(BigNumber::from_number(12345), BigNumber::from_number(67890));
        let s = p.to_string_repr();
        let recovered = PointInFiniteField::from_string_repr(&s).unwrap();
        assert_eq!(recovered.x.cmp(&p.x), 0);
        assert_eq!(recovered.y.cmp(&p.y), 0);
    }

    #[test]
    fn test_polynomial_value_at_intercept() {
        // A polynomial through (0, 42) and (1, 100) evaluated at x=0 should return 42
        let points = vec![
            PointInFiniteField::new(BigNumber::zero(), BigNumber::from_number(42)),
            PointInFiniteField::new(BigNumber::one(), BigNumber::from_number(100)),
        ];
        let poly = Polynomial::new(points, Some(2));
        let val = poly.value_at(&BigNumber::zero());
        assert_eq!(val.cmp(&BigNumber::from_number(42)), 0);
    }

    #[test]
    fn test_polynomial_value_at_known_point() {
        // A polynomial through (0, 42) and (1, 100) evaluated at x=1 should return 100
        let points = vec![
            PointInFiniteField::new(BigNumber::zero(), BigNumber::from_number(42)),
            PointInFiniteField::new(BigNumber::one(), BigNumber::from_number(100)),
        ];
        let poly = Polynomial::new(points, Some(2));
        let val = poly.value_at(&BigNumber::one());
        assert_eq!(val.cmp(&BigNumber::from_number(100)), 0);
    }

    #[test]
    fn test_polynomial_lagrange_three_points() {
        // Three points: (1, 5), (2, 10), (3, 17)
        // Lagrange interpolation at x=0 should recover the secret
        let points = vec![
            PointInFiniteField::new(BigNumber::from_number(1), BigNumber::from_number(5)),
            PointInFiniteField::new(BigNumber::from_number(2), BigNumber::from_number(10)),
            PointInFiniteField::new(BigNumber::from_number(3), BigNumber::from_number(17)),
        ];
        let poly = Polynomial::new(points, Some(3));
        let secret = poly.value_at(&BigNumber::zero());

        // Verify: the polynomial is y = x^2 + x + 2 (or something that fits)
        // Actually let's compute manually:
        // L1(0) at x1=1: (0-2)(0-3)/((1-2)(1-3)) = (-2)(-3)/((-1)(-2)) = 6/2 = 3
        // L2(0) at x2=2: (0-1)(0-3)/((2-1)(2-3)) = (-1)(-3)/((1)(-1)) = 3/(-1) = -3
        // L3(0) at x3=3: (0-1)(0-2)/((3-1)(3-2)) = (-1)(-2)/((2)(1)) = 2/2 = 1
        // secret = 5*3 + 10*(-3) + 17*1 = 15 - 30 + 17 = 2
        assert_eq!(secret.cmp(&BigNumber::from_number(2)), 0);
    }

    #[test]
    fn test_polynomial_from_private_key() {
        let key_bytes = BigNumber::from_number(42).to_array(Endian::Big, Some(32));
        let poly = Polynomial::from_private_key(&key_bytes, 3);
        assert_eq!(poly.points.len(), 3);
        assert_eq!(poly.threshold, 3);

        // First point should be (0, 42)
        assert_eq!(poly.points[0].x.cmp(&BigNumber::zero()), 0);
        assert_eq!(poly.points[0].y.cmp(&BigNumber::from_number(42)), 0);
    }

    #[test]
    fn test_polynomial_from_private_key_reconstruct() {
        // Create polynomial from key, evaluate at several x values,
        // then use those points to reconstruct the key at x=0
        let secret = BigNumber::from_number(123456789);
        let key_bytes = secret.to_array(Endian::Big, Some(32));
        let poly = Polynomial::from_private_key(&key_bytes, 3);

        // Evaluate at x=1, 2, 3 to get shares
        let shares: Vec<PointInFiniteField> = (1..=3)
            .map(|i| {
                let x = BigNumber::from_number(i);
                let y = poly.value_at(&x);
                PointInFiniteField::new(x, y)
            })
            .collect();

        // Reconstruct using all 3 shares
        let recon_poly = Polynomial::new(shares, Some(3));
        let recovered = recon_poly.value_at(&BigNumber::zero());
        assert_eq!(recovered.cmp(&secret), 0, "Should recover original secret");
    }
}
