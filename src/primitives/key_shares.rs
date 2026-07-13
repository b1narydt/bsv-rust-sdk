//! Shamir's Secret Sharing for private keys.
//!
//! Implements key splitting and reconstruction using polynomial interpolation
//! over GF(p). Follows the TS SDK PrivateKey.ts KeyShares implementation.

use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::curve::Curve;
use crate::primitives::error::PrimitivesError;
use crate::primitives::hash::sha512_hmac;
use crate::primitives::polynomial::{PointInFiniteField, Polynomial};
use crate::primitives::private_key::PrivateKey;
use crate::primitives::random::random_bytes;
use crate::primitives::utils::to_hex;

/// Shamir's Secret Sharing for PrivateKey backup and recovery.
///
/// Splits a private key into `total` shares such that any `threshold`
/// shares can reconstruct the original key, but fewer shares reveal
/// nothing about the secret.
///
/// Share format (backup string): "base58(x).base58(y).threshold.integrity"
/// where integrity is the first 8 hex chars of hash160(pubkey) as hex.
pub struct KeyShares {
    pub points: Vec<PointInFiniteField>,
    pub threshold: usize,
    pub integrity: String,
}

impl KeyShares {
    /// Create a new KeyShares instance.
    pub fn new(points: Vec<PointInFiniteField>, threshold: usize, integrity: String) -> Self {
        KeyShares {
            points,
            threshold,
            integrity,
        }
    }

    /// Split a private key into shares using Shamir's Secret Sharing.
    ///
    /// # Arguments
    /// * `key` - The private key to split
    /// * `threshold` - Minimum shares needed to reconstruct (must be >= 2)
    /// * `total` - Total shares to generate (must be >= threshold)
    ///
    /// # Returns
    /// A KeyShares instance containing the shares, threshold, and integrity hash.
    pub fn split(
        key: &PrivateKey,
        threshold: usize,
        total: usize,
    ) -> Result<Self, PrimitivesError> {
        if threshold < 2 {
            return Err(PrimitivesError::ThresholdError(
                "threshold must be at least 2".to_string(),
            ));
        }
        if total < 2 {
            return Err(PrimitivesError::ThresholdError(
                "totalShares must be at least 2".to_string(),
            ));
        }
        if threshold > total {
            return Err(PrimitivesError::ThresholdError(
                "threshold should be less than or equal to totalShares".to_string(),
            ));
        }

        let curve = Curve::secp256k1();
        let key_bytes = key.to_bytes();
        let poly = Polynomial::from_private_key(&key_bytes, threshold);

        let mut points = Vec::with_capacity(total);
        let mut used_x_coords: Vec<BigNumber> = Vec::new();

        // Cryptographically secure x-coordinate generation
        // Matching TS SDK: uses HMAC-SHA-512 with master seed for x-coordinate generation
        let seed = random_bytes(64);

        for i in 0..total {
            let mut x: BigNumber;
            let mut attempts = 0u32;

            loop {
                let mut counter = Vec::new();
                counter.push(i as u8);
                counter.push(attempts as u8);
                counter.extend_from_slice(&random_bytes(32));

                let h = sha512_hmac(&seed, &counter);
                x = BigNumber::from_bytes(&h, Endian::Big);
                x = x
                    .umod(&curve.p)
                    .map_err(|e| PrimitivesError::ArithmeticError(format!("mod p: {e}")))?;

                attempts += 1;
                if attempts > 5 {
                    return Err(PrimitivesError::ThresholdError(
                        "Failed to generate unique x coordinate after 5 attempts".to_string(),
                    ));
                }

                // Check x is non-zero and not already used
                if x.is_zero() {
                    continue;
                }
                let mut duplicate = false;
                for existing in &used_x_coords {
                    if existing.cmp(&x) == 0 {
                        duplicate = true;
                        break;
                    }
                }
                if !duplicate {
                    break;
                }
            }

            used_x_coords.push(x.clone());
            let y = poly.value_at(&x);
            points.push(PointInFiniteField::new(x, y));
        }

        // Integrity hash: first 8 hex chars of hash160(compressed pubkey) as hex
        // TS SDK: this.toPublicKey().toHash('hex').slice(0, 8)
        let pubkey = key.to_public_key();
        let pubkey_hash = pubkey.to_hash();
        let integrity = to_hex(&pubkey_hash);
        let integrity = integrity[..8].to_string();

        Ok(KeyShares {
            points,
            threshold,
            integrity,
        })
    }

    /// Convert shares to backup format strings.
    ///
    /// Each share is formatted as: "base58(x).base58(y).threshold.integrity"
    pub fn to_backup_format(&self) -> Vec<String> {
        self.points
            .iter()
            .map(|share| {
                format!(
                    "{}.{}.{}",
                    share.to_string_repr(),
                    self.threshold,
                    self.integrity
                )
            })
            .collect()
    }

    /// Parse shares from backup format strings.
    ///
    /// Each share must be in format: "base58(x).base58(y).threshold.integrity"
    pub fn from_backup_format(shares: &[String]) -> Result<Self, PrimitivesError> {
        if shares.is_empty() {
            return Err(PrimitivesError::InvalidFormat(
                "No shares provided".to_string(),
            ));
        }

        let mut threshold = 0usize;
        let mut integrity = String::new();
        let mut points = Vec::with_capacity(shares.len());

        for (idx, share) in shares.iter().enumerate() {
            let parts: Vec<&str> = share.split('.').collect();
            if parts.len() != 4 {
                return Err(PrimitivesError::InvalidFormat(format!(
                    "Invalid share format in share {idx}. Expected format: \"x.y.t.i\" - received {share}"
                )));
            }

            let t_str = parts[2];
            let i_str = parts[3];

            let t: usize = t_str.parse().map_err(|_| {
                PrimitivesError::InvalidFormat(format!(
                    "Threshold not a valid number in share {idx}"
                ))
            })?;

            if idx != 0 && threshold != t {
                return Err(PrimitivesError::InvalidFormat(format!(
                    "Threshold mismatch in share {idx}"
                )));
            }
            if idx != 0 && integrity != i_str {
                return Err(PrimitivesError::InvalidFormat(format!(
                    "Integrity mismatch in share {idx}"
                )));
            }

            threshold = t;
            integrity = i_str.to_string();

            let point_str = format!("{}.{}", parts[0], parts[1]);
            let point = PointInFiniteField::from_string_repr(&point_str)?;
            points.push(point);
        }

        Ok(KeyShares::new(points, threshold, integrity))
    }

    /// Reconstruct a private key from shares.
    ///
    /// Requires at least `threshold` shares. Uses Lagrange interpolation
    /// to recover the secret (polynomial value at x=0).
    ///
    /// # Arguments
    /// * `shares` - The KeyShares containing points, threshold, and integrity hash
    ///
    /// # Returns
    /// The reconstructed PrivateKey, validated against the integrity hash.
    pub fn reconstruct(shares: &KeyShares) -> Result<PrivateKey, PrimitivesError> {
        let threshold = shares.threshold;

        if threshold < 2 {
            return Err(PrimitivesError::ThresholdError(
                "threshold must be at least 2".to_string(),
            ));
        }

        if shares.points.len() < threshold {
            return Err(PrimitivesError::ThresholdError(format!(
                "At least {threshold} shares are required to reconstruct the private key"
            )));
        }

        // Check for duplicate x values
        for i in 0..threshold {
            for j in (i + 1)..threshold {
                if shares.points[i].x.cmp(&shares.points[j].x) == 0 {
                    return Err(PrimitivesError::ThresholdError(
                        "Duplicate share detected, each must be unique.".to_string(),
                    ));
                }
            }
        }

        // Lagrange interpolation at x=0
        let poly = Polynomial::new(shares.points.clone(), Some(threshold));
        let secret = poly.value_at(&BigNumber::zero());

        // Create PrivateKey from recovered secret
        let secret_bytes = secret.to_array(Endian::Big, Some(32));
        let key = PrivateKey::from_bytes(&secret_bytes)?;

        // Validate integrity hash
        let pubkey = key.to_public_key();
        let pubkey_hash = pubkey.to_hash();
        let integrity_hash = to_hex(&pubkey_hash);
        let integrity_check = &integrity_hash[..8];

        if integrity_check != shares.integrity {
            return Err(PrimitivesError::ThresholdError(
                "Integrity hash mismatch".to_string(),
            ));
        }

        Ok(key)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_shares_split_produces_correct_count() {
        let key = PrivateKey::from_random().unwrap();
        let shares = KeyShares::split(&key, 2, 5).unwrap();
        assert_eq!(shares.points.len(), 5);
        assert_eq!(shares.threshold, 2);
        assert!(!shares.integrity.is_empty());
    }

    #[test]
    fn test_key_shares_split_and_reconstruct_threshold_2_of_3() {
        let key = PrivateKey::from_random().unwrap();
        let shares = KeyShares::split(&key, 2, 3).unwrap();

        // Use first 2 shares (indices 0, 1)
        let subset = KeyShares::new(
            shares.points[..2].to_vec(),
            shares.threshold,
            shares.integrity.clone(),
        );
        let recovered = KeyShares::reconstruct(&subset).unwrap();
        assert_eq!(
            recovered.to_hex(),
            key.to_hex(),
            "Should recover original key from 2 of 3 shares"
        );
    }

    #[test]
    fn test_key_shares_split_and_reconstruct_threshold_3_of_5() {
        let key = PrivateKey::from_random().unwrap();
        let shares = KeyShares::split(&key, 3, 5).unwrap();

        // Use shares at indices 0, 2, 4
        let subset = KeyShares::new(
            vec![
                shares.points[0].clone(),
                shares.points[2].clone(),
                shares.points[4].clone(),
            ],
            shares.threshold,
            shares.integrity.clone(),
        );
        let recovered = KeyShares::reconstruct(&subset).unwrap();
        assert_eq!(
            recovered.to_hex(),
            key.to_hex(),
            "Should recover original key from 3 of 5 shares"
        );
    }

    #[test]
    fn test_key_shares_insufficient_shares_fails() {
        let key = PrivateKey::from_random().unwrap();
        let shares = KeyShares::split(&key, 3, 5).unwrap();

        // Only provide 2 shares when threshold is 3
        let subset = KeyShares::new(
            shares.points[..2].to_vec(),
            shares.threshold,
            shares.integrity.clone(),
        );
        let result = KeyShares::reconstruct(&subset);
        assert!(
            result.is_err(),
            "Should fail with fewer than threshold shares"
        );
    }

    #[test]
    fn test_key_shares_threshold_validation() {
        let key = PrivateKey::from_random().unwrap();

        // threshold < 2
        assert!(KeyShares::split(&key, 1, 3).is_err());

        // total < 2
        assert!(KeyShares::split(&key, 2, 1).is_err());

        // threshold > total
        assert!(KeyShares::split(&key, 4, 3).is_err());
    }

    #[test]
    fn test_key_shares_backup_format_roundtrip() {
        let key = PrivateKey::from_random().unwrap();
        let shares = KeyShares::split(&key, 2, 3).unwrap();

        // Convert to backup format
        let backup = shares.to_backup_format();
        assert_eq!(backup.len(), 3);

        // Each backup string should have 4 dot-separated parts
        for b in &backup {
            let parts: Vec<&str> = b.split('.').collect();
            assert_eq!(parts.len(), 4, "Backup format should be x.y.t.i");
        }

        // Parse back and reconstruct
        let parsed = KeyShares::from_backup_format(&backup[..2]).unwrap();
        let recovered = KeyShares::reconstruct(&parsed).unwrap();
        assert_eq!(
            recovered.to_hex(),
            key.to_hex(),
            "Should recover from backup format"
        );
    }

    #[test]
    fn test_key_shares_integrity_hash() {
        let key = PrivateKey::from_random().unwrap();
        let shares = KeyShares::split(&key, 2, 3).unwrap();

        // Integrity should be 8 hex chars
        assert_eq!(
            shares.integrity.len(),
            8,
            "Integrity hash should be 8 hex chars"
        );

        // All shares in backup format should have the same integrity
        let backup = shares.to_backup_format();
        for b in &backup {
            assert!(b.ends_with(&shares.integrity));
        }
    }

    #[test]
    fn test_key_shares_integrity_mismatch_detected() {
        let key = PrivateKey::from_random().unwrap();
        let shares = KeyShares::split(&key, 2, 3).unwrap();

        // Corrupt integrity
        let corrupt_shares = KeyShares::new(
            shares.points[..2].to_vec(),
            shares.threshold,
            "deadbeef".to_string(), // wrong integrity
        );
        let result = KeyShares::reconstruct(&corrupt_shares);
        assert!(result.is_err(), "Should fail on integrity mismatch");
    }

    #[test]
    fn test_key_shares_known_key() {
        // Use a known key for reproducibility
        let key = PrivateKey::from_hex(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();

        let shares = KeyShares::split(&key, 2, 3).unwrap();
        let subset = KeyShares::new(
            shares.points[1..3].to_vec(),
            shares.threshold,
            shares.integrity.clone(),
        );
        let recovered = KeyShares::reconstruct(&subset).unwrap();
        assert_eq!(recovered.to_hex(), key.to_hex(), "Should recover known key");
    }

    #[test]
    fn test_key_shares_invalid_backup_format() {
        let bad = vec!["not.valid".to_string()];
        assert!(KeyShares::from_backup_format(&bad).is_err());
    }

    #[test]
    fn test_key_shares_any_subset_reconstructs() {
        // With threshold=2, total=4, any 2 shares should work
        let key = PrivateKey::from_random().unwrap();
        let shares = KeyShares::split(&key, 2, 4).unwrap();

        // Try all pairs
        for i in 0..4 {
            for j in (i + 1)..4 {
                let subset = KeyShares::new(
                    vec![shares.points[i].clone(), shares.points[j].clone()],
                    shares.threshold,
                    shares.integrity.clone(),
                );
                let recovered = KeyShares::reconstruct(&subset).unwrap();
                assert_eq!(
                    recovered.to_hex(),
                    key.to_hex(),
                    "Shares ({i}, {j}) should reconstruct"
                );
            }
        }
    }
}
