//! Schnorr Zero-Knowledge Proof (ZKP) protocol implementation.
//!
//! This is a Discrete Log Equality (DLEQ) proof, NOT BIP-340 Schnorr signatures.
//! The protocol proves knowledge of a private key `a` such that A = a*G and S = a*B,
//! linking a public key A to a shared secret S without revealing the private key.
//!
//! Follows the TS SDK Schnorr.ts implementation exactly.

use crate::primitives::base_point::BasePoint;
use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::curve::Curve;
use crate::primitives::error::PrimitivesError;
use crate::primitives::hash::sha256;
use crate::primitives::point::Point;
use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;

/// A Schnorr ZKP proof consisting of two auxiliary points and a scalar.
///
/// This represents a DLEQ proof that the prover knows a private key `a`
/// such that A = a*G and S = a*B (i.e., A and S share the same discrete log
/// relative to G and B respectively).
#[derive(Clone, Debug)]
pub struct SchnorrProof {
    /// R = r*G where r is the random nonce
    pub r_point: Point,
    /// S' = r*B (nonce applied to the other party's public key)
    pub s_prime: Point,
    /// z = r + e*a mod n (the response scalar)
    pub z: BigNumber,
}

/// Compute the Fiat-Shamir challenge hash for the Schnorr DLEQ protocol.
///
/// e = SHA-256(A || B || S || S' || R) mod n
///
/// All points are encoded as compressed DER (33 bytes each).
fn compute_challenge(
    big_a: &Point,
    big_b: &Point,
    big_s: &Point,
    s_prime: &Point,
    r_point: &Point,
) -> BigNumber {
    let curve = Curve::secp256k1();

    let mut message = Vec::with_capacity(33 * 5);
    message.extend_from_slice(&big_a.to_der(true));
    message.extend_from_slice(&big_b.to_der(true));
    message.extend_from_slice(&big_s.to_der(true));
    message.extend_from_slice(&s_prime.to_der(true));
    message.extend_from_slice(&r_point.to_der(true));

    let hash = sha256(&message);
    let e = BigNumber::from_bytes(&hash, Endian::Big);
    e.umod(&curve.n).unwrap_or_else(|_| BigNumber::zero())
}

/// Generate a Schnorr DLEQ proof.
///
/// Proves that the prover knows `a` such that A = a*G and S = a*B.
///
/// Protocol:
/// 1. Generate random nonce r
/// 2. R = r*G, S' = r*B
/// 3. e = SHA-256(A || B || S || S' || R) mod n
/// 4. z = r + e*a mod n
///
/// # Arguments
/// * `a` - The prover's private key
/// * `big_a` - The prover's public key (A = a*G)
/// * `big_b` - The other party's public key
/// * `big_s` - The shared secret point (S = a*B)
///
/// # Returns
/// A `SchnorrProof` containing (R, S', z).
pub fn schnorr_generate_proof(
    a: &PrivateKey,
    big_a: &PublicKey,
    big_b: &PublicKey,
    big_s: &Point,
) -> Result<SchnorrProof, PrimitivesError> {
    let curve = Curve::secp256k1();

    // Generate random nonce r
    let r = PrivateKey::from_random()?;
    let r_pub = r.to_public_key();
    let r_point = r_pub.point().clone();

    // S' = r * B
    let s_prime = big_b.point().mul(r.bn());

    // Compute challenge e = SHA-256(A || B || S || S' || R) mod n
    let e = compute_challenge(big_a.point(), big_b.point(), big_s, &s_prime, &r_point);

    // z = r + e*a mod n
    // Following TS: z = r.add(e.mul(aArg)).umod(this.curve.n)
    let ea = e.mul(a.bn());
    let r_plus_ea = r.bn().add(&ea);
    let z = r_plus_ea
        .umod(&curve.n)
        .map_err(|err| PrimitivesError::ArithmeticError(format!("mod n: {err}")))?;

    Ok(SchnorrProof {
        r_point,
        s_prime,
        z,
    })
}

/// Verify a Schnorr DLEQ proof.
///
/// Checks that the prover knows `a` such that A = a*G and S = a*B.
///
/// Verification:
/// 1. Recompute e = SHA-256(A || B || S || S' || R) mod n
/// 2. Check z*G == R + e*A
/// 3. Check z*B == S' + e*S
///
/// # Arguments
/// * `big_a` - The prover's public key point
/// * `big_b` - The other party's public key point
/// * `big_s` - The shared secret point
/// * `proof` - The proof to verify
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise.
pub fn schnorr_verify_proof(
    big_a: &Point,
    big_b: &Point,
    big_s: &Point,
    proof: &SchnorrProof,
) -> bool {
    let base_point = BasePoint::instance();

    let e = compute_challenge(big_a, big_b, big_s, &proof.s_prime, &proof.r_point);

    // Check 1: z*G == R + e*A
    let z_g = base_point.mul(&proof.z);
    let e_a = big_a.mul(&e);
    let r_plus_ea = proof.r_point.add(&e_a);
    if !z_g.eq(&r_plus_ea) {
        return false;
    }

    // Check 2: z*B == S' + e*S
    let z_b = big_b.mul(&proof.z);
    let e_s = big_s.mul(&e);
    let s_prime_plus_es = proof.s_prime.add(&e_s);
    if !z_b.eq(&s_prime_plus_es) {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_generate_and_verify_proof() {
        // Generate keys
        let a = PrivateKey::from_random().unwrap();
        let big_a = a.to_public_key();

        let b = PrivateKey::from_random().unwrap();
        let big_b = b.to_public_key();

        // Shared secret S = a * B
        let big_s = big_b.point().mul(a.bn());

        // Generate proof
        let proof = schnorr_generate_proof(&a, &big_a, &big_b, &big_s).unwrap();

        // Verify proof
        assert!(
            schnorr_verify_proof(big_a.point(), big_b.point(), &big_s, &proof),
            "Valid proof should verify"
        );
    }

    #[test]
    fn test_schnorr_verify_rejects_tampered_z() {
        let a = PrivateKey::from_random().unwrap();
        let big_a = a.to_public_key();
        let b = PrivateKey::from_random().unwrap();
        let big_b = b.to_public_key();
        let big_s = big_b.point().mul(a.bn());

        let proof = schnorr_generate_proof(&a, &big_a, &big_b, &big_s).unwrap();

        // Tamper with z
        let tampered_proof = SchnorrProof {
            r_point: proof.r_point.clone(),
            s_prime: proof.s_prime.clone(),
            z: proof.z.add(&BigNumber::one()),
        };

        assert!(
            !schnorr_verify_proof(big_a.point(), big_b.point(), &big_s, &tampered_proof),
            "Tampered proof should not verify"
        );
    }

    #[test]
    fn test_schnorr_verify_rejects_wrong_public_key() {
        let a = PrivateKey::from_random().unwrap();
        let big_a = a.to_public_key();
        let b = PrivateKey::from_random().unwrap();
        let big_b = b.to_public_key();
        let big_s = big_b.point().mul(a.bn());

        let proof = schnorr_generate_proof(&a, &big_a, &big_b, &big_s).unwrap();

        // Use wrong A (a different key's public key)
        let wrong_key = PrivateKey::from_random().unwrap();
        let wrong_a = wrong_key.to_public_key();

        assert!(
            !schnorr_verify_proof(wrong_a.point(), big_b.point(), &big_s, &proof),
            "Proof with wrong public key should not verify"
        );
    }

    #[test]
    fn test_schnorr_verify_rejects_wrong_shared_secret() {
        let a = PrivateKey::from_random().unwrap();
        let big_a = a.to_public_key();
        let b = PrivateKey::from_random().unwrap();
        let big_b = b.to_public_key();
        let big_s = big_b.point().mul(a.bn());

        let proof = schnorr_generate_proof(&a, &big_a, &big_b, &big_s).unwrap();

        // Use wrong S (different shared secret)
        let wrong_b = PrivateKey::from_random().unwrap();
        let wrong_s = wrong_b.to_public_key().point().mul(a.bn());

        assert!(
            !schnorr_verify_proof(big_a.point(), big_b.point(), &wrong_s, &proof),
            "Proof with wrong shared secret should not verify"
        );
    }

    #[test]
    fn test_schnorr_multiple_proofs_same_keys() {
        // Multiple proofs with same keys should all verify independently
        let a = PrivateKey::from_random().unwrap();
        let big_a = a.to_public_key();
        let b = PrivateKey::from_random().unwrap();
        let big_b = b.to_public_key();
        let big_s = big_b.point().mul(a.bn());

        for _ in 0..3 {
            let proof = schnorr_generate_proof(&a, &big_a, &big_b, &big_s).unwrap();
            assert!(
                schnorr_verify_proof(big_a.point(), big_b.point(), &big_s, &proof),
                "Each proof should verify independently"
            );
        }
    }

    #[test]
    fn test_schnorr_proof_format() {
        // Verify proof has the expected structure
        let a = PrivateKey::from_random().unwrap();
        let big_a = a.to_public_key();
        let b = PrivateKey::from_random().unwrap();
        let big_b = b.to_public_key();
        let big_s = big_b.point().mul(a.bn());

        let proof = schnorr_generate_proof(&a, &big_a, &big_b, &big_s).unwrap();

        // R should be a valid point on the curve
        assert!(proof.r_point.validate(), "R should be on the curve");

        // S' should be a valid point on the curve
        assert!(proof.s_prime.validate(), "S' should be on the curve");

        // z should be non-zero
        assert!(!proof.z.is_zero(), "z should be non-zero");
    }

    #[test]
    fn test_schnorr_known_key() {
        // Use a known private key for deterministic testing
        let a = PrivateKey::from_hex("1").unwrap();
        let big_a = a.to_public_key();

        let b = PrivateKey::from_hex("2").unwrap();
        let big_b = b.to_public_key();

        // S = a * B = 1 * (2*G) = 2*G
        let big_s = big_b.point().mul(a.bn());

        let proof = schnorr_generate_proof(&a, &big_a, &big_b, &big_s).unwrap();

        assert!(
            schnorr_verify_proof(big_a.point(), big_b.point(), &big_s, &proof),
            "Proof with known keys should verify"
        );
    }
}
