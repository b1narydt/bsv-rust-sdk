//! ECDSA signing and verification using secp256k1.
//!
//! Implements the Elliptic Curve Digital Signature Algorithm (ECDSA) with
//! RFC 6979 deterministic nonce generation via HMAC-DRBG. Follows the
//! TS SDK ECDSA.ts implementation for cross-language compatibility.

use crate::primitives::base_point::BasePoint;
use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::curve::Curve;
use crate::primitives::drbg::Drbg;
use crate::primitives::error::PrimitivesError;
use crate::primitives::jacobian_point::JacobianPoint;
use crate::primitives::point::Point;
use crate::primitives::signature::Signature;

/// Truncate a message hash BigNumber to the bit length of the curve order n.
///
/// If the hash has more bits than n, right-shift to truncate.
/// If truncOnly is false and the result is >= n, subtract n.
/// This follows FIPS 186-4 message truncation rules.
fn truncate_to_n(msg: &BigNumber, trunc_only: bool) -> BigNumber {
    let curve = Curve::secp256k1();
    let n_bit_length = curve.n.bit_length();
    let delta = (msg.byte_length() * 8).saturating_sub(n_bit_length);

    let mut result = msg.clone();
    if delta > 0 {
        result = result.ushrn(delta);
    }
    if !trunc_only && result.cmp(&curve.n) >= 0 {
        result = result.sub(&curve.n);
    }
    result
}

/// Sign a message hash using ECDSA with RFC 6979 deterministic nonce.
///
/// Arguments:
/// - message_hash: 32-byte SHA-256 hash of the message
/// - private_key: the private key as a BigNumber in [1, n-1]
/// - force_low_s: if true, ensure s <= n/2 (BIP 62 / BIP 146)
///
/// Returns a Signature(r, s) or an error.
pub fn ecdsa_sign(
    message_hash: &[u8; 32],
    private_key: &BigNumber,
    force_low_s: bool,
) -> Result<Signature, PrimitivesError> {
    let curve = Curve::secp256k1();
    let n = &curve.n;
    let n_byte_len = n.byte_length();

    // Convert message hash to BigNumber and truncate
    let msg_bn = BigNumber::from_bytes(message_hash, Endian::Big);
    let msg = truncate_to_n(&msg_bn, false);

    // Prepare DRBG entropy (private key bytes) and nonce (message hash bytes)
    let key_bytes = private_key.to_array(Endian::Big, Some(n_byte_len));
    let nonce_bytes = msg.to_array(Endian::Big, Some(n_byte_len));

    let mut entropy = [0u8; 32];
    let mut nonce = [0u8; 32];
    entropy.copy_from_slice(&key_bytes[..32]);
    nonce.copy_from_slice(&nonce_bytes[..32]);

    let mut drbg = Drbg::new(&entropy, &nonce);

    let ns1 = n.subn(1);
    let base_point = BasePoint::instance();

    loop {
        // Generate k from DRBG
        let k_bytes = drbg.generate(n_byte_len);
        let k_hex: String = k_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let k_bn = BigNumber::from_hex(&k_hex)
            .map_err(|_| PrimitivesError::ArithmeticError("invalid k hex".to_string()))?;

        // Truncate k to n bit length (trunc_only=true)
        let k_bn = truncate_to_n(&k_bn, true);

        // k must be in [1, n-1]
        if k_bn.cmpn(1) < 0 || k_bn.cmp(&ns1) > 0 {
            continue;
        }

        // R = k * G
        let r_point = base_point.mul(&k_bn);
        if r_point.is_infinity() {
            continue;
        }

        // r = R.x mod n
        let r_bn = r_point
            .get_x()
            .umod(n)
            .map_err(|e| PrimitivesError::ArithmeticError(format!("r mod n: {e}")))?;

        if r_bn.is_zero() {
            continue;
        }

        // s = k^-1 * (hash + r * privkey) mod n
        let k_inv = k_bn
            .invm(n)
            .map_err(|e| PrimitivesError::ArithmeticError(format!("k inverse: {e}")))?;

        let r_times_key = r_bn
            .mul(private_key)
            .umod(n)
            .map_err(|e| PrimitivesError::ArithmeticError(format!("r*key mod n: {e}")))?;

        let sum = msg
            .add(&r_times_key)
            .umod(n)
            .map_err(|e| PrimitivesError::ArithmeticError(format!("hash+r*key mod n: {e}")))?;

        let mut s_bn = k_inv
            .mul(&sum)
            .umod(n)
            .map_err(|e| PrimitivesError::ArithmeticError(format!("s mod n: {e}")))?;

        if s_bn.is_zero() {
            continue;
        }

        // Enforce low-S if requested
        if force_low_s && s_bn.cmp(&curve.half_n) > 0 {
            s_bn = n.sub(&s_bn);
        }

        return Ok(Signature::new(r_bn, s_bn));
    }
}

/// Sign a message hash using ECDSA with a caller-specified k value.
///
/// This is used by RPuzzle to produce a signature whose R-value is
/// deterministic and known to the signer. The k value must be in [1, n-1].
///
/// Arguments:
/// - message_hash: 32-byte SHA-256 hash of the message
/// - private_key: the private key as a BigNumber in [1, n-1]
/// - k: the nonce value to use (must be in [1, n-1])
/// - force_low_s: if true, ensure s <= n/2 (BIP 62 / BIP 146)
///
/// Returns a Signature(r, s) or an error.
pub fn ecdsa_sign_with_k(
    message_hash: &[u8; 32],
    private_key: &BigNumber,
    k: &BigNumber,
    force_low_s: bool,
) -> Result<Signature, PrimitivesError> {
    let curve = Curve::secp256k1();
    let n = &curve.n;

    // Convert message hash to BigNumber and truncate
    let msg_bn = BigNumber::from_bytes(message_hash, Endian::Big);
    let msg = truncate_to_n(&msg_bn, false);

    let ns1 = n.subn(1);

    // Validate k is in [1, n-1]
    if k.cmpn(1) < 0 || k.cmp(&ns1) > 0 {
        return Err(PrimitivesError::ArithmeticError(
            "k must be in [1, n-1]".to_string(),
        ));
    }

    let base_point = BasePoint::instance();

    // R = k * G
    let r_point = base_point.mul(k);
    if r_point.is_infinity() {
        return Err(PrimitivesError::ArithmeticError(
            "k*G is point at infinity".to_string(),
        ));
    }

    // r = R.x mod n
    let r_bn = r_point
        .get_x()
        .umod(n)
        .map_err(|e| PrimitivesError::ArithmeticError(format!("r mod n: {e}")))?;

    if r_bn.is_zero() {
        return Err(PrimitivesError::ArithmeticError("r is zero".to_string()));
    }

    // s = k^-1 * (hash + r * privkey) mod n
    let k_inv = k
        .invm(n)
        .map_err(|e| PrimitivesError::ArithmeticError(format!("k inverse: {e}")))?;

    let r_times_key = r_bn
        .mul(private_key)
        .umod(n)
        .map_err(|e| PrimitivesError::ArithmeticError(format!("r*key mod n: {e}")))?;

    let sum = msg
        .add(&r_times_key)
        .umod(n)
        .map_err(|e| PrimitivesError::ArithmeticError(format!("hash+r*key mod n: {e}")))?;

    let mut s_bn = k_inv
        .mul(&sum)
        .umod(n)
        .map_err(|e| PrimitivesError::ArithmeticError(format!("s mod n: {e}")))?;

    if s_bn.is_zero() {
        return Err(PrimitivesError::ArithmeticError("s is zero".to_string()));
    }

    // Enforce low-S if requested
    if force_low_s && s_bn.cmp(&curve.half_n) > 0 {
        s_bn = n.sub(&s_bn);
    }

    Ok(Signature::new(r_bn, s_bn))
}

/// Verify an ECDSA signature against a message hash and public key.
///
/// Arguments:
/// - message_hash: 32-byte SHA-256 hash of the message
/// - signature: the (r, s) signature to verify
/// - public_key: the signer's public key as a Point
///
/// Returns true if the signature is valid.
pub fn ecdsa_verify(message_hash: &[u8; 32], signature: &Signature, public_key: &Point) -> bool {
    let curve = Curve::secp256k1();
    let n = &curve.n;

    // Convert message hash to BigNumber
    let msg_bn = BigNumber::from_bytes(message_hash, Endian::Big);

    let r = signature.r();
    let s = signature.s();

    // Check r and s are in [1, n-1]
    if r.cmpn(1) < 0 || r.cmp(n) >= 0 {
        return false;
    }
    if s.cmpn(1) < 0 || s.cmp(n) >= 0 {
        return false;
    }

    // s_inv = s^-1 mod n
    let s_inv = match s.invm(n) {
        Ok(inv) => inv,
        Err(_) => return false,
    };

    // u1 = hash * s_inv mod n
    let u1 = match msg_bn.mul(&s_inv).umod(n) {
        Ok(val) => val,
        Err(_) => return false,
    };

    // u2 = r * s_inv mod n
    let u2 = match r.mul(&s_inv).umod(n) {
        Ok(val) => val,
        Err(_) => return false,
    };

    // R = u1*G + u2*Q using Shamir's trick (shared doublings)
    let base_point = BasePoint::instance();
    let q_jac = JacobianPoint::from_affine(&public_key.x, &public_key.y);
    let r_jac = JacobianPoint::shamir_mul_wnaf(&u1, base_point.table(), &u2, &q_jac);

    if r_jac.is_infinity() {
        return false;
    }

    let (rx, _ry) = r_jac.to_affine();

    // v = R.x mod n
    let v = match rx.umod(n) {
        Ok(val) => val,
        Err(_) => return false,
    };

    // Check v == r
    v.cmp(r) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hash::sha256;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // -----------------------------------------------------------------------
    // ECDSA sign: deterministic output
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_sign_deterministic() {
        // Same key + message should always produce the same signature
        let key = BigNumber::from_number(1);
        let msg_hash = sha256(b"test message");

        let sig1 = ecdsa_sign(&msg_hash, &key, false).unwrap();
        let sig2 = ecdsa_sign(&msg_hash, &key, false).unwrap();

        assert_eq!(
            sig1.r().to_hex(),
            sig2.r().to_hex(),
            "r should be deterministic"
        );
        assert_eq!(
            sig1.s().to_hex(),
            sig2.s().to_hex(),
            "s should be deterministic"
        );
    }

    // -----------------------------------------------------------------------
    // ECDSA sign then verify roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_sign_verify_roundtrip() {
        let key = BigNumber::from_number(42);
        let msg_hash = sha256(b"Hello, BSV!");

        let sig = ecdsa_sign(&msg_hash, &key, true).unwrap();

        // Derive public key: pubkey = key * G
        let base_point = BasePoint::instance();
        let pubkey = base_point.mul(&key);

        assert!(
            ecdsa_verify(&msg_hash, &sig, &pubkey),
            "Valid signature should verify"
        );
    }

    // -----------------------------------------------------------------------
    // ECDSA verify: wrong public key
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_verify_wrong_key() {
        let key = BigNumber::from_number(1);
        let wrong_key = BigNumber::from_number(2);
        let msg_hash = sha256(b"test");

        let sig = ecdsa_sign(&msg_hash, &key, false).unwrap();

        let base_point = BasePoint::instance();
        let wrong_pubkey = base_point.mul(&wrong_key);

        assert!(
            !ecdsa_verify(&msg_hash, &sig, &wrong_pubkey),
            "Wrong public key should fail verification"
        );
    }

    // -----------------------------------------------------------------------
    // ECDSA verify: wrong message
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_verify_wrong_message() {
        let key = BigNumber::from_number(1);
        let msg_hash = sha256(b"correct message");
        let wrong_hash = sha256(b"wrong message");

        let sig = ecdsa_sign(&msg_hash, &key, false).unwrap();

        let base_point = BasePoint::instance();
        let pubkey = base_point.mul(&key);

        assert!(
            !ecdsa_verify(&wrong_hash, &sig, &pubkey),
            "Wrong message should fail verification"
        );
    }

    // -----------------------------------------------------------------------
    // ECDSA sign: low-S enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_sign_low_s() {
        let curve = Curve::secp256k1();
        let key = BigNumber::from_number(12345);
        let msg_hash = sha256(b"low-s test");

        let sig = ecdsa_sign(&msg_hash, &key, true).unwrap();
        assert!(
            sig.s().cmp(&curve.half_n) <= 0,
            "S should be <= n/2 when force_low_s is true"
        );
    }

    // -----------------------------------------------------------------------
    // ECDSA sign: test vectors from JSON
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_sign_vectors() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct SignVector {
            private_key_hex: String,
            message_hash_hex: String,
            expected_r: String,
            expected_s: String,
            force_low_s: bool,
            #[allow(dead_code)]
            description: String,
            #[allow(dead_code)]
            note: String,
        }

        let data = include_str!("../../test-vectors/ecdsa_sign.json");
        let vectors: Vec<SignVector> = serde_json::from_str(data).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let key = BigNumber::from_hex(&v.private_key_hex).unwrap();
            let msg_bytes = hex_to_bytes(&v.message_hash_hex);
            let mut msg_hash = [0u8; 32];
            msg_hash.copy_from_slice(&msg_bytes);

            let sig = ecdsa_sign(&msg_hash, &key, v.force_low_s).unwrap();

            let r_hex = sig.r().to_hex();
            let s_hex = sig.s().to_hex();

            // Pad r and s to 64 hex chars for comparison
            let r_padded = format!("{r_hex:0>64}");
            let s_padded = format!("{s_hex:0>64}");

            assert_eq!(r_padded, v.expected_r, "Vector {i}: r mismatch");
            assert_eq!(s_padded, v.expected_s, "Vector {i}: s mismatch");
        }
    }

    // -----------------------------------------------------------------------
    // ECDSA verify: test vectors from JSON
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_verify_vectors() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct VerifyVector {
            message_hash_hex: String,
            public_key_x: String,
            public_key_y: String,
            signature_r: String,
            signature_s: String,
            expected_valid: bool,
            #[allow(dead_code)]
            description: String,
            #[allow(dead_code)]
            note: String,
        }

        let data = include_str!("../../test-vectors/ecdsa_verify.json");
        let vectors: Vec<VerifyVector> = serde_json::from_str(data).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let msg_bytes = hex_to_bytes(&v.message_hash_hex);
            let mut msg_hash = [0u8; 32];
            msg_hash.copy_from_slice(&msg_bytes);

            let pub_x = BigNumber::from_hex(&v.public_key_x).unwrap();
            let pub_y = BigNumber::from_hex(&v.public_key_y).unwrap();
            let pubkey = Point::new(pub_x, pub_y);

            let r = BigNumber::from_hex(&v.signature_r).unwrap();
            let s = BigNumber::from_hex(&v.signature_s).unwrap();
            let sig = Signature::new(r, s);

            let result = ecdsa_verify(&msg_hash, &sig, &pubkey);
            assert_eq!(
                result, v.expected_valid,
                "Vector {}: expected valid={}, got {}",
                i, v.expected_valid, result
            );
        }
    }

    // -----------------------------------------------------------------------
    // ECDSA verify: tampered signature
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_verify_tampered_signature() {
        let key = BigNumber::from_number(7);
        let msg_hash = sha256(b"tamper test");

        let sig = ecdsa_sign(&msg_hash, &key, false).unwrap();

        let base_point = BasePoint::instance();
        let pubkey = base_point.mul(&key);

        // Tamper with r
        let bad_r = sig.r().addn(1);
        let bad_sig = Signature::new(bad_r, sig.s().clone());
        assert!(
            !ecdsa_verify(&msg_hash, &bad_sig, &pubkey),
            "Tampered r should fail"
        );

        // Tamper with s
        let bad_s = sig.s().addn(1);
        let bad_sig = Signature::new(sig.r().clone(), bad_s);
        assert!(
            !ecdsa_verify(&msg_hash, &bad_sig, &pubkey),
            "Tampered s should fail"
        );
    }

    // -----------------------------------------------------------------------
    // ECDSA: multiple keys roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_multiple_keys() {
        let base_point = BasePoint::instance();

        for i in 1..=5 {
            let key = BigNumber::from_number(i * 1000);
            let msg_hash = sha256(format!("message {i}").as_bytes());

            let sig = ecdsa_sign(&msg_hash, &key, true).unwrap();
            let pubkey = base_point.mul(&key);

            assert!(
                ecdsa_verify(&msg_hash, &sig, &pubkey),
                "Key {i} should verify"
            );
        }
    }
}
