//! AuthCertificate: auth-layer wrapper around wallet::Certificate.
//!
//! Provides sign, verify, field encryption/decryption, and serialization
//! methods for the BRC-31 certificate protocol. Translates from
//! TS SDK Certificate.ts and Go SDK certificate.go.

use std::collections::HashMap;
use std::ops::Deref;

use crate::auth::AuthError;
use crate::primitives::public_key::PublicKey;
use crate::primitives::symmetric_key::SymmetricKey;
use crate::wallet::interfaces::{
    Certificate, CreateSignatureArgs, DecryptArgs, EncryptArgs, GetPublicKeyArgs,
    VerifySignatureArgs, WalletInterface,
};
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Protocol string used when signing/verifying certificates.
pub const CERTIFICATE_SIGNATURE_PROTOCOL: &str = "certificate signature";

/// Protocol string used when encrypting/decrypting certificate field keys.
pub const CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL: &str = "certificate field encryption";

/// Security level for certificate operations.
pub const SECURITY_LEVEL: u8 = 2;

// ---------------------------------------------------------------------------
// Base64 encode/decode helpers (self-contained, no external crate)
// ---------------------------------------------------------------------------

pub(crate) fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

pub(crate) fn base64_decode(s: &str) -> Result<Vec<u8>, AuthError> {
    fn char_to_val(c: u8) -> Result<u8, AuthError> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(AuthError::SerializationError(format!(
                "invalid base64 character: {}",
                c as char
            ))),
        }
    }
    let bytes = s.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            break;
        }
        let a = char_to_val(bytes[i])?;
        let b = if i + 1 < bytes.len() && bytes[i + 1] != b'=' {
            char_to_val(bytes[i + 1])?
        } else {
            0
        };
        let c = if i + 2 < bytes.len() && bytes[i + 2] != b'=' {
            char_to_val(bytes[i + 2])?
        } else {
            0
        };
        let d = if i + 3 < bytes.len() && bytes[i + 3] != b'=' {
            char_to_val(bytes[i + 3])?
        } else {
            0
        };
        let triple = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        result.push(((triple >> 16) & 0xFF) as u8);
        if i + 2 < bytes.len() && bytes[i + 2] != b'=' {
            result.push(((triple >> 8) & 0xFF) as u8);
        }
        if i + 3 < bytes.len() && bytes[i + 3] != b'=' {
            result.push((triple & 0xFF) as u8);
        }
        i += 4;
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// AuthCertificate
// ---------------------------------------------------------------------------

/// Auth-layer wrapper around wallet::Certificate.
///
/// Adds sign, verify, and field encryption/decryption methods used by
/// the BRC-31 authentication protocol. Derefs to the inner
/// wallet::Certificate for transparent field access.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthCertificate {
    /// The underlying wallet Certificate.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub inner: Certificate,
}

impl Deref for AuthCertificate {
    type Target = Certificate;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AuthCertificate {
    /// Create a new AuthCertificate wrapping the given wallet Certificate.
    pub fn new(inner: Certificate) -> Self {
        AuthCertificate { inner }
    }

    /// Serialize the certificate to binary for signing/verification.
    ///
    /// Follows the TS SDK Certificate.toBinary(false) format:
    /// cert_type(32) + serial_number(32) + subject(33) + certifier(33)
    /// + revocation_outpoint(txid_32 + varint_output_index)
    /// + varint(num_fields) + for each field: varint(name_len) + name + varint(val_len) + val
    fn to_binary_for_signing(cert: &Certificate) -> Vec<u8> {
        let mut data = Vec::new();

        // cert_type: 32 bytes
        data.extend_from_slice(&cert.cert_type.0);

        // serial_number: 32 bytes
        data.extend_from_slice(&cert.serial_number.0);

        // subject: 33 bytes compressed public key
        let subject_bytes = cert.subject.to_der();
        data.extend_from_slice(&subject_bytes);

        // certifier: 33 bytes compressed public key
        let certifier_bytes = cert.certifier.to_der();
        data.extend_from_slice(&certifier_bytes);

        // revocation_outpoint: txid(32 bytes) + varint(output_index)
        //
        // TS parity (Certificate.toBinary):
        //   const [txid, outputIndex] = revocationOutpoint.split('.')
        //   writer.write(Utils.toArray(txid, 'hex'))
        //   writer.writeVarIntNum(Number(outputIndex))
        //
        // Two subtleties are load-bearing and mirrored exactly here:
        //  1. `split('.')` with destructuring takes the segment BEFORE the first
        //     dot as txid and the segment between the first and second dot as
        //     outputIndex (any trailing segments are ignored).
        //  2. When there is NO dot (the default sentinel `'00'.repeat(32)`),
        //     `outputIndex` is `undefined`, so `Number(undefined)` is `NaN`, and
        //     `writeVarIntNum(NaN)` falls through every `<` comparison into the
        //     64-bit branch, emitting `0xff` followed by 8 zero bytes (ToInt32(NaN)
        //     == 0 for both the low and high words). This is verified against the
        //     TS SDK: `'00'.repeat(32)` serializes to 32 zero bytes + `ff` + 8
        //     zero bytes (41 bytes total), NOT 32 zero bytes + `00` (33 bytes).
        if let Some(ref outpoint) = cert.revocation_outpoint {
            let mut segments = outpoint.split('.');
            let txid_hex = segments.next().unwrap_or("");
            let output_index_segment = segments.next();

            // Decode txid hex to bytes and write.
            let txid_bytes = hex_decode(txid_hex);
            data.extend_from_slice(&txid_bytes);

            // Number(outputIndex): `undefined` (no dot) -> NaN.
            let output_index = match output_index_segment {
                None => f64::NAN,
                Some(s) => js_number(s),
            };
            write_var_int_num_js(&mut data, output_index);
        }

        // fields: sorted by name
        if let Some(ref fields) = cert.fields {
            let mut field_names: Vec<&String> = fields.keys().collect();
            field_names.sort();
            write_varint(&mut data, field_names.len() as u64);
            for name in field_names {
                let name_bytes = name.as_bytes();
                write_varint(&mut data, name_bytes.len() as u64);
                data.extend_from_slice(name_bytes);

                let value = &fields[name];
                let value_bytes = value.as_bytes();
                write_varint(&mut data, value_bytes.len() as u64);
                data.extend_from_slice(value_bytes);
            }
        } else {
            write_varint(&mut data, 0);
        }

        data
    }

    /// Sign the certificate using the certifier wallet.
    ///
    /// Sets the certificate's signature field. The certifier wallet's identity
    /// key is used as the signing key.
    ///
    /// Translated from TS SDK Certificate.prototype.sign().
    pub async fn sign<W: WalletInterface + ?Sized>(
        cert: &mut Certificate,
        wallet: &W,
    ) -> Result<(), AuthError> {
        if cert.signature.is_some() {
            return Err(AuthError::CertificateValidation(
                "certificate has already been signed".to_string(),
            ));
        }

        // Set certifier to the wallet's identity key
        let identity_result = wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;
        cert.certifier = identity_result.public_key;

        let preimage = Self::to_binary_for_signing(cert);
        let key_id = format!(
            "{} {}",
            base64_encode(&cert.cert_type.0),
            base64_encode(&cert.serial_number.0)
        );

        let result = wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(preimage),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol {
                        security_level: SECURITY_LEVEL,
                        protocol: CERTIFICATE_SIGNATURE_PROTOCOL.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Uninitialized,
                        public_key: None,
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        cert.signature = Some(result.signature);
        Ok(())
    }

    /// Verify the certificate's signature.
    ///
    /// Uses an "anyone" wallet (ProtoWallet with no specific identity) to verify
    /// that the certifier actually signed this certificate.
    ///
    /// Translated from TS SDK Certificate.prototype.verify().
    pub async fn verify<W: WalletInterface + ?Sized>(
        cert: &Certificate,
        wallet: &W,
    ) -> Result<bool, AuthError> {
        let preimage = Self::to_binary_for_signing(cert);
        let signature = cert.signature.clone().unwrap_or_default();
        let key_id = format!(
            "{} {}",
            base64_encode(&cert.cert_type.0),
            base64_encode(&cert.serial_number.0)
        );

        let result = wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(preimage),
                    hash_to_directly_verify: None,
                    signature,
                    protocol_id: Protocol {
                        security_level: SECURITY_LEVEL,
                        protocol: CERTIFICATE_SIGNATURE_PROTOCOL.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(cert.certifier.clone()),
                    },
                    for_self: None,
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        Ok(result.valid)
    }

    /// Get the protocol ID and key ID for certificate field encryption.
    ///
    /// For master cert fields (no serial number yet), pass None for serial_number
    /// and the key_id is just the field_name. For verifiable certificate keyrings,
    /// pass Some(serial_number) and key_id is "{serial_number} {field_name}".
    ///
    /// Translated from TS SDK Certificate.getCertificateFieldEncryptionDetails().
    pub fn get_certificate_field_encryption_details(
        field_name: &str,
        serial_number: Option<&str>,
    ) -> (Protocol, String) {
        let key_id = match serial_number {
            Some(sn) => format!("{} {}", sn, field_name),
            None => field_name.to_string(),
        };
        (
            Protocol {
                security_level: SECURITY_LEVEL,
                protocol: CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL.to_string(),
            },
            key_id,
        )
    }

    /// Encrypt certificate fields using the wallet.
    ///
    /// For each field, generates a random symmetric key, encrypts the field value
    /// with it, then encrypts the symmetric key using the wallet's encrypt method
    /// for the given counterparty.
    ///
    /// Returns (encrypted_fields, keyring) where encrypted_fields maps field names
    /// to base64-encoded encrypted values, and keyring maps field names to
    /// base64-encoded encrypted symmetric keys.
    pub async fn encrypt_fields<W: WalletInterface + ?Sized>(
        fields: &HashMap<String, String>,
        serial_number: Option<&str>,
        counterparty: &PublicKey,
        wallet: &W,
    ) -> Result<(HashMap<String, String>, HashMap<String, String>), AuthError> {
        let mut encrypted_fields = HashMap::new();
        let mut keyring = HashMap::new();

        for (field_name, field_value) in fields {
            // Generate random symmetric key
            let sym_key = SymmetricKey::from_random();

            // Encrypt field value with symmetric key
            let encrypted_value = sym_key.encrypt(field_value.as_bytes())?;
            encrypted_fields.insert(field_name.clone(), base64_encode(&encrypted_value));

            // Encrypt the symmetric key for the counterparty
            let (protocol, key_id) =
                Self::get_certificate_field_encryption_details(field_name, serial_number);

            let encrypt_result = wallet
                .encrypt(
                    EncryptArgs {
                        plaintext: sym_key.to_bytes(),
                        protocol_id: protocol,
                        key_id,
                        counterparty: Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: Some(counterparty.clone()),
                        },
                        privileged: false,
                        privileged_reason: None,
                        seek_permission: None,
                    },
                    None,
                )
                .await?;

            keyring.insert(
                field_name.clone(),
                base64_encode(&encrypt_result.ciphertext),
            );
        }

        Ok((encrypted_fields, keyring))
    }

    /// Decrypt certificate fields using a keyring and the wallet.
    ///
    /// For each field in the keyring:
    /// 1. Decrypt the keyring entry to get the symmetric key
    /// 2. Use the symmetric key to decrypt the field value
    ///
    /// The counterparty is the subject (the party who encrypted the fields).
    pub async fn decrypt_fields<W: WalletInterface + ?Sized>(
        encrypted_fields: &HashMap<String, String>,
        keyring: &HashMap<String, String>,
        serial_number: &str,
        counterparty: &PublicKey,
        wallet: &W,
    ) -> Result<HashMap<String, String>, AuthError> {
        if keyring.is_empty() {
            return Err(AuthError::CertificateValidation(
                "a keyring is required to decrypt certificate fields".to_string(),
            ));
        }

        let mut decrypted = HashMap::new();

        for (field_name, encrypted_key_b64) in keyring {
            // Decrypt the field revelation key from the keyring
            let encrypted_key = base64_decode(encrypted_key_b64)?;
            let (protocol, key_id) =
                Self::get_certificate_field_encryption_details(field_name, Some(serial_number));

            let decrypt_result = wallet
                .decrypt(
                    DecryptArgs {
                        ciphertext: encrypted_key,
                        protocol_id: protocol,
                        key_id,
                        counterparty: Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: Some(counterparty.clone()),
                        },
                        privileged: false,
                        privileged_reason: None,
                        seek_permission: None,
                    },
                    None,
                )
                .await?;

            // Use the decrypted symmetric key to decrypt the field value
            let sym_key = SymmetricKey::from_bytes(&decrypt_result.plaintext)?;
            let encrypted_field_value = match encrypted_fields.get(field_name) {
                Some(v) => base64_decode(v)?,
                None => {
                    return Err(AuthError::CertificateValidation(format!(
                        "field '{}' not found in encrypted fields",
                        field_name
                    )));
                }
            };
            let plaintext_bytes = sym_key.decrypt(&encrypted_field_value)?;
            let plaintext = String::from_utf8(plaintext_bytes).map_err(|e| {
                AuthError::CertificateValidation(format!(
                    "decrypted field '{}' is not valid UTF-8: {}",
                    field_name, e
                ))
            })?;
            decrypted.insert(field_name.clone(), plaintext);
        }

        Ok(decrypted)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Decode hex string to bytes.
fn hex_decode(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    let hex_bytes = hex.as_bytes();
    while i + 1 < hex_bytes.len() {
        let hi = hex_nibble(hex_bytes[i]);
        let lo = hex_nibble(hex_bytes[i + 1]);
        bytes.push((hi << 4) | lo);
        i += 2;
    }
    bytes
}

fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
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

/// Mirror of the TS SDK `Utils.Writer.varIntNum(n: number)` for the
/// revocation-outpoint output index, which is a JS `number` (f64) — including
/// the `NaN` case that arises from `Number(undefined)` when the outpoint has no
/// `.vout` suffix (the default sentinel).
///
/// For all finite, non-negative integer values this is byte-for-byte identical
/// to [`write_varint`]. The extra fidelity is the `NaN` path: because every
/// `NaN < x` comparison in JS is `false`, `varIntNum(NaN)` falls into the 64-bit
/// branch and, since `ToInt32(NaN) == 0`, emits `0xff` followed by 8 zero bytes.
fn write_var_int_num_js(buf: &mut Vec<u8>, n: f64) {
    if n < 0.0 {
        // TS routes negatives through varIntBn(n) which adds 2^64. This is not a
        // valid outpoint index; reproduce the wrap-around best-effort so we never
        // silently diverge on the (unreachable-for-outpoints) negative path.
        let wrapped = (n as i64) as u64;
        buf.push(0xff);
        buf.extend_from_slice(&wrapped.to_le_bytes());
    } else if n < 253.0 {
        buf.push(n as u8);
    } else if n < 0x1_0000 as f64 {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n < 0x1_0000_0000u64 as f64 {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        // >= 2^32 OR NaN (all `<` comparisons above are false for NaN).
        // Rust's `NaN as u64` saturates to 0, matching JS `ToInt32(NaN) == 0`
        // for both the low and high 32-bit words.
        let v = n as u64;
        let low = (v & 0xffff_ffff) as u32;
        let high = ((v >> 32) & 0xffff_ffff) as u32;
        buf.push(0xff);
        buf.extend_from_slice(&low.to_le_bytes());
        buf.extend_from_slice(&high.to_le_bytes());
    }
}

/// Mirror of JS `Number(s)` for the outpoint output-index segment, restricted to
/// the inputs that occur in practice: a decimal integer string, an empty/blank
/// string (JS `Number('') === 0`), or a non-numeric string (JS -> `NaN`).
fn js_number(s: &str) -> f64 {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return 0.0;
    }
    trimmed.parse::<f64>().unwrap_or(f64::NAN)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::interfaces::{Certificate, CertificateType, SerialNumber};
    use std::collections::HashMap;

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// PublicKey for secp256k1 scalar `k` (big-endian 32-byte private key).
    fn pubkey_for_scalar(k: u8) -> PublicKey {
        let mut buf = [0u8; 32];
        buf[31] = k;
        PrivateKey::from_bytes(&buf).unwrap().to_public_key()
    }

    fn sample_fields() -> HashMap<String, String> {
        // Inserted unsorted on purpose; to_binary must sort lexicographically.
        let mut f = HashMap::new();
        f.insert("b".to_string(), "two".to_string());
        f.insert("a".to_string(), "one".to_string());
        f
    }

    /// Golden vector cross-checked against the TS SDK `@bsv/sdk`
    /// `Certificate.toBinary(false)`. The default revocation-outpoint sentinel
    /// (`'00'.repeat(32)`, no `.vout`) MUST serialize as 32 zero bytes followed by
    /// `ff` + 8 zero bytes (the `writeVarIntNum(Number(undefined)) == varIntNum(NaN)`
    /// path), NOT 32 zero bytes + `00`.
    ///
    /// Provenance (Node, @bsv/sdk):
    ///   subject   = new PrivateKey(1).toPublicKey() = 0279be66...f81798
    ///   certifier = new PrivateKey(2).toPublicKey() = 02c6047f...709ee5
    ///   type      = base64([1;32]), serial = base64([2;32])
    ///   revocationOutpoint = '00'.repeat(32), fields = { b: 'two', a: 'one' }
    #[test]
    fn to_binary_for_signing_default_sentinel_matches_ts_golden() {
        const GOLDEN_DEFAULT: &str = "010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50000000000000000000000000000000000000000000000000000000000000000ff0000000000000000020161036f6e6501620374776f";

        let cert = Certificate {
            cert_type: CertificateType([1u8; 32]),
            serial_number: SerialNumber([2u8; 32]),
            subject: pubkey_for_scalar(1),
            certifier: pubkey_for_scalar(2),
            // Default sentinel: 64 hex zeros, NO `.vout` suffix.
            revocation_outpoint: Some("00".repeat(32)),
            fields: Some(sample_fields()),
            signature: None,
        };

        let bin = AuthCertificate::to_binary_for_signing(&cert);
        assert_eq!(hex_encode(&bin), GOLDEN_DEFAULT);

        // Explicitly pin the revocation portion: 32 zero bytes + NaN-varint.
        assert!(
            hex_encode(&bin).contains(
                "0000000000000000000000000000000000000000000000000000000000000000ff0000000000000000"
            ),
            "default sentinel must serialize the NaN varint (0xff + 8 zero bytes)"
        );
    }

    /// Golden vector for a normal dotted outpoint (`<txid>.1`) — regression guard
    /// ensuring the parity fix did not change the ordinary path. Cross-checked
    /// against the same TS SDK `toBinary(false)`.
    #[test]
    fn to_binary_for_signing_dotted_outpoint_matches_ts_golden() {
        const GOLDEN_DOTTED: &str = "010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef01020161036f6e6501620374776f";

        let cert = Certificate {
            cert_type: CertificateType([1u8; 32]),
            serial_number: SerialNumber([2u8; 32]),
            subject: pubkey_for_scalar(1),
            certifier: pubkey_for_scalar(2),
            revocation_outpoint: Some(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.1".to_string(),
            ),
            fields: Some(sample_fields()),
            signature: None,
        };

        let bin = AuthCertificate::to_binary_for_signing(&cert);
        assert_eq!(hex_encode(&bin), GOLDEN_DOTTED);
    }

    /// `write_var_int_num_js` unit checks: NaN (no dot) and small integers.
    #[test]
    fn write_var_int_num_js_nan_and_small_ints() {
        let mut nan_buf = Vec::new();
        write_var_int_num_js(&mut nan_buf, f64::NAN);
        assert_eq!(nan_buf, vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0]);

        let mut zero_buf = Vec::new();
        write_var_int_num_js(&mut zero_buf, 0.0);
        assert_eq!(zero_buf, vec![0x00]);

        let mut one_buf = Vec::new();
        write_var_int_num_js(&mut one_buf, 1.0);
        assert_eq!(one_buf, vec![0x01]);

        // 253 crosses into the 0xfd branch (little-endian u16).
        let mut wide_buf = Vec::new();
        write_var_int_num_js(&mut wide_buf, 253.0);
        assert_eq!(wide_buf, vec![0xfd, 0xfd, 0x00]);
    }
}
