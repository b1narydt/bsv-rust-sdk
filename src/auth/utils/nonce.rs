//! Nonce creation and verification for the auth protocol.
//!
//! A nonce is 16 random bytes concatenated with their HMAC, then base64-encoded.
//! Verification decodes the nonce, splits at byte 16, and verifies the HMAC.

use crate::auth::error::AuthError;
use crate::auth::types::{NONCE_SECURITY_LEVEL, SERVER_HMAC_PROTOCOL};
use crate::primitives::random::random_bytes;
use crate::wallet::interfaces::{CreateHmacArgs, VerifyHmacArgs, WalletInterface};
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

/// Create a new nonce using the wallet's HMAC capability.
///
/// Generates 16 random bytes, computes an HMAC over them using the wallet,
/// concatenates random_bytes + hmac, and returns the result as a base64 string.
pub async fn create_nonce<W: WalletInterface + ?Sized>(wallet: &W) -> Result<String, AuthError> {
    let random = random_bytes(16);
    let key_id = String::from_utf8_lossy(&random).to_string();

    let hmac_result = wallet
        .create_hmac(
            CreateHmacArgs {
                protocol_id: Protocol {
                    security_level: NONCE_SECURITY_LEVEL,
                    protocol: SERVER_HMAC_PROTOCOL.into(),
                },
                key_id,
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                data: random.clone(),
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await?;

    let mut combined = random;
    combined.extend_from_slice(&hmac_result.hmac);

    Ok(base64_encode(&combined))
}

/// Verify that a nonce was created by this wallet.
///
/// Decodes the base64 nonce, splits at byte 16 (random vs hmac),
/// and verifies the HMAC using the wallet.
pub async fn verify_nonce<W: WalletInterface + ?Sized>(wallet: &W, nonce: &str) -> Result<bool, AuthError> {
    let decoded = base64_decode(nonce)?;
    if decoded.len() < 17 {
        return Err(AuthError::InvalidNonce(
            "nonce too short after base64 decode".into(),
        ));
    }

    let random = &decoded[..16];
    let hmac_bytes = &decoded[16..];
    let key_id = String::from_utf8_lossy(random).to_string();

    let result = wallet
        .verify_hmac(
            VerifyHmacArgs {
                protocol_id: Protocol {
                    security_level: NONCE_SECURITY_LEVEL,
                    protocol: SERVER_HMAC_PROTOCOL.into(),
                },
                key_id,
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                data: random.to_vec(),
                hmac: hmac_bytes.to_vec(),
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await?;

    Ok(result.valid)
}

// ---------------------------------------------------------------------------
// Base64 helpers (inline, matching wallet serializer pattern)
// ---------------------------------------------------------------------------

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let a = data[i] as u32;
        let b = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let c = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };
        let n = (a << 16) | (b << 8) | c;
        result.push(CHARS[(n >> 18 & 0x3f) as usize] as char);
        result.push(CHARS[(n >> 12 & 0x3f) as usize] as char);
        if i + 1 < data.len() {
            result.push(CHARS[(n >> 6 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < data.len() {
            result.push(CHARS[(n & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}

fn base64_decode(s: &str) -> Result<Vec<u8>, AuthError> {
    let mut result = Vec::new();
    let chars: Vec<char> = s
        .chars()
        .filter(|c| *c != '=' && *c != '\n' && *c != '\r')
        .collect();
    let mut i = 0;
    while i < chars.len() {
        let a = b64_val(chars[i])?;
        let b = if i + 1 < chars.len() {
            b64_val(chars[i + 1])?
        } else {
            0
        };
        let c = if i + 2 < chars.len() {
            b64_val(chars[i + 2])?
        } else {
            0
        };
        let d = if i + 3 < chars.len() {
            b64_val(chars[i + 3])?
        } else {
            0
        };
        let n = (a as u32) << 18 | (b as u32) << 12 | (c as u32) << 6 | (d as u32);
        result.push((n >> 16) as u8);
        if i + 2 < chars.len() {
            result.push((n >> 8) as u8);
        }
        if i + 3 < chars.len() {
            result.push(n as u8);
        }
        i += 4;
    }
    Ok(result)
}

fn b64_val(c: char) -> Result<u8, AuthError> {
    match c {
        'A'..='Z' => Ok(c as u8 - b'A'),
        'a'..='z' => Ok(c as u8 - b'a' + 26),
        '0'..='9' => Ok(c as u8 - b'0' + 52),
        '+' => Ok(62),
        '/' => Ok(63),
        _ => Err(AuthError::SerializationError(format!(
            "invalid base64 char: {}",
            c
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::error::WalletError;
    use crate::wallet::interfaces::*;
    use crate::wallet::ProtoWallet;

    /// Minimal WalletInterface wrapper around ProtoWallet for testing.
    /// Only create_hmac and verify_hmac are implemented; all other methods
    /// panic with unimplemented.
    struct TestWallet {
        inner: ProtoWallet,
    }

    impl TestWallet {
        fn new(pk: PrivateKey) -> Self {
            TestWallet {
                inner: ProtoWallet::new(pk),
            }
        }
    }

    /// Generates an unimplemented stub for a WalletInterface method.
    /// Uses desugared async-trait form so it works inside #[async_trait] impl blocks.
    macro_rules! stub_method {
        ($name:ident, $args:ty, $ret:ty) => {
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _args: $args,
                _originator: Option<&'life1 str>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<Output = Result<$ret, WalletError>>
                        + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    unimplemented!(concat!(stringify!($name), " not needed for nonce tests"))
                })
            }
        };
        ($name:ident, $ret:ty) => {
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _originator: Option<&'life1 str>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<Output = Result<$ret, WalletError>>
                        + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    unimplemented!(concat!(stringify!($name), " not needed for nonce tests"))
                })
            }
        };
    }

    #[async_trait::async_trait]
    impl WalletInterface for TestWallet {
        stub_method!(create_action, CreateActionArgs, CreateActionResult);
        stub_method!(sign_action, SignActionArgs, SignActionResult);
        stub_method!(abort_action, AbortActionArgs, AbortActionResult);
        stub_method!(list_actions, ListActionsArgs, ListActionsResult);
        stub_method!(
            internalize_action,
            InternalizeActionArgs,
            InternalizeActionResult
        );
        stub_method!(list_outputs, ListOutputsArgs, ListOutputsResult);
        stub_method!(
            relinquish_output,
            RelinquishOutputArgs,
            RelinquishOutputResult
        );
        stub_method!(get_public_key, GetPublicKeyArgs, GetPublicKeyResult);
        stub_method!(
            reveal_counterparty_key_linkage,
            RevealCounterpartyKeyLinkageArgs,
            RevealCounterpartyKeyLinkageResult
        );
        stub_method!(
            reveal_specific_key_linkage,
            RevealSpecificKeyLinkageArgs,
            RevealSpecificKeyLinkageResult
        );
        stub_method!(encrypt, EncryptArgs, EncryptResult);
        stub_method!(decrypt, DecryptArgs, DecryptResult);

        async fn create_hmac(
            &self,
            args: CreateHmacArgs,
            _originator: Option<&str>,
        ) -> Result<CreateHmacResult, WalletError> {
            let hmac = self.inner.create_hmac_sync(
                &args.data,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(CreateHmacResult { hmac })
        }

        async fn verify_hmac(
            &self,
            args: VerifyHmacArgs,
            _originator: Option<&str>,
        ) -> Result<VerifyHmacResult, WalletError> {
            let valid = self.inner.verify_hmac_sync(
                &args.data,
                &args.hmac,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(VerifyHmacResult { valid })
        }

        stub_method!(create_signature, CreateSignatureArgs, CreateSignatureResult);
        stub_method!(verify_signature, VerifySignatureArgs, VerifySignatureResult);
        stub_method!(acquire_certificate, AcquireCertificateArgs, Certificate);
        stub_method!(
            list_certificates,
            ListCertificatesArgs,
            ListCertificatesResult
        );
        stub_method!(
            prove_certificate,
            ProveCertificateArgs,
            ProveCertificateResult
        );
        stub_method!(
            relinquish_certificate,
            RelinquishCertificateArgs,
            RelinquishCertificateResult
        );
        stub_method!(
            discover_by_identity_key,
            DiscoverByIdentityKeyArgs,
            DiscoverCertificatesResult
        );
        stub_method!(
            discover_by_attributes,
            DiscoverByAttributesArgs,
            DiscoverCertificatesResult
        );
        stub_method!(is_authenticated, AuthenticatedResult);
        stub_method!(wait_for_authentication, AuthenticatedResult);
        stub_method!(get_height, GetHeightResult);
        stub_method!(get_header_for_height, GetHeaderArgs, GetHeaderResult);
        stub_method!(get_network, GetNetworkResult);
        stub_method!(get_version, GetVersionResult);
    }

    #[tokio::test]
    async fn test_create_and_verify_nonce() {
        let wallet = TestWallet::new(PrivateKey::from_random().unwrap());

        let nonce = create_nonce(&wallet).await.expect("create_nonce failed");
        assert!(!nonce.is_empty(), "nonce should not be empty");

        let valid = verify_nonce(&wallet, &nonce)
            .await
            .expect("verify_nonce failed");
        assert!(valid, "nonce should verify successfully");
    }

    #[tokio::test]
    async fn test_verify_nonce_rejects_tampered() {
        let wallet = TestWallet::new(PrivateKey::from_random().unwrap());

        let nonce = create_nonce(&wallet).await.expect("create_nonce failed");

        // Tamper with the nonce by changing a character
        let mut chars: Vec<char> = nonce.chars().collect();
        if let Some(c) = chars.get_mut(5) {
            *c = if *c == 'A' { 'B' } else { 'A' };
        }
        let tampered: String = chars.into_iter().collect();

        let valid = verify_nonce(&wallet, &tampered).await;
        match valid {
            Ok(v) => assert!(!v, "tampered nonce should not verify"),
            Err(_) => {} // Error is also acceptable for tampered input
        }
    }

    #[tokio::test]
    async fn test_verify_nonce_rejects_different_wallet() {
        let wallet1 = TestWallet::new(PrivateKey::from_random().unwrap());
        let wallet2 = TestWallet::new(PrivateKey::from_random().unwrap());

        let nonce = create_nonce(&wallet1).await.expect("create_nonce failed");

        let valid = verify_nonce(&wallet2, &nonce).await;
        match valid {
            Ok(v) => assert!(!v, "nonce from different wallet should not verify"),
            Err(_) => {} // Error is also acceptable
        }
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).expect("decode failed");
        assert_eq!(data, decoded);
    }
}
