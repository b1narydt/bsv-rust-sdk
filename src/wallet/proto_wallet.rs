//! ProtoWallet: crypto-only wallet wrapping KeyDeriver.
//!
//! ProtoWallet provides sign, verify, encrypt, decrypt, HMAC, and key linkage
//! revelation operations. It implements WalletInterface so it can be used
//! anywhere a wallet is needed (e.g. auth, certificates, testing).
//! Unsupported methods (transactions, outputs, certificates, blockchain queries)
//! return `WalletError::NotImplemented`.

use crate::primitives::ecdsa::{ecdsa_sign, ecdsa_verify};
use crate::primitives::hash::{sha256, sha256_hmac};
use crate::primitives::point::Point;
use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;
use crate::primitives::schnorr::schnorr_generate_proof;
use crate::primitives::signature::Signature;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult, Certificate,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult, GetPublicKeyArgs,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsArgs, ListOutputsResult, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult, SignActionArgs, SignActionResult,
    VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult, WalletInterface,
};
use crate::wallet::key_deriver::KeyDeriver;
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

/// Result of revealing counterparty key linkage.
pub struct RevealCounterpartyResult {
    /// The prover's identity public key.
    pub prover: PublicKey,
    /// The counterparty's public key.
    pub counterparty: PublicKey,
    /// The verifier's public key (who can decrypt the revelation).
    pub verifier: PublicKey,
    /// ISO 8601 timestamp of the revelation.
    pub revelation_time: String,
    /// Encrypted shared secret (linkage), encrypted for the verifier.
    pub encrypted_linkage: Vec<u8>,
    /// Encrypted proof of the linkage, encrypted for the verifier.
    pub encrypted_linkage_proof: Vec<u8>,
}

/// Result of revealing specific key linkage.
pub struct RevealSpecificResult {
    /// Encrypted specific secret, encrypted for the verifier.
    pub encrypted_linkage: Vec<u8>,
    /// Encrypted proof bytes, encrypted for the verifier.
    pub encrypted_linkage_proof: Vec<u8>,
    /// The prover's identity public key.
    pub prover: PublicKey,
    /// The verifier's public key.
    pub verifier: PublicKey,
    /// The counterparty's public key.
    pub counterparty: PublicKey,
    /// The protocol used for this specific derivation.
    pub protocol: Protocol,
    /// The key ID used for this specific derivation.
    pub key_id: String,
    /// Proof type (0 = no proof for specific linkage).
    pub proof_type: u8,
}

/// ProtoWallet is a crypto-only wallet wrapping KeyDeriver.
///
/// It provides foundational cryptographic operations: key derivation,
/// signing, verification, encryption, decryption, HMAC, and key linkage
/// revelation. Unlike a full wallet, it does not create transactions,
/// manage outputs, or interact with the blockchain.
pub struct ProtoWallet {
    key_deriver: KeyDeriver,
}

impl ProtoWallet {
    /// Create a new ProtoWallet from a private key.
    pub fn new(private_key: PrivateKey) -> Self {
        ProtoWallet {
            key_deriver: KeyDeriver::new(private_key),
        }
    }

    /// Create a new ProtoWallet from an existing KeyDeriver.
    pub fn from_key_deriver(kd: KeyDeriver) -> Self {
        ProtoWallet { key_deriver: kd }
    }

    /// Create an "anyone" ProtoWallet using the special anyone key (PrivateKey(1)).
    pub fn anyone() -> Self {
        ProtoWallet {
            key_deriver: KeyDeriver::new_anyone(),
        }
    }

    /// Get a public key, either the identity key or a derived key.
    ///
    /// If `identity_key` is true, returns the root identity public key
    /// (protocol, key_id, counterparty, for_self are ignored).
    /// Otherwise, derives a public key using the given parameters.
    /// If counterparty is Uninitialized, it defaults to Self_.
    pub fn get_public_key_sync(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
        identity_key: bool,
    ) -> Result<PublicKey, WalletError> {
        if identity_key {
            return Ok(self.key_deriver.identity_key());
        }

        if protocol.protocol.is_empty() || key_id.is_empty() {
            return Err(WalletError::InvalidParameter(
                "protocolID and keyID are required if identityKey is false".to_string(),
            ));
        }

        let effective = self.default_counterparty(counterparty, CounterpartyType::Self_);
        self.key_deriver
            .derive_public_key(protocol, key_id, &effective, for_self)
    }

    /// Create an ECDSA signature over data or a pre-computed hash.
    ///
    /// If `data` is provided, hashes it with SHA-256 then signs.
    /// If `hash_to_directly_sign` is provided, signs it directly.
    /// Returns the DER-encoded signature bytes.
    pub fn create_signature_sync(
        &self,
        data: Option<&[u8]>,
        hash_to_directly_sign: Option<&[u8]>,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<Vec<u8>, WalletError> {
        let effective = self.default_counterparty(counterparty, CounterpartyType::Anyone);
        let derived_key = self
            .key_deriver
            .derive_private_key(protocol, key_id, &effective)?;

        let hash = if let Some(h) = hash_to_directly_sign {
            if h.len() != 32 {
                return Err(WalletError::InvalidParameter(
                    "hash_to_directly_sign must be exactly 32 bytes".to_string(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(h);
            arr
        } else if let Some(d) = data {
            sha256(d)
        } else {
            return Err(WalletError::InvalidParameter(
                "either data or hash_to_directly_sign must be provided".to_string(),
            ));
        };
        let sig = ecdsa_sign(&hash, derived_key.bn(), true)?;
        Ok(sig.to_der())
    }

    /// Verify an ECDSA signature over data or a pre-computed hash.
    ///
    /// If `data` is provided, hashes it with SHA-256 then verifies.
    /// If `hash_to_directly_verify` is provided, verifies against it directly.
    pub fn verify_signature_sync(
        &self,
        data: Option<&[u8]>,
        hash_to_directly_verify: Option<&[u8]>,
        signature: &[u8],
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<bool, WalletError> {
        let effective = self.default_counterparty(counterparty, CounterpartyType::Self_);
        let derived_pub = self
            .key_deriver
            .derive_public_key(protocol, key_id, &effective, for_self)?;

        let sig = Signature::from_der(signature)?;
        let hash = if let Some(h) = hash_to_directly_verify {
            if h.len() != 32 {
                return Err(WalletError::InvalidParameter(
                    "hash_to_directly_verify must be exactly 32 bytes".to_string(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(h);
            arr
        } else if let Some(d) = data {
            sha256(d)
        } else {
            return Err(WalletError::InvalidParameter(
                "either data or hash_to_directly_verify must be provided".to_string(),
            ));
        };
        Ok(ecdsa_verify(&hash, &sig, derived_pub.point()))
    }

    /// Encrypt plaintext using a derived symmetric key (AES-GCM).
    ///
    /// Derives a symmetric key from the protocol, key ID, and counterparty,
    /// then encrypts the plaintext. Returns IV || ciphertext || auth tag.
    pub fn encrypt_sync(
        &self,
        plaintext: &[u8],
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<Vec<u8>, WalletError> {
        let effective = self.default_counterparty(counterparty, CounterpartyType::Self_);
        let sym_key = self
            .key_deriver
            .derive_symmetric_key(protocol, key_id, &effective)?;
        Ok(sym_key.encrypt(plaintext)?)
    }

    /// Decrypt ciphertext using a derived symmetric key (AES-GCM).
    ///
    /// Derives the same symmetric key used for encryption and decrypts.
    /// Expects format: IV(32) || ciphertext || auth tag(16).
    pub fn decrypt_sync(
        &self,
        ciphertext: &[u8],
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<Vec<u8>, WalletError> {
        let effective = self.default_counterparty(counterparty, CounterpartyType::Self_);
        let sym_key = self
            .key_deriver
            .derive_symmetric_key(protocol, key_id, &effective)?;
        Ok(sym_key.decrypt(ciphertext)?)
    }

    /// Create an HMAC-SHA256 over data using a derived symmetric key.
    ///
    /// Returns a 32-byte HMAC value.
    pub fn create_hmac_sync(
        &self,
        data: &[u8],
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<Vec<u8>, WalletError> {
        let effective = self.default_counterparty(counterparty, CounterpartyType::Self_);
        let sym_key = self
            .key_deriver
            .derive_symmetric_key(protocol, key_id, &effective)?;
        let key_bytes = sym_key.to_bytes();
        let hmac = sha256_hmac(&key_bytes, data);
        Ok(hmac.to_vec())
    }

    /// Verify an HMAC-SHA256 value over data using a derived symmetric key.
    ///
    /// Computes the expected HMAC and compares it with the provided value
    /// using constant-time comparison.
    pub fn verify_hmac_sync(
        &self,
        data: &[u8],
        hmac_value: &[u8],
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<bool, WalletError> {
        let expected = self.create_hmac_sync(data, protocol, key_id, counterparty)?;
        // Constant-time comparison to prevent timing attacks
        Ok(constant_time_eq(&expected, hmac_value))
    }

    /// Reveal counterparty key linkage to a verifier.
    ///
    /// Creates an encrypted revelation of the shared secret between this wallet
    /// and the counterparty, along with an encrypted HMAC proof. Both are
    /// encrypted for the verifier using the "counterparty linkage revelation" protocol.
    pub fn reveal_counterparty_key_linkage_sync(
        &self,
        counterparty: &Counterparty,
        verifier: &PublicKey,
    ) -> Result<RevealCounterpartyResult, WalletError> {
        // Get the shared secret point as a public key
        let linkage_point = self.key_deriver.reveal_counterparty_secret(counterparty)?;
        let linkage_bytes = linkage_point.to_der(); // compressed 33 bytes

        let prover = self.key_deriver.identity_key();

        // Create a revelation timestamp
        // Use a simple UTC timestamp format
        let revelation_time = current_utc_timestamp();

        let verifier_counterparty = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(verifier.clone()),
        };

        let linkage_protocol = Protocol {
            security_level: 2,
            protocol: "counterparty linkage revelation".to_string(),
        };

        // Encrypt the linkage bytes for the verifier
        let encrypted_linkage = self.encrypt_sync(
            &linkage_bytes,
            &linkage_protocol,
            &revelation_time,
            &verifier_counterparty,
        )?;

        // Create Schnorr DLEQ proof (matching TS SDK ProtoWallet.ts)
        // Proves knowledge of private key `a` such that A = a*G and S = a*B
        let linkage_point = Point::from_der(&linkage_bytes)
            .map_err(|e| WalletError::Internal(format!("invalid linkage point: {}", e)))?;
        let counterparty_pub = match &counterparty.public_key {
            Some(pk) => pk.clone(),
            None => {
                return Err(WalletError::InvalidParameter(
                    "counterparty public key required for linkage revelation".to_string(),
                ))
            }
        };
        let schnorr_proof = schnorr_generate_proof(
            self.key_deriver.root_key(),
            &self.key_deriver.identity_key(),
            &counterparty_pub,
            &linkage_point,
        )?;
        // Serialize proof as R(33) || S'(33) || z(variable) matching TS SDK format
        let mut proof_bin = Vec::with_capacity(33 + 33 + 32);
        proof_bin.extend_from_slice(&schnorr_proof.r_point.to_der(true));
        proof_bin.extend_from_slice(&schnorr_proof.s_prime.to_der(true));
        proof_bin.extend_from_slice(&schnorr_proof.z.to_bytes());
        let encrypted_proof = self.encrypt_sync(
            &proof_bin,
            &linkage_protocol,
            &revelation_time,
            &verifier_counterparty,
        )?;

        Ok(RevealCounterpartyResult {
            prover,
            counterparty: counterparty_pub,
            verifier: verifier.clone(),
            revelation_time,
            encrypted_linkage,
            encrypted_linkage_proof: encrypted_proof,
        })
    }

    /// Reveal specific key linkage for a given protocol and key ID to a verifier.
    ///
    /// Encrypts the specific secret and a proof byte for the verifier using a
    /// special "specific linkage revelation" protocol.
    pub fn reveal_specific_key_linkage_sync(
        &self,
        counterparty: &Counterparty,
        verifier: &PublicKey,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<RevealSpecificResult, WalletError> {
        // Get the specific secret (HMAC of shared secret + invoice number)
        let linkage = self
            .key_deriver
            .reveal_specific_secret(counterparty, protocol, key_id)?;

        let prover = self.key_deriver.identity_key();

        let verifier_counterparty = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(verifier.clone()),
        };

        // Build the special protocol for specific linkage revelation
        let encrypt_protocol = Protocol {
            security_level: 2,
            protocol: format!(
                "specific linkage revelation {} {}",
                protocol.security_level, protocol.protocol
            ),
        };

        // Encrypt the linkage for the verifier
        let encrypted_linkage =
            self.encrypt_sync(&linkage, &encrypt_protocol, key_id, &verifier_counterparty)?;

        // Encrypt proof type byte (0 = no proof) for the verifier
        let proof_bytes: [u8; 1] = [0];
        let encrypted_proof = self.encrypt_sync(
            &proof_bytes,
            &encrypt_protocol,
            key_id,
            &verifier_counterparty,
        )?;

        // Extract the counterparty public key
        let counterparty_pub = match &counterparty.public_key {
            Some(pk) => pk.clone(),
            None => {
                return Err(WalletError::InvalidParameter(
                    "counterparty public key required for linkage revelation".to_string(),
                ))
            }
        };

        Ok(RevealSpecificResult {
            encrypted_linkage,
            encrypted_linkage_proof: encrypted_proof,
            prover,
            verifier: verifier.clone(),
            counterparty: counterparty_pub,
            protocol: protocol.clone(),
            key_id: key_id.to_string(),
            proof_type: 0,
        })
    }

    /// Default an Uninitialized counterparty to the given type.
    fn default_counterparty(
        &self,
        counterparty: &Counterparty,
        default_type: CounterpartyType,
    ) -> Counterparty {
        if counterparty.counterparty_type == CounterpartyType::Uninitialized {
            Counterparty {
                counterparty_type: default_type,
                public_key: None,
            }
        } else {
            counterparty.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// WalletInterface implementation
// ---------------------------------------------------------------------------
//
// Matches TS SDK CompletedProtoWallet: crypto methods delegate to existing
// ProtoWallet logic; all other methods return NotImplemented.

#[async_trait::async_trait]
impl WalletInterface for ProtoWallet {
    // -- Action methods (not supported) --

    async fn create_action(
        &self,
        _args: CreateActionArgs,
        _originator: Option<&str>,
    ) -> Result<CreateActionResult, WalletError> {
        Err(WalletError::NotImplemented("createAction".to_string()))
    }

    async fn sign_action(
        &self,
        _args: SignActionArgs,
        _originator: Option<&str>,
    ) -> Result<SignActionResult, WalletError> {
        Err(WalletError::NotImplemented("signAction".to_string()))
    }

    async fn abort_action(
        &self,
        _args: AbortActionArgs,
        _originator: Option<&str>,
    ) -> Result<AbortActionResult, WalletError> {
        Err(WalletError::NotImplemented("abortAction".to_string()))
    }

    async fn list_actions(
        &self,
        _args: ListActionsArgs,
        _originator: Option<&str>,
    ) -> Result<ListActionsResult, WalletError> {
        Err(WalletError::NotImplemented("listActions".to_string()))
    }

    async fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
        _originator: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError> {
        Err(WalletError::NotImplemented("internalizeAction".to_string()))
    }

    // -- Output methods (not supported) --

    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _originator: Option<&str>,
    ) -> Result<ListOutputsResult, WalletError> {
        Err(WalletError::NotImplemented("listOutputs".to_string()))
    }

    async fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
        _originator: Option<&str>,
    ) -> Result<RelinquishOutputResult, WalletError> {
        Err(WalletError::NotImplemented("relinquishOutput".to_string()))
    }

    // -- Key/Crypto methods (supported — delegates to ProtoWallet methods) --

    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        _originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        if args.privileged {
            return Err(WalletError::NotImplemented(
                "privileged key access not supported by ProtoWallet".to_string(),
            ));
        }
        let protocol = args.protocol_id.unwrap_or(Protocol {
            security_level: 0,
            protocol: String::new(),
        });
        let key_id = args.key_id.unwrap_or_default();
        let counterparty = args.counterparty.unwrap_or(Counterparty {
            counterparty_type: CounterpartyType::Uninitialized,
            public_key: None,
        });
        let for_self = args.for_self.unwrap_or(false);
        let pk = self.get_public_key_sync(
            &protocol,
            &key_id,
            &counterparty,
            for_self,
            args.identity_key,
        )?;
        Ok(GetPublicKeyResult { public_key: pk })
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        _originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(args.counterparty),
        };
        let result = self.reveal_counterparty_key_linkage_sync(&counterparty, &args.verifier)?;
        Ok(RevealCounterpartyKeyLinkageResult {
            prover: result.prover,
            counterparty: result.counterparty,
            verifier: result.verifier,
            revelation_time: result.revelation_time,
            encrypted_linkage: result.encrypted_linkage,
            encrypted_linkage_proof: result.encrypted_linkage_proof,
        })
    }

    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        _originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        let result = self.reveal_specific_key_linkage_sync(
            &args.counterparty,
            &args.verifier,
            &args.protocol_id,
            &args.key_id,
        )?;
        Ok(RevealSpecificKeyLinkageResult {
            encrypted_linkage: result.encrypted_linkage,
            encrypted_linkage_proof: result.encrypted_linkage_proof,
            prover: result.prover,
            verifier: result.verifier,
            counterparty: result.counterparty,
            protocol_id: result.protocol.clone(),
            key_id: result.key_id.clone(),
            proof_type: result.proof_type,
        })
    }

    async fn encrypt(
        &self,
        args: EncryptArgs,
        _originator: Option<&str>,
    ) -> Result<EncryptResult, WalletError> {
        let ciphertext = self.encrypt_sync(
            &args.plaintext,
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
        )?;
        Ok(EncryptResult { ciphertext })
    }

    async fn decrypt(
        &self,
        args: DecryptArgs,
        _originator: Option<&str>,
    ) -> Result<DecryptResult, WalletError> {
        let plaintext = self.decrypt_sync(
            &args.ciphertext,
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
        )?;
        Ok(DecryptResult { plaintext })
    }

    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        _originator: Option<&str>,
    ) -> Result<CreateHmacResult, WalletError> {
        let hmac = self.create_hmac_sync(
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
        let valid = self.verify_hmac_sync(
            &args.data,
            &args.hmac,
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
        )?;
        // Match TS SDK behavior: throw error on invalid HMAC instead of returning false
        if !valid {
            return Err(WalletError::InvalidHmac);
        }
        Ok(VerifyHmacResult { valid: true })
    }

    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        _originator: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError> {
        let signature = self.create_signature_sync(
            args.data.as_deref(),
            args.hash_to_directly_sign.as_deref(),
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
        )?;
        Ok(CreateSignatureResult { signature })
    }

    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        _originator: Option<&str>,
    ) -> Result<VerifySignatureResult, WalletError> {
        let for_self = args.for_self.unwrap_or(false);
        let valid = self.verify_signature_sync(
            args.data.as_deref(),
            args.hash_to_directly_verify.as_deref(),
            &args.signature,
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
            for_self,
        )?;
        // Match TS SDK behavior: throw error on invalid signature instead of returning false
        if !valid {
            return Err(WalletError::InvalidSignature);
        }
        Ok(VerifySignatureResult { valid: true })
    }

    // -- Certificate methods (not supported) --

    async fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<Certificate, WalletError> {
        Err(WalletError::NotImplemented(
            "acquireCertificate".to_string(),
        ))
    }

    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _originator: Option<&str>,
    ) -> Result<ListCertificatesResult, WalletError> {
        Err(WalletError::NotImplemented("listCertificates".to_string()))
    }

    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<ProveCertificateResult, WalletError> {
        Err(WalletError::NotImplemented("proveCertificate".to_string()))
    }

    async fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<RelinquishCertificateResult, WalletError> {
        Err(WalletError::NotImplemented(
            "relinquishCertificate".to_string(),
        ))
    }

    // -- Discovery methods (not supported) --

    async fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
        _originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        Err(WalletError::NotImplemented(
            "discoverByIdentityKey".to_string(),
        ))
    }

    async fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
        _originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        Err(WalletError::NotImplemented(
            "discoverByAttributes".to_string(),
        ))
    }

    // -- Auth/Info methods (not supported) --

    async fn is_authenticated(
        &self,
        _originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        Err(WalletError::NotImplemented("isAuthenticated".to_string()))
    }

    async fn wait_for_authentication(
        &self,
        _originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        Err(WalletError::NotImplemented(
            "waitForAuthentication".to_string(),
        ))
    }

    async fn get_height(&self, _originator: Option<&str>) -> Result<GetHeightResult, WalletError> {
        Err(WalletError::NotImplemented("getHeight".to_string()))
    }

    async fn get_header_for_height(
        &self,
        _args: GetHeaderArgs,
        _originator: Option<&str>,
    ) -> Result<GetHeaderResult, WalletError> {
        Err(WalletError::NotImplemented(
            "getHeaderForHeight".to_string(),
        ))
    }

    async fn get_network(
        &self,
        _originator: Option<&str>,
    ) -> Result<GetNetworkResult, WalletError> {
        Err(WalletError::NotImplemented("getNetwork".to_string()))
    }

    async fn get_version(
        &self,
        _originator: Option<&str>,
    ) -> Result<GetVersionResult, WalletError> {
        Err(WalletError::NotImplemented("getVersion".to_string()))
    }
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Returns a UTC timestamp string suitable for use as a key ID.
fn current_utc_timestamp() -> String {
    // Use a simple epoch-based timestamp to avoid external dependencies.
    // Format: seconds since epoch as a string.
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};

    fn test_protocol() -> Protocol {
        Protocol {
            security_level: 2,
            protocol: "test proto wallet".to_string(),
        }
    }

    fn self_counterparty() -> Counterparty {
        Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        }
    }

    fn test_private_key() -> PrivateKey {
        PrivateKey::from_hex("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
            .unwrap()
    }

    #[test]
    fn test_new_creates_wallet_with_correct_identity_key() {
        let pk = test_private_key();
        let expected_pub = pk.to_public_key();
        let wallet = ProtoWallet::new(pk);
        let identity = wallet
            .get_public_key_sync(&test_protocol(), "1", &self_counterparty(), false, true)
            .unwrap();
        assert_eq!(identity.to_der_hex(), expected_pub.to_der_hex());
    }

    #[test]
    fn test_get_public_key_identity_key_true() {
        let pk = test_private_key();
        let expected = pk.to_public_key().to_der_hex();
        let wallet = ProtoWallet::new(pk);
        let result = wallet
            .get_public_key_sync(&test_protocol(), "1", &self_counterparty(), false, true)
            .unwrap();
        assert_eq!(result.to_der_hex(), expected);
    }

    #[test]
    fn test_get_public_key_derived() {
        let wallet = ProtoWallet::new(test_private_key());
        let protocol = test_protocol();
        let pub1 = wallet
            .get_public_key_sync(&protocol, "key1", &self_counterparty(), true, false)
            .unwrap();
        let pub2 = wallet
            .get_public_key_sync(&protocol, "key2", &self_counterparty(), true, false)
            .unwrap();
        // Different key IDs should produce different derived keys
        assert_ne!(pub1.to_der_hex(), pub2.to_der_hex());
    }

    #[test]
    fn test_create_and_verify_signature_roundtrip() {
        let wallet = ProtoWallet::new(test_private_key());
        let protocol = test_protocol();
        let counterparty = self_counterparty();
        let data = b"hello world signature test";

        let sig = wallet
            .create_signature_sync(Some(data), None, &protocol, "sig1", &counterparty)
            .unwrap();
        assert!(!sig.is_empty());

        let valid = wallet
            .verify_signature_sync(Some(data), None, &sig, &protocol, "sig1", &counterparty, true)
            .unwrap();
        assert!(valid, "signature should verify");
    }

    #[test]
    fn test_verify_signature_rejects_wrong_data() {
        let wallet = ProtoWallet::new(test_private_key());
        let protocol = test_protocol();
        let counterparty = self_counterparty();

        let sig = wallet
            .create_signature_sync(Some(b"correct data"), None, &protocol, "sig2", &counterparty)
            .unwrap();
        let valid = wallet
            .verify_signature_sync(Some(b"wrong data"), None, &sig, &protocol, "sig2", &counterparty, true)
            .unwrap();
        assert!(!valid, "signature should not verify for wrong data");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let wallet = ProtoWallet::new(test_private_key());
        let protocol = test_protocol();
        let counterparty = self_counterparty();
        let plaintext = b"secret message for encryption";

        let ciphertext = wallet
            .encrypt_sync(plaintext, &protocol, "enc1", &counterparty)
            .unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = wallet
            .decrypt_sync(&ciphertext, &protocol, "enc1", &counterparty)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let wallet = ProtoWallet::new(test_private_key());
        let protocol = test_protocol();
        let counterparty = self_counterparty();

        let ciphertext = wallet
            .encrypt_sync(b"", &protocol, "enc2", &counterparty)
            .unwrap();
        let decrypted = wallet
            .decrypt_sync(&ciphertext, &protocol, "enc2", &counterparty)
            .unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_create_and_verify_hmac_roundtrip() {
        let wallet = ProtoWallet::new(test_private_key());
        let protocol = test_protocol();
        let counterparty = self_counterparty();
        let data = b"hmac test data";

        let hmac = wallet
            .create_hmac_sync(data, &protocol, "hmac1", &counterparty)
            .unwrap();
        assert_eq!(hmac.len(), 32);

        let valid = wallet
            .verify_hmac_sync(data, &hmac, &protocol, "hmac1", &counterparty)
            .unwrap();
        assert!(valid, "HMAC should verify");
    }

    #[test]
    fn test_verify_hmac_rejects_wrong_data() {
        let wallet = ProtoWallet::new(test_private_key());
        let protocol = test_protocol();
        let counterparty = self_counterparty();

        let hmac = wallet
            .create_hmac_sync(b"correct", &protocol, "hmac2", &counterparty)
            .unwrap();
        let valid = wallet
            .verify_hmac_sync(b"wrong", &hmac, &protocol, "hmac2", &counterparty)
            .unwrap();
        assert!(!valid, "HMAC should not verify for wrong data");
    }

    #[test]
    fn test_hmac_deterministic() {
        let wallet = ProtoWallet::new(test_private_key());
        let protocol = test_protocol();
        let counterparty = self_counterparty();
        let data = b"deterministic hmac";

        let hmac1 = wallet
            .create_hmac_sync(data, &protocol, "hmac3", &counterparty)
            .unwrap();
        let hmac2 = wallet
            .create_hmac_sync(data, &protocol, "hmac3", &counterparty)
            .unwrap();
        assert_eq!(hmac1, hmac2);
    }

    #[test]
    fn test_anyone_wallet_encrypt_decrypt() {
        let anyone = ProtoWallet::anyone();
        let other_key = test_private_key();
        let other_pub = other_key.to_public_key();

        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(other_pub),
        };
        let protocol = test_protocol();
        let plaintext = b"message from anyone";

        let ciphertext = anyone
            .encrypt_sync(plaintext, &protocol, "anon1", &counterparty)
            .unwrap();
        let decrypted = anyone
            .decrypt_sync(&ciphertext, &protocol, "anon1", &counterparty)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_uninitialized_counterparty_defaults_to_self_for_encrypt() {
        let wallet = ProtoWallet::new(test_private_key());
        let protocol = test_protocol();
        let uninit = Counterparty {
            counterparty_type: CounterpartyType::Uninitialized,
            public_key: None,
        };
        let self_cp = self_counterparty();

        let ct_uninit = wallet.encrypt_sync(b"test", &protocol, "def1", &uninit).unwrap();
        // Both should decrypt with Self_ counterparty
        let decrypted = wallet
            .decrypt_sync(&ct_uninit, &protocol, "def1", &self_cp)
            .unwrap();
        assert_eq!(decrypted, b"test");
    }

    #[test]
    fn test_reveal_specific_key_linkage() {
        let wallet_a = ProtoWallet::new(test_private_key());
        let verifier_key = PrivateKey::from_hex("ff").unwrap();
        let verifier_pub = verifier_key.to_public_key();

        let counterparty_key = PrivateKey::from_hex("bb").unwrap();
        let counterparty_pub = counterparty_key.to_public_key();

        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(counterparty_pub),
        };

        let protocol = test_protocol();
        let result = wallet_a
            .reveal_specific_key_linkage_sync(&counterparty, &verifier_pub, &protocol, "link1")
            .unwrap();

        assert!(!result.encrypted_linkage.is_empty());
        assert!(!result.encrypted_linkage_proof.is_empty());
        assert_eq!(result.proof_type, 0);
        assert_eq!(result.key_id, "link1");
    }

    #[test]
    fn test_reveal_counterparty_key_linkage() {
        let wallet = ProtoWallet::new(test_private_key());
        let verifier_key = PrivateKey::from_hex("ff").unwrap();
        let verifier_pub = verifier_key.to_public_key();

        let counterparty_key = PrivateKey::from_hex("cc").unwrap();
        let counterparty_pub = counterparty_key.to_public_key();

        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(counterparty_pub.clone()),
        };

        let result = wallet
            .reveal_counterparty_key_linkage_sync(&counterparty, &verifier_pub)
            .unwrap();

        assert!(!result.encrypted_linkage.is_empty());
        assert!(!result.encrypted_linkage_proof.is_empty());
        assert_eq!(
            result.counterparty.to_der_hex(),
            counterparty_pub.to_der_hex()
        );
        assert_eq!(result.verifier.to_der_hex(), verifier_pub.to_der_hex());
        assert!(!result.revelation_time.is_empty());
    }

    // -----------------------------------------------------------------------
    // WalletInterface trait tests
    // -----------------------------------------------------------------------

    /// Helper: call WalletInterface method through trait to verify dispatch.
    async fn get_pub_key_via_trait<W: WalletInterface + ?Sized>(
        w: &W,
        args: GetPublicKeyArgs,
    ) -> Result<GetPublicKeyResult, WalletError> {
        w.get_public_key(args, None).await
    }

    #[tokio::test]
    async fn test_wallet_interface_get_public_key_identity() {
        let pk = test_private_key();
        let expected = pk.to_public_key().to_der_hex();
        let wallet = ProtoWallet::new(pk);

        let result = get_pub_key_via_trait(
            &wallet,
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
        )
        .await
        .unwrap();

        assert_eq!(result.public_key.to_der_hex(), expected);
    }

    #[tokio::test]
    async fn test_wallet_interface_get_public_key_derived() {
        let wallet = ProtoWallet::new(test_private_key());

        let result = get_pub_key_via_trait(
            &wallet,
            GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(test_protocol()),
                key_id: Some("derived1".to_string()),
                counterparty: Some(self_counterparty()),
                privileged: false,
                privileged_reason: None,
                for_self: Some(true),
                seek_permission: None,
            },
        )
        .await
        .unwrap();

        // Should match the direct method call
        let direct = wallet
            .get_public_key_sync(
                &test_protocol(),
                "derived1",
                &self_counterparty(),
                true,
                false,
            )
            .unwrap();
        assert_eq!(result.public_key.to_der_hex(), direct.to_der_hex());
    }

    #[tokio::test]
    async fn test_wallet_interface_privileged_rejected() {
        let wallet = ProtoWallet::new(test_private_key());
        let err = WalletInterface::get_public_key(
            &wallet,
            GetPublicKeyArgs {
                identity_key: true,
                protocol_id: None,
                key_id: None,
                counterparty: None,
                privileged: true,
                privileged_reason: Some("test".to_string()),
                for_self: None,
                seek_permission: None,
            },
            None,
        )
        .await;

        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("not implemented"), "got: {}", msg);
    }

    #[tokio::test]
    async fn test_wallet_interface_create_verify_signature() {
        let wallet = ProtoWallet::new(test_private_key());
        let data = b"test data for wallet interface sig".to_vec();

        let sig_result = WalletInterface::create_signature(
            &wallet,
            CreateSignatureArgs {
                protocol_id: test_protocol(),
                key_id: "wsig1".to_string(),
                counterparty: self_counterparty(),
                data: Some(data.clone()),
                hash_to_directly_sign: None,
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();

        let verify_result = WalletInterface::verify_signature(
            &wallet,
            VerifySignatureArgs {
                protocol_id: test_protocol(),
                key_id: "wsig1".to_string(),
                counterparty: self_counterparty(),
                data: Some(data),
                hash_to_directly_verify: None,
                signature: sig_result.signature,
                for_self: Some(true),
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();

        assert!(verify_result.valid);
    }

    #[tokio::test]
    async fn test_wallet_interface_encrypt_decrypt() {
        let wallet = ProtoWallet::new(test_private_key());
        let plaintext = b"wallet interface encrypt test".to_vec();

        let enc = WalletInterface::encrypt(
            &wallet,
            EncryptArgs {
                protocol_id: test_protocol(),
                key_id: "wenc1".to_string(),
                counterparty: self_counterparty(),
                plaintext: plaintext.clone(),
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();

        let dec = WalletInterface::decrypt(
            &wallet,
            DecryptArgs {
                protocol_id: test_protocol(),
                key_id: "wenc1".to_string(),
                counterparty: self_counterparty(),
                ciphertext: enc.ciphertext,
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();

        assert_eq!(dec.plaintext, plaintext);
    }

    #[tokio::test]
    async fn test_wallet_interface_hmac_roundtrip() {
        let wallet = ProtoWallet::new(test_private_key());
        let data = b"wallet interface hmac test".to_vec();

        let hmac_result = WalletInterface::create_hmac(
            &wallet,
            CreateHmacArgs {
                protocol_id: test_protocol(),
                key_id: "whmac1".to_string(),
                counterparty: self_counterparty(),
                data: data.clone(),
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();

        assert_eq!(hmac_result.hmac.len(), 32);

        let verify = WalletInterface::verify_hmac(
            &wallet,
            VerifyHmacArgs {
                protocol_id: test_protocol(),
                key_id: "whmac1".to_string(),
                counterparty: self_counterparty(),
                data,
                hmac: hmac_result.hmac,
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();

        assert!(verify.valid);
    }

    #[tokio::test]
    async fn test_wallet_interface_unsupported_methods_return_not_implemented() {
        use crate::wallet::interfaces::*;
        let wallet = ProtoWallet::new(test_private_key());

        // Each unsupported method should return NotImplemented, matching TS SDK
        // CompletedProtoWallet which throws "not implemented" for these.
        let err = WalletInterface::is_authenticated(&wallet, None).await;
        assert!(matches!(err, Err(WalletError::NotImplemented(_))));

        let err = WalletInterface::wait_for_authentication(&wallet, None).await;
        assert!(matches!(err, Err(WalletError::NotImplemented(_))));

        let err = WalletInterface::get_network(&wallet, None).await;
        assert!(matches!(err, Err(WalletError::NotImplemented(_))));

        let err = WalletInterface::get_version(&wallet, None).await;
        assert!(matches!(err, Err(WalletError::NotImplemented(_))));

        let err = WalletInterface::get_height(&wallet, None).await;
        assert!(matches!(err, Err(WalletError::NotImplemented(_))));

        let err =
            WalletInterface::get_header_for_height(&wallet, GetHeaderArgs { height: 0 }, None)
                .await;
        assert!(matches!(err, Err(WalletError::NotImplemented(_))));

        let err = WalletInterface::list_outputs(
            &wallet,
            ListOutputsArgs {
                basket: "test".to_string(),
                tags: vec![],
                tag_query_mode: None,
                include: None,
                include_custom_instructions: BooleanDefaultFalse(None),
                include_tags: BooleanDefaultFalse(None),
                include_labels: BooleanDefaultFalse(None),
                limit: Some(10),
                offset: None,
                seek_permission: BooleanDefaultTrue(None),
            },
            None,
        )
        .await;
        assert!(matches!(err, Err(WalletError::NotImplemented(_))));
    }

    #[tokio::test]
    async fn test_wallet_interface_reveal_counterparty_key_linkage() {
        let wallet = ProtoWallet::new(test_private_key());
        let verifier_key = PrivateKey::from_hex("ff").unwrap();
        let counterparty_key = PrivateKey::from_hex("cc").unwrap();

        let result = WalletInterface::reveal_counterparty_key_linkage(
            &wallet,
            RevealCounterpartyKeyLinkageArgs {
                counterparty: counterparty_key.to_public_key(),
                verifier: verifier_key.to_public_key(),
                privileged: None,
                privileged_reason: None,
            },
            None,
        )
        .await
        .unwrap();

        assert!(!result.encrypted_linkage.is_empty());
        assert!(!result.encrypted_linkage_proof.is_empty());
        assert_eq!(
            result.counterparty.to_der_hex(),
            counterparty_key.to_public_key().to_der_hex()
        );
        assert!(!result.revelation_time.is_empty());
    }

    #[tokio::test]
    async fn test_wallet_interface_reveal_specific_key_linkage() {
        let wallet = ProtoWallet::new(test_private_key());
        let verifier_key = PrivateKey::from_hex("ff").unwrap();
        let counterparty_key = PrivateKey::from_hex("bb").unwrap();

        let result = WalletInterface::reveal_specific_key_linkage(
            &wallet,
            RevealSpecificKeyLinkageArgs {
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Other,
                    public_key: Some(counterparty_key.to_public_key()),
                },
                verifier: verifier_key.to_public_key(),
                protocol_id: test_protocol(),
                key_id: "wlink1".to_string(),
                privileged: None,
                privileged_reason: None,
            },
            None,
        )
        .await
        .unwrap();

        assert!(!result.encrypted_linkage.is_empty());
        assert_eq!(result.proof_type, 0);
        assert_eq!(result.key_id, "wlink1");
    }
}
