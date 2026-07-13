//! Certificate Operations Example
//!
//! Demonstrates creating, inspecting, and working with BRC-52 certificates
//! using the BSV SDK. Certificates are the identity and trust layer in the
//! BSV overlay network, allowing certifiers to attest to subject attributes.
//!
//! This offline example shows:
//!   - Creating a Certificate with typed fields
//!   - Wrapping it as an AuthCertificate for signing/verification
//!   - Inspecting certificate structure and binary representation
//!   - Demonstrating field management for selective revelation
//!
//! Note: Actual certificate signing/verification requires a WalletInterface
//! (async network operations). This example focuses on certificate construction
//! and the data model.
//!
//! Run with: `cargo run --example certificate_operations`

use std::collections::HashMap;

use bsv::auth::certificates::certificate::AuthCertificate;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::interfaces::{Certificate, CertificateType, SerialNumber};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -----------------------------------------------------------------------
    // 1. Create subject and certifier keys
    // -----------------------------------------------------------------------
    let subject_key = PrivateKey::from_hex("1")?;
    let certifier_key = PrivateKey::from_hex("ff")?;

    let subject_pubkey = subject_key.to_public_key();
    let certifier_pubkey = certifier_key.to_public_key();

    println!("Subject public key:   {}", subject_pubkey.to_der_hex());
    println!("Certifier public key: {}", certifier_pubkey.to_der_hex());
    println!();

    // -----------------------------------------------------------------------
    // 2. Define the certificate type and serial number
    // -----------------------------------------------------------------------
    // Certificate type: a 32-byte identifier for the kind of certificate.
    // For example, "identity" padded to 32 bytes.
    let cert_type = CertificateType::from_string("identity-verification")?;

    // Serial number: unique 32-byte identifier for this certificate instance.
    let mut serial_bytes = [0u8; 32];
    let serial_str = b"cert-2026-0001";
    serial_bytes[..serial_str.len()].copy_from_slice(serial_str);
    let serial = SerialNumber(serial_bytes);

    println!("Certificate type: identity-verification");
    println!("Serial number:    cert-2026-0001");
    println!();

    // -----------------------------------------------------------------------
    // 3. Create certificate fields (attestations)
    // -----------------------------------------------------------------------
    let mut fields = HashMap::new();
    fields.insert("name".to_string(), "Alice Johnson".to_string());
    fields.insert("email".to_string(), "alice@example.com".to_string());
    fields.insert("organization".to_string(), "BSV Association".to_string());
    fields.insert("role".to_string(), "Developer".to_string());

    println!("Certificate fields:");
    let mut field_names: Vec<&String> = fields.keys().collect();
    field_names.sort();
    for name in &field_names {
        println!("  {}: {}", name, fields[*name]);
    }
    println!();

    // -----------------------------------------------------------------------
    // 4. Construct the Certificate
    // -----------------------------------------------------------------------
    let certificate = Certificate {
        cert_type,
        serial_number: serial,
        subject: subject_pubkey.clone(),
        certifier: certifier_pubkey.clone(),
        revocation_outpoint: Some(
            "0000000000000000000000000000000000000000000000000000000000000000.0".to_string(),
        ),
        fields: Some(fields.clone()),
        signature: None, // unsigned -- signing requires async WalletInterface
    };

    // -----------------------------------------------------------------------
    // 5. Wrap as AuthCertificate and inspect
    // -----------------------------------------------------------------------
    let auth_cert = AuthCertificate::new(certificate);

    println!("AuthCertificate created successfully.");
    println!("  Subject:   {}", auth_cert.inner.subject.to_der_hex());
    println!("  Certifier: {}", auth_cert.inner.certifier.to_der_hex());
    println!(
        "  Fields:    {} fields",
        auth_cert.inner.fields.as_ref().map_or(0, |f| f.len())
    );
    println!(
        "  Signed:    {}",
        if auth_cert.inner.signature.is_some() {
            "yes"
        } else {
            "no (requires WalletInterface)"
        }
    );
    println!();

    // -----------------------------------------------------------------------
    // 6. Demonstrate selective field revelation
    // -----------------------------------------------------------------------
    // In the BRC-52 protocol, a certificate holder can reveal only specific
    // fields to a verifier. This is done through the VerifiableCertificate
    // type which includes an encrypted keyring for each revealed field.
    //
    // Here we show how fields would be selected for revelation.
    let fields_to_reveal = ["name", "organization"];
    let revealed: HashMap<String, String> = fields
        .iter()
        .filter(|(k, _)| fields_to_reveal.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    println!("Selective revelation (2 of {} fields):", fields.len());
    for (name, value) in &revealed {
        println!("  {name}: {value}");
    }
    println!();

    // -----------------------------------------------------------------------
    // 7. Summary of certificate workflow
    // -----------------------------------------------------------------------
    println!("Certificate workflow summary:");
    println!("  1. Subject and certifier establish identity keys");
    println!("  2. Certifier creates certificate with attested fields");
    println!("  3. Certificate is signed via WalletInterface (async)");
    println!("  4. Subject can selectively reveal fields to verifiers");
    println!("  5. Verifiers check signature and decrypt revealed fields");
    println!();
    println!("Certificate operations example completed successfully.");

    Ok(())
}
