//! WalletWireTransceiver: implements WalletInterface by serializing calls
//! and transmitting them over a WalletWire transport.
//!
//! This is the client-side half of the wire protocol. Each wallet method
//! serializes its arguments, builds a request frame, transmits via the
//! WalletWire, reads the result frame, and deserializes the result.
//!
//! Translated from Go SDK wallet/substrates/wallet_wire_transceiver.go.

use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use crate::wallet::serializer::frame::{read_result_frame, write_request_frame, RequestFrame};
use crate::wallet::substrates::wallet_wire_calls::WalletWireCall;
use crate::wallet::substrates::WalletWire;

/// Implements WalletInterface by serializing each call and sending it over
/// a WalletWire transport. Pairs with WalletWireProcessor on the server side.
pub struct WalletWireTransceiver<W: WalletWire> {
    wire: W,
}

impl<W: WalletWire> WalletWireTransceiver<W> {
    /// Create a new transceiver wrapping the given wire transport.
    pub fn new(wire: W) -> Self {
        Self { wire }
    }

    /// Transmit a call: build frame, send over wire, read result.
    async fn transmit(
        &self,
        call: WalletWireCall,
        originator: Option<&str>,
        params: Vec<u8>,
    ) -> Result<Vec<u8>, WalletError> {
        let frame = write_request_frame(&RequestFrame {
            call: call as u8,
            originator: originator.unwrap_or("").to_string(),
            params,
        });

        let result = self.wire.transmit_to_wallet(&frame).await?;
        read_result_frame(&result)
    }
}

/// Macro to reduce boilerplate for the 28 method implementations.
/// Pattern: serialize args -> transmit -> deserialize result.
/// Uses desugared async-trait form so it works inside #[async_trait] impl blocks.
macro_rules! impl_wire_method {
    // Methods with args
    ($method:ident, $call:ident, $args_type:ty, $result_type:ty,
     $serialize:path, $deserialize:path) => {
        fn $method<'life0, 'life1, 'async_trait>(
            &'life0 self,
            args: $args_type,
            originator: Option<&'life1 str>,
        ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = Result<$result_type, WalletError>> + ::core::marker::Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                let data = $serialize(&args)?;
                let resp = self
                    .transmit(WalletWireCall::$call, originator, data)
                    .await?;
                $deserialize(&resp)
            })
        }
    };
    // Methods without args (only originator)
    (no_args $method:ident, $call:ident, $result_type:ty, $deserialize:path) => {
        fn $method<'life0, 'life1, 'async_trait>(
            &'life0 self,
            originator: Option<&'life1 str>,
        ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = Result<$result_type, WalletError>> + ::core::marker::Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                let resp = self
                    .transmit(WalletWireCall::$call, originator, Vec::new())
                    .await?;
                $deserialize(&resp)
            })
        }
    };
}

use crate::wallet::serializer::{
    abort_action, acquire_certificate, authenticated, certificate_ser, create_action, create_hmac,
    create_signature, decrypt, discover_by_attributes, discover_by_identity_key,
    discover_certificates_result, encrypt, get_header, get_height, get_network, get_public_key,
    get_version, internalize_action, list_actions, list_certificates, list_outputs,
    prove_certificate, relinquish_certificate, relinquish_output, reveal_counterparty_key_linkage,
    reveal_specific_key_linkage, sign_action, verify_hmac, verify_signature,
};

#[async_trait::async_trait]
impl<W: WalletWire> WalletInterface for WalletWireTransceiver<W> {
    impl_wire_method!(
        create_action,
        CreateAction,
        CreateActionArgs,
        CreateActionResult,
        create_action::serialize_create_action_args,
        create_action::deserialize_create_action_result
    );

    impl_wire_method!(
        sign_action,
        SignAction,
        SignActionArgs,
        SignActionResult,
        sign_action::serialize_sign_action_args,
        sign_action::deserialize_sign_action_result
    );

    impl_wire_method!(
        abort_action,
        AbortAction,
        AbortActionArgs,
        AbortActionResult,
        abort_action::serialize_abort_action_args,
        abort_action::deserialize_abort_action_result
    );

    impl_wire_method!(
        list_actions,
        ListActions,
        ListActionsArgs,
        ListActionsResult,
        list_actions::serialize_list_actions_args,
        list_actions::deserialize_list_actions_result
    );

    impl_wire_method!(
        internalize_action,
        InternalizeAction,
        InternalizeActionArgs,
        InternalizeActionResult,
        internalize_action::serialize_internalize_action_args,
        internalize_action::deserialize_internalize_action_result
    );

    impl_wire_method!(
        list_outputs,
        ListOutputs,
        ListOutputsArgs,
        ListOutputsResult,
        list_outputs::serialize_list_outputs_args,
        list_outputs::deserialize_list_outputs_result
    );

    impl_wire_method!(
        relinquish_output,
        RelinquishOutput,
        RelinquishOutputArgs,
        RelinquishOutputResult,
        relinquish_output::serialize_relinquish_output_args,
        relinquish_output::deserialize_relinquish_output_result
    );

    impl_wire_method!(
        get_public_key,
        GetPublicKey,
        GetPublicKeyArgs,
        GetPublicKeyResult,
        get_public_key::serialize_get_public_key_args,
        get_public_key::deserialize_get_public_key_result
    );

    impl_wire_method!(
        reveal_counterparty_key_linkage,
        RevealCounterpartyKeyLinkage,
        RevealCounterpartyKeyLinkageArgs,
        RevealCounterpartyKeyLinkageResult,
        reveal_counterparty_key_linkage::serialize_reveal_counterparty_key_linkage_args,
        reveal_counterparty_key_linkage::deserialize_reveal_counterparty_key_linkage_result
    );

    impl_wire_method!(
        reveal_specific_key_linkage,
        RevealSpecificKeyLinkage,
        RevealSpecificKeyLinkageArgs,
        RevealSpecificKeyLinkageResult,
        reveal_specific_key_linkage::serialize_reveal_specific_key_linkage_args,
        reveal_specific_key_linkage::deserialize_reveal_specific_key_linkage_result
    );

    impl_wire_method!(
        encrypt,
        Encrypt,
        EncryptArgs,
        EncryptResult,
        encrypt::serialize_encrypt_args,
        encrypt::deserialize_encrypt_result
    );

    impl_wire_method!(
        decrypt,
        Decrypt,
        DecryptArgs,
        DecryptResult,
        decrypt::serialize_decrypt_args,
        decrypt::deserialize_decrypt_result
    );

    impl_wire_method!(
        create_hmac,
        CreateHmac,
        CreateHmacArgs,
        CreateHmacResult,
        create_hmac::serialize_create_hmac_args,
        create_hmac::deserialize_create_hmac_result
    );

    impl_wire_method!(
        verify_hmac,
        VerifyHmac,
        VerifyHmacArgs,
        VerifyHmacResult,
        verify_hmac::serialize_verify_hmac_args,
        verify_hmac::deserialize_verify_hmac_result
    );

    impl_wire_method!(
        create_signature,
        CreateSignature,
        CreateSignatureArgs,
        CreateSignatureResult,
        create_signature::serialize_create_signature_args,
        create_signature::deserialize_create_signature_result
    );

    impl_wire_method!(
        verify_signature,
        VerifySignature,
        VerifySignatureArgs,
        VerifySignatureResult,
        verify_signature::serialize_verify_signature_args,
        verify_signature::deserialize_verify_signature_result
    );

    impl_wire_method!(
        acquire_certificate,
        AcquireCertificate,
        AcquireCertificateArgs,
        Certificate,
        acquire_certificate::serialize_acquire_certificate_args,
        certificate_ser::deserialize_certificate
    );

    impl_wire_method!(
        list_certificates,
        ListCertificates,
        ListCertificatesArgs,
        ListCertificatesResult,
        list_certificates::serialize_list_certificates_args,
        list_certificates::deserialize_list_certificates_result
    );

    impl_wire_method!(
        prove_certificate,
        ProveCertificate,
        ProveCertificateArgs,
        ProveCertificateResult,
        prove_certificate::serialize_prove_certificate_args,
        prove_certificate::deserialize_prove_certificate_result
    );

    impl_wire_method!(
        relinquish_certificate,
        RelinquishCertificate,
        RelinquishCertificateArgs,
        RelinquishCertificateResult,
        relinquish_certificate::serialize_relinquish_certificate_args,
        relinquish_certificate::deserialize_relinquish_certificate_result
    );

    impl_wire_method!(
        discover_by_identity_key,
        DiscoverByIdentityKey,
        DiscoverByIdentityKeyArgs,
        DiscoverCertificatesResult,
        discover_by_identity_key::serialize_discover_by_identity_key_args,
        discover_certificates_result::deserialize_discover_certificates_result
    );

    impl_wire_method!(
        discover_by_attributes,
        DiscoverByAttributes,
        DiscoverByAttributesArgs,
        DiscoverCertificatesResult,
        discover_by_attributes::serialize_discover_by_attributes_args,
        discover_certificates_result::deserialize_discover_certificates_result
    );

    impl_wire_method!(no_args
        is_authenticated, IsAuthenticated, AuthenticatedResult,
        authenticated::deserialize_is_authenticated_result
    );

    impl_wire_method!(no_args
        wait_for_authentication, WaitForAuthentication, AuthenticatedResult,
        authenticated::deserialize_wait_authenticated_result
    );

    impl_wire_method!(no_args
        get_height, GetHeight, GetHeightResult,
        get_height::deserialize_get_height_result
    );

    impl_wire_method!(
        get_header_for_height,
        GetHeaderForHeight,
        GetHeaderArgs,
        GetHeaderResult,
        get_header::serialize_get_header_args,
        get_header::deserialize_get_header_result
    );

    impl_wire_method!(no_args
        get_network, GetNetwork, GetNetworkResult,
        get_network::deserialize_get_network_result
    );

    impl_wire_method!(no_args
        get_version, GetVersion, GetVersionResult,
        get_version::deserialize_get_version_result
    );
}
