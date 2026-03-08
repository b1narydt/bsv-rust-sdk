//! WalletClient: validates args before delegating to wire transport.
//!
//! Wraps a WalletWireTransceiver and adds argument validation to each
//! method call before sending over the wire. This prevents invalid
//! requests from being transmitted.
//!
//! Translated from Go SDK wallet/substrates/wallet_client.go.

use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use crate::wallet::substrates::{WalletWire, WalletWireTransceiver};
use crate::wallet::validation;

/// Client that validates all arguments before delegating to wire transport.
pub struct WalletClient<W: WalletWire> {
    transceiver: WalletWireTransceiver<W>,
}

impl<W: WalletWire> WalletClient<W> {
    /// Create a new WalletClient wrapping the given wire substrate.
    pub fn new(substrate: W) -> Self {
        Self {
            transceiver: WalletWireTransceiver::new(substrate),
        }
    }
}

/// Macro to reduce boilerplate: validate args then delegate to transceiver.
/// Uses desugared async-trait form so it works inside #[async_trait] impl blocks.
macro_rules! impl_validated_method {
    // Methods with args
    ($method:ident, $args_type:ty, $result_type:ty, $validator:path) => {
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
                $validator(&args)?;
                self.transceiver.$method(args, originator).await
            })
        }
    };
    // Methods without args (no validation needed, just delegate)
    (no_args $method:ident, $result_type:ty) => {
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
                self.transceiver.$method(originator).await
            })
        }
    };
}

#[async_trait::async_trait]
impl<W: WalletWire> WalletInterface for WalletClient<W> {
    impl_validated_method!(
        create_action,
        CreateActionArgs,
        CreateActionResult,
        validation::validate_create_action_args
    );

    impl_validated_method!(
        sign_action,
        SignActionArgs,
        SignActionResult,
        validation::validate_sign_action_args
    );

    impl_validated_method!(
        abort_action,
        AbortActionArgs,
        AbortActionResult,
        validation::validate_abort_action_args
    );

    impl_validated_method!(
        list_actions,
        ListActionsArgs,
        ListActionsResult,
        validation::validate_list_actions_args
    );

    impl_validated_method!(
        internalize_action,
        InternalizeActionArgs,
        InternalizeActionResult,
        validation::validate_internalize_action_args
    );

    impl_validated_method!(
        list_outputs,
        ListOutputsArgs,
        ListOutputsResult,
        validation::validate_list_outputs_args
    );

    impl_validated_method!(
        relinquish_output,
        RelinquishOutputArgs,
        RelinquishOutputResult,
        validation::validate_relinquish_output_args
    );

    impl_validated_method!(
        get_public_key,
        GetPublicKeyArgs,
        GetPublicKeyResult,
        validation::validate_get_public_key_args
    );

    impl_validated_method!(
        reveal_counterparty_key_linkage,
        RevealCounterpartyKeyLinkageArgs,
        RevealCounterpartyKeyLinkageResult,
        validation::validate_reveal_counterparty_key_linkage_args
    );

    impl_validated_method!(
        reveal_specific_key_linkage,
        RevealSpecificKeyLinkageArgs,
        RevealSpecificKeyLinkageResult,
        validation::validate_reveal_specific_key_linkage_args
    );

    impl_validated_method!(
        encrypt,
        EncryptArgs,
        EncryptResult,
        validation::validate_encrypt_args
    );

    impl_validated_method!(
        decrypt,
        DecryptArgs,
        DecryptResult,
        validation::validate_decrypt_args
    );

    impl_validated_method!(
        create_hmac,
        CreateHmacArgs,
        CreateHmacResult,
        validation::validate_create_hmac_args
    );

    impl_validated_method!(
        verify_hmac,
        VerifyHmacArgs,
        VerifyHmacResult,
        validation::validate_verify_hmac_args
    );

    impl_validated_method!(
        create_signature,
        CreateSignatureArgs,
        CreateSignatureResult,
        validation::validate_create_signature_args
    );

    impl_validated_method!(
        verify_signature,
        VerifySignatureArgs,
        VerifySignatureResult,
        validation::validate_verify_signature_args
    );

    impl_validated_method!(
        acquire_certificate,
        AcquireCertificateArgs,
        Certificate,
        validation::validate_acquire_certificate_args
    );

    impl_validated_method!(
        list_certificates,
        ListCertificatesArgs,
        ListCertificatesResult,
        validation::validate_list_certificates_args
    );

    impl_validated_method!(
        prove_certificate,
        ProveCertificateArgs,
        ProveCertificateResult,
        validation::validate_prove_certificate_args
    );

    impl_validated_method!(
        relinquish_certificate,
        RelinquishCertificateArgs,
        RelinquishCertificateResult,
        validation::validate_relinquish_certificate_args
    );

    impl_validated_method!(
        discover_by_identity_key,
        DiscoverByIdentityKeyArgs,
        DiscoverCertificatesResult,
        validation::validate_discover_by_identity_key_args
    );

    impl_validated_method!(
        discover_by_attributes,
        DiscoverByAttributesArgs,
        DiscoverCertificatesResult,
        validation::validate_discover_by_attributes_args
    );

    impl_validated_method!(no_args is_authenticated, AuthenticatedResult);
    impl_validated_method!(no_args wait_for_authentication, AuthenticatedResult);
    impl_validated_method!(no_args get_height, GetHeightResult);

    impl_validated_method!(
        get_header_for_height,
        GetHeaderArgs,
        GetHeaderResult,
        validation::validate_get_header_args
    );

    impl_validated_method!(no_args get_network, GetNetworkResult);
    impl_validated_method!(no_args get_version, GetVersionResult);
}
