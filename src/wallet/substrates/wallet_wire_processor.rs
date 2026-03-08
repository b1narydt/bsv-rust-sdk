//! WalletWireProcessor: receives wire frames, dispatches to a wallet
//! implementation, and returns wire result frames.
//!
//! This is the server-side half of the wire protocol. It reads the request
//! frame, deserializes args, calls the real wallet, serializes the result,
//! and writes a result frame.
//!
//! Also implements WalletWire so it can be used as an in-memory transport
//! for testing (transceiver -> processor -> wallet).
//!
//! Translated from Go SDK wallet/substrates/wallet_wire_processor.go.

use crate::wallet::error::WalletError;
use crate::wallet::interfaces::WalletInterface;
use crate::wallet::serializer::frame::{read_request_frame, write_result_frame};
use crate::wallet::substrates::wallet_wire_calls::WalletWireCall;
use crate::wallet::substrates::WalletWire;

use crate::wallet::serializer::{
    abort_action, acquire_certificate, authenticated, certificate_ser, create_action, create_hmac,
    create_signature, decrypt, discover_by_attributes, discover_by_identity_key,
    discover_certificates_result, encrypt, get_header, get_height, get_network, get_public_key,
    get_version, internalize_action, list_actions, list_certificates, list_outputs,
    prove_certificate, relinquish_certificate, relinquish_output, reveal_counterparty_key_linkage,
    reveal_specific_key_linkage, sign_action, verify_hmac, verify_signature,
};

/// Receives wire protocol messages and dispatches them to a wallet implementation.
pub struct WalletWireProcessor<W: WalletInterface> {
    wallet: W,
}

impl<W: WalletInterface> WalletWireProcessor<W> {
    /// Create a new processor wrapping a wallet implementation.
    pub fn new(wallet: W) -> Self {
        Self { wallet }
    }

    /// Process a raw wire message: parse frame, dispatch, return result frame.
    pub async fn process(&self, message: &[u8]) -> Vec<u8> {
        match self.process_inner(message).await {
            Ok(result_data) => write_result_frame(Some(&result_data), None),
            Err(err) => write_result_frame(None, Some(&err)),
        }
    }

    async fn process_inner(&self, message: &[u8]) -> Result<Vec<u8>, WalletError> {
        if message.is_empty() {
            return Err(WalletError::Internal("empty message".to_string()));
        }

        let frame = read_request_frame(message)?;
        let call = WalletWireCall::try_from(frame.call)?;
        let originator = if frame.originator.is_empty() {
            None
        } else {
            Some(frame.originator.as_str())
        };

        match call {
            WalletWireCall::CreateAction => {
                let args = create_action::deserialize_create_action_args(&frame.params)?;
                let result = self.wallet.create_action(args, originator).await?;
                create_action::serialize_create_action_result(&result)
            }
            WalletWireCall::SignAction => {
                let args = sign_action::deserialize_sign_action_args(&frame.params)?;
                let result = self.wallet.sign_action(args, originator).await?;
                sign_action::serialize_sign_action_result(&result)
            }
            WalletWireCall::AbortAction => {
                let args = abort_action::deserialize_abort_action_args(&frame.params)?;
                let result = self.wallet.abort_action(args, originator).await?;
                abort_action::serialize_abort_action_result(&result)
            }
            WalletWireCall::ListActions => {
                let args = list_actions::deserialize_list_actions_args(&frame.params)?;
                let result = self.wallet.list_actions(args, originator).await?;
                list_actions::serialize_list_actions_result(&result)
            }
            WalletWireCall::InternalizeAction => {
                let args = internalize_action::deserialize_internalize_action_args(&frame.params)?;
                let result = self.wallet.internalize_action(args, originator).await?;
                internalize_action::serialize_internalize_action_result(&result)
            }
            WalletWireCall::ListOutputs => {
                let args = list_outputs::deserialize_list_outputs_args(&frame.params)?;
                let result = self.wallet.list_outputs(args, originator).await?;
                list_outputs::serialize_list_outputs_result(&result)
            }
            WalletWireCall::RelinquishOutput => {
                let args = relinquish_output::deserialize_relinquish_output_args(&frame.params)?;
                let result = self.wallet.relinquish_output(args, originator).await?;
                relinquish_output::serialize_relinquish_output_result(&result)
            }
            WalletWireCall::GetPublicKey => {
                let args = get_public_key::deserialize_get_public_key_args(&frame.params)?;
                let result = self.wallet.get_public_key(args, originator).await?;
                get_public_key::serialize_get_public_key_result(&result)
            }
            WalletWireCall::RevealCounterpartyKeyLinkage => {
                let args = reveal_counterparty_key_linkage::deserialize_reveal_counterparty_key_linkage_args(&frame.params)?;
                let result = self
                    .wallet
                    .reveal_counterparty_key_linkage(args, originator)
                    .await?;
                reveal_counterparty_key_linkage::serialize_reveal_counterparty_key_linkage_result(
                    &result,
                )
            }
            WalletWireCall::RevealSpecificKeyLinkage => {
                let args =
                    reveal_specific_key_linkage::deserialize_reveal_specific_key_linkage_args(
                        &frame.params,
                    )?;
                let result = self
                    .wallet
                    .reveal_specific_key_linkage(args, originator)
                    .await?;
                reveal_specific_key_linkage::serialize_reveal_specific_key_linkage_result(&result)
            }
            WalletWireCall::Encrypt => {
                let args = encrypt::deserialize_encrypt_args(&frame.params)?;
                let result = self.wallet.encrypt(args, originator).await?;
                encrypt::serialize_encrypt_result(&result)
            }
            WalletWireCall::Decrypt => {
                let args = decrypt::deserialize_decrypt_args(&frame.params)?;
                let result = self.wallet.decrypt(args, originator).await?;
                decrypt::serialize_decrypt_result(&result)
            }
            WalletWireCall::CreateHmac => {
                let args = create_hmac::deserialize_create_hmac_args(&frame.params)?;
                let result = self.wallet.create_hmac(args, originator).await?;
                create_hmac::serialize_create_hmac_result(&result)
            }
            WalletWireCall::VerifyHmac => {
                let args = verify_hmac::deserialize_verify_hmac_args(&frame.params)?;
                let result = self.wallet.verify_hmac(args, originator).await?;
                verify_hmac::serialize_verify_hmac_result(&result)
            }
            WalletWireCall::CreateSignature => {
                let args = create_signature::deserialize_create_signature_args(&frame.params)?;
                let result = self.wallet.create_signature(args, originator).await?;
                create_signature::serialize_create_signature_result(&result)
            }
            WalletWireCall::VerifySignature => {
                let args = verify_signature::deserialize_verify_signature_args(&frame.params)?;
                let result = self.wallet.verify_signature(args, originator).await?;
                verify_signature::serialize_verify_signature_result(&result)
            }
            WalletWireCall::AcquireCertificate => {
                let args =
                    acquire_certificate::deserialize_acquire_certificate_args(&frame.params)?;
                let result = self.wallet.acquire_certificate(args, originator).await?;
                certificate_ser::serialize_certificate(&result)
            }
            WalletWireCall::ListCertificates => {
                let args = list_certificates::deserialize_list_certificates_args(&frame.params)?;
                let result = self.wallet.list_certificates(args, originator).await?;
                list_certificates::serialize_list_certificates_result(&result)
            }
            WalletWireCall::ProveCertificate => {
                let args = prove_certificate::deserialize_prove_certificate_args(&frame.params)?;
                let result = self.wallet.prove_certificate(args, originator).await?;
                prove_certificate::serialize_prove_certificate_result(&result)
            }
            WalletWireCall::RelinquishCertificate => {
                let args =
                    relinquish_certificate::deserialize_relinquish_certificate_args(&frame.params)?;
                let result = self.wallet.relinquish_certificate(args, originator).await?;
                relinquish_certificate::serialize_relinquish_certificate_result(&result)
            }
            WalletWireCall::DiscoverByIdentityKey => {
                let args = discover_by_identity_key::deserialize_discover_by_identity_key_args(
                    &frame.params,
                )?;
                let result = self
                    .wallet
                    .discover_by_identity_key(args, originator)
                    .await?;
                discover_certificates_result::serialize_discover_certificates_result(&result)
            }
            WalletWireCall::DiscoverByAttributes => {
                let args =
                    discover_by_attributes::deserialize_discover_by_attributes_args(&frame.params)?;
                let result = self.wallet.discover_by_attributes(args, originator).await?;
                discover_certificates_result::serialize_discover_certificates_result(&result)
            }
            WalletWireCall::IsAuthenticated => {
                let result = self.wallet.is_authenticated(originator).await?;
                authenticated::serialize_is_authenticated_result(&result)
            }
            WalletWireCall::WaitForAuthentication => {
                let result = self.wallet.wait_for_authentication(originator).await?;
                authenticated::serialize_wait_authenticated_result(&result)
            }
            WalletWireCall::GetHeight => {
                let result = self.wallet.get_height(originator).await?;
                get_height::serialize_get_height_result(&result)
            }
            WalletWireCall::GetHeaderForHeight => {
                let args = get_header::deserialize_get_header_args(&frame.params)?;
                let result = self.wallet.get_header_for_height(args, originator).await?;
                get_header::serialize_get_header_result(&result)
            }
            WalletWireCall::GetNetwork => {
                let result = self.wallet.get_network(originator).await?;
                get_network::serialize_get_network_result(&result)
            }
            WalletWireCall::GetVersion => {
                let result = self.wallet.get_version(originator).await?;
                get_version::serialize_get_version_result(&result)
            }
        }
    }
}

/// WalletWireProcessor also implements WalletWire so it can serve as an
/// in-memory transport for testing (transceiver -> processor -> wallet).
#[async_trait::async_trait]
impl<W: WalletInterface + Send + Sync> WalletWire for WalletWireProcessor<W> {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, WalletError> {
        Ok(self.process(message).await)
    }
}
