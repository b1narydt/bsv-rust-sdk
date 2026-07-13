//! WalletWireCall enum mapping wallet methods to u8 call codes.
//!
//! Each variant corresponds to a specific wallet operation that can be
//! invoked over the wire protocol. Translated from Go SDK
//! wallet/substrates/wallet_wire_calls.go.

/// All 28 wallet wire protocol call types with their corresponding byte codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WalletWireCall {
    CreateAction = 1,
    SignAction = 2,
    AbortAction = 3,
    ListActions = 4,
    InternalizeAction = 5,
    ListOutputs = 6,
    RelinquishOutput = 7,
    GetPublicKey = 8,
    RevealCounterpartyKeyLinkage = 9,
    RevealSpecificKeyLinkage = 10,
    Encrypt = 11,
    Decrypt = 12,
    CreateHmac = 13,
    VerifyHmac = 14,
    CreateSignature = 15,
    VerifySignature = 16,
    AcquireCertificate = 17,
    ListCertificates = 18,
    ProveCertificate = 19,
    RelinquishCertificate = 20,
    DiscoverByIdentityKey = 21,
    DiscoverByAttributes = 22,
    IsAuthenticated = 23,
    WaitForAuthentication = 24,
    GetHeight = 25,
    GetHeaderForHeight = 26,
    GetNetwork = 27,
    GetVersion = 28,
}

impl TryFrom<u8> for WalletWireCall {
    type Error = crate::wallet::error::WalletError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(WalletWireCall::CreateAction),
            2 => Ok(WalletWireCall::SignAction),
            3 => Ok(WalletWireCall::AbortAction),
            4 => Ok(WalletWireCall::ListActions),
            5 => Ok(WalletWireCall::InternalizeAction),
            6 => Ok(WalletWireCall::ListOutputs),
            7 => Ok(WalletWireCall::RelinquishOutput),
            8 => Ok(WalletWireCall::GetPublicKey),
            9 => Ok(WalletWireCall::RevealCounterpartyKeyLinkage),
            10 => Ok(WalletWireCall::RevealSpecificKeyLinkage),
            11 => Ok(WalletWireCall::Encrypt),
            12 => Ok(WalletWireCall::Decrypt),
            13 => Ok(WalletWireCall::CreateHmac),
            14 => Ok(WalletWireCall::VerifyHmac),
            15 => Ok(WalletWireCall::CreateSignature),
            16 => Ok(WalletWireCall::VerifySignature),
            17 => Ok(WalletWireCall::AcquireCertificate),
            18 => Ok(WalletWireCall::ListCertificates),
            19 => Ok(WalletWireCall::ProveCertificate),
            20 => Ok(WalletWireCall::RelinquishCertificate),
            21 => Ok(WalletWireCall::DiscoverByIdentityKey),
            22 => Ok(WalletWireCall::DiscoverByAttributes),
            23 => Ok(WalletWireCall::IsAuthenticated),
            24 => Ok(WalletWireCall::WaitForAuthentication),
            25 => Ok(WalletWireCall::GetHeight),
            26 => Ok(WalletWireCall::GetHeaderForHeight),
            27 => Ok(WalletWireCall::GetNetwork),
            28 => Ok(WalletWireCall::GetVersion),
            _ => Err(crate::wallet::error::WalletError::Internal(format!(
                "unknown call code: {value}"
            ))),
        }
    }
}

impl WalletWireCall {
    /// Returns the URL path segment for this call (used by HTTP substrates).
    pub fn to_call_path(&self) -> &'static str {
        match self {
            WalletWireCall::CreateAction => "createAction",
            WalletWireCall::SignAction => "signAction",
            WalletWireCall::AbortAction => "abortAction",
            WalletWireCall::ListActions => "listActions",
            WalletWireCall::InternalizeAction => "internalizeAction",
            WalletWireCall::ListOutputs => "listOutputs",
            WalletWireCall::RelinquishOutput => "relinquishOutput",
            WalletWireCall::GetPublicKey => "getPublicKey",
            WalletWireCall::RevealCounterpartyKeyLinkage => "revealCounterpartyKeyLinkage",
            WalletWireCall::RevealSpecificKeyLinkage => "revealSpecificKeyLinkage",
            WalletWireCall::Encrypt => "encrypt",
            WalletWireCall::Decrypt => "decrypt",
            WalletWireCall::CreateHmac => "createHmac",
            WalletWireCall::VerifyHmac => "verifyHmac",
            WalletWireCall::CreateSignature => "createSignature",
            WalletWireCall::VerifySignature => "verifySignature",
            WalletWireCall::AcquireCertificate => "acquireCertificate",
            WalletWireCall::ListCertificates => "listCertificates",
            WalletWireCall::ProveCertificate => "proveCertificate",
            WalletWireCall::RelinquishCertificate => "relinquishCertificate",
            WalletWireCall::DiscoverByIdentityKey => "discoverByIdentityKey",
            WalletWireCall::DiscoverByAttributes => "discoverByAttributes",
            WalletWireCall::IsAuthenticated => "isAuthenticated",
            WalletWireCall::WaitForAuthentication => "waitForAuthentication",
            WalletWireCall::GetHeight => "getHeight",
            WalletWireCall::GetHeaderForHeight => "getHeaderForHeight",
            WalletWireCall::GetNetwork => "getNetwork",
            WalletWireCall::GetVersion => "getVersion",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_all_valid_codes() {
        for code in 1u8..=28 {
            let call = WalletWireCall::try_from(code);
            assert!(call.is_ok(), "code {code} should be valid");
            assert_eq!(call.unwrap() as u8, code);
        }
    }

    #[test]
    fn test_try_from_invalid_codes() {
        assert!(WalletWireCall::try_from(0).is_err());
        assert!(WalletWireCall::try_from(29).is_err());
        assert!(WalletWireCall::try_from(255).is_err());
    }

    #[test]
    fn test_call_paths() {
        assert_eq!(WalletWireCall::CreateAction.to_call_path(), "createAction");
        assert_eq!(WalletWireCall::Encrypt.to_call_path(), "encrypt");
        assert_eq!(WalletWireCall::GetVersion.to_call_path(), "getVersion");
        assert_eq!(WalletWireCall::CreateHmac.to_call_path(), "createHmac");
        assert_eq!(
            WalletWireCall::RevealCounterpartyKeyLinkage.to_call_path(),
            "revealCounterpartyKeyLinkage"
        );
    }
}
