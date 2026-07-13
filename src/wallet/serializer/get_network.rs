//! GetNetwork result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{GetNetworkResult, Network};

const NETWORK_MAINNET_CODE: u8 = 0;
const NETWORK_TESTNET_CODE: u8 = 1;

pub fn serialize_get_network_result(result: &GetNetworkResult) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| match result.network {
        Network::Mainnet => write_byte(w, NETWORK_MAINNET_CODE),
        Network::Testnet => write_byte(w, NETWORK_TESTNET_CODE),
    })
}

pub fn deserialize_get_network_result(data: &[u8]) -> Result<GetNetworkResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let b = read_byte(&mut r)?;
    let network = match b {
        NETWORK_MAINNET_CODE => Network::Mainnet,
        NETWORK_TESTNET_CODE => Network::Testnet,
        _ => return Err(WalletError::Internal(format!("invalid network byte: {b}"))),
    };
    Ok(GetNetworkResult { network })
}
