//! DiscoverByAttributes args serialization.
//! Result uses the shared DiscoverCertificatesResult (see discover_certificates_result).

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;

pub fn serialize_discover_by_attributes_args(
    args: &DiscoverByAttributesArgs,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Attributes (JavaScript object insertion order). TS writes UTF-16
        // String.length with UTF-8 bytes for non-ASCII text, producing a
        // self-inconsistent frame; write_bytes deliberately uses UTF-8 length.
        write_varint(w, args.attributes.len() as u64)?;
        for (key, value) in &args.attributes {
            write_bytes(w, key.as_bytes())?;
            write_bytes(w, value.as_bytes())?;
        }
        // Limit, offset, seek permission
        write_optional_uint32(w, args.limit)?;
        write_optional_uint32(w, args.offset)?;
        write_optional_bool(w, args.seek_permission)
    })
}

pub fn deserialize_discover_by_attributes_args(
    data: &[u8],
) -> Result<DiscoverByAttributesArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    // Attributes
    let attr_len = read_varint(&mut r)?;
    let mut attributes = indexmap::IndexMap::with_capacity(attr_len as usize);
    for _ in 0..attr_len {
        let key = String::from_utf8(read_bytes(&mut r)?)
            .map_err(|e| WalletError::Internal(e.to_string()))?;
        let value = String::from_utf8(read_bytes(&mut r)?)
            .map_err(|e| WalletError::Internal(e.to_string()))?;
        attributes.insert(key, value);
    }
    let limit = read_optional_uint32(&mut r)?;
    let offset = read_optional_uint32(&mut r)?;
    let seek_permission = read_optional_bool(&mut r)?;
    Ok(DiscoverByAttributesArgs {
        attributes,
        limit,
        offset,
        seek_permission,
    })
}
