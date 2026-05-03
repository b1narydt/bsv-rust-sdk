//! Owner address — P2PKH key hash or P2MPKH script hash.
//!
//! Both produce a 20-byte HASH160 in the STAS-3 owner slot. The difference
//! is in how the unlocking script is constructed at spend time
//! (per spec v0.2 §10).

use crate::primitives::hash::hash160;

/// 20-byte HASH160 used as STAS-3 owner / receiveAddr / authority.
///
/// Two constructive forms; both result in the same on-chain bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerAddress {
    /// HASH160(pubkey) — single-key (P2PKH-style) ownership.
    Pkh([u8; 20]),
    /// HASH160(P2MPKH redeem script) — m-of-n multisig ownership.
    Mpkh([u8; 20]),
}

impl OwnerAddress {
    /// The 20-byte hash that appears in the locking script.
    pub fn hash(&self) -> [u8; 20] {
        match self {
            OwnerAddress::Pkh(h) => *h,
            OwnerAddress::Mpkh(h) => *h,
        }
    }

    /// `true` if this is the spec-defined `EMPTY_HASH160` sentinel
    /// (signature-suppression mode per §10.3).
    pub fn is_empty_sentinel(&self) -> bool {
        self.hash() == super::constants::EMPTY_HASH160
    }
}

impl From<[u8; 20]> for OwnerAddress {
    fn from(h: [u8; 20]) -> Self {
        OwnerAddress::Pkh(h)
    }
}

/// HASH160 a compressed public key into the 20-byte form used in the
/// STAS-3 owner slot. Communicates intent at the call site — equivalent
/// to `hash160(pubkey)`.
pub fn pkh_from_compressed_pubkey(pubkey: &[u8]) -> [u8; 20] {
    hash160(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::templates::stas3::constants::EMPTY_HASH160;

    #[test]
    fn test_hash_returns_inner_pkh() {
        let h = [0x11u8; 20];
        let owner = OwnerAddress::Pkh(h);
        assert_eq!(owner.hash(), h);
    }

    #[test]
    fn test_hash_returns_inner_mpkh() {
        let h = [0x22u8; 20];
        let owner = OwnerAddress::Mpkh(h);
        assert_eq!(owner.hash(), h);
    }

    #[test]
    fn test_is_empty_sentinel_detects_constant() {
        // The sentinel equals HASH160("") — both Pkh and Mpkh forms count.
        assert!(OwnerAddress::Pkh(EMPTY_HASH160).is_empty_sentinel());
        assert!(OwnerAddress::Mpkh(EMPTY_HASH160).is_empty_sentinel());
        // Anything else does not.
        assert!(!OwnerAddress::Pkh([0u8; 20]).is_empty_sentinel());
        assert!(!OwnerAddress::Pkh([0xffu8; 20]).is_empty_sentinel());
    }

    #[test]
    fn test_pkh_from_compressed_pubkey_uses_hash160() {
        // Synthetic 33-byte compressed pubkey; just verify the helper is
        // a thin wrapper around hash160.
        let pubkey = [0x02u8; 33];
        let direct = hash160(&pubkey);
        let via_helper = pkh_from_compressed_pubkey(&pubkey);
        assert_eq!(direct, via_helper);
    }

    #[test]
    fn test_from_array_constructs_pkh() {
        let h = [0xabu8; 20];
        let owner: OwnerAddress = h.into();
        assert_eq!(owner, OwnerAddress::Pkh(h));
    }
}
