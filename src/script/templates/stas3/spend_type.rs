//! STAS-3 spend types and tx types per spec v0.2 §8.

/// Spend type byte (slot 20 of unlocking script).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpendType {
    /// Regular owner spend (transfer, split, merge, swap-execute legs).
    Transfer = 1,
    /// Freeze or unfreeze (requires freeze authority).
    FreezeUnfreeze = 2,
    /// Confiscation (requires confiscation authority).
    Confiscation = 3,
    /// Swap cancellation (requires swap maker authorization).
    SwapCancellation = 4,
}

impl SpendType {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Transfer),
            2 => Some(Self::FreezeUnfreeze),
            3 => Some(Self::Confiscation),
            4 => Some(Self::SwapCancellation),
            _ => None,
        }
    }
}

/// TX type byte (slot 18 of unlocking script). Spec v0.2 §8.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxType {
    Regular = 0,
    AtomicSwap = 1,
    Merge2 = 2,
    Merge3 = 3,
    Merge4 = 4,
    Merge5 = 5,
    Merge6 = 6,
    Merge7 = 7,
}

impl TxType {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Regular),
            1 => Some(Self::AtomicSwap),
            2 => Some(Self::Merge2),
            3 => Some(Self::Merge3),
            4 => Some(Self::Merge4),
            5 => Some(Self::Merge5),
            6 => Some(Self::Merge6),
            7 => Some(Self::Merge7),
            _ => None,
        }
    }

    /// For merge variants, returns the piece count (2..=7), else None.
    pub fn merge_piece_count(self) -> Option<u8> {
        match self {
            Self::Merge2 | Self::Merge3 | Self::Merge4 | Self::Merge5 | Self::Merge6
            | Self::Merge7 => Some(self as u8),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spend_type_round_trip() {
        for v in [
            SpendType::Transfer,
            SpendType::FreezeUnfreeze,
            SpendType::Confiscation,
            SpendType::SwapCancellation,
        ] {
            assert_eq!(SpendType::from_u8(v.to_u8()), Some(v));
        }
    }

    #[test]
    fn test_spend_type_invalid_returns_none() {
        // 0 is reserved, anything > 4 is invalid.
        assert_eq!(SpendType::from_u8(0), None);
        assert_eq!(SpendType::from_u8(5), None);
        assert_eq!(SpendType::from_u8(255), None);
    }

    #[test]
    fn test_spend_type_byte_values() {
        // Wire format must be exactly these bytes per spec §8.2.
        assert_eq!(SpendType::Transfer.to_u8(), 1);
        assert_eq!(SpendType::FreezeUnfreeze.to_u8(), 2);
        assert_eq!(SpendType::Confiscation.to_u8(), 3);
        assert_eq!(SpendType::SwapCancellation.to_u8(), 4);
    }

    #[test]
    fn test_tx_type_round_trip() {
        for v in [
            TxType::Regular,
            TxType::AtomicSwap,
            TxType::Merge2,
            TxType::Merge3,
            TxType::Merge4,
            TxType::Merge5,
            TxType::Merge6,
            TxType::Merge7,
        ] {
            assert_eq!(TxType::from_u8(v.to_u8()), Some(v));
        }
    }

    #[test]
    fn test_tx_type_invalid_returns_none() {
        assert_eq!(TxType::from_u8(8), None);
        assert_eq!(TxType::from_u8(255), None);
    }

    #[test]
    fn test_merge_piece_count() {
        assert_eq!(TxType::Regular.merge_piece_count(), None);
        assert_eq!(TxType::AtomicSwap.merge_piece_count(), None);
        assert_eq!(TxType::Merge2.merge_piece_count(), Some(2));
        assert_eq!(TxType::Merge3.merge_piece_count(), Some(3));
        assert_eq!(TxType::Merge4.merge_piece_count(), Some(4));
        assert_eq!(TxType::Merge5.merge_piece_count(), Some(5));
        assert_eq!(TxType::Merge6.merge_piece_count(), Some(6));
        assert_eq!(TxType::Merge7.merge_piece_count(), Some(7));
    }

    #[test]
    fn test_tx_type_byte_values() {
        assert_eq!(TxType::Regular.to_u8(), 0);
        assert_eq!(TxType::AtomicSwap.to_u8(), 1);
        assert_eq!(TxType::Merge2.to_u8(), 2);
        assert_eq!(TxType::Merge7.to_u8(), 7);
    }
}
