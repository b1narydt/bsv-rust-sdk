//! STAS-3 flag bits (spec v0.2 §5.2.2).

/// Bit 0: token issuance permits freeze/unfreeze by the freeze authority.
pub const FREEZABLE: u8 = 0x01;
/// Bit 1: token issuance permits confiscation by the confiscation authority.
pub const CONFISCATABLE: u8 = 0x02;

/// Build the flags byte from boolean options.
pub fn build_flags(freezable: bool, confiscatable: bool) -> u8 {
    let mut f = 0u8;
    if freezable {
        f |= FREEZABLE;
    }
    if confiscatable {
        f |= CONFISCATABLE;
    }
    f
}

#[inline]
pub fn is_freezable(flags: u8) -> bool {
    flags & FREEZABLE != 0
}

#[inline]
pub fn is_confiscatable(flags: u8) -> bool {
    flags & CONFISCATABLE != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_flags_all_combinations() {
        assert_eq!(build_flags(false, false), 0x00);
        assert_eq!(build_flags(true, false), 0x01);
        assert_eq!(build_flags(false, true), 0x02);
        assert_eq!(build_flags(true, true), 0x03);
    }

    #[test]
    fn test_is_freezable_round_trip() {
        for &(freezable, confiscatable) in &[
            (false, false),
            (true, false),
            (false, true),
            (true, true),
        ] {
            let f = build_flags(freezable, confiscatable);
            assert_eq!(is_freezable(f), freezable);
            assert_eq!(is_confiscatable(f), confiscatable);
        }
    }

    #[test]
    fn test_flag_bits_are_independent() {
        // Setting one flag must not change the other.
        assert!(is_freezable(FREEZABLE));
        assert!(!is_confiscatable(FREEZABLE));
        assert!(is_confiscatable(CONFISCATABLE));
        assert!(!is_freezable(CONFISCATABLE));
    }
}
