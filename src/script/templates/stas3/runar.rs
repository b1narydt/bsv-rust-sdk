//! Runar template export (spec §8.6).
//!
//! Exposes the byte layout of an EAC locking script with explicit
//! per-field slot offsets. A Runar VPPA contract embeds the static
//! portions as constants and validates per-tx fields by byte comparison
//! at known offsets. This is the bridge between Runar covenants and
//! STAS-3 tokens for the atomic-mint pattern (spec §8.5).
//!
//! All `[u8; 20]` PKH inputs MUST be Type-42 derived by the caller — see
//! spec §1A. This helper performs no derivation.
//!
//! # Layout (fixed, derived from `build_locking_script`)
//!
//! ```text
//! byte 0       : 0x14 (push20)
//! bytes 1..21  : owner_pkh slot              <- per-tx
//! byte 21      : 0x00 (OP_0 — placeholder var2 for Passive(empty))
//! bytes 22..2921 : engine (2899 bytes)        — constant
//! byte 2921    : 0x14 (push20)
//! bytes 2922..2942 : redemption_pkh           — constant per issuance
//! byte 2942    : 0x01 (push1 flags header)
//! byte 2943    : flags byte                   — constant per issuance
//! [service_fields...]                         — constant per issuance, 21 bytes each
//! [optional_data EAC layout follows]
//!   "EAC1"          (header 0x04 + 4 bytes)   — CONSTANT
//!   quantity_wh     (header 0x08 + 8 bytes)   — per-tx
//!   interval_start  (header 0x08 + 8 bytes)   — per-tx
//!   interval_end    (header 0x08 + 8 bytes)   — per-tx
//!   energy_source   (header 0x10 + 16 bytes)  — per-tx
//!   country         (header 0x02 + 2 bytes)   — per-tx
//!   device_id       (header 0x20 + 32 bytes)  — per-tx
//!   id_range_start  (header 0x08 + 8 bytes)   — per-tx
//!   id_range_end    (header 0x08 + 8 bytes)   — per-tx
//!   issue_date      (header 0x08 + 8 bytes)   — per-tx
//!   storage_tag     (header 0x08 + 8 bytes)   — per-tx
//! ```

use super::action_data::ActionData;
use super::constants::STAS3_ENGINE_BYTES;
use super::eac::EacFields;
use super::error::Stas3Error;
use super::lock::{build_locking_script, LockParams};

/// One field slot in the EAC locking script that varies per-tx.
/// The Runar contract validates the bytes at this offset against
/// the per-tx expected value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EacFieldSlot {
    pub field_name: &'static str,
    pub byte_offset: usize,
    pub byte_length: usize,
}

/// Full EAC locking-script template with sample bytes and per-tx slot
/// offsets. The Runar contract uses `template_bytes` for the constant
/// byte regions and validates per-tx slots against the actual values
/// from the settlement event.
#[derive(Clone, Debug)]
pub struct EacRunarTemplate {
    /// Sample EAC locking script bytes with PLACEHOLDER values for all
    /// per-tx slots (owner_pkh = [0; 20], EAC fields all zero).
    pub template_bytes: Vec<u8>,
    /// Per-tx slots that the Runar contract must validate. Offsets are
    /// into `template_bytes`. Order: `owner_pkh` first, then EAC fields
    /// in `optional_data` order.
    pub slots: Vec<EacFieldSlot>,
}

/// Build the EAC locking-script template for a given issuance config.
///
/// # Inputs
/// All 20-byte hashes here MUST be Type-42 (BRC-42) derived public-key
/// hashes produced by `wallet.get_public_key(...)` and HASH160'd. The
/// helper does not validate this — usage outside this contract violates §1A.
///
/// # Returns
/// An `EacRunarTemplate` whose `template_bytes` is a sample EAC locking
/// script with placeholder values, and whose `slots` describe the byte
/// offsets the Runar contract must validate.
pub fn build_eac_runar_template(
    redemption_pkh: [u8; 20],
    flags: u8,
    freeze_auth: Option<[u8; 20]>,
    confiscation_auth: Option<[u8; 20]>,
) -> Result<EacRunarTemplate, Stas3Error> {
    let placeholder_owner = [0u8; 20];
    let placeholder_fields = EacFields {
        quantity_wh: 0,
        interval_start: 0,
        interval_end: 0,
        energy_source: super::eac::EnergySource::Wind,
        country: *b"XX",
        device_id: [0u8; 32],
        id_range: (0, 0),
        issue_date: 0,
        storage_tag: 0,
    };

    let mut service_fields: Vec<Vec<u8>> = Vec::new();
    if let Some(fa) = freeze_auth {
        service_fields.push(fa.to_vec());
    }
    if let Some(ca) = confiscation_auth {
        service_fields.push(ca.to_vec());
    }

    let lock = build_locking_script(&LockParams {
        owner_pkh: placeholder_owner,
        action_data: ActionData::Passive(vec![]),
        redemption_pkh,
        flags,
        service_fields: service_fields.clone(),
        optional_data: placeholder_fields.to_optional_data(),
    })?;
    let template_bytes = lock.to_binary();

    // Compute slot offsets (see module-doc layout).
    //
    // owner slot is bytes [1..21].
    let mut slots = vec![EacFieldSlot {
        field_name: "owner_pkh",
        byte_offset: 1,
        byte_length: 20,
    }];

    // Walk to the start of the optional_data region:
    //   owner push (21) + var2 (1) + engine (2899) + protoID push (21) + flags push (2)
    //   = 2944 bytes
    //   + service_fields (each is 0x14 + 20 = 21 bytes)
    let mut offset = 21 + 1 + STAS3_ENGINE_BYTES.len() + 21 + 2;
    offset += service_fields.len() * 21;

    // Skip the EAC1 schema-tag push (constant): header (1 byte) + 4 bytes
    offset += 1 + 4;

    // Per-tx EAC field slots (each push: 1-byte header + N bytes payload)
    let add_slot = |name: &'static str, length: usize, offset: &mut usize, slots: &mut Vec<EacFieldSlot>| {
        *offset += 1; // push header (length 2..=75 fits in a single bare push byte)
        slots.push(EacFieldSlot {
            field_name: name,
            byte_offset: *offset,
            byte_length: length,
        });
        *offset += length;
    };

    add_slot("quantity_wh", 8, &mut offset, &mut slots);
    add_slot("interval_start", 8, &mut offset, &mut slots);
    add_slot("interval_end", 8, &mut offset, &mut slots);
    add_slot("energy_source", 16, &mut offset, &mut slots);
    add_slot("country", 2, &mut offset, &mut slots);
    add_slot("device_id", 32, &mut offset, &mut slots);
    add_slot("id_range_start", 8, &mut offset, &mut slots);
    add_slot("id_range_end", 8, &mut offset, &mut slots);
    add_slot("issue_date", 8, &mut offset, &mut slots);
    add_slot("storage_tag", 8, &mut offset, &mut slots);

    // Sanity: walking the slots should arrive at the end of template_bytes.
    debug_assert_eq!(
        offset,
        template_bytes.len(),
        "slot walk did not consume entire template_bytes"
    );

    Ok(EacRunarTemplate {
        template_bytes,
        slots,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::templates::stas3::eac::{build_eac_lock, EnergySource};
    use crate::script::templates::stas3::flags::{CONFISCATABLE, FREEZABLE};

    fn realistic_fields() -> EacFields {
        EacFields {
            quantity_wh: 1_500_000,
            interval_start: 1_700_000_000,
            interval_end: 1_700_003_600,
            energy_source: EnergySource::Solar,
            country: *b"US",
            device_id: [0xab; 32],
            id_range: (1_000, 2_499),
            issue_date: 1_700_010_000,
            storage_tag: 0,
        }
    }

    /// Verify the slot offsets exactly align with bytes in a real EAC lock
    /// produced via `build_eac_lock`. This is the load-bearing test: if a
    /// slot offset is wrong by a single byte, this fails.
    #[test]
    fn test_runar_template_offsets_align_with_real_bytes() {
        let owner_pkh = [0x77; 20];
        let redemption_pkh = [0xbb; 20];
        let fields = realistic_fields();
        let real_lock = build_eac_lock(owner_pkh, redemption_pkh, 0, vec![], &fields).unwrap();
        let real_bytes = real_lock.to_binary();

        let template =
            build_eac_runar_template(redemption_pkh, 0, None, None).unwrap();

        // Lengths must match — the EAC layout is fixed-size for all per-tx slots.
        assert_eq!(
            real_bytes.len(),
            template.template_bytes.len(),
            "real EAC lock and template differ in length"
        );

        // The non-slot bytes must be identical (template uses placeholders for slots).
        // We verify by checking each slot's *bytes in real_bytes* match the encoded
        // field, then check the bytes outside the slots match the template.
        let owner_slot = &template.slots[0];
        assert_eq!(owner_slot.field_name, "owner_pkh");
        assert_eq!(
            &real_bytes[owner_slot.byte_offset..owner_slot.byte_offset + owner_slot.byte_length],
            &owner_pkh,
            "owner_pkh slot bytes don't match real lock"
        );

        let opt_data = fields.to_optional_data();
        // EAC field expected bytes (skip index 0 which is the schema tag).
        let expected: Vec<&[u8]> = opt_data[1..].iter().map(|v| v.as_slice()).collect();

        // Field slots after owner_pkh, in EAC order.
        let field_order = [
            "quantity_wh",
            "interval_start",
            "interval_end",
            "energy_source",
            "country",
            "device_id",
            "id_range_start",
            "id_range_end",
            "issue_date",
            "storage_tag",
        ];

        for (i, name) in field_order.iter().enumerate() {
            let slot = &template.slots[i + 1]; // +1 to skip owner_pkh
            assert_eq!(slot.field_name, *name, "slot ordering mismatch at {i}");
            let real_slice =
                &real_bytes[slot.byte_offset..slot.byte_offset + slot.byte_length];
            assert_eq!(
                real_slice,
                expected[i],
                "slot {name} (offset {}, len {}) bytes don't match expected EAC field",
                slot.byte_offset,
                slot.byte_length
            );
        }

        // Verify bytes outside slots match the template exactly.
        let mut slot_byte_set = std::collections::HashSet::new();
        for s in &template.slots {
            for b in s.byte_offset..s.byte_offset + s.byte_length {
                slot_byte_set.insert(b);
            }
        }
        for i in 0..real_bytes.len() {
            if !slot_byte_set.contains(&i) {
                assert_eq!(
                    real_bytes[i], template.template_bytes[i],
                    "non-slot byte {i} differs between real lock and template"
                );
            }
        }
    }

    #[test]
    fn test_runar_template_with_no_authorities() {
        let redemption_pkh = [0xbb; 20];
        let template =
            build_eac_runar_template(redemption_pkh, 0, None, None).unwrap();

        // Owner slot must be the very first per-tx slot at offset 1.
        assert_eq!(template.slots[0].field_name, "owner_pkh");
        assert_eq!(template.slots[0].byte_offset, 1);
        assert_eq!(template.slots[0].byte_length, 20);

        // Optional data starts at: 21 + 1 + 2899 + 21 + 2 = 2944
        // Schema tag push spans 5 bytes (0x04 + 4)
        // First per-tx slot (quantity_wh) data starts at 2944 + 5 + 1 = 2950
        assert_eq!(template.slots[1].field_name, "quantity_wh");
        assert_eq!(template.slots[1].byte_offset, 2950);
        assert_eq!(template.slots[1].byte_length, 8);

        // Verify total slot count: owner + 10 EAC per-tx fields = 11
        assert_eq!(template.slots.len(), 11);
    }

    #[test]
    fn test_runar_template_with_freeze_only() {
        let redemption_pkh = [0xbb; 20];
        let freeze_auth = [0x11u8; 20];
        let template = build_eac_runar_template(
            redemption_pkh,
            FREEZABLE,
            Some(freeze_auth),
            None,
        )
        .unwrap();

        // One service field shifts everything after the flags push by 21 bytes.
        // quantity_wh data offset shifts from 2950 to 2950 + 21 = 2971.
        assert_eq!(template.slots[0].field_name, "owner_pkh");
        assert_eq!(template.slots[0].byte_offset, 1);
        assert_eq!(template.slots[1].field_name, "quantity_wh");
        assert_eq!(template.slots[1].byte_offset, 2950 + 21);

        // Verify the freeze_auth bytes appear in the template at the expected position.
        // Service fields begin right after the flags push (offset 2944).
        // First service field push: 0x14 + 20 bytes = bytes 2944..2965.
        assert_eq!(template.template_bytes[2944], 0x14);
        assert_eq!(&template.template_bytes[2945..2965], &freeze_auth);

        assert_eq!(template.slots.len(), 11);
    }

    #[test]
    fn test_runar_template_with_both_authorities() {
        let redemption_pkh = [0xbb; 20];
        let freeze_auth = [0x11u8; 20];
        let confiscate_auth = [0x22u8; 20];
        let template = build_eac_runar_template(
            redemption_pkh,
            FREEZABLE | CONFISCATABLE,
            Some(freeze_auth),
            Some(confiscate_auth),
        )
        .unwrap();

        // Two service fields shift per-tx slots by 2 * 21 = 42 bytes.
        assert_eq!(template.slots[0].byte_offset, 1);
        assert_eq!(template.slots[1].field_name, "quantity_wh");
        assert_eq!(template.slots[1].byte_offset, 2950 + 42);

        // Verify both auth pushes appear in the template at expected positions.
        // First svc field at bytes 2944..2965, second at 2965..2986.
        assert_eq!(template.template_bytes[2944], 0x14);
        assert_eq!(&template.template_bytes[2945..2965], &freeze_auth);
        assert_eq!(template.template_bytes[2965], 0x14);
        assert_eq!(&template.template_bytes[2966..2986], &confiscate_auth);

        // Spot-check an EAC slot offset: storage_tag is the last per-tx slot.
        // Sequence after svc fields:
        //   2944 + 42 = 2986 — start of optional_data
        //   2986: 0x04, 2987..2991: "EAC1"     -> next at 2991
        //   2991: 0x08, 2992..3000: quantity_wh  -> next at 3000
        //   3000: 0x08, 3001..3009: interval_start
        //   3009: 0x08, 3010..3018: interval_end
        //   3018: 0x10, 3019..3035: energy_source
        //   3035: 0x02, 3036..3038: country
        //   3038: 0x20, 3039..3071: device_id
        //   3071: 0x08, 3072..3080: id_range_start
        //   3080: 0x08, 3081..3089: id_range_end
        //   3089: 0x08, 3090..3098: issue_date
        //   3098: 0x08, 3099..3107: storage_tag
        let storage_slot = template.slots.last().unwrap();
        assert_eq!(storage_slot.field_name, "storage_tag");
        assert_eq!(storage_slot.byte_offset, 3099);
        assert_eq!(storage_slot.byte_length, 8);
        assert_eq!(template.template_bytes.len(), 3107);
    }
}
