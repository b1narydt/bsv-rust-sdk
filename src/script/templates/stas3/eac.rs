//! MetaWatt EAC (Energy Attribute Certificate) field schema (spec §9.1).
//!
//! EAC tokens are STAS-3 tokens with a fixed `optional_data` layout
//! tagged `"EAC1"` for schema versioning. This module encodes/decodes
//! EAC-specific fields and exposes EAC-flavored convenience builders.
//!
//! Layout:
//! ```text
//! optional_data[0]  = "EAC1"                       # 4-byte schema tag
//! optional_data[1]  = quantity_wh        (8 B u64 LE)
//! optional_data[2]  = interval_start_ts  (8 B i64 LE Unix seconds)
//! optional_data[3]  = interval_end_ts    (8 B i64 LE)
//! optional_data[4]  = energy_source      (16 B ASCII fixed, NUL-padded)
//! optional_data[5]  = country_code       (2 B ISO 3166-1 alpha-2)
//! optional_data[6]  = device_id          (32 B application-defined hash)
//! optional_data[7]  = id_range_start     (8 B u64 LE)
//! optional_data[8]  = id_range_end       (8 B u64 LE)
//! optional_data[9]  = issue_date_ts      (8 B i64 LE)
//! optional_data[10] = storage_tag        (8 B u64 LE — 0 if not storage-derived)
//! optional_data[11..] = reserved
//! ```
//!
//! All `[u8; 20]` PKHs handled here MUST be Type-42 derived by the caller —
//! see spec §1A. This module performs no derivation.

use super::action_data::ActionData;
use super::error::Stas3Error;
use super::lock::{build_locking_script, LockParams};
use crate::script::locking_script::LockingScript;

/// EAC schema version tag (4 bytes, ASCII).
pub const EAC_SCHEMA_TAG_V1: &[u8; 4] = b"EAC1";

/// Number of EAC fields in the `optional_data` Vec (including the schema tag).
const EAC_FIELD_COUNT: usize = 11;

/// Energy source enum. Encoded as a 16-byte ASCII fixed-length, NUL-padded field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnergySource {
    Wind,
    Solar,
    Hydro,
    Geothermal,
    Biomass,
    Nuclear,
    Storage,
    Other(String),
}

impl EnergySource {
    /// Encode as a 16-byte ASCII fixed-length field, NUL-padded (truncated if >16 bytes).
    pub fn to_field(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        let s: &str = match self {
            Self::Wind => "WIND",
            Self::Solar => "SOLAR",
            Self::Hydro => "HYDRO",
            Self::Geothermal => "GEOTHERMAL",
            Self::Biomass => "BIOMASS",
            Self::Nuclear => "NUCLEAR",
            Self::Storage => "STORAGE",
            Self::Other(s) => s.as_str(),
        };
        let bytes = s.as_bytes();
        let n = bytes.len().min(16);
        buf[..n].copy_from_slice(&bytes[..n]);
        buf
    }

    /// Parse from a 16-byte ASCII fixed-length, NUL-padded field.
    pub fn from_field(field: &[u8; 16]) -> Self {
        let end = field.iter().position(|&b| b == 0).unwrap_or(16);
        let s = std::str::from_utf8(&field[..end]).unwrap_or("");
        match s {
            "WIND" => Self::Wind,
            "SOLAR" => Self::Solar,
            "HYDRO" => Self::Hydro,
            "GEOTHERMAL" => Self::Geothermal,
            "BIOMASS" => Self::Biomass,
            "NUCLEAR" => Self::Nuclear,
            "STORAGE" => Self::Storage,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Decoded EAC fields per spec §9.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EacFields {
    pub quantity_wh: u64,
    pub interval_start: i64,
    pub interval_end: i64,
    pub energy_source: EnergySource,
    pub country: [u8; 2],
    pub device_id: [u8; 32],
    pub id_range: (u64, u64),
    pub issue_date: i64,
    pub storage_tag: u64,
}

impl EacFields {
    /// Encode as an `optional_data` Vec, where each element is one push payload.
    /// Caller passes this Vec directly into `LockParams.optional_data`.
    pub fn to_optional_data(&self) -> Vec<Vec<u8>> {
        vec![
            EAC_SCHEMA_TAG_V1.to_vec(),
            self.quantity_wh.to_le_bytes().to_vec(),
            self.interval_start.to_le_bytes().to_vec(),
            self.interval_end.to_le_bytes().to_vec(),
            self.energy_source.to_field().to_vec(),
            self.country.to_vec(),
            self.device_id.to_vec(),
            self.id_range.0.to_le_bytes().to_vec(),
            self.id_range.1.to_le_bytes().to_vec(),
            self.issue_date.to_le_bytes().to_vec(),
            self.storage_tag.to_le_bytes().to_vec(),
        ]
    }

    /// Parse EAC fields from an `optional_data` Vec.
    /// Validates the schema tag and the length of every fixed-size field.
    /// Trailing entries beyond index 10 are ignored (reserved per §9.1).
    pub fn from_optional_data(data: &[Vec<u8>]) -> Result<Self, Stas3Error> {
        if data.len() < EAC_FIELD_COUNT {
            return Err(Stas3Error::InvalidScript(format!(
                "EAC needs at least {} optional_data entries, got {}",
                EAC_FIELD_COUNT,
                data.len()
            )));
        }
        if data[0].as_slice() != EAC_SCHEMA_TAG_V1 {
            return Err(Stas3Error::InvalidScript(format!(
                "EAC schema tag mismatch: expected {:?}, got {:?}",
                EAC_SCHEMA_TAG_V1, &data[0]
            )));
        }

        let quantity_wh = read_u64_le(&data[1], "quantity_wh")?;
        let interval_start = read_i64_le(&data[2], "interval_start")?;
        let interval_end = read_i64_le(&data[3], "interval_end")?;

        if data[4].len() != 16 {
            return Err(Stas3Error::InvalidScript(format!(
                "EAC energy_source must be 16 bytes, got {}",
                data[4].len()
            )));
        }
        let mut es_field = [0u8; 16];
        es_field.copy_from_slice(&data[4]);
        let energy_source = EnergySource::from_field(&es_field);

        if data[5].len() != 2 {
            return Err(Stas3Error::InvalidScript(format!(
                "EAC country must be 2 bytes, got {}",
                data[5].len()
            )));
        }
        let mut country = [0u8; 2];
        country.copy_from_slice(&data[5]);

        if data[6].len() != 32 {
            return Err(Stas3Error::InvalidScript(format!(
                "EAC device_id must be 32 bytes, got {}",
                data[6].len()
            )));
        }
        let mut device_id = [0u8; 32];
        device_id.copy_from_slice(&data[6]);

        let id_range_start = read_u64_le(&data[7], "id_range_start")?;
        let id_range_end = read_u64_le(&data[8], "id_range_end")?;
        let issue_date = read_i64_le(&data[9], "issue_date")?;
        let storage_tag = read_u64_le(&data[10], "storage_tag")?;

        Ok(Self {
            quantity_wh,
            interval_start,
            interval_end,
            energy_source,
            country,
            device_id,
            id_range: (id_range_start, id_range_end),
            issue_date,
            storage_tag,
        })
    }
}

fn read_u64_le(bytes: &[u8], field: &str) -> Result<u64, Stas3Error> {
    let arr: [u8; 8] = bytes.try_into().map_err(|_| {
        Stas3Error::InvalidScript(format!(
            "EAC {field} must be 8 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(u64::from_le_bytes(arr))
}

fn read_i64_le(bytes: &[u8], field: &str) -> Result<i64, Stas3Error> {
    let arr: [u8; 8] = bytes.try_into().map_err(|_| {
        Stas3Error::InvalidScript(format!(
            "EAC {field} must be 8 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(i64::from_le_bytes(arr))
}

/// Build a STAS-3 locking script for an EAC. Convenience wrapper around
/// `build_locking_script` that constrains `optional_data` to the EAC schema.
///
/// All `[u8; 20]` PKH inputs MUST be Type-42 derived by the caller.
pub fn build_eac_lock(
    owner_pkh: [u8; 20],
    redemption_pkh: [u8; 20],
    flags: u8,
    service_fields: Vec<Vec<u8>>,
    fields: &EacFields,
) -> Result<LockingScript, Stas3Error> {
    build_locking_script(&LockParams {
        owner_pkh,
        action_data: ActionData::Passive(vec![]),
        redemption_pkh,
        flags,
        service_fields,
        optional_data: fields.to_optional_data(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::templates::stas3::decode::decode_locking_script;
    use crate::script::templates::stas3::flags::{CONFISCATABLE, FREEZABLE};

    fn sample_fields() -> EacFields {
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

    #[test]
    fn test_eac_fields_round_trip() {
        let fields = sample_fields();
        let encoded = fields.to_optional_data();
        assert_eq!(encoded.len(), EAC_FIELD_COUNT);
        let decoded = EacFields::from_optional_data(&encoded).unwrap();
        assert_eq!(fields, decoded);
    }

    #[test]
    fn test_energy_source_round_trip_all_variants() {
        let cases = vec![
            EnergySource::Wind,
            EnergySource::Solar,
            EnergySource::Hydro,
            EnergySource::Geothermal,
            EnergySource::Biomass,
            EnergySource::Nuclear,
            EnergySource::Storage,
            EnergySource::Other("OFFSHORE_WIND".to_string()),
        ];
        for src in cases {
            let field = src.to_field();
            let parsed = EnergySource::from_field(&field);
            assert_eq!(src, parsed, "round trip failed for {src:?}");
        }
    }

    #[test]
    fn test_energy_source_other_handles_long_strings() {
        // 13 bytes — fits in 16
        let src = EnergySource::Other("OFFSHORE_WIND".to_string());
        let field = src.to_field();
        assert_eq!(&field[..13], b"OFFSHORE_WIND");
        // Trailing bytes are NUL-padded
        assert_eq!(&field[13..], &[0u8; 3]);
        let back = EnergySource::from_field(&field);
        assert_eq!(back, src);

        // Exactly 16 bytes — no NUL padding
        let src16 = EnergySource::Other("ABCDEFGHIJKLMNOP".to_string());
        let field16 = src16.to_field();
        assert_eq!(&field16, b"ABCDEFGHIJKLMNOP");
        let back16 = EnergySource::from_field(&field16);
        assert_eq!(back16, src16);

        // Truncation at 16 bytes (longer input is silently cut)
        let too_long = EnergySource::Other("VERY_LONG_NAME_THAT_EXCEEDS".to_string());
        let field_long = too_long.to_field();
        assert_eq!(&field_long, b"VERY_LONG_NAME_T");
    }

    #[test]
    fn test_from_optional_data_rejects_wrong_tag() {
        let mut data = sample_fields().to_optional_data();
        data[0] = b"EAC2".to_vec();
        let err = EacFields::from_optional_data(&data).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("schema tag mismatch"), "unexpected msg: {msg}")
            }
            other => panic!("expected InvalidScript, got {other:?}"),
        }
    }

    #[test]
    fn test_from_optional_data_rejects_wrong_field_count() {
        let data = vec![EAC_SCHEMA_TAG_V1.to_vec(); 5];
        let err = EacFields::from_optional_data(&data).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => assert!(
                msg.contains("at least 11"),
                "unexpected msg: {msg}"
            ),
            other => panic!("expected InvalidScript, got {other:?}"),
        }
    }

    #[test]
    fn test_from_optional_data_rejects_wrong_field_length() {
        let mut data = sample_fields().to_optional_data();
        // Truncate quantity_wh to 7 bytes
        data[1] = vec![0x00; 7];
        let err = EacFields::from_optional_data(&data).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(
                    msg.contains("quantity_wh") && msg.contains("8 bytes"),
                    "unexpected msg: {msg}"
                )
            }
            other => panic!("expected InvalidScript, got {other:?}"),
        }

        // Wrong country length
        let mut data = sample_fields().to_optional_data();
        data[5] = vec![0x55; 3];
        let err = EacFields::from_optional_data(&data).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("country") && msg.contains("2 bytes"), "unexpected msg: {msg}")
            }
            other => panic!("expected InvalidScript, got {other:?}"),
        }

        // Wrong device_id length
        let mut data = sample_fields().to_optional_data();
        data[6] = vec![0x55; 16];
        let err = EacFields::from_optional_data(&data).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("device_id") && msg.contains("32 bytes"), "unexpected msg: {msg}")
            }
            other => panic!("expected InvalidScript, got {other:?}"),
        }

        // Wrong energy_source length
        let mut data = sample_fields().to_optional_data();
        data[4] = vec![0x55; 8];
        let err = EacFields::from_optional_data(&data).unwrap_err();
        match err {
            Stas3Error::InvalidScript(msg) => {
                assert!(msg.contains("energy_source") && msg.contains("16 bytes"), "unexpected msg: {msg}")
            }
            other => panic!("expected InvalidScript, got {other:?}"),
        }
    }

    #[test]
    fn test_build_eac_lock_round_trip() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let fields = sample_fields();
        let lock = build_eac_lock(owner_pkh, redemption_pkh, 0, vec![], &fields).unwrap();
        let decoded = decode_locking_script(&lock).unwrap();
        assert_eq!(decoded.owner_pkh, owner_pkh);
        assert_eq!(decoded.redemption_pkh, redemption_pkh);
        assert_eq!(decoded.flags, 0);
        assert!(decoded.service_fields.is_empty());
        let recovered = EacFields::from_optional_data(&decoded.optional_data).unwrap();
        assert_eq!(recovered, fields);
    }

    #[test]
    fn test_eac_lock_with_freezable_and_authorities() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let freeze_auth = vec![0x11; 20];
        let confiscate_auth = vec![0x22; 20];
        let fields = sample_fields();
        let lock = build_eac_lock(
            owner_pkh,
            redemption_pkh,
            FREEZABLE | CONFISCATABLE,
            vec![freeze_auth.clone(), confiscate_auth.clone()],
            &fields,
        )
        .unwrap();
        let decoded = decode_locking_script(&lock).unwrap();
        assert_eq!(decoded.flags, FREEZABLE | CONFISCATABLE);
        assert_eq!(decoded.service_fields, vec![freeze_auth, confiscate_auth]);
        let recovered = EacFields::from_optional_data(&decoded.optional_data).unwrap();
        assert_eq!(recovered, fields);
    }
}
