//! Radiotap (v0) header decoder.
//!
//! We only care about the fields that airodump-ng actually displays:
//! signal strength, channel/frequency, and rate. Everything else is
//! skipped over using the field-length table from the spec.
//!
//! Spec: https://www.radiotap.org/

use airscope_core::{Error, Result};
use byteorder::{ByteOrder, LittleEndian};

/// Parsed view of the interesting parts of a radiotap header.
#[derive(Debug, Clone, Copy, Default)]
pub struct RadiotapInfo {
    pub length: u16,
    pub signal_dbm: Option<i8>,
    pub noise_dbm: Option<i8>,
    pub channel_mhz: Option<u16>,
    pub rate_mbps: Option<f32>,
    pub has_bad_fcs: bool,
}

/// Raw header + the parsed view.
#[derive(Debug, Clone, Copy)]
pub struct RadiotapHeader {
    pub version: u8,
    pub info: RadiotapInfo,
}

// Field indices and the length each consumes. Taken from the radiotap spec.
// We only list the ones we need plus any that appear before them, because
// the presence bitmap is ordered and we have to skip in order.
const TSFT: usize = 0;
const FLAGS: usize = 1;
const RATE: usize = 2;
const CHANNEL: usize = 3;
const FHSS: usize = 4;
const ANT_SIGNAL: usize = 5;
const ANT_NOISE: usize = 6;
const LOCK_QUAL: usize = 7;
const TX_ATTEN: usize = 8;
const DB_TX_ATTEN: usize = 9;
const DBM_TX_POWER: usize = 10;
const ANTENNA: usize = 11;
const DB_ANT_SIG: usize = 12;
const DB_ANT_NOISE: usize = 13;
const RX_FLAGS: usize = 14;
const TX_FLAGS: usize = 15;

// Alignment + size (in bytes) for each present-bit.
// `align` is the alignment boundary inside the radiotap body.
struct FieldDef {
    align: usize,
    size: usize,
}

fn field_def(bit: usize) -> Option<FieldDef> {
    Some(match bit {
        TSFT => FieldDef { align: 8, size: 8 },
        FLAGS => FieldDef { align: 1, size: 1 },
        RATE => FieldDef { align: 1, size: 1 },
        CHANNEL => FieldDef { align: 2, size: 4 },
        FHSS => FieldDef { align: 1, size: 2 },
        ANT_SIGNAL => FieldDef { align: 1, size: 1 },
        ANT_NOISE => FieldDef { align: 1, size: 1 },
        LOCK_QUAL => FieldDef { align: 2, size: 2 },
        TX_ATTEN => FieldDef { align: 2, size: 2 },
        DB_TX_ATTEN => FieldDef { align: 2, size: 2 },
        DBM_TX_POWER => FieldDef { align: 1, size: 1 },
        ANTENNA => FieldDef { align: 1, size: 1 },
        DB_ANT_SIG => FieldDef { align: 1, size: 1 },
        DB_ANT_NOISE => FieldDef { align: 1, size: 1 },
        RX_FLAGS => FieldDef { align: 2, size: 2 },
        TX_FLAGS => FieldDef { align: 2, size: 2 },
        _ => return None,
    })
}

fn align_up(offset: usize, align: usize) -> usize {
    (offset + align - 1) & !(align - 1)
}

impl RadiotapHeader {
    /// Decode a radiotap header at the front of the buffer.
    ///
    /// Returns the parsed header and the number of bytes consumed,
    /// so the caller can slice to the 802.11 frame that follows.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 4 {
            return Err(Error::Parse("radiotap: short header".into()));
        }
        let version = buf[0];
        if version != 0 {
            return Err(Error::Unsupported(format!("radiotap v{version}")));
        }
        let length = LittleEndian::read_u16(&buf[2..4]) as usize;
        if buf.len() < length {
            return Err(Error::Parse("radiotap: truncated".into()));
        }

        // Collect the present bitmaps (there can be several, chained by the
        // high bit). We only care about the first 32 flags so if more maps
        // follow we read past them to find the start of the data section.
        let mut data_start = 4;
        let mut first_present: u32 = 0;
        let mut got_first = false;
        loop {
            if data_start + 4 > length {
                break;
            }
            let word = LittleEndian::read_u32(&buf[data_start..data_start + 4]);
            if !got_first {
                first_present = word;
                got_first = true;
            }
            data_start += 4;
            if word & (1 << 31) == 0 {
                break;
            }
        }

        let mut info = RadiotapInfo { length: length as u16, ..Default::default() };

        let data_base = data_start;
        let mut cursor = 0usize;

        for bit in 0..16 {
            if first_present & (1u32 << bit) == 0 {
                continue;
            }
            let Some(def) = field_def(bit) else { continue };
            cursor = align_up(cursor, def.align);
            let abs = data_base + cursor;
            if abs + def.size > length {
                break; // truncated - give up, keep what we have
            }
            let field = &buf[abs..abs + def.size];
            match bit {
                FLAGS => {
                    info.has_bad_fcs = field[0] & 0x40 != 0;
                }
                RATE => {
                    info.rate_mbps = Some(field[0] as f32 * 0.5);
                }
                CHANNEL => {
                    info.channel_mhz = Some(LittleEndian::read_u16(&field[0..2]));
                }
                ANT_SIGNAL | DB_ANT_SIG => {
                    info.signal_dbm = Some(field[0] as i8);
                }
                ANT_NOISE | DB_ANT_NOISE => {
                    info.noise_dbm = Some(field[0] as i8);
                }
                _ => {}
            }
            cursor += def.size;
        }

        Ok((Self { version, info }, length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal radiotap: version=0, pad=0, len=12,
    // present=0x0000486e (tsft, flags, rate, channel, ant_signal -> bits 0,1,2,3,5)
    // Actually let's just test with a known-good beacon blob below.

    #[test]
    fn parse_short_errors() {
        let buf = [0u8; 2];
        assert!(RadiotapHeader::parse(&buf).is_err());
    }

    #[test]
    fn parse_wrong_version_errors() {
        let buf = [1u8, 0, 8, 0, 0, 0, 0, 0];
        assert!(RadiotapHeader::parse(&buf).is_err());
    }

    #[test]
    fn parse_minimal_header_no_fields() {
        // version=0, pad=0, len=8, present=0 -> no data fields
        let buf = [0u8, 0, 8, 0, 0, 0, 0, 0];
        let (hdr, consumed) = RadiotapHeader::parse(&buf).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(hdr.info.length, 8);
        assert!(hdr.info.signal_dbm.is_none());
    }
}
