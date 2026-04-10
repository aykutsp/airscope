//! 802.11 MAC header parser.
//!
//! Focus is on _reading_ management frames - beacons, probes, deauth -
//! well enough to feed airodump-ng's scanner view. Data frames are
//! recognised but mostly left opaque; airodump doesn't need to decrypt
//! them to count traffic per station.

use airscope_core::{Cipher, Encryption, Error, FrameKind, KeyManagement, MacAddr, Result};
use byteorder::{ByteOrder, LittleEndian};

/// Top-level 802.11 frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Extension,
}

/// Sub-type inside a management frame, matched on the FC type/subtype bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSubtype {
    AssocRequest,
    AssocResponse,
    ReassocRequest,
    ReassocResponse,
    ProbeRequest,
    ProbeResponse,
    Beacon,
    Atim,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
    /// Control frames (RTS/CTS/ACK/...) and data frames we don't unpack.
    Other,
}

/// A parsed 802.11 frame header with its body attached.
#[derive(Debug, Clone)]
pub struct Dot11Frame<'a> {
    pub frame_type: FrameType,
    pub subtype: FrameSubtype,
    pub to_ds: bool,
    pub from_ds: bool,
    pub duration_us: u16,
    pub addr1: MacAddr, // destination / RA
    pub addr2: MacAddr, // source / TA
    pub addr3: MacAddr, // BSSID or final DA/SA depending on DS bits
    pub sequence: u16,
    pub fragment: u8,
    pub body: &'a [u8],
}

impl<'a> Dot11Frame<'a> {
    /// Parse a frame assuming the buffer starts at the MAC header.
    /// Radiotap, if any, must be stripped by the caller.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < 24 {
            return Err(Error::Parse("dot11: short frame".into()));
        }
        let fc = LittleEndian::read_u16(&buf[0..2]);
        let version = (fc & 0x0003) as u8;
        if version != 0 {
            return Err(Error::Unsupported(format!("802.11 proto v{version}")));
        }
        let type_bits = ((fc >> 2) & 0x0003) as u8;
        let subtype_bits = ((fc >> 4) & 0x000f) as u8;
        let to_ds = fc & 0x0100 != 0;
        let from_ds = fc & 0x0200 != 0;

        let frame_type = match type_bits {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            3 => FrameType::Extension,
            _ => unreachable!(),
        };
        let subtype = decode_subtype(frame_type, subtype_bits);

        let duration_us = LittleEndian::read_u16(&buf[2..4]);
        let addr1 = MacAddr::from_slice(&buf[4..10])?;
        let addr2 = MacAddr::from_slice(&buf[10..16])?;
        let addr3 = MacAddr::from_slice(&buf[16..22])?;
        let seq_field = LittleEndian::read_u16(&buf[22..24]);
        let sequence = seq_field >> 4;
        let fragment = (seq_field & 0x000f) as u8;

        let body = &buf[24..];
        Ok(Self {
            frame_type,
            subtype,
            to_ds,
            from_ds,
            duration_us,
            addr1,
            addr2,
            addr3,
            sequence,
            fragment,
            body,
        })
    }

    pub fn kind(&self) -> FrameKind {
        match (self.frame_type, self.subtype) {
            (FrameType::Management, FrameSubtype::Beacon) => FrameKind::Beacon,
            (FrameType::Management, FrameSubtype::ProbeRequest) => FrameKind::ProbeRequest,
            (FrameType::Management, FrameSubtype::ProbeResponse) => FrameKind::ProbeResponse,
            (FrameType::Management, FrameSubtype::Authentication) => FrameKind::Authentication,
            (FrameType::Management, FrameSubtype::Deauthentication) => FrameKind::Deauthentication,
            (FrameType::Management, FrameSubtype::AssocRequest)
            | (FrameType::Management, FrameSubtype::AssocResponse)
            | (FrameType::Management, FrameSubtype::ReassocRequest)
            | (FrameType::Management, FrameSubtype::ReassocResponse) => FrameKind::Association,
            (FrameType::Data, _) => FrameKind::Data,
            (FrameType::Control, _) => FrameKind::Control,
            (FrameType::Management, _) => FrameKind::Other,
            (FrameType::Extension, _) => FrameKind::Other,
        }
    }

    /// Shortcut: the BSSID of the frame, as derived from addr fields
    /// and the ToDS/FromDS bits.
    pub fn bssid(&self) -> MacAddr {
        match (self.to_ds, self.from_ds) {
            (false, false) => self.addr3,
            (false, true) => self.addr2,
            (true, false) => self.addr1,
            (true, true) => self.addr1, // 4-address frame, addr1 is RA
        }
    }

    /// For beacons / probe responses, the "management body" begins
    /// after the fixed 12-byte prelude (timestamp + interval + caps)
    /// and is a sequence of tagged parameters (IEs).
    pub fn management_body(&self) -> Option<ManagementBody<'_>> {
        match self.subtype {
            FrameSubtype::Beacon | FrameSubtype::ProbeResponse => {
                if self.body.len() < 12 {
                    return None;
                }
                Some(ManagementBody {
                    timestamp: LittleEndian::read_u64(&self.body[0..8]),
                    beacon_interval_tu: LittleEndian::read_u16(&self.body[8..10]),
                    capabilities: LittleEndian::read_u16(&self.body[10..12]),
                    ies: InformationElements { buf: &self.body[12..] },
                })
            }
            FrameSubtype::ProbeRequest => Some(ManagementBody {
                timestamp: 0,
                beacon_interval_tu: 0,
                capabilities: 0,
                ies: InformationElements { buf: self.body },
            }),
            _ => None,
        }
    }
}

fn decode_subtype(ty: FrameType, bits: u8) -> FrameSubtype {
    use FrameSubtype::*;
    match (ty, bits) {
        (FrameType::Management, 0x0) => AssocRequest,
        (FrameType::Management, 0x1) => AssocResponse,
        (FrameType::Management, 0x2) => ReassocRequest,
        (FrameType::Management, 0x3) => ReassocResponse,
        (FrameType::Management, 0x4) => ProbeRequest,
        (FrameType::Management, 0x5) => ProbeResponse,
        (FrameType::Management, 0x8) => Beacon,
        (FrameType::Management, 0x9) => Atim,
        (FrameType::Management, 0xa) => Disassociation,
        (FrameType::Management, 0xb) => Authentication,
        (FrameType::Management, 0xc) => Deauthentication,
        (FrameType::Management, 0xd) => Action,
        _ => Other,
    }
}

/// The fixed prelude of a management body + its information elements.
#[derive(Debug, Clone)]
pub struct ManagementBody<'a> {
    pub timestamp: u64,
    pub beacon_interval_tu: u16,
    pub capabilities: u16,
    pub ies: InformationElements<'a>,
}

impl<'a> ManagementBody<'a> {
    /// True if the `Privacy` bit is set in the capability info field.
    /// Airodump uses this to light up the `ENC` column even before it
    /// has seen the RSN IE.
    pub fn privacy(&self) -> bool {
        self.capabilities & 0x0010 != 0
    }

    /// Extract SSID, supported rates, primary channel, and encryption
    /// configuration in one pass over the IEs.
    pub fn decode(&self) -> DecodedManagement {
        let mut out = DecodedManagement {
            ssid: None,
            channel: None,
            encryption: Encryption::default(),
            vendor_tags: 0,
        };

        // A beacon with the Privacy bit set but no RSN IE → WEP (legacy).
        let mut has_rsn = false;
        let mut has_wpa = false;

        for ie in self.ies.iter() {
            match ie.tag {
                0 => {
                    // SSID
                    if !ie.data.is_empty() {
                        out.ssid =
                            Some(String::from_utf8_lossy(ie.data).trim_matches('\0').to_string());
                    } else {
                        out.ssid = Some(String::new()); // explicit empty
                    }
                }
                3 => {
                    // DS Parameter Set - current channel
                    if ie.data.len() == 1 {
                        out.channel = Some(ie.data[0] as u16);
                    }
                }
                48 => {
                    // RSN IE → WPA2/WPA3
                    has_rsn = true;
                    decode_rsn(ie.data, &mut out.encryption);
                }
                221 => {
                    // Vendor specific - WPA1 lives here under MS OUI 00:50:f2.
                    out.vendor_tags += 1;
                    if ie.data.len() >= 4
                        && ie.data[0] == 0x00
                        && ie.data[1] == 0x50
                        && ie.data[2] == 0xf2
                        && ie.data[3] == 0x01
                    {
                        has_wpa = true;
                        decode_wpa1(&ie.data[4..], &mut out.encryption);
                    }
                }
                _ => {}
            }
        }

        // Deduce the family from what we found.
        if has_rsn {
            out.encryption.open = false;
            out.encryption.wpa2 = true;
            if out.encryption.akm.iter().any(|a| {
                matches!(a, KeyManagement::Sae | KeyManagement::FtSae | KeyManagement::Owe)
            }) {
                out.encryption.wpa3 = true;
            }
        } else if has_wpa {
            out.encryption.open = false;
            out.encryption.wpa = true;
        } else if self.privacy() {
            out.encryption.open = false;
            out.encryption.wep = true;
        }

        out
    }
}

/// The flattened management-body view we actually use at the app layer.
#[derive(Debug, Clone)]
pub struct DecodedManagement {
    pub ssid: Option<String>,
    pub channel: Option<u16>,
    pub encryption: Encryption,
    pub vendor_tags: usize,
}

/// Lazy iterator over the tagged (tag, length, value) IEs in a body.
#[derive(Debug, Clone, Copy)]
pub struct InformationElements<'a> {
    pub buf: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct InformationElement<'a> {
    pub tag: u8,
    pub data: &'a [u8],
}

impl<'a> InformationElements<'a> {
    pub fn iter(&self) -> InfoElementIter<'a> {
        InfoElementIter { buf: self.buf }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InfoElementIter<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for InfoElementIter<'a> {
    type Item = InformationElement<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 2 {
            return None;
        }
        let tag = self.buf[0];
        let len = self.buf[1] as usize;
        if self.buf.len() < 2 + len {
            return None;
        }
        let data = &self.buf[2..2 + len];
        self.buf = &self.buf[2 + len..];
        Some(InformationElement { tag, data })
    }
}

fn decode_rsn(ie: &[u8], enc: &mut Encryption) {
    // Layout: version(2) | group cipher(4) | pairwise count(2) | pairwise* |
    //         akm count(2) | akm*  | rsn caps(2) | ...
    if ie.len() < 2 {
        return;
    }
    let mut off = 2; // skip version
    if ie.len() < off + 4 {
        return;
    }
    let group_oui = [ie[off], ie[off + 1], ie[off + 2]];
    enc.group = Cipher::from_ieee(group_oui, ie[off + 3]);
    off += 4;

    if ie.len() < off + 2 {
        return;
    }
    let pcount = LittleEndian::read_u16(&ie[off..off + 2]) as usize;
    off += 2;
    for _ in 0..pcount {
        if ie.len() < off + 4 {
            return;
        }
        let oui = [ie[off], ie[off + 1], ie[off + 2]];
        enc.pairwise.push(Cipher::from_ieee(oui, ie[off + 3]));
        off += 4;
    }

    if ie.len() < off + 2 {
        return;
    }
    let acount = LittleEndian::read_u16(&ie[off..off + 2]) as usize;
    off += 2;
    for _ in 0..acount {
        if ie.len() < off + 4 {
            return;
        }
        let oui = [ie[off], ie[off + 1], ie[off + 2]];
        enc.akm.push(KeyManagement::from_ieee(oui, ie[off + 3]));
        off += 4;
    }
}

fn decode_wpa1(ie: &[u8], enc: &mut Encryption) {
    // Same layout as RSN but with a WPA1 OUI (00:50:f2) on each cipher suite.
    if ie.len() < 2 {
        return;
    }
    let mut off = 2;
    if ie.len() < off + 4 {
        return;
    }
    enc.group = Cipher::from_ieee([0x00, 0x50, 0xf2], ie[off + 3]);
    off += 4;
    if ie.len() < off + 2 {
        return;
    }
    let pcount = LittleEndian::read_u16(&ie[off..off + 2]) as usize;
    off += 2;
    for _ in 0..pcount {
        if ie.len() < off + 4 {
            return;
        }
        enc.pairwise.push(Cipher::from_ieee([0x00, 0x50, 0xf2], ie[off + 3]));
        off += 4;
    }
    if ie.len() < off + 2 {
        return;
    }
    let acount = LittleEndian::read_u16(&ie[off..off + 2]) as usize;
    off += 2;
    for _ in 0..acount {
        if ie.len() < off + 4 {
            return;
        }
        enc.akm.push(KeyManagement::from_ieee([0x00, 0x50, 0xf2], ie[off + 3]));
        off += 4;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder;

    #[test]
    fn round_trip_beacon_ssid_and_bssid() {
        // Build a beacon with a known BSSID and SSID, then parse it back.
        let bssid: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let frame = builder::build_beacon(bssid, "TestNetwork", 6, 100, false);
        // builder returns a raw 802.11 frame, no radiotap.
        let parsed = Dot11Frame::parse(&frame).unwrap();
        assert_eq!(parsed.frame_type, FrameType::Management);
        assert_eq!(parsed.subtype, FrameSubtype::Beacon);
        assert_eq!(parsed.addr3, bssid);

        let decoded = parsed.management_body().unwrap().decode();
        assert_eq!(decoded.ssid.as_deref(), Some("TestNetwork"));
        assert_eq!(decoded.channel, Some(6));
        assert!(decoded.encryption.open);
    }

    #[test]
    fn beacon_with_privacy_is_wep_when_no_rsn() {
        let bssid: MacAddr = "10:20:30:40:50:60".parse().unwrap();
        let frame = builder::build_beacon(bssid, "Legacy", 1, 100, true);
        let parsed = Dot11Frame::parse(&frame).unwrap();
        let decoded = parsed.management_body().unwrap().decode();
        assert!(!decoded.encryption.open);
        assert!(decoded.encryption.wep);
    }
}
