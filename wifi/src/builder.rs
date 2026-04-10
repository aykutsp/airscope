//! Frame crafting helpers.
//!
//! These build bare 802.11 MAC frames. The caller is responsible for
//! prepending a radiotap header if the injection interface needs one
//! (most Linux monitor-mode drivers do).
//!
//! Reason codes for deauth are from IEEE 802.11-2020 Table 9-49.

use airscope_core::MacAddr;
use byteorder::{ByteOrder, LittleEndian};

/// Common 802.11 reason codes - enough to drive aireplay-style workflows.
#[derive(Debug, Clone, Copy)]
pub enum ReasonCode {
    Unspecified = 1,
    PrevAuthNotValid = 2,
    LeavingNetwork = 3,
    InactivityTimeout = 4,
    ApBusy = 5,
    Class2FrameFromNonauth = 6,
    Class3FrameFromNonassoc = 7,
    StaLeavingBss = 8,
    RequestingReauth = 9,
}

/// Build a deauthentication frame.
/// When `source` equals the BSSID the AP is "kicking" the client; when
/// `destination` equals the BSSID the client is pretending to walk away.
pub fn build_deauth(
    destination: MacAddr,
    source: MacAddr,
    bssid: MacAddr,
    reason: ReasonCode,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(26);
    // Frame control: type=Management(0), subtype=Deauth(12) -> 0xc0
    out.extend_from_slice(&[0xc0, 0x00]);
    // Duration
    out.extend_from_slice(&[0x3a, 0x01]);
    out.extend_from_slice(destination.bytes());
    out.extend_from_slice(source.bytes());
    out.extend_from_slice(bssid.bytes());
    // Sequence control
    out.extend_from_slice(&[0x00, 0x00]);
    // Reason code
    let rc = reason as u16;
    let mut rc_buf = [0u8; 2];
    LittleEndian::write_u16(&mut rc_buf, rc);
    out.extend_from_slice(&rc_buf);
    out
}

/// Build a probe request for a given SSID (or broadcast if empty).
pub fn build_probe_request(source: MacAddr, ssid: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + ssid.len());
    // FC: type=Management(0), subtype=ProbeRequest(4) -> 0x40
    out.extend_from_slice(&[0x40, 0x00]);
    out.extend_from_slice(&[0x00, 0x00]); // duration
    out.extend_from_slice(MacAddr::BROADCAST.bytes()); // dst
    out.extend_from_slice(source.bytes()); // src
    out.extend_from_slice(MacAddr::BROADCAST.bytes()); // bssid
    out.extend_from_slice(&[0x00, 0x00]); // seq

    push_ie(&mut out, 0, ssid.as_bytes());
    // Supported rates (Tag 1): 1, 2, 5.5, 11, 6, 9, 12, 18 Mbps
    push_ie(&mut out, 1, &[0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    out
}

/// Build a beacon for a fake AP.
///
/// `privacy` only flips the capability bit; it does **not** add an RSN IE.
/// Combined with no RSN this produces a frame airodump would flag as WEP -
/// which is exactly what old-school airbase-ng does for "soft AP" mode.
pub fn build_beacon(
    bssid: MacAddr,
    ssid: &str,
    channel: u8,
    beacon_interval_tu: u16,
    privacy: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + ssid.len());
    // FC: type=Management(0), subtype=Beacon(8) -> 0x80
    out.extend_from_slice(&[0x80, 0x00]);
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(MacAddr::BROADCAST.bytes()); // dst
    out.extend_from_slice(bssid.bytes()); // src
    out.extend_from_slice(bssid.bytes()); // bssid
    out.extend_from_slice(&[0x00, 0x00]); // seq

    // Timestamp placeholder (firmware fills it, but parsers expect 8 bytes).
    out.extend_from_slice(&[0u8; 8]);

    let mut bi = [0u8; 2];
    LittleEndian::write_u16(&mut bi, beacon_interval_tu);
    out.extend_from_slice(&bi);

    // Capability info: ESS bit, and optionally Privacy.
    let mut caps: u16 = 0x0001;
    if privacy {
        caps |= 0x0010;
    }
    let mut cap_buf = [0u8; 2];
    LittleEndian::write_u16(&mut cap_buf, caps);
    out.extend_from_slice(&cap_buf);

    push_ie(&mut out, 0, ssid.as_bytes()); // SSID
    push_ie(&mut out, 1, &[0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c]); // Supported Rates
    push_ie(&mut out, 3, &[channel]); // DS Parameter Set
                                      // TIM (Tag 5): DTIM count=0, DTIM period=1, bitmap control=0, bitmap=0
    push_ie(&mut out, 5, &[0x00, 0x01, 0x00, 0x00]);

    out
}

/// Prepend a minimal radiotap header useful for injecting on Linux.
/// Sets only the length field (no present bits) so the driver knows
/// to skip straight to the 802.11 frame behind it.
pub fn wrap_radiotap(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + frame.len());
    out.extend_from_slice(&[0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(frame);
    out
}

fn push_ie(buf: &mut Vec<u8>, tag: u8, data: &[u8]) {
    assert!(data.len() <= 255);
    buf.push(tag);
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deauth_is_26_bytes() {
        let d = build_deauth(
            MacAddr::BROADCAST,
            "aa:bb:cc:dd:ee:ff".parse().unwrap(),
            "aa:bb:cc:dd:ee:ff".parse().unwrap(),
            ReasonCode::Unspecified,
        );
        assert_eq!(d.len(), 26);
        assert_eq!(d[0], 0xc0); // deauth subtype marker
    }

    #[test]
    fn beacon_starts_with_management_subtype_marker() {
        let b = build_beacon("aa:bb:cc:dd:ee:ff".parse().unwrap(), "demo", 6, 100, false);
        assert_eq!(b[0], 0x80); // beacon
    }
}
