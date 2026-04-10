//! Stateful view of the scanner: access points + stations, updated from
//! whatever [`airscope_wifi::capture::CapturedPacket`] the backend hands
//! us. It keeps no sockets itself - the backend is the owner of I/O.

use std::collections::HashMap;

use airscope_core::{AccessPoint, Channel, Encryption, FrameKind, MacAddr, Station};
use airscope_wifi::{
    capture::{CapturedPacket, LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP},
    frame::{Dot11Frame, FrameSubtype, FrameType},
    radiotap::RadiotapHeader,
};
use time::OffsetDateTime;

/// Summary line shown above the AP table.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    pub total_packets: u64,
    pub beacons: u64,
    pub probes: u64,
    pub data: u64,
    pub deauth: u64,
    pub bad_fcs: u64,
}

/// What the scanner exposes to the TUI. Plain POD, Clone-on-read.
#[derive(Debug, Default)]
pub struct ScanState {
    pub aps: HashMap<MacAddr, AccessPoint>,
    pub stations: HashMap<MacAddr, Station>,
    pub counters: Counters,
    pub current_channel: Option<u16>,
}

impl ScanState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one raw capture packet to the scanner.
    pub fn ingest(&mut self, linktype: u32, pkt: &CapturedPacket) {
        self.counters.total_packets += 1;
        let (body, rt_info) = match linktype {
            LINKTYPE_IEEE802_11_RADIOTAP => match RadiotapHeader::parse(&pkt.data) {
                Ok((hdr, consumed)) => (&pkt.data[consumed..], Some(hdr.info)),
                Err(_) => return,
            },
            LINKTYPE_IEEE802_11 => (&pkt.data[..], None),
            _ => return,
        };

        if let Some(info) = rt_info {
            if info.has_bad_fcs {
                self.counters.bad_fcs += 1;
            }
        }

        let Ok(frame) = Dot11Frame::parse(body) else {
            return;
        };

        match frame.kind() {
            FrameKind::Beacon => self.counters.beacons += 1,
            FrameKind::ProbeRequest => self.counters.probes += 1,
            FrameKind::ProbeResponse => self.counters.probes += 1,
            FrameKind::Data | FrameKind::Qos => self.counters.data += 1,
            FrameKind::Deauthentication => self.counters.deauth += 1,
            _ => {}
        }

        let now = OffsetDateTime::now_utc();
        let signal = rt_info.and_then(|i| i.signal_dbm).map(|v| v as i16).unwrap_or(0);

        match frame.frame_type {
            FrameType::Management => self.ingest_management(&frame, now, signal),
            FrameType::Data => self.ingest_data(&frame, now, signal),
            _ => {}
        }
    }

    fn ingest_management(&mut self, frame: &Dot11Frame<'_>, now: OffsetDateTime, signal: i16) {
        match frame.subtype {
            FrameSubtype::Beacon | FrameSubtype::ProbeResponse => {
                let bssid = frame.bssid();
                let body = match frame.management_body() {
                    Some(b) => b,
                    None => return,
                };
                let decoded = body.decode();
                let channel = decoded
                    .channel
                    .and_then(|n| Channel::from_number(n).ok())
                    .unwrap_or_else(|| {
                        Channel::from_number(self.current_channel.unwrap_or(1))
                            .unwrap_or(Channel::from_number(1).unwrap())
                    });

                let entry = self.aps.entry(bssid).or_insert_with(|| AccessPoint {
                    bssid,
                    ssid: decoded.ssid.clone(),
                    channel,
                    signal_dbm: signal,
                    beacons: 0,
                    data_frames: 0,
                    encryption: Encryption::default(),
                    first_seen: now,
                    last_seen: now,
                });
                if frame.subtype == FrameSubtype::Beacon {
                    entry.beacons = entry.beacons.saturating_add(1);
                }
                if decoded.ssid.is_some() {
                    entry.ssid = decoded.ssid.clone();
                }
                entry.channel = channel;
                entry.signal_dbm = signal;
                entry.encryption = decoded.encryption;
                entry.last_seen = now;
            }
            FrameSubtype::ProbeRequest => {
                let station = frame.addr2;
                let body = match frame.management_body() {
                    Some(b) => b,
                    None => return,
                };
                // Pull SSID out of the tagged body.
                let mut probe = None;
                for ie in body.ies.iter() {
                    if ie.tag == 0 {
                        let s = String::from_utf8_lossy(ie.data).into_owned();
                        probe = Some(s);
                        break;
                    }
                }
                let entry = self.stations.entry(station).or_insert_with(|| Station {
                    mac: station,
                    bssid: None,
                    signal_dbm: signal,
                    frames: 0,
                    probes: Vec::new(),
                    last_seen: now,
                });
                entry.signal_dbm = signal;
                entry.frames = entry.frames.saturating_add(1);
                entry.last_seen = now;
                if let Some(p) = probe {
                    if !p.is_empty() && !entry.probes.iter().any(|q| q == &p) {
                        entry.probes.push(p);
                        if entry.probes.len() > 8 {
                            entry.probes.remove(0);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn ingest_data(&mut self, frame: &Dot11Frame<'_>, now: OffsetDateTime, signal: i16) {
        let bssid = frame.bssid();
        if let Some(ap) = self.aps.get_mut(&bssid) {
            ap.data_frames = ap.data_frames.saturating_add(1);
            ap.last_seen = now;
        }
        // The station side: pick the non-BSSID address as the client.
        let sta_mac = if frame.addr1 != bssid { frame.addr1 } else { frame.addr2 };
        if sta_mac == bssid || sta_mac.is_broadcast() || sta_mac.is_multicast() {
            return;
        }
        let entry = self.stations.entry(sta_mac).or_insert_with(|| Station {
            mac: sta_mac,
            bssid: Some(bssid),
            signal_dbm: signal,
            frames: 0,
            probes: Vec::new(),
            last_seen: now,
        });
        entry.bssid = Some(bssid);
        entry.signal_dbm = signal;
        entry.frames = entry.frames.saturating_add(1);
        entry.last_seen = now;
    }

    /// Get APs as a stable, sorted list for rendering.
    /// Sort: strongest signal first, then SSID alphabetically.
    pub fn aps_sorted(&self) -> Vec<AccessPoint> {
        let mut out: Vec<_> = self.aps.values().cloned().collect();
        out.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm).then_with(|| a.label().cmp(&b.label())));
        out
    }

    /// Stations sorted by liveliness (most recent first).
    pub fn stations_sorted(&self) -> Vec<Station> {
        let mut out: Vec<_> = self.stations.values().cloned().collect();
        out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        out
    }
}
