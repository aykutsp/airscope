//! Domain primitives shared across the Airscope suite.
//!
//! Nothing here touches the kernel, sockets, or `pcap` - it's pure data.
//! Keeping it dependency-light means every binary can link it cheaply
//! and test against it without standing up a capture backend.

#![deny(rust_2018_idioms)]
#![warn(missing_debug_implementations)]

pub mod channel;
pub mod error;
pub mod mac;
pub mod oui;
pub mod security;

pub use channel::{Band, Channel};
pub use error::{Error, Result};
pub use mac::MacAddr;
pub use security::{Cipher, Encryption, KeyManagement};

use std::time::Duration;

/// A single access point observed over the air.
///
/// Fields mirror what the discovery pipeline in `airscope-wifi` emits,
/// but we keep the struct small enough to drop on the wire or in a log line.
#[derive(Debug, Clone)]
pub struct AccessPoint {
    pub bssid: MacAddr,
    pub ssid: Option<String>,
    pub channel: Channel,
    pub signal_dbm: i16,
    pub beacons: u32,
    pub data_frames: u32,
    pub encryption: Encryption,
    pub first_seen: time::OffsetDateTime,
    pub last_seen: time::OffsetDateTime,
}

impl AccessPoint {
    pub fn age(&self) -> Duration {
        let now = time::OffsetDateTime::now_utc();
        let delta = now - self.last_seen;
        Duration::from_secs(delta.whole_seconds().max(0) as u64)
    }

    /// A short, stable label usable in tables.
    pub fn label(&self) -> String {
        match &self.ssid {
            Some(s) if !s.is_empty() => s.clone(),
            _ => format!("<hidden {}>", self.bssid),
        }
    }
}

/// A station (client) either associated with an AP or probing for one.
#[derive(Debug, Clone)]
pub struct Station {
    pub mac: MacAddr,
    pub bssid: Option<MacAddr>,
    pub signal_dbm: i16,
    pub frames: u32,
    pub probes: Vec<String>,
    pub last_seen: time::OffsetDateTime,
}

impl Station {
    pub fn is_associated(&self) -> bool {
        self.bssid.is_some()
    }
}

/// Frame classes we care about at the TUI level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameKind {
    Beacon,
    ProbeRequest,
    ProbeResponse,
    Authentication,
    Deauthentication,
    Association,
    Data,
    Qos,
    Control,
    Other,
}

impl FrameKind {
    pub fn short(&self) -> &'static str {
        match self {
            FrameKind::Beacon           => "BCN",
            FrameKind::ProbeRequest     => "PRQ",
            FrameKind::ProbeResponse    => "PRS",
            FrameKind::Authentication   => "AUTH",
            FrameKind::Deauthentication => "DEAU",
            FrameKind::Association      => "ASSO",
            FrameKind::Data             => "DATA",
            FrameKind::Qos              => "QOS",
            FrameKind::Control          => "CTRL",
            FrameKind::Other            => "?",
        }
    }
}
