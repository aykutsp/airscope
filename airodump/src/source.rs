//! A tiny trait that hides "where do frames come from" from the TUI.
//!
//! Two implementations live here:
//!   - [`LiveSource`]  : wraps `airscope_wifi::capture::live::LiveCapture`
//!   - [`ReplaySource`]: pumps a pcap file in real-ish time, so the
//!                       scanner can be demoed on a machine that isn't
//!                       anywhere near a Wi-Fi card.
//!
//! Both return `Ok(None)` when nothing is ready right now, so the TUI
//! can stay responsive to keystrokes.

use std::time::{Duration, Instant};

use airscope_core::Result;
use airscope_wifi::capture::{live::LiveCapture, CapturedPacket, PcapFileReader};

pub trait FrameSource {
    fn linktype(&self) -> u32;
    fn next(&mut self) -> Result<Option<CapturedPacket>>;
}

/// A live interface.
pub struct LiveSource {
    inner: LiveCapture,
}

impl LiveSource {
    pub fn new(interface: &str) -> Result<Self> {
        let mut cap = LiveCapture::open(interface)?;
        // Only want management + QoS data; airodump-ng uses a similar filter.
        let _ = cap.set_filter("type mgt or (type data and subtype qos-data)");
        Ok(Self { inner: cap })
    }
}

impl FrameSource for LiveSource {
    fn linktype(&self) -> u32 {
        // Live captures on monitor interfaces are almost always radiotap
        // wrapped. We don't bother with an accessor here - the backend
        // reports it on open and we cached it in LiveCapture.
        airscope_wifi::capture::LINKTYPE_IEEE802_11_RADIOTAP
    }
    fn next(&mut self) -> Result<Option<CapturedPacket>> {
        self.inner.next()
    }
}

/// Replay from a pcap file, spacing packets out in real time so the
/// TUI animates naturally. `rate` = 1.0 means true-time replay; 2.0 = 2x.
pub struct ReplaySource {
    reader: PcapFileReader,
    first_capture_micros: Option<i64>,
    replay_start: Instant,
    rate: f32,
    next_pkt: Option<CapturedPacket>,
}

impl ReplaySource {
    pub fn new(path: impl AsRef<std::path::Path>, rate: f32) -> Result<Self> {
        let reader = PcapFileReader::open(path.as_ref())?;
        Ok(Self {
            reader,
            first_capture_micros: None,
            replay_start: Instant::now(),
            rate: rate.max(0.1),
            next_pkt: None,
        })
    }
}

impl FrameSource for ReplaySource {
    fn linktype(&self) -> u32 {
        self.reader.linktype
    }

    fn next(&mut self) -> Result<Option<CapturedPacket>> {
        if self.next_pkt.is_none() {
            self.next_pkt = self.reader.next_packet()?;
        }
        let Some(pkt) = self.next_pkt.as_ref() else {
            return Ok(None);
        };
        let first = *self
            .first_capture_micros
            .get_or_insert(pkt.timestamp_micros);
        let elapsed_capture = (pkt.timestamp_micros - first) as f64 / self.rate as f64;
        let target = Duration::from_micros(elapsed_capture.max(0.0) as u64);
        if self.replay_start.elapsed() < target {
            return Ok(None); // too early, let the caller come back
        }
        Ok(self.next_pkt.take())
    }
}
