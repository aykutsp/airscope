//! A tiny trait that hides "where do frames come from" from the TUI.
//!
//! Two implementations live here:
//!
//! - [`LiveSource`] wraps `airscope_wifi::capture::live::LiveCapture`.
//! - [`ReplaySource`] pumps a pcap file in real-ish time, so the
//!   scanner can be demoed on a machine that isn't anywhere near a
//!   Wi-Fi card.
//!
//! Both return `Ok(None)` when nothing is ready right now, so the TUI
//! can stay responsive to keystrokes.

use std::time::{Duration, Instant};

use airscope_core::{Error, Result};
use airscope_wifi::capture::{
    live::LiveCapture, CapturedPacket, PcapFileReader, LINKTYPE_ETHERNET, LINKTYPE_IEEE802_11,
    LINKTYPE_IEEE802_11_RADIOTAP,
};

pub trait FrameSource {
    fn linktype(&self) -> u32;
    fn next_packet(&mut self) -> Result<Option<CapturedPacket>>;
}

/// A live interface.
pub struct LiveSource {
    inner: LiveCapture,
    linktype: u32,
}

impl LiveSource {
    /// Open a live capture on `interface`. `interface` can be:
    ///   * the literal pcap device name (`\Device\NPF_{GUID}` on Windows,
    ///     `wlan0` on Linux, `en0` on macOS), or
    ///   * a friendly name like `Wi-Fi` / `Ethernet` — we fuzzy-match
    ///     against pcap's description list and use the first hit.
    ///
    /// The fallback exists because Windows is the only OS where pcap
    /// devices look like `\Device\NPF_{...}`, and nobody wants to
    /// paste a GUID into their shell.
    pub fn new(interface: &str) -> Result<Self> {
        // First try the exact name the user gave us.
        match LiveCapture::open(interface) {
            Ok(cap) => Ok(Self::wrap(cap)),
            Err(first_err) => {
                // Fuzzy match: look at every pcap device and find one whose
                // name or description contains the user's string (case
                // insensitive). Only do this if the live feature is on —
                // without it `list_interfaces` returns Unsupported and we'd
                // just report the same error twice.
                #[cfg(feature = "live")]
                if let Some(resolved) = Self::fuzzy_resolve(interface)? {
                    if resolved != interface {
                        eprintln!("airodump: resolved `{}` -> `{}`", interface, resolved);
                    }
                    return LiveCapture::open(&resolved).map(Self::wrap).map_err(|e| {
                        Error::Capture(format!(
                            "{e}\n\nhint: run `airodump --list-interfaces` \
                                 and copy the NAME column verbatim (on Windows \
                                 those look like \\Device\\NPF_{{...}})."
                        ))
                    });
                }
                Err(Self::enrich_open_error(interface, first_err))
            }
        }
    }

    fn wrap(cap: LiveCapture) -> Self {
        let mut cap = cap;
        let linktype = cap.linktype;

        // Only apply the 802.11 BPF filter when the link really speaks
        // 802.11. On Ethernet the "type mgt" expression compiles to
        // nothing and we'd sit on zero frames forever, silently.
        if matches!(linktype, LINKTYPE_IEEE802_11_RADIOTAP | LINKTYPE_IEEE802_11) {
            // airodump-ng uses a similar filter: management + QoS data only.
            let _ = cap.set_filter("type mgt or (type data and subtype qos-data)");
        }

        Self { inner: cap, linktype }
    }

    /// Short human hint describing what the link layer of an open live
    /// source means for the scanner. Returns `None` when everything is
    /// as expected (radiotap + 802.11 on a monitor interface).
    pub fn linktype_warning(&self) -> Option<String> {
        match self.linktype {
            LINKTYPE_IEEE802_11_RADIOTAP => None,
            LINKTYPE_IEEE802_11 => Some(
                "link is raw 802.11 (no radiotap). signal / channel columns \
                 will read 0 but frame counts and SSIDs are fine."
                    .to_string(),
            ),
            LINKTYPE_ETHERNET => Some(
                "managed mode detected (link layer = ethernet)\n\
                 \n\
                 the capture backend is handing us decoded ethernet frames,\n\
                 not 802.11. that means the wifi driver is stripping beacons,\n\
                 probes and deauth before pcap ever sees them - there is\n\
                 nothing the scanner can reconstruct from this view.\n\
                 \n\
                 you need MONITOR MODE:\n\
                   linux:   sudo airmon start wlan0 --channel 6\n\
                   windows: needs an Npcap-friendly adapter (see docs/INSTALL.md §3.4)\n\
                   macos:   Wireless Diagnostics → Sniffer, then airodump -i <iface>"
                    .to_string(),
            ),
            other => Some(format!(
                "unfamiliar link type {other}; the scanner will probably \
                 ignore every frame."
            )),
        }
    }

    /// Return a better name to retry with, or None if we can't do better.
    /// Uses pcap's own device list so the suggestion is always something
    /// the backend can actually open.
    #[cfg(feature = "live")]
    fn fuzzy_resolve(requested: &str) -> Result<Option<String>> {
        use airscope_wifi::capture::live as capture_live;
        let wanted = requested.to_ascii_lowercase();
        let devs = capture_live::list_interfaces()?;
        // Exact case-insensitive match first.
        if let Some(d) = devs.iter().find(|d| d.name.eq_ignore_ascii_case(requested)) {
            return Ok(Some(d.name.clone()));
        }
        // Substring hit in the description ("Intel(R) Wi-Fi 6 AX200" etc).
        if let Some(d) = devs.iter().find(|d| {
            d.description
                .as_deref()
                .map(|desc| desc.to_ascii_lowercase().contains(&wanted))
                .unwrap_or(false)
        }) {
            return Ok(Some(d.name.clone()));
        }
        // Substring hit inside the device name itself.
        if let Some(d) = devs.iter().find(|d| d.name.to_ascii_lowercase().contains(&wanted)) {
            return Ok(Some(d.name.clone()));
        }
        Ok(None)
    }

    fn enrich_open_error(interface: &str, err: Error) -> Error {
        // Windows pcap errors tend to be opaque ("The filename, directory
        // name, or volume label syntax is incorrect. (123)"). Wrap the
        // message with a pointer to list-interfaces so people aren't
        // left guessing.
        Error::Capture(format!(
            "could not open `{interface}`: {err}\n\
             hint: run `airodump --list-interfaces` to see the exact device \
             names the capture backend accepts. on Windows those look like \
             \\Device\\NPF_{{GUID}} and you can pass either that or the \
             adapter's friendly name (e.g. \"Wi-Fi\")."
        ))
    }
}

impl FrameSource for LiveSource {
    fn linktype(&self) -> u32 {
        self.linktype
    }
    fn next_packet(&mut self) -> Result<Option<CapturedPacket>> {
        self.inner.next_packet()
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

    fn next_packet(&mut self) -> Result<Option<CapturedPacket>> {
        if self.next_pkt.is_none() {
            self.next_pkt = self.reader.next_packet()?;
        }
        let Some(pkt) = self.next_pkt.as_ref() else {
            return Ok(None);
        };
        let first = *self.first_capture_micros.get_or_insert(pkt.timestamp_micros);
        let elapsed_capture = (pkt.timestamp_micros - first) as f64 / self.rate as f64;
        let target = Duration::from_micros(elapsed_capture.max(0.0) as u64);
        if self.replay_start.elapsed() < target {
            return Ok(None); // too early, let the caller come back
        }
        Ok(self.next_pkt.take())
    }
}
