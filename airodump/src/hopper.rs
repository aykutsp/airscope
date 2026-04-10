//! Channel hopping for live scans.
//!
//! airodump-ng hops through a configurable list of channels, holding
//! each one for a short dwell time, so a single radio can survey a
//! whole band. We do the same thing — except the kernel call to move
//! the card is platform-specific, so it lives behind a trait with a
//! Linux implementation and a "do nothing" default.
//!
//! On Linux we shell out to `iw dev <iface> set channel N`. This is
//! the same mechanism `airmon start --channel` uses and it's what
//! every wireless-security course on earth already has the user
//! running under `sudo`.
//!
//! On Windows / macOS there is no portable way to change a monitor
//! interface's channel from user-space, so the hopper becomes a
//! no-op: the card stays on whatever channel the driver last locked
//! it to. `airmon start --channel` covers the one-off case there.

use std::time::{Duration, Instant};

use airscope_core::{Band, Channel};

/// How long we sit on each channel before stepping to the next one.
/// 250 ms is the airodump-ng default and hits a reasonable sweet
/// spot: long enough to catch a couple of beacons per AP on a
/// 2.4 GHz band, short enough that the UI still feels live.
pub const DEFAULT_DWELL: Duration = Duration::from_millis(250);

/// Abstract "something that can put the radio on a given channel".
/// Exists so tests and non-Linux targets can stub it out.
pub trait ChannelControl {
    fn set_channel(&mut self, channel: u16) -> Result<(), String>;
}

/// Linux implementation: `iw dev <iface> set channel <n>`. Needs
/// the process to hold CAP_NET_ADMIN (or be root).
#[derive(Debug)]
pub struct IwHopper {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    interface: String,
}

impl IwHopper {
    pub fn new(interface: impl Into<String>) -> Self {
        Self { interface: interface.into() }
    }
}

impl ChannelControl for IwHopper {
    fn set_channel(&mut self, channel: u16) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            use std::process::{Command, Stdio};
            let out = Command::new("iw")
                .args(["dev", &self.interface, "set", "channel", &channel.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .map_err(|e| format!("spawn iw: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "iw dev {} set channel {channel}: {}",
                    self.interface,
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = channel;
            Err(format!(
                "channel hopping is not implemented on {} — use `airmon start --channel`",
                std::env::consts::OS
            ))
        }
    }
}

/// Returned when a hop was attempted but there was no channel controller
/// available or the requested channel failed. The hopper keeps going
/// rather than aborting the scan.
#[derive(Debug, Clone)]
pub enum HopOutcome {
    Moved(Channel),
    Skipped { channel: Channel, reason: String },
    NoChange,
}

/// Stateful round-robin walker over a channel list.
#[derive(Debug)]
pub struct Hopper {
    channels: Vec<Channel>,
    idx: usize,
    last_hop: Instant,
    dwell: Duration,
}

impl Hopper {
    pub fn new(channels: Vec<Channel>, dwell: Duration) -> Self {
        Self {
            channels,
            idx: 0,
            last_hop: Instant::now().checked_sub(dwell).unwrap_or_else(Instant::now),
            dwell,
        }
    }

    /// The default airodump-ng list: the 2.4 GHz band (channels 1..13).
    #[allow(dead_code)] // exposed for downstream users of the crate
    pub fn default_24ghz() -> Self {
        Self::new(Channel::hop_set(Band::Twenty4), DEFAULT_DWELL)
    }

    #[allow(dead_code)]
    pub fn current(&self) -> Option<Channel> {
        self.channels.get(self.idx).copied()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Called from the capture loop. Advances to the next channel if
    /// `dwell` has elapsed since the last hop and `controller` lets us.
    pub fn tick<C: ChannelControl>(&mut self, controller: &mut C) -> HopOutcome {
        if self.channels.is_empty() || self.last_hop.elapsed() < self.dwell {
            return HopOutcome::NoChange;
        }
        self.idx = (self.idx + 1) % self.channels.len();
        let ch = self.channels[self.idx];
        self.last_hop = Instant::now();
        match controller.set_channel(ch.number) {
            Ok(()) => HopOutcome::Moved(ch),
            Err(reason) => HopOutcome::Skipped { channel: ch, reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockControl {
        log: Vec<u16>,
    }
    impl ChannelControl for MockControl {
        fn set_channel(&mut self, channel: u16) -> Result<(), String> {
            self.log.push(channel);
            Ok(())
        }
    }

    #[test]
    fn hopper_walks_the_list_in_order() {
        let mut h = Hopper::new(
            vec![
                Channel::from_number(1).unwrap(),
                Channel::from_number(6).unwrap(),
                Channel::from_number(11).unwrap(),
            ],
            Duration::from_millis(0),
        );
        let mut ctl = MockControl { log: vec![] };
        for _ in 0..6 {
            let _ = h.tick(&mut ctl);
        }
        assert_eq!(ctl.log, vec![6, 11, 1, 6, 11, 1]);
    }

    #[test]
    fn hopper_respects_dwell() {
        let mut h = Hopper::new(
            vec![Channel::from_number(1).unwrap(), Channel::from_number(6).unwrap()],
            Duration::from_secs(10),
        );
        let mut ctl = MockControl { log: vec![] };
        let _ = h.tick(&mut ctl);
        let _ = h.tick(&mut ctl);
        // only the very first call should actually move the radio
        assert_eq!(ctl.log.len(), 1);
    }

    #[test]
    fn default_24ghz_has_13_entries() {
        let h = Hopper::default_24ghz();
        assert_eq!(h.len(), 13);
    }
}
