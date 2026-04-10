//! Wireless specifics for the Airscope suite.
//!
//! Splits into four areas:
//!
//! * [`radiotap`] – minimal radiotap header decoder (flags + signal + channel).
//! * [`frame`]    – 802.11 MAC header + a few management body decoders.
//! * [`builder`]  – frame crafting helpers (deauth, beacon, probe).
//! * [`capture`]  – pcap wrapper gated behind the `live` feature, plus a
//!   cross-platform pcap-file reader so offline analysis works on any OS.

#![deny(rust_2018_idioms)]

pub mod builder;
pub mod capture;
pub mod frame;
pub mod radiotap;

pub use frame::{Dot11Frame, FrameSubtype, FrameType, ManagementBody};
pub use radiotap::{RadiotapHeader, RadiotapInfo};
