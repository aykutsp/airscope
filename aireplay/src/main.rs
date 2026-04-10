//! `aireplay` - builds 802.11 frames and optionally injects them.
//!
//! There are three modes:
//!   * `deauth`  - send deauth frames to a client (or broadcast)
//!   * `probe`   - send a probe request for an SSID
//!   * `inspect` - parse a hex-encoded frame and print the fields
//!
//! Injection is done via `airscope-wifi`'s pcap wrapper, which requires
//! the interface to already be in monitor mode. Without `--interface`
//! the tool just prints the crafted frame as hex - handy for test
//! harnesses, documentation, and demos without a radio.

use std::time::Duration;

use airscope_core::MacAddr;
use airscope_wifi::builder::{build_deauth, build_probe_request, wrap_radiotap, ReasonCode};
use airscope_wifi::capture::live::LiveCapture;
use airscope_wifi::{Dot11Frame, ManagementBody};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "aireplay",
    version,
    about = "Craft and inject 802.11 management frames",
    long_about = "Aireplay builds deauthentication, probe request, and other 802.11 \
                  frames. With --interface it injects them on a monitor-mode radio; \
                  without, it just prints the frame as hex so you can audit it or \
                  pipe it into a capture file."
)]
struct Cli {
    /// Monitor-mode interface to inject on. When omitted, frames are printed.
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// How many times to transmit the frame. 0 = run forever.
    #[arg(short = 'c', long, default_value_t = 1)]
    count: u32,

    /// Delay between transmissions, in milliseconds.
    #[arg(long, default_value_t = 100)]
    delay_ms: u64,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Craft a deauthentication frame.
    Deauth {
        /// Target station (use `ff:ff:ff:ff:ff:ff` for broadcast).
        #[arg(long)]
        client: String,
        /// BSSID of the access point.
        #[arg(long)]
        bssid: String,
        /// Reason code. Default = 1 (unspecified).
        #[arg(long, default_value_t = 1)]
        reason: u16,
    },
    /// Craft a probe request.
    Probe {
        /// SSID to probe for (empty for wildcard).
        #[arg(long, default_value = "")]
        ssid: String,
        /// Source MAC. Default = random locally administered.
        #[arg(long)]
        source: Option<String>,
    },
    /// Parse a raw 802.11 frame supplied as hex and print the fields.
    Inspect {
        /// Hex string (spaces / colons ignored).
        hex: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .without_time()
        .init();

    match &cli.cmd {
        Cmd::Deauth { client, bssid, reason } => {
            let client: MacAddr = client.parse().map_err(|e| anyhow!("client: {e}"))?;
            let bssid: MacAddr = bssid.parse().map_err(|e| anyhow!("bssid: {e}"))?;
            let reason = map_reason(*reason);
            let raw = build_deauth(client, bssid, bssid, reason);
            transmit_or_print(&cli, &raw, "deauth")
        }
        Cmd::Probe { ssid, source } => {
            let src = match source {
                Some(s) => s.parse().map_err(|e| anyhow!("source: {e}"))?,
                None => MacAddr::random_with_seed(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0xcafef00d),
                ),
            };
            let raw = build_probe_request(src, ssid);
            transmit_or_print(&cli, &raw, "probe_request")
        }
        Cmd::Inspect { hex } => inspect(hex),
    }
}

fn transmit_or_print(cli: &Cli, frame: &[u8], label: &str) -> Result<()> {
    println!("{label}: {} bytes   {}", frame.len(), hex::encode(frame));
    let Some(iface) = cli.interface.as_ref() else {
        if cli.count > 1 {
            println!("(not injecting - supply --interface to actually send)");
        }
        return Ok(());
    };

    let mut cap = LiveCapture::open(iface)
        .map_err(|e| anyhow!(e.to_string()))
        .with_context(|| format!("open {iface}"))?;

    let wrapped = wrap_radiotap(frame);
    let max = if cli.count == 0 { u32::MAX } else { cli.count };
    let delay = Duration::from_millis(cli.delay_ms);
    for i in 1..=max {
        cap.inject(&wrapped).map_err(|e| anyhow!(e.to_string()))?;
        if cli.count == 0 || i < max {
            std::thread::sleep(delay);
        }
        if i.is_power_of_two() || i == max {
            eprintln!("sent {i} frames");
        }
    }
    Ok(())
}

fn inspect(hex: &str) -> Result<()> {
    let cleaned: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let bytes = hex::decode(&cleaned).map_err(|e| anyhow!("not valid hex: {e}"))?;
    let frame = Dot11Frame::parse(&bytes).map_err(|e| anyhow!(e.to_string()))?;
    println!("frame.type     = {:?}", frame.frame_type);
    println!("frame.subtype  = {:?}", frame.subtype);
    println!("frame.addr1    = {}", frame.addr1);
    println!("frame.addr2    = {}", frame.addr2);
    println!("frame.addr3    = {}", frame.addr3);
    println!("frame.seq/frag = {}/{}", frame.sequence, frame.fragment);
    if let Some(body) = frame.management_body() {
        print_body(&body);
    }
    Ok(())
}

fn print_body(body: &ManagementBody<'_>) {
    println!("mgmt.beacon_interval = {} TU", body.beacon_interval_tu);
    println!("mgmt.capabilities    = 0x{:04x}", body.capabilities);
    let decoded = body.decode();
    if let Some(ssid) = &decoded.ssid {
        println!("mgmt.ssid            = {ssid:?}");
    }
    if let Some(ch) = decoded.channel {
        println!("mgmt.channel         = {ch}");
    }
    println!("mgmt.encryption      = {}", decoded.encryption);
    println!("mgmt.vendor_tags     = {}", decoded.vendor_tags);
}

fn map_reason(code: u16) -> ReasonCode {
    match code {
        2 => ReasonCode::PrevAuthNotValid,
        3 => ReasonCode::LeavingNetwork,
        4 => ReasonCode::InactivityTimeout,
        5 => ReasonCode::ApBusy,
        6 => ReasonCode::Class2FrameFromNonauth,
        7 => ReasonCode::Class3FrameFromNonassoc,
        8 => ReasonCode::StaLeavingBss,
        9 => ReasonCode::RequestingReauth,
        _ => ReasonCode::Unspecified,
    }
}
