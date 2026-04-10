//! `airbase` - soft AP / beacon flooder.
//!
//! Broadcasts beacons for one or many SSIDs. On a monitor-mode Linux
//! radio this makes the named networks appear in anyone's scan list -
//! the classic "honeypot" setup that airbase-ng does in its simplest
//! mode. Without `--interface` the tool prints the first crafted frame
//! as hex, which is still useful for inspection / documentation.
//!
//! The beacon timing follows the standard: 100 TU (≈102.4 ms) per AP.
//! Many APs means many beacons per interval, so the tool walks through
//! the list inside a ticker.

use std::time::Duration;

use airscope_core::MacAddr;
use airscope_wifi::builder::{build_beacon, wrap_radiotap};
use airscope_wifi::capture::live::LiveCapture;
use anyhow::{anyhow, Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "airbase",
    version,
    about = "Broadcast 802.11 beacons for fake access points",
    long_about = "Airbase crafts and optionally transmits beacon frames. It's modelled \
                  on the --essids mode of airbase-ng: you give it one or more SSIDs \
                  and a channel and it fills the air with beacons. A random BSSID is \
                  assigned to each SSID on startup."
)]
struct Cli {
    /// Monitor-mode interface to transmit on. Omit for dry-run.
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// SSIDs to broadcast. Can be repeated.
    #[arg(short = 's', long = "ssid", required = true)]
    ssids: Vec<String>,

    /// Operating channel for the advertised networks.
    #[arg(short = 'c', long, default_value_t = 6)]
    channel: u8,

    /// Beacon interval in Time Units (1024 µs each). Default = 100 TU ≈ 102.4 ms.
    #[arg(long, default_value_t = 100)]
    beacon_interval: u16,

    /// Set the Privacy bit on all beacons (WEP-flavoured without an RSN IE).
    #[arg(long)]
    privacy: bool,

    /// Stop after N seconds. 0 = run until Ctrl-C.
    #[arg(long, default_value_t = 0)]
    duration: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .without_time()
        .init();

    let cli = Cli::parse();
    if cli.ssids.is_empty() {
        anyhow::bail!("at least one --ssid is required");
    }

    // Stable BSSIDs across the life of a single run.
    let beacons: Vec<(MacAddr, String, Vec<u8>)> = cli
        .ssids
        .iter()
        .enumerate()
        .map(|(idx, ssid)| {
            let bssid = MacAddr::random_with_seed(0xbeef_1000 + idx as u64);
            let frame = build_beacon(bssid, ssid, cli.channel, cli.beacon_interval, cli.privacy);
            (bssid, ssid.clone(), frame)
        })
        .collect();

    println!("airbase: advertising {} SSIDs on channel {}", beacons.len(), cli.channel);
    for (bssid, ssid, frame) in &beacons {
        println!("  {}  {:<32}  ({} bytes)", bssid, ssid, frame.len());
    }

    let Some(iface) = cli.interface.as_ref() else {
        println!("\ndry-run: pass --interface <iface> to actually transmit");
        if let Some((_, _, f)) = beacons.first() {
            println!("first frame hex:\n{}", hex::encode(f));
        }
        return Ok(());
    };

    let mut cap = LiveCapture::open(iface)
        .map_err(|e| anyhow!(e.to_string()))
        .with_context(|| format!("open {iface}"))?;

    let interval = Duration::from_micros(cli.beacon_interval as u64 * 1024);
    let deadline = if cli.duration == 0 {
        None
    } else {
        Some(std::time::Instant::now() + Duration::from_secs(cli.duration))
    };

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut counter: u64 = 0;
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                eprintln!("\nctrl-c: stopping after {counter} beacons");
                break;
            }
            _ = ticker.tick() => {
                if let Some(d) = deadline {
                    if std::time::Instant::now() >= d {
                        eprintln!("\nduration reached: stopping after {counter} beacons");
                        break;
                    }
                }
                for (_, _, frame) in &beacons {
                    let wrapped = wrap_radiotap(frame);
                    if let Err(e) = cap.inject(&wrapped) {
                        anyhow::bail!("inject failed: {e}");
                    }
                    counter += 1;
                }
            }
        }
    }

    println!("total beacons sent: {counter}");
    Ok(())
}

// Local hex helper to avoid pulling in the hex crate for one call.
mod hex {
    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len() * 2);
        for b in data {
            out.push(to_hex((b >> 4) as u8));
            out.push(to_hex((b & 0x0f) as u8));
        }
        out
    }
    fn to_hex(n: u8) -> char {
        match n {
            0..=9 => (b'0' + n) as char,
            10..=15 => (b'a' + n - 10) as char,
            _ => '?',
        }
    }
}
