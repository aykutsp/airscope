//! `airmon` - the Airscope replacement for `airmon-ng`.
//!
//! Responsible for three things:
//!   * listing wireless interfaces that the OS exposes to us,
//!   * flipping one of them into monitor mode, and
//!   * flipping it back when the user is done.
//!
//! On Linux we shell out to `ip` / `iw` because those tools already know
//! every driver quirk; reimplementing them would buy us nothing. On other
//! platforms we only list. That's a deliberate scope decision: real
//! monitor mode on Windows or macOS needs kernel extensions that aren't
//! ours to ship.

#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

use airscope_wifi::capture::live;
use anyhow::{anyhow, Result};
#[cfg(not(target_os = "linux"))]
use anyhow::bail;
#[cfg(target_os = "linux")]
use anyhow::{bail, Context};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "airmon",
    version,
    about = "Manage wireless interfaces and monitor mode",
    long_about = "Airmon is the Airscope equivalent of airmon-ng. It lists wireless \
                  interfaces, puts one into monitor mode, and restores managed mode \
                  afterwards. On Linux it wraps `ip link` and `iw`."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List wireless (and other) interfaces visible to the capture backend.
    List,

    /// Switch `iface` into monitor mode. Requires root on Linux.
    Start {
        /// Interface name, e.g. `wlan0`.
        iface: String,
        /// Optional channel to lock to after going monitor.
        #[arg(short, long)]
        channel: Option<u16>,
    },

    /// Restore `iface` back to managed mode.
    Stop {
        iface: String,
    },

    /// Check whether the interface is currently in monitor mode.
    Status {
        iface: String,
    },
}

fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::List => list_interfaces(),
        Cmd::Start { iface, channel } => start(&iface, channel),
        Cmd::Stop { iface } => stop(&iface),
        Cmd::Status { iface } => status(&iface),
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .without_time()
        .init();
}

fn list_interfaces() -> Result<()> {
    let interfaces = live::list_interfaces().map_err(|e| anyhow!(e.to_string()))?;
    if interfaces.is_empty() {
        println!("(no interfaces reported - do you have Npcap / libpcap installed?)");
        return Ok(());
    }
    println!("{:<16} {:<6} description", "interface", "state");
    println!("{}", "-".repeat(60));
    for iface in interfaces {
        println!(
            "{:<16} {:<6} {}",
            iface.name,
            if iface.is_up { "up" } else { "down" },
            iface.description.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

fn start(iface: &str, channel: Option<u16>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run(&["ip", "link", "set", iface, "down"]).context("ip link set down")?;
        run(&["iw", "dev", iface, "set", "type", "monitor"])
            .context("iw set type monitor")?;
        run(&["ip", "link", "set", iface, "up"]).context("ip link set up")?;
        if let Some(c) = channel {
            run(&[
                "iw",
                "dev",
                iface,
                "set",
                "channel",
                &c.to_string(),
            ])
            .context("iw set channel")?;
        }
        println!("{iface} → monitor mode");
        if let Some(c) = channel {
            println!("{iface} → locked to channel {c}");
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (iface, channel);
        bail!(
            "monitor mode toggling is only implemented on Linux. \
             On Windows / macOS use your vendor's capture mode and \
             run `airodump` directly on the resulting interface."
        );
    }
}

fn stop(iface: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run(&["ip", "link", "set", iface, "down"]).context("ip link set down")?;
        run(&["iw", "dev", iface, "set", "type", "managed"])
            .context("iw set type managed")?;
        run(&["ip", "link", "set", iface, "up"]).context("ip link set up")?;
        println!("{iface} → managed mode");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = iface;
        bail!("stop is only implemented on Linux");
    }
}

fn status(iface: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("iw")
            .args(["dev", iface, "info"])
            .stderr(Stdio::inherit())
            .output()
            .context("spawn iw dev info")?;
        if !out.status.success() {
            bail!("iw dev {iface} info failed");
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mode = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("type "))
            .unwrap_or("unknown");
        let channel = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("channel "))
            .map(|rest| rest.split(' ').next().unwrap_or("?"))
            .unwrap_or("-");
        println!("{iface}: mode={mode}, channel={channel}");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = iface;
        bail!("status is only implemented on Linux");
    }
}

#[cfg(target_os = "linux")]
fn run(argv: &[&str]) -> Result<()> {
    let status = Command::new(argv[0])
        .args(&argv[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("spawn {}", argv.join(" ")))?;
    if !status.success() {
        bail!("{} exited with {}", argv.join(" "), status);
    }
    Ok(())
}
