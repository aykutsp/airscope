//! `airmon` - the Airscope replacement for `airmon-ng`.
//!
//! Responsible for three things:
//!   * listing network interfaces the OS exposes to us,
//!   * flipping one of them into monitor mode, and
//!   * flipping it back when the user is done.
//!
//! On Linux we shell out to `ip` / `iw` because those tools already know
//! every driver quirk; reimplementing them would buy us nothing. On other
//! platforms we only list. That's a deliberate scope decision: real
//! monitor mode on Windows or macOS needs kernel extensions that aren't
//! ours to ship.
//!
//! Interface listing is done through `if-addrs` (pure Rust) so this
//! binary works on any platform with no Npcap / libpcap dependency.
//! When you enable the `live` feature, the tool additionally queries
//! pcap so the output agrees with what the capture backend sees.

use std::collections::BTreeMap;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{bail, Context};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "airmon",
    version,
    about = "Manage wireless interfaces and monitor mode",
    long_about = "Airmon is the Airscope equivalent of airmon-ng. It lists network \
                  interfaces, puts one into monitor mode, and restores managed mode \
                  afterwards. On Linux it wraps `ip link` and `iw`."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List network interfaces the OS reports.
    List {
        /// Emit machine-readable JSON instead of a table.
        #[arg(long)]
        json: bool,
    },

    /// Switch `iface` into monitor mode. Requires root on Linux.
    Start {
        /// Interface name, e.g. `wlan0`.
        iface: String,
        /// Optional channel to lock to after going monitor.
        #[arg(short, long)]
        channel: Option<u16>,
    },

    /// Restore `iface` back to managed mode.
    Stop { iface: String },

    /// Check whether the interface is currently in monitor mode.
    Status { iface: String },
}

fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::List { json } => list_interfaces(json),
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

/// One merged view of an interface: what the OS calls it, whether it
/// carries an IP, and whether our capture backend can see it.
#[derive(Debug, Default)]
struct Iface {
    name: String,
    ips: Vec<IpAddr>,
    is_loopback: bool,
    pcap_seen: bool,
    description: Option<String>,
    /// True if this looks like a wireless interface (best-effort guess).
    is_wireless: bool,
}

fn list_interfaces(as_json: bool) -> Result<()> {
    let by_name = collect_interfaces();
    if by_name.is_empty() {
        if as_json {
            println!("[]");
        } else {
            println!("(no interfaces found)");
        }
        return Ok(());
    }
    if as_json {
        print_interfaces_json(&by_name);
    } else {
        print_interfaces_table(&by_name);
    }
    Ok(())
}

fn collect_interfaces() -> BTreeMap<String, Iface> {
    let mut by_name: BTreeMap<String, Iface> = BTreeMap::new();

    // 1. Pure-Rust OS-level enumeration. Works everywhere, no native deps.
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            for iface in ifaces {
                let entry = by_name.entry(iface.name.clone()).or_default();
                entry.name = iface.name.clone();
                entry.ips.push(iface.ip());
                if iface.is_loopback() {
                    entry.is_loopback = true;
                }
            }
        }
        Err(e) => {
            eprintln!("warning: if_addrs enumeration failed: {e}");
        }
    }

    // 2. Linux bonus: /sys/class/net/<name>/wireless exists for cards
    //    that speak cfg80211, which is exactly what we want to flag.
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for ent in entries.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                let is_wireless = ent.path().join("wireless").exists();
                let entry = by_name
                    .entry(name.clone())
                    .or_insert_with(|| Iface { name, ..Default::default() });
                entry.is_wireless = is_wireless;
            }
        }
    }

    // 2b. Windows / macOS fallback: we don't have /sys/class/net, so the
    //     best we can do is a name heuristic. It catches the obvious
    //     cases ("Wi-Fi", "wlan0", "en0 (Wi-Fi)").
    #[cfg(not(target_os = "linux"))]
    {
        for iface in by_name.values_mut() {
            let lower = iface.name.to_ascii_lowercase();
            if lower.starts_with("wlan")
                || lower.starts_with("wi-fi")
                || lower.starts_with("wifi")
                || lower.contains("wireless")
                || lower.contains("802.11")
            {
                iface.is_wireless = true;
            }
        }
    }

    // 3. Opportunistic pcap lookup - only when the live feature is on.
    //    This gives us the human-readable description string that
    //    Npcap / libpcap report, which is often more useful than the
    //    adapter GUID you see on Windows.
    #[cfg(feature = "live")]
    {
        use airscope_wifi::capture::live as capture_live;
        if let Ok(pcap_ifaces) = capture_live::list_interfaces() {
            for p in pcap_ifaces {
                let entry = by_name
                    .entry(p.name.clone())
                    .or_insert_with(|| Iface { name: p.name.clone(), ..Default::default() });
                entry.pcap_seen = true;
                if entry.description.is_none() {
                    entry.description = p.description;
                }
            }
        }
    }

    by_name
}

fn iface_kind(iface: &Iface) -> &'static str {
    if iface.is_wireless {
        "wifi"
    } else if iface.is_loopback {
        "loop"
    } else if iface.name.starts_with("eth")
        || iface.name.starts_with("en")
        || iface.name.to_ascii_lowercase().starts_with("ethernet")
    {
        "eth"
    } else {
        "-"
    }
}

fn print_interfaces_table(by_name: &BTreeMap<String, Iface>) {
    // Render. Column widths are fluid so Windows' long friendly
    // names ("Loopback Pseudo-Interface 1") don't get truncated.
    let name_width = by_name.values().map(|i| i.name.chars().count()).max().unwrap_or(10).max(10);
    println!(
        "{:<name_w$}  {:<6}  {:<5}  {:<6}  notes",
        "interface",
        "kind",
        "pcap",
        "ips",
        name_w = name_width
    );
    println!("{}", "-".repeat(name_width + 32));
    for iface in by_name.values() {
        let pcap = if cfg!(feature = "live") {
            if iface.pcap_seen {
                "yes"
            } else {
                "no"
            }
        } else {
            "n/a"
        };
        let ip_summary =
            if iface.ips.is_empty() { "0".to_string() } else { iface.ips.len().to_string() };
        let notes = iface.description.as_deref().unwrap_or("");
        println!(
            "{:<name_w$}  {:<6}  {:<5}  {:<6}  {}",
            iface.name,
            iface_kind(iface),
            pcap,
            ip_summary,
            notes,
            name_w = name_width
        );
        for ip in &iface.ips {
            println!("{:<name_w$}    {ip}", "", name_w = name_width);
        }
    }

    if !cfg!(feature = "live") {
        println!();
        println!(
            "note: built without the `live` feature. This listing is from the OS directly.\n\
             To also query the capture backend (Npcap / libpcap), rebuild with\n\
             `cargo build -p airscope-airmon --features live`."
        );
    }
}

fn print_interfaces_json(by_name: &BTreeMap<String, Iface>) {
    let ifaces: Vec<&Iface> = by_name.values().collect();
    println!("[");
    for (i, iface) in ifaces.iter().enumerate() {
        let comma = if i + 1 == ifaces.len() { "" } else { "," };
        println!("  {{");
        println!("    \"name\": {},", json_string(&iface.name));
        println!("    \"kind\": \"{}\",", iface_kind(iface));
        println!("    \"loopback\": {},", iface.is_loopback);
        println!("    \"wireless\": {},", iface.is_wireless);
        println!(
            "    \"description\": {},",
            iface.description.as_deref().map(json_string).unwrap_or_else(|| "null".into())
        );
        println!(
            "    \"pcap_seen\": {},",
            if cfg!(feature = "live") { iface.pcap_seen.to_string() } else { "null".into() }
        );
        print!("    \"addresses\": [");
        for (j, ip) in iface.ips.iter().enumerate() {
            if j > 0 {
                print!(", ");
            }
            print!("\"{ip}\"");
        }
        println!("]");
        println!("  }}{comma}");
    }
    println!("]");
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn start(iface: &str, channel: Option<u16>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run(&["ip", "link", "set", iface, "down"]).context("ip link set down")?;
        run(&["iw", "dev", iface, "set", "type", "monitor"]).context("iw set type monitor")?;
        run(&["ip", "link", "set", iface, "up"]).context("ip link set up")?;
        if let Some(c) = channel {
            run(&["iw", "dev", iface, "set", "channel", &c.to_string()])
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
        run(&["iw", "dev", iface, "set", "type", "managed"]).context("iw set type managed")?;
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
        let mode = text.lines().find_map(|l| l.trim().strip_prefix("type ")).unwrap_or("unknown");
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
