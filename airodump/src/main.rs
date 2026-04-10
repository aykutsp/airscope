//! `airodump` - the Airscope scanner.
//!
//! Takes frames from either a live monitor interface or a pcap file,
//! feeds them into a [`scanner::ScanState`], and renders the result
//! in a ratatui TUI. With `--no-tui` it prints the final snapshot on
//! exit, which is what we use in CI and in the pcap unit tests.

mod scanner;
mod source;
mod tui;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use airscope_ui::TerminalGuard;
use airscope_wifi::capture::{PcapFileWriter, LINKTYPE_IEEE802_11_RADIOTAP};
use anyhow::{Context, Result};
use clap::Parser;

use crate::scanner::ScanState;
use crate::source::{FrameSource, LiveSource, ReplaySource};

#[derive(Parser, Debug)]
#[command(
    name = "airodump",
    version,
    about = "Real-time 802.11 scanner with a TUI",
    long_about = "Airodump is the Airscope scanner. It shows beacons, probe requests, \
                  associated stations and traffic counters as they come off the air. \
                  Use --interface on Linux for a live capture, or --read to replay a \
                  .pcap file on any platform."
)]
struct Cli {
    /// Wireless interface to capture from (must already be in monitor mode).
    #[arg(short = 'i', long, conflicts_with_all = ["read", "list_interfaces"])]
    interface: Option<String>,

    /// Replay a pcap file instead of a live interface.
    #[arg(short = 'r', long, conflicts_with_all = ["interface", "list_interfaces"])]
    read: Option<PathBuf>,

    /// Print the interfaces the OS reports and exit.
    ///
    /// Useful as a quick `which interface should I capture on?` — so you
    /// don't need to leave airodump and run `airmon list`. Combine with
    /// `--format json` for machine-readable output.
    #[arg(long)]
    list_interfaces: bool,

    /// Replay speed multiplier (1.0 = real time, 5.0 = 5x).
    #[arg(long, default_value_t = 1.0)]
    rate: f32,

    /// Skip the TUI and print the final state on exit.
    #[arg(long)]
    no_tui: bool,

    /// Output format for `--no-tui` and `--list-interfaces`. One of: table, json.
    #[arg(long, default_value = "table")]
    format: OutputFormat,

    /// Write every observed frame to a pcap file as we go. Combines well with --read.
    #[arg(short = 'w', long)]
    write: Option<PathBuf>,

    /// Force-stop after N seconds, useful for scripting.
    #[arg(long)]
    duration: Option<u64>,

    /// Log level (trace|debug|info|warn|error).
    #[arg(long, default_value = "warn")]
    log: String,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    if cli.list_interfaces {
        return list_interfaces(cli.format);
    }

    // Tri-state from the source: the FrameSource itself, a display
    // label for the banner, and an optional one-off warning (e.g.
    // "you're in managed mode, the table will stay empty") that we
    // surface both on stderr and inside the TUI.
    let (mut source, label, warning): (Box<dyn FrameSource>, String, Option<String>) =
        match (cli.interface.as_ref(), cli.read.as_ref()) {
            (Some(iface), None) => {
                let live = LiveSource::new(iface).map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let warn = live.linktype_warning();
                if let Some(w) = warn.as_deref() {
                    eprintln!("airodump: {w}\n");
                }
                (Box::new(live), format!("live:{iface}"), warn)
            }
            (None, Some(path)) => (
                Box::new(
                    ReplaySource::new(path, cli.rate)
                        .map_err(|e| anyhow::anyhow!(e.to_string()))?,
                ),
                format!("pcap:{}", path.display()),
                None,
            ),
            _ => {
                anyhow::bail!("pick exactly one source: --interface <iface> or --read <file.pcap>")
            }
        };

    let mut scan = ScanState::new();

    let mut writer: Option<PcapFileWriter> = if let Some(path) = cli.write.as_ref() {
        // Use the source's linktype so the written file replays cleanly
        // through both airodump and any other pcap reader.
        let linktype = source.linktype();
        Some(
            PcapFileWriter::create(path, linktype, 4096)
                .map_err(|e| anyhow::anyhow!(e.to_string()))
                .with_context(|| format!("open {}", path.display()))?,
        )
    } else {
        None
    };
    let _ = LINKTYPE_IEEE802_11_RADIOTAP; // keep the constant's import live

    if cli.no_tui {
        return headless_loop(
            source.as_mut(),
            &mut scan,
            writer.as_mut(),
            cli.duration,
            cli.format,
        );
    }

    run_tui(source.as_mut(), &mut scan, writer.as_mut(), label, warning, cli.duration)
        .context("airodump TUI crashed")
}

/// Handle `--list-interfaces`.
///
/// Output shape depends on whether the `live` feature is compiled in:
///   * default build → friendly-name list from the OS (`if_addrs`).
///   * live build    → the pcap device list from the capture backend,
///                     which is what you actually pass to `-i`. On
///                     Windows these are `\Device\NPF_{GUID}` strings,
///                     so seeing them directly is the whole point.
///
/// For richer output (wireless detection on Linux, pcap descriptions)
/// use `airmon list`.
fn list_interfaces(format: OutputFormat) -> Result<()> {
    #[cfg(feature = "live")]
    {
        return list_interfaces_live(format);
    }

    #[cfg(not(feature = "live"))]
    list_interfaces_os(format)
}

/// OS-level listing. Works without any native pcap dep.
#[allow(dead_code)]
fn list_interfaces_os(format: OutputFormat) -> Result<()> {
    let ifaces = if_addrs::get_if_addrs().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    use std::collections::BTreeMap;
    let mut by_name: BTreeMap<String, Vec<std::net::IpAddr>> = BTreeMap::new();
    let mut loopback: std::collections::BTreeSet<String> = Default::default();
    for iface in ifaces {
        by_name.entry(iface.name.clone()).or_default().push(iface.ip());
        if iface.is_loopback() {
            loopback.insert(iface.name);
        }
    }

    match format {
        OutputFormat::Table => {
            let name_width = by_name.keys().map(|n| n.chars().count()).max().unwrap_or(12).max(12);
            println!("{:<name_w$}  {:<6}  addresses", "interface", "kind", name_w = name_width);
            println!("{}", "-".repeat(name_width + 20));
            for (name, ips) in &by_name {
                let kind = classify_name(name, loopback.contains(name));
                println!(
                    "{:<name_w$}  {:<6}  {}",
                    name,
                    kind,
                    ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
                    name_w = name_width
                );
            }
            println!();
            println!(
                "note: this build does not link libpcap. pass any of the \
                 names above to `-i`,\n      or rebuild with `--features live` \
                 to also see the raw capture-backend device names."
            );
        }
        OutputFormat::Json => {
            let names: Vec<&String> = by_name.keys().collect();
            println!("[");
            for (i, name) in names.iter().enumerate() {
                let comma = if i + 1 == names.len() { "" } else { "," };
                let ips = &by_name[*name];
                let kind = classify_name(name, loopback.contains(*name));
                println!("  {{");
                println!("    \"name\": {},", json_escape(name));
                println!("    \"kind\": \"{kind}\",");
                println!("    \"pcap_device\": null,");
                print!("    \"addresses\": [");
                for (j, ip) in ips.iter().enumerate() {
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
    }
    Ok(())
}

/// Live-capable listing. Uses the pcap device list as the source of
/// truth because those are the strings `-i` actually accepts. We still
/// look at `if_addrs` for the IP addresses, joining on description.
#[cfg(feature = "live")]
fn list_interfaces_live(format: OutputFormat) -> Result<()> {
    use airscope_wifi::capture::live as capture_live;

    let pcap_devs = capture_live::list_interfaces().map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Sidecar: IPs from if_addrs keyed by friendly name. We'll try to
    // match these to pcap descriptions so Windows users see their
    // "Wi-Fi" address next to `\Device\NPF_{GUID}`.
    let ip_addrs = if_addrs::get_if_addrs().unwrap_or_default();

    match format {
        OutputFormat::Table => {
            let dev_width =
                pcap_devs.iter().map(|d| d.name.chars().count()).max().unwrap_or(20).max(20);
            println!("{:<dev_w$}  {:<5}  description", "device", "state", dev_w = dev_width);
            println!("{}", "-".repeat(dev_width + 30));
            for dev in &pcap_devs {
                let state = if dev.is_up { "up" } else { "down" };
                let desc = dev.description.as_deref().unwrap_or("-");
                println!("{:<dev_w$}  {:<5}  {}", dev.name, state, desc, dev_w = dev_width);
                // Attach any matching IPv4/IPv6 addresses.
                if let Some(desc) = dev.description.as_deref() {
                    let matches: Vec<_> = ip_addrs
                        .iter()
                        .filter(|a| {
                            desc.to_ascii_lowercase().contains(&a.name.to_ascii_lowercase())
                        })
                        .collect();
                    for ip in matches {
                        println!("{:<dev_w$}    {} ({})", "", ip.ip(), ip.name, dev_w = dev_width);
                    }
                }
            }
            println!();
            println!(
                "tip: pass any value in the `device` column to `-i`. on Windows you \
                 can also use\n     a friendly name like `Wi-Fi` — airodump will \
                 fuzzy-match it against descriptions."
            );
        }
        OutputFormat::Json => {
            println!("[");
            for (i, dev) in pcap_devs.iter().enumerate() {
                let comma = if i + 1 == pcap_devs.len() { "" } else { "," };
                println!("  {{");
                println!("    \"pcap_device\": {},", json_escape(&dev.name));
                println!(
                    "    \"description\": {},",
                    dev.description.as_deref().map(json_escape).unwrap_or_else(|| "null".into())
                );
                println!("    \"is_up\": {}", dev.is_up);
                println!("  }}{comma}");
            }
            println!("]");
        }
    }
    Ok(())
}

fn classify_name(name: &str, is_loopback: bool) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if is_loopback {
        "loop"
    } else if lower.starts_with("wlan")
        || lower.starts_with("wi-fi")
        || lower.starts_with("wifi")
        || lower.contains("wireless")
    {
        "wifi"
    } else {
        "-"
    }
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ =
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}

fn headless_loop(
    source: &mut dyn FrameSource,
    scan: &mut ScanState,
    writer: Option<&mut PcapFileWriter>,
    duration: Option<u64>,
    format: OutputFormat,
) -> Result<()> {
    let start = Instant::now();
    let mut writer = writer;
    loop {
        if let Some(secs) = duration {
            if start.elapsed().as_secs() >= secs {
                break;
            }
        }
        match source.next() {
            Ok(Some(pkt)) => {
                scan.ingest(source.linktype(), &pkt);
                if let Some(w) = writer.as_deref_mut() {
                    let _ = w.write(&pkt);
                }
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                eprintln!("capture error: {e}");
                break;
            }
        }
    }
    if let Some(w) = writer.as_deref_mut() {
        let _ = w.flush();
    }
    match format {
        OutputFormat::Table => print_table(scan),
        OutputFormat::Json => print_json(scan),
    }
    Ok(())
}

fn print_table(scan: &ScanState) {
    println!("# airodump snapshot");
    println!(
        "beacons={} data={} probes={} deauth={} bad_fcs={}",
        scan.counters.beacons,
        scan.counters.data,
        scan.counters.probes,
        scan.counters.deauth,
        scan.counters.bad_fcs
    );
    println!();
    println!(
        "{:<17}  {:>5}  {:>4}  {:>6}  {:>6}  {:<6}  ESSID",
        "BSSID", "PWR", "CH", "BCN", "DATA", "ENC"
    );
    for ap in scan.aps_sorted() {
        println!(
            "{:<17}  {:>5}  {:>4}  {:>6}  {:>6}  {:<6}  {}",
            ap.bssid,
            ap.signal_dbm,
            ap.channel,
            ap.beacons,
            ap.data_frames,
            ap.encryption.family(),
            ap.label()
        );
    }
}

/// A hand-rolled JSON emitter. We only have five types to handle and
/// they all survive a simple escape rule, so pulling in serde_json for
/// this would be more weight than it's worth.
fn print_json(scan: &ScanState) {
    let c = &scan.counters;
    println!("{{");
    println!("  \"counters\": {{");
    println!("    \"beacons\": {},", c.beacons);
    println!("    \"probes\": {},", c.probes);
    println!("    \"data\": {},", c.data);
    println!("    \"deauth\": {},", c.deauth);
    println!("    \"bad_fcs\": {},", c.bad_fcs);
    println!("    \"total_packets\": {}", c.total_packets);
    println!("  }},");
    println!("  \"access_points\": [");
    let aps = scan.aps_sorted();
    for (i, ap) in aps.iter().enumerate() {
        let comma = if i + 1 == aps.len() { "" } else { "," };
        println!("    {{");
        println!("      \"bssid\": \"{}\",", ap.bssid);
        println!("      \"ssid\": {},", json_string_opt(ap.ssid.as_deref()));
        println!("      \"channel\": {},", ap.channel);
        println!("      \"signal_dbm\": {},", ap.signal_dbm);
        println!("      \"beacons\": {},", ap.beacons);
        println!("      \"data_frames\": {},", ap.data_frames);
        println!("      \"encryption\": \"{}\"", ap.encryption.family());
        println!("    }}{comma}");
    }
    println!("  ],");
    println!("  \"stations\": [");
    let stas = scan.stations_sorted();
    for (i, sta) in stas.iter().enumerate() {
        let comma = if i + 1 == stas.len() { "" } else { "," };
        println!("    {{");
        println!("      \"mac\": \"{}\",", sta.mac);
        println!(
            "      \"bssid\": {},",
            sta.bssid.map(|b| format!("\"{b}\"")).unwrap_or_else(|| "null".into())
        );
        println!("      \"signal_dbm\": {},", sta.signal_dbm);
        println!("      \"frames\": {},", sta.frames);
        println!(
            "      \"probes\": [{}]",
            sta.probes.iter().map(|p| json_escape(p)).collect::<Vec<_>>().join(",")
        );
        println!("    }}{comma}");
    }
    println!("  ]");
    println!("}}");
}

fn json_string_opt(s: Option<&str>) -> String {
    match s {
        Some(v) => json_escape(v),
        None => "null".into(),
    }
}

fn json_escape(s: &str) -> String {
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

fn run_tui(
    source: &mut dyn FrameSource,
    scan: &mut ScanState,
    writer: Option<&mut PcapFileWriter>,
    label: String,
    warning: Option<String>,
    duration: Option<u64>,
) -> Result<()> {
    let mut guard = TerminalGuard::enter().context("enter alternate screen")?;
    let mut state = tui::TuiState::new(label);
    state.warning = warning;
    let mut writer = writer;

    let tick = Duration::from_millis(80);
    let start = Instant::now();

    loop {
        // Drain everything the source is willing to hand us right now.
        for _ in 0..256 {
            match source.next() {
                Ok(Some(pkt)) => {
                    scan.ingest(source.linktype(), &pkt);
                    if let Some(w) = writer.as_deref_mut() {
                        let _ = w.write(&pkt);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        guard.terminal.draw(|f| tui::draw(f, &mut state, scan))?;

        match tui::poll_event(tick, &mut state)? {
            tui::TuiOutcome::Quit => break,
            tui::TuiOutcome::SelectPrev => {
                let len = scan.aps.len();
                if len > 0 {
                    let i = state.table.selected().unwrap_or(0);
                    state.table.select(Some(if i == 0 { len - 1 } else { i - 1 }));
                }
            }
            tui::TuiOutcome::SelectNext => {
                let len = scan.aps.len();
                if len > 0 {
                    let i = state.table.selected().unwrap_or(0);
                    state.table.select(Some((i + 1) % len));
                }
            }
            tui::TuiOutcome::ToggleFollow | tui::TuiOutcome::None => {}
        }

        if let Some(secs) = duration {
            if start.elapsed().as_secs() >= secs {
                break;
            }
        }
    }

    if let Some(w) = writer.as_deref_mut() {
        let _ = w.flush();
    }
    drop(guard);
    Ok(())
}
