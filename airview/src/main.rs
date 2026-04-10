//! `airview` - pcap browser.
//!
//! Opens a capture file and renders the frames in a ratatui table with
//! a hex+ASCII dump panel for the selected row. Mini-wireshark, basically.
//! It's deliberately scoped to 802.11: radiotap is unwrapped, the frame
//! header is decoded, and management bodies are split into their tagged
//! IEs in the detail panel.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use airscope_core::FrameKind;
use airscope_ui::{status_bar, TerminalGuard, Theme};
use airscope_wifi::{
    capture::{CapturedPacket, PcapFileReader, LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP},
    frame::{Dot11Frame, ManagementBody},
    radiotap::{RadiotapHeader, RadiotapInfo},
};
use anyhow::{Context, Result};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    prelude::*,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};

#[derive(Parser, Debug)]
#[command(
    name = "airview",
    version,
    about = "Browse a pcap file with an 802.11-aware decoder",
    long_about = "Airview reads a pcap file and lets you walk through every frame in \
                  a TUI. Selected frame gets decoded and hex-dumped. Use --filter to \
                  pre-filter by frame kind (beacon, probe_req, deauth, data, ...)."
)]
struct Cli {
    /// Capture file to open.
    pcap: PathBuf,

    /// Only show frames of this kind.
    /// One of: beacon, probe_req, probe_resp, auth, deauth, assoc, data, ctrl, any.
    #[arg(long, default_value = "any")]
    filter: String,

    /// Exit after printing a text summary (no TUI). Good for piping.
    #[arg(long)]
    dump: bool,
}

#[derive(Debug, Clone)]
struct DecodedRow {
    index: usize,
    timestamp_us: i64,
    kind: FrameKind,
    length: usize,
    signal: Option<i8>,
    bssid: String,
    addr2: String,
    addr1: String,
    ssid: Option<String>,
    raw: Vec<u8>,
    radiotap_len: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rows = load_pcap(&cli.pcap, &cli.filter)
        .with_context(|| format!("load {}", cli.pcap.display()))?;

    if cli.dump {
        print_text(&rows);
        return Ok(());
    }
    run_tui(rows, cli.pcap).context("airview tui crashed")
}

fn load_pcap(path: &PathBuf, filter: &str) -> Result<Vec<DecodedRow>> {
    let mut reader = PcapFileReader::open(path)?;
    let linktype = reader.linktype;
    let mut out = Vec::new();
    let mut index = 0usize;
    while let Some(pkt) = reader.next_packet()? {
        index += 1;
        if let Some(row) = decode_packet(linktype, index, &pkt) {
            if kind_matches(filter, row.kind) {
                out.push(row);
            }
        }
    }
    Ok(out)
}

fn decode_packet(linktype: u32, index: usize, pkt: &CapturedPacket) -> Option<DecodedRow> {
    let (body, rt_info, radiotap_len) = match linktype {
        LINKTYPE_IEEE802_11_RADIOTAP => {
            let (hdr, n) = RadiotapHeader::parse(&pkt.data).ok()?;
            (&pkt.data[n..], Some(hdr.info), n)
        }
        LINKTYPE_IEEE802_11 => (&pkt.data[..], None::<RadiotapInfo>, 0),
        _ => return None,
    };
    let frame = Dot11Frame::parse(body).ok()?;
    let ssid = frame.management_body().and_then(|b: ManagementBody<'_>| b.decode().ssid);
    Some(DecodedRow {
        index,
        timestamp_us: pkt.timestamp_micros,
        kind: frame.kind(),
        length: body.len(),
        signal: rt_info.and_then(|i| i.signal_dbm),
        bssid: frame.bssid().to_string(),
        addr1: frame.addr1.to_string(),
        addr2: frame.addr2.to_string(),
        ssid,
        raw: pkt.data.clone(),
        radiotap_len,
    })
}

fn kind_matches(filter: &str, kind: FrameKind) -> bool {
    match filter.to_ascii_lowercase().as_str() {
        "any" | "all" | "" => true,
        "beacon" => matches!(kind, FrameKind::Beacon),
        "probe_req" => matches!(kind, FrameKind::ProbeRequest),
        "probe_resp" => matches!(kind, FrameKind::ProbeResponse),
        "probe" => matches!(kind, FrameKind::ProbeRequest | FrameKind::ProbeResponse),
        "auth" => matches!(kind, FrameKind::Authentication),
        "deauth" => matches!(kind, FrameKind::Deauthentication),
        "assoc" => matches!(kind, FrameKind::Association),
        "data" => matches!(kind, FrameKind::Data | FrameKind::Qos),
        "ctrl" | "control" => matches!(kind, FrameKind::Control),
        _ => true,
    }
}

fn print_text(rows: &[DecodedRow]) {
    println!("# airview dump ({} frames)", rows.len());
    println!("{:>5}  {:<5}  {:>4}  {:<17}  {:<17}  ESSID", "#", "KIND", "SIG", "BSSID", "ADDR2");
    for r in rows.iter().take(200) {
        println!(
            "{:>5}  {:<5}  {:>4}  {:<17}  {:<17}  {}",
            r.index,
            r.kind.short(),
            r.signal.map(|v| v as i16).unwrap_or(0),
            r.bssid,
            r.addr2,
            r.ssid.as_deref().unwrap_or("")
        );
    }
    if rows.len() > 200 {
        println!("... ({} more)", rows.len() - 200);
    }
}

struct TuiState {
    rows: Vec<DecodedRow>,
    table: TableState,
    theme: Theme,
    path: PathBuf,
}

fn run_tui(rows: Vec<DecodedRow>, path: PathBuf) -> Result<()> {
    let mut guard = TerminalGuard::enter()?;
    let mut state = TuiState {
        rows,
        table: {
            let mut t = TableState::default();
            t.select(Some(0));
            t
        },
        theme: Theme::DARK,
        path,
    };

    loop {
        guard.terminal.draw(|f| draw(f, &mut state))?;
        if event::poll(std::time::Duration::from_millis(200))? {
            if let Event::Key(KeyEvent { code, kind, .. }) = event::read()? {
                if kind != KeyEventKind::Press {
                    continue;
                }
                match code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        let len = state.rows.len();
                        if len > 0 {
                            let i = state.table.selected().unwrap_or(0);
                            state.table.select(Some((i + 1) % len));
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let len = state.rows.len();
                        if len > 0 {
                            let i = state.table.selected().unwrap_or(0);
                            state.table.select(Some(if i == 0 { len - 1 } else { i - 1 }));
                        }
                    }
                    KeyCode::Char('g') => {
                        if !state.rows.is_empty() {
                            state.table.select(Some(0));
                        }
                    }
                    KeyCode::Char('G') => {
                        if !state.rows.is_empty() {
                            state.table.select(Some(state.rows.len() - 1));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    drop(guard);
    Ok(())
}

fn draw(f: &mut Frame<'_>, state: &mut TuiState) {
    let area = f.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(50),
            Constraint::Percentage(50),
            Constraint::Length(1),
        ])
        .split(area);

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "airview ",
                Style::default().fg(state.theme.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("• {}", state.path.display()),
                Style::default().fg(state.theme.muted),
            ),
            Span::raw("   "),
            Span::styled(
                format!("{} frames loaded", state.rows.len()),
                Style::default().fg(Color::Rgb(220, 220, 230)),
            ),
        ]),
        Line::from(Span::styled("offline 802.11 decoder", Style::default().fg(state.theme.muted))),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(state.theme.accent_dim))
            .title(" airscope / airview "),
    );
    f.render_widget(header, outer[0]);

    draw_table(f, outer[1], state);
    draw_detail(f, outer[2], state);

    let hints: &[(&str, &str)] = &[("↑/↓", "navigate"), ("g/G", "top/bottom"), ("q", "quit")];
    f.render_widget(status_bar(hints, &state.theme), outer[3]);
}

fn draw_table(f: &mut Frame<'_>, area: Rect, state: &mut TuiState) {
    let header = Row::new(
        ["#", "TIME (s)", "LEN", "SIG", "KIND", "BSSID", "ADDR2", "ESSID"].iter().map(|h| {
            Cell::from(*h)
                .style(Style::default().fg(state.theme.accent).add_modifier(Modifier::BOLD))
        }),
    )
    .style(Style::default().bg(state.theme.header_bg));

    let rows: Vec<Row<'_>> = state
        .rows
        .iter()
        .map(|r| {
            Row::new(vec![
                Cell::from(r.index.to_string()),
                Cell::from(format!("{:.6}", r.timestamp_us as f64 / 1_000_000.0)),
                Cell::from(r.length.to_string()),
                Cell::from(
                    r.signal
                        .map(|v| format!("{} dBm", v as i16))
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Cell::from(r.kind.short()),
                Cell::from(r.bssid.clone()),
                Cell::from(r.addr2.clone()),
                Cell::from(r.ssid.clone().unwrap_or_default()),
            ])
        })
        .collect();

    let t = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Length(5),
            Constraint::Length(9),
            Constraint::Length(5),
            Constraint::Length(17),
            Constraint::Length(17),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" frames "))
    .row_highlight_style(Style::default().bg(Color::Rgb(35, 42, 60)).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");

    f.render_stateful_widget(t, area, &mut state.table);
}

fn draw_detail(f: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let selected = state.table.selected().and_then(|i| state.rows.get(i));

    let text: Vec<Line<'_>> = match selected {
        None => vec![Line::from(Span::styled("(empty)", Style::default().fg(state.theme.muted)))],
        Some(row) => {
            let mut lines = Vec::new();
            lines.push(Line::from(vec![
                Span::styled("kind  ", Style::default().fg(state.theme.muted)),
                Span::raw(format!("{:?}", row.kind)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("bssid ", Style::default().fg(state.theme.muted)),
                Span::raw(row.bssid.clone()),
                Span::raw("   "),
                Span::styled("rx-mac ", Style::default().fg(state.theme.muted)),
                Span::raw(row.addr1.clone()),
                Span::raw("   "),
                Span::styled("tx-mac ", Style::default().fg(state.theme.muted)),
                Span::raw(row.addr2.clone()),
            ]));
            if let Some(ssid) = &row.ssid {
                lines.push(Line::from(vec![
                    Span::styled("ssid  ", Style::default().fg(state.theme.muted)),
                    Span::raw(ssid.clone()),
                ]));
            }
            lines.push(Line::from(Span::styled(
                "────── hex dump ──────",
                Style::default().fg(state.theme.accent_dim),
            )));
            for line in hex_dump(&row.raw[row.radiotap_len..], 16).lines() {
                lines.push(Line::from(Span::raw(line.to_string())));
            }
            lines
        }
    };

    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" selected frame "))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn hex_dump(data: &[u8], width: usize) -> String {
    let mut out = String::new();
    for (offset, chunk) in data.chunks(width).enumerate() {
        out.push_str(&format!("{:04x}  ", offset * width));
        for b in chunk {
            out.push_str(&format!("{:02x} ", b));
        }
        for _ in chunk.len()..width {
            out.push_str("   ");
        }
        out.push_str(" │ ");
        for b in chunk {
            let c = *b as char;
            out.push(if c.is_ascii_graphic() || c == ' ' { c } else { '.' });
        }
        out.push('\n');
    }
    out
}
