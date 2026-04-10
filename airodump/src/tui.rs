//! The interactive scanner view.
//!
//! Three panels:
//!   ┌───────────── banner + counters ──────────────┐
//!   │ APs table (sorted by signal)                │
//!   │                                             │
//!   ├─────── stations for the selected AP ────────┤
//!   └──────────── status bar / hints ─────────────┘

use std::time::{Duration, Instant};

use airscope_core::{AccessPoint, Station};
use airscope_ui::{banner, signal_bar, signal_color, status_bar, Theme};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    prelude::*,
    style::{Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};

use crate::scanner::ScanState;

pub enum TuiOutcome {
    Quit,
    ToggleFollow,
    SelectPrev,
    SelectNext,
    None,
}

pub struct TuiState {
    pub theme: Theme,
    pub table: TableState,
    pub follow_selected: bool,
    pub started_at: Instant,
    pub iface_label: String,
    /// A sticky warning shown above the AP table. Used to surface the
    /// "you're not in monitor mode" situation on Windows so the user
    /// isn't left staring at an empty table with no explanation.
    pub warning: Option<String>,
    /// Set by the channel hopper every time it moves the radio. Rendered
    /// next to the banner so the user knows which channel is live.
    pub current_channel: Option<u16>,
}

impl TuiState {
    pub fn new(iface_label: String) -> Self {
        let mut table = TableState::default();
        table.select(Some(0));
        Self {
            theme: Theme::DARK,
            table,
            follow_selected: true,
            started_at: Instant::now(),
            iface_label,
            warning: None,
            current_channel: None,
        }
    }

    pub fn selected_ap<'a>(&self, aps: &'a [AccessPoint]) -> Option<&'a AccessPoint> {
        self.table.selected().and_then(|i| aps.get(i))
    }
}

pub fn poll_event(tick: Duration, state: &mut TuiState) -> std::io::Result<TuiOutcome> {
    if event::poll(tick)? {
        if let Event::Key(KeyEvent { code, kind, .. }) = event::read()? {
            if kind != KeyEventKind::Press {
                return Ok(TuiOutcome::None);
            }
            return Ok(match code {
                KeyCode::Char('q') | KeyCode::Esc => TuiOutcome::Quit,
                KeyCode::Char('f') => {
                    state.follow_selected = !state.follow_selected;
                    TuiOutcome::ToggleFollow
                }
                KeyCode::Up => TuiOutcome::SelectPrev,
                KeyCode::Down => TuiOutcome::SelectNext,
                _ => TuiOutcome::None,
            });
        }
    }
    Ok(TuiOutcome::None)
}

pub fn draw(frame: &mut Frame<'_>, state: &mut TuiState, scan: &ScanState) {
    let area = frame.area();
    // Figure out how many lines the warning will need so we can reserve
    // the right amount of space; otherwise a long managed-mode banner
    // would push the tables off the bottom of the terminal.
    let warning_lines = state.warning.as_deref().map(|w| 2 + w.lines().count() as u16).unwrap_or(0);

    let mut constraints = vec![Constraint::Length(4)];
    if warning_lines > 0 {
        constraints.push(Constraint::Length(warning_lines));
    }
    constraints.push(Constraint::Min(10));
    constraints.push(Constraint::Length(8));
    constraints.push(Constraint::Length(1));

    let outer =
        Layout::default().direction(Direction::Vertical).constraints(constraints).split(area);

    draw_banner(frame, outer[0], state, scan);
    let mut next = 1;
    if warning_lines > 0 {
        draw_warning(frame, outer[next], state);
        next += 1;
    }
    let aps = scan.aps_sorted();
    draw_ap_table(frame, outer[next], state, &aps);
    next += 1;
    let selected = state.selected_ap(&aps).cloned();
    draw_stations(frame, outer[next], state, scan, selected.as_ref());
    next += 1;
    draw_status(frame, outer[next], state);
}

fn draw_warning(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let Some(msg) = state.warning.as_deref() else {
        return;
    };
    let title = Span::styled(
        " ⚠ heads up ",
        Style::default().fg(state.theme.warn).add_modifier(Modifier::BOLD),
    );
    let mut lines: Vec<Line<'_>> = Vec::new();
    for (i, ln) in msg.lines().enumerate() {
        let style = if i == 0 {
            Style::default().fg(state.theme.warn).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Rgb(220, 220, 230))
        };
        lines.push(Line::from(Span::styled(ln.to_string(), style)));
    }
    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(state.theme.warn))
            .title(title),
    );
    frame.render_widget(p, area);
}

fn draw_banner(frame: &mut Frame<'_>, area: Rect, state: &TuiState, scan: &ScanState) {
    let uptime = state.started_at.elapsed();
    let c = &scan.counters;
    let channel_label = state.current_channel.map(|n| format!("CH {n}  ")).unwrap_or_default();
    let sub = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "airodump  ",
                Style::default().fg(state.theme.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("• iface {}", state.iface_label),
                Style::default().fg(state.theme.muted),
            ),
            Span::raw("   "),
            Span::styled(
                format!(
                    "{channel_label}BCN {}  DATA {}  PRB {}  DEAU {}  BADFCS {}  •  {}s",
                    c.beacons,
                    c.data,
                    c.probes,
                    c.deauth,
                    c.bad_fcs,
                    uptime.as_secs()
                ),
                Style::default().fg(Color::Rgb(220, 220, 230)),
            ),
        ]),
        Line::from(Span::styled(
            "real-time 802.11 scanner  │  press [h] for help",
            Style::default().fg(state.theme.muted),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(state.theme.accent_dim))
            .title(Span::styled(
                " ▞▞▞ airscope suite ",
                Style::default().fg(state.theme.accent).add_modifier(Modifier::BOLD),
            )),
    );
    let _ = banner; // keep the import live if we want to swap the header later
    frame.render_widget(sub, area);
}

fn draw_ap_table(frame: &mut Frame<'_>, area: Rect, state: &mut TuiState, aps: &[AccessPoint]) {
    let header = Row::new(
        ["BSSID", "SIG", " bars ", "CH", "BCN", "#DATA", "ENC", "ESSID"].iter().map(|h| {
            Cell::from(*h)
                .style(Style::default().fg(state.theme.accent).add_modifier(Modifier::BOLD))
        }),
    )
    .style(Style::default().bg(state.theme.header_bg))
    .height(1);

    let rows: Vec<Row<'_>> = aps
        .iter()
        .map(|ap| {
            let sig_color = signal_color(ap.signal_dbm, &state.theme);
            Row::new(vec![
                Cell::from(ap.bssid.to_string()),
                Cell::from(format!("{:>4} dBm", ap.signal_dbm))
                    .style(Style::default().fg(sig_color)),
                Cell::from(signal_bar(ap.signal_dbm)).style(Style::default().fg(sig_color)),
                Cell::from(format!("{}", ap.channel)),
                Cell::from(ap.beacons.to_string()),
                Cell::from(ap.data_frames.to_string()),
                Cell::from(ap.encryption.family()),
                Cell::from(ap.label()),
            ])
            .height(1)
        })
        .collect();

    let t = Table::new(
        rows,
        [
            Constraint::Length(17), // BSSID
            Constraint::Length(9),  // dBm
            Constraint::Length(7),  // bars
            Constraint::Length(4),  // CH
            Constraint::Length(6),  // BCN
            Constraint::Length(7),  // DATA
            Constraint::Length(6),  // ENC
            Constraint::Min(10),    // ESSID
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(state.theme.accent_dim))
            .title(Span::styled(
                format!(" access points ({}) ", aps.len()),
                Style::default().fg(state.theme.accent),
            )),
    )
    .row_highlight_style(Style::default().bg(Color::Rgb(35, 42, 60)).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");

    frame.render_stateful_widget(t, area, &mut state.table);

    // Clamp selection to the new row count.
    if aps.is_empty() {
        state.table.select(None);
    } else if let Some(i) = state.table.selected() {
        if i >= aps.len() {
            state.table.select(Some(aps.len() - 1));
        }
    }
}

fn draw_stations(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &TuiState,
    scan: &ScanState,
    selected: Option<&AccessPoint>,
) {
    let header = Row::new(["STATION", "SIG", "FRAMES", "BSSID", "PROBES"].iter().map(|h| {
        Cell::from(*h).style(Style::default().fg(state.theme.accent).add_modifier(Modifier::BOLD))
    }))
    .style(Style::default().bg(state.theme.header_bg));

    let stations: Vec<Station> = scan
        .stations_sorted()
        .into_iter()
        .filter(|s| {
            !state.follow_selected
                || selected.map(|ap| s.bssid.map_or(true, |b| b == ap.bssid)).unwrap_or(true)
        })
        .take(8)
        .collect();

    let rows: Vec<Row<'_>> = stations
        .iter()
        .map(|s| {
            Row::new(vec![
                Cell::from(s.mac.to_string()),
                Cell::from(format!("{:>4} dBm", s.signal_dbm))
                    .style(Style::default().fg(signal_color(s.signal_dbm, &state.theme))),
                Cell::from(s.frames.to_string()),
                Cell::from(s.bssid.map(|b| b.to_string()).unwrap_or_else(|| "(none)".into())),
                Cell::from(s.probes.join(",")),
            ])
        })
        .collect();

    let title = if state.follow_selected {
        match selected {
            Some(ap) => format!(" stations for {} ", ap.label()),
            None => " stations ".into(),
        }
    } else {
        " stations (all) ".into()
    };

    let t = Table::new(
        rows,
        [
            Constraint::Length(17),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(17),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(state.theme.accent_dim))
            .title(Span::styled(title, Style::default().fg(state.theme.accent))),
    );
    frame.render_widget(t, area);
}

fn draw_status(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let hints: &[(&str, &str)] = &[
        ("↑/↓", "select AP"),
        ("f", if state.follow_selected { "show all stations" } else { "follow selected" }),
        ("q", "quit"),
    ];
    frame.render_widget(status_bar(hints, &state.theme), area);
}
