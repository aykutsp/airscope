//! `airscope` - the unified launcher.
//!
//! Not a wrapper that re-implements every tool; just a pretty picker.
//! It lets you browse the suite in one terminal, pick a tool, and the
//! launcher execs it with any extra arguments you type into the prompt.
//!
//! Rationale: each of airmon/airodump/aireplay/airbase/airview is its
//! own binary so you can pipe them, put them in scripts, and drop this
//! launcher without losing anything. The TUI is the quality-of-life
//! layer on top, not the thing holding the suite together.

#![forbid(unsafe_code)]

use std::{io, process::Command};

use airscope_ui::{banner, status_bar, TerminalGuard, Theme};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::*,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

/// Each entry lists the binary to spawn and a short description. The
/// order is the one we show on screen - deliberately mirroring the
/// aircrack-ng workflow (monitor -> scan -> replay -> fake AP -> view).
struct ToolEntry {
    name: &'static str,
    binary: &'static str,
    tagline: &'static str,
    description: &'static str,
    example: &'static str,
}

const TOOLS: &[ToolEntry] = &[
    ToolEntry {
        name: "airmon",
        binary: "airmon",
        tagline: "monitor-mode manager",
        description: "Flip a wireless interface into monitor mode and back, and inspect \
                      what the OS reports about it. Linux: wraps `ip link` and `iw`.",
        example: "airmon start wlan0 --channel 6",
    },
    ToolEntry {
        name: "airodump",
        binary: "airodump",
        tagline: "real-time 802.11 scanner",
        description: "Watch access points and clients appear as beacons come in, with \
                      live signal bars, BSSID, channel, encryption and station lists. \
                      Works on a live radio (needs monitor mode) or on a pcap replay.",
        example: "airodump -i wlan0mon",
    },
    ToolEntry {
        name: "aireplay",
        binary: "aireplay",
        tagline: "frame builder + injector",
        description: "Craft 802.11 management frames (deauth, probes, ...), dump them \
                      as hex, or inject them on a monitor-mode interface. Also parses \
                      a hex frame back into fields for inspection.",
        example: "aireplay deauth --bssid AA:BB:CC:DD:EE:FF --client ff:ff:ff:ff:ff:ff",
    },
    ToolEntry {
        name: "airbase",
        binary: "airbase",
        tagline: "beacon / soft AP generator",
        description: "Broadcast beacons for one or many SSIDs - think honeypot / fake \
                      AP. Can advertise open or 'privacy-bit' (WEP-like) networks on \
                      whatever channel you pick.",
        example: "airbase -i wlan0mon -s FreeWiFi -s CoffeeShop -c 6",
    },
    ToolEntry {
        name: "airview",
        binary: "airview",
        tagline: "offline pcap browser",
        description: "Open a .pcap file, browse every frame in a table, and hex-dump \
                      the selected one. 802.11-aware: radiotap is stripped, tagged \
                      IEs are decoded for management bodies.",
        example: "airview ./samples/sample.pcap",
    },
];

fn main() -> Result<()> {
    let mut guard = TerminalGuard::enter()?;
    let theme = Theme::DARK;
    let mut list = ListState::default();
    list.select(Some(0));

    let outcome = loop {
        guard.terminal.draw(|f| draw(f, &theme, &mut list))?;
        match read_key()? {
            KeyAction::Quit => break None,
            KeyAction::Up => {
                let i = list.selected().unwrap_or(0);
                list.select(Some(if i == 0 { TOOLS.len() - 1 } else { i - 1 }));
            }
            KeyAction::Down => {
                let i = list.selected().unwrap_or(0);
                list.select(Some((i + 1) % TOOLS.len()));
            }
            KeyAction::Launch => {
                let i = list.selected().unwrap_or(0);
                break Some(i);
            }
            KeyAction::None => {}
        }
    };

    // Leave the alternate screen BEFORE spawning the child so its own
    // TUI (if any) draws in the real terminal.
    drop(guard);

    if let Some(index) = outcome {
        let tool = &TOOLS[index];
        eprintln!("launching `{}` ...", tool.binary);
        let status = Command::new(tool.binary).status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => eprintln!("{} exited with {}", tool.binary, s),
            Err(e) => {
                eprintln!(
                    "could not spawn `{}`: {e}\n\
                     tip: either build the workspace first (`cargo build --release`) \
                     or make sure the binary is on PATH.",
                    tool.binary
                );
            }
        }
    }
    Ok(())
}

enum KeyAction {
    Quit,
    Up,
    Down,
    Launch,
    None,
}

fn read_key() -> io::Result<KeyAction> {
    if !event::poll(std::time::Duration::from_millis(200))? {
        return Ok(KeyAction::None);
    }
    match event::read()? {
        Event::Key(KeyEvent { code, kind: KeyEventKind::Press, .. }) => Ok(match code {
            KeyCode::Char('q') | KeyCode::Esc => KeyAction::Quit,
            KeyCode::Up | KeyCode::Char('k') => KeyAction::Up,
            KeyCode::Down | KeyCode::Char('j') => KeyAction::Down,
            KeyCode::Enter | KeyCode::Char(' ') => KeyAction::Launch,
            _ => KeyAction::None,
        }),
        _ => Ok(KeyAction::None),
    }
}

fn draw(f: &mut Frame<'_>, theme: &Theme, list: &mut ListState) {
    let area = f.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(10), Constraint::Length(1)])
        .split(area);

    f.render_widget(banner("AIRSCOPE", "a wireless suite, reimagined in rust", theme), outer[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(26), Constraint::Min(20)])
        .split(outer[1]);

    draw_menu(f, body[0], theme, list);
    draw_detail(f, body[1], theme, list);

    let hints: &[(&str, &str)] = &[("↑/↓", "navigate"), ("↵", "launch"), ("q", "quit")];
    f.render_widget(status_bar(hints, theme), outer[2]);
}

fn draw_menu(f: &mut Frame<'_>, area: Rect, theme: &Theme, list: &mut ListState) {
    let items: Vec<ListItem<'_>> = TOOLS
        .iter()
        .map(|t| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("  {:<9}", t.name),
                    Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(t.tagline, Style::default().fg(theme.muted)),
            ]))
        })
        .collect();

    let list_widget = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent_dim))
                .title(Span::styled(" tools ", Style::default().fg(theme.accent))),
        )
        .highlight_style(Style::default().bg(Color::Rgb(35, 42, 60)).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list_widget, area, list);
}

fn draw_detail(f: &mut Frame<'_>, area: Rect, theme: &Theme, list: &ListState) {
    let i = list.selected().unwrap_or(0);
    let tool = &TOOLS[i];
    let body = vec![
        Line::from(vec![
            Span::styled(tool.name, Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  — {}", tool.tagline), Style::default().fg(theme.muted)),
        ]),
        Line::from(""),
        Line::from(Span::raw(tool.description)),
        Line::from(""),
        Line::from(Span::styled("example:", Style::default().fg(theme.muted))),
        Line::from(Span::styled(format!("  $ {}", tool.example), Style::default().fg(theme.good))),
    ];

    let p = Paragraph::new(body)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent_dim))
                .title(Span::styled(" detail ", Style::default().fg(theme.accent))),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}
