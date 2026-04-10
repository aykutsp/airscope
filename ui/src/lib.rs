//! TUI primitives shared by every Airscope binary.
//!
//! Kept deliberately small: a colour palette, a status bar, a signal
//! meter, and a terminal guard. Anything bigger lives inside the binary
//! that uses it, so the shared surface stays cheap to change.

#![deny(rust_2018_idioms)]

use std::io::{self, Stdout};

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};

/// A single palette used across the suite so every binary looks like it
/// belongs to the same tool. Pick something that stays legible on both
/// dark and light terminals.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub accent: Color,
    pub accent_dim: Color,
    pub good: Color,
    pub bad: Color,
    pub warn: Color,
    pub muted: Color,
    pub panel_bg: Color,
    pub header_bg: Color,
}

impl Theme {
    pub const DARK: Self = Theme {
        accent: Color::Rgb(120, 220, 232),
        accent_dim: Color::Rgb(80, 160, 172),
        good: Color::Rgb(140, 210, 140),
        bad: Color::Rgb(230, 120, 120),
        warn: Color::Rgb(240, 200, 120),
        muted: Color::Rgb(120, 120, 135),
        panel_bg: Color::Rgb(18, 20, 28),
        header_bg: Color::Rgb(30, 32, 44),
    };
}

/// Colour for a signal strength value, matched to how airodump-ng
/// colour-codes its `PWR` column.
pub fn signal_color(dbm: i16, theme: &Theme) -> Color {
    match dbm {
        d if d >= -50 => theme.good,
        d if d >= -65 => Color::Rgb(200, 220, 140),
        d if d >= -75 => theme.warn,
        _ => theme.bad,
    }
}

/// Build a compact 5-cell signal bar like `▂▄▆█▁`.
pub fn signal_bar(dbm: i16) -> String {
    let strength = ((dbm + 100).clamp(0, 70) as f32 / 70.0 * 5.0) as usize;
    let glyphs = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];
    let mut out = String::with_capacity(5);
    for i in 0..5 {
        let h = if i < strength { 7 } else { 0 };
        out.push_str(glyphs[h]);
    }
    out
}

/// A centered banner built from a few large glyphs. Used by every tool's
/// splash and by the unified launcher.
pub fn banner<'a>(tool: &'a str, tagline: &'a str, theme: &Theme) -> Paragraph<'a> {
    Paragraph::new(vec![
        Line::from(vec![
            Span::styled("▞▞▞  ", Style::default().fg(theme.accent_dim)),
            Span::styled(tool, Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled("  ▞▞▞", Style::default().fg(theme.accent_dim)),
        ]),
        Line::from(Span::styled(tagline, Style::default().fg(theme.muted))),
    ])
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(theme.accent_dim)),
    )
}

/// The one-line help bar rendered at the bottom of every screen.
pub fn status_bar<'a>(hints: &'a [(&'a str, &'a str)], theme: &Theme) -> Paragraph<'a> {
    let mut spans: Vec<Span<'a>> = Vec::with_capacity(hints.len() * 3);
    for (i, (key, label)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  │  ", Style::default().fg(theme.muted)));
        }
        spans.push(Span::styled(
            format!("[{}]", key),
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(*label, Style::default().fg(Color::Rgb(220, 220, 230))));
    }
    Paragraph::new(Line::from(spans))
        .alignment(Alignment::Left)
        .style(Style::default().bg(theme.header_bg))
}

/// Split a rect into [body, status line(1)].
pub fn body_with_status(area: Rect) -> (Rect, Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);
    (chunks[0], chunks[1])
}

// ---------- terminal guard --------------------------------------------------

/// RAII-style holder for an initialised terminal. Dropping it restores
/// the cooked terminal state even if the caller panics.
pub struct TerminalGuard {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture);
        let _ = self.terminal.show_cursor();
    }
}
