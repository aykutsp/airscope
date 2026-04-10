# Changelog

All notable changes to this project will live here. Versions follow
[SemVer](https://semver.org/) and entries are grouped the way
[Keep a Changelog](https://keepachangelog.com/) suggests.

## [0.2.0] - 2026-04-10

This is the first version of the project that anyone other than me
would recognise. The previous `0.1.0` was a service-health monitor
that I built to learn ratatui; everything in that tree has been
replaced.

### Added

- **airmon** — monitor-mode manager. Lists interfaces, flips a card
  into monitor mode, restores it afterwards. Linux shells out to
  `ip link` and `iw`.
- **airodump** — real-time 802.11 scanner with a ratatui TUI, a
  headless `--no-tui` mode, `--format table|json` output, `--write`
  pcap recording, and a `--read` replay path that works on any
  platform (no radio required).
- **aireplay** — frame builder + injector. Crafts deauth / probe
  frames, can inspect a hex-encoded frame and print the decoded
  fields, and can transmit on a monitor-mode interface.
- **airbase** — beacon / soft-AP broadcaster. Advertises one or
  many SSIDs at the standard beacon interval, optionally with the
  Privacy bit set.
- **airview** — offline pcap browser TUI with an 802.11-aware
  decoder and a hex-dump detail pane.
- **airscope** — unified launcher TUI that lists the tools, shows
  a short description and example invocation, and spawns the
  selected binary.
- **`core`** crate — shared types (`MacAddr`, `Channel`, `Encryption`,
  `AccessPoint`, `Station`, `FrameKind`), error type, small built-in
  OUI table.
- **`wifi`** crate — radiotap decoder, 802.11 frame parser, RSN/WPA
  IE decoder, frame builders (`build_beacon`, `build_deauth`,
  `build_probe_request`, `wrap_radiotap`), pcap file reader / writer,
  and an optional live capture backend behind the `live` feature.
- **`ui`** crate — shared ratatui widgets: colour theme, banner,
  signal meter, status bar, RAII terminal guard.
- **`samples/demo-01.pcap`** + an example that regenerates it.
- **`docs/ARCHITECTURE.md`**, **`docs/SECURITY.md`**, **`docs/TODO.md`**.
- **GitHub Actions CI** — cargo fmt + test on Linux, macOS, and
  Windows, plus a Linux job that builds the `live` feature with
  `libpcap-dev` installed.

### Design notes

- The `live` feature is opt-in. `cargo build` / `cargo test` work
  on any machine that has rustc and nothing else; enabling live
  capture adds a dependency on libpcap (Linux) or Npcap (Windows).
- The 802.11 parser is hand-rolled. No `nom`, no external 802.11
  crate. Every byte that comes off the wire passes through code
  I control, which keeps the attack surface small and makes the
  unit tests a lot easier to reason about.
- All six tools are independent binaries. The launcher is the
  quality-of-life layer on top of them, not the thing holding
  the suite together.

### Removed

- The previous `0.1.0` service-health monitor. Its crates
  (`airscope-collector`, `airscope-telemetry`, `airscope-settings`,
  `airscope-ai`) have been deleted along with the `airscope-cli`
  binary. The repository history still has them if you need a
  reference.

## [0.1.0] - 2026-04-10

First tagged version. Service-health monitor with a ratatui
dashboard. Superseded by 0.2.0 (see above).
