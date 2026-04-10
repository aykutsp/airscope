# Changelog

All notable changes to this project will live here. Versions follow
[SemVer](https://semver.org/) and entries are grouped the way
[Keep a Changelog](https://keepachangelog.com/) suggests.

## [Unreleased]

### Added

- **Channel hopping for airodump** on Linux via `--hop` (`24ghz`,
  `5ghz`, `6ghz`, or a comma-separated channel list) plus
  `--hop-dwell-ms`. The hopper lives behind a `ChannelControl`
  trait so it can be unit-tested with a mock and cleanly degrades
  to a no-op on platforms without `iw`.
- **Sticky warning banner inside the airodump TUI** when the link
  layer comes back as Ethernet (Windows managed-mode trap). No more
  silently empty tables.
- **`cargo xtask`** for in-tree build automation. Subcommands:
  `sample`, `ci`, `dist`, `completions`, `manpages`. Same workflow
  as rustc / wasmtime / probe-rs. Exposed through a `cargo`
  alias so you can just type `cargo xtask ci`.
- **Shell completions** generated for bash, zsh, fish, PowerShell,
  and elvish via `clap_complete` (under `dist/completions/`).
- **Man pages** generated for every binary via `clap_mangen`
  (under `dist/man/`).
- **Criterion benchmarks** for the 802.11 parser: single-beacon,
  1k-frame mixed workload, and radiotap strip + parse. Throughput
  metrics survive a `cargo bench` run and a browsable HTML report
  lives under `target/criterion/report/`.
- **`deny.toml`** (cargo-deny) for license, advisory, and source
  gating. Only permissive licenses are allowed.
- **`cargo-audit` + `cargo-deny` workflow** that runs on every push
  and weekly on a cron schedule.
- **Dependabot** config grouping patch + minor bumps into one
  weekly PR, with a separate PR per major bump.
- **Cross-platform release workflow** that builds every Airscope
  binary for `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`,
  `aarch64-apple-darwin`, and `x86_64-pc-windows-msvc` on every
  `v*` tag and publishes a GitHub Release with archives + SHA-256.
- **MSRV guard job** in CI against Rust 1.85 so the pinned minimum
  doesn't regress.
- **Fuzz-lite integration test** (`wifi/tests/fuzz_like.rs`): 15k
  pseudorandom buffers through the frame + radiotap parsers with a
  hard "no panic" requirement, plus end-to-end builder↔parser
  round-trips and a pcap writer↔reader round-trip.
- **Community docs**: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, bug/feature issue templates, pull-request template.
- **`justfile`** aliasing every `cargo xtask` entry point so
  contributors who prefer `just` don't have to type `cargo xtask`.
- **`rust-toolchain.toml`** pinning stable + clippy + rustfmt so a
  fresh checkout installs exactly what CI uses.

### Changed

- **`#![forbid(unsafe_code)]`** on every library and binary root.
  The entire workspace is safe Rust end-to-end.
- **Clippy clean with `-D warnings`** across default and `--features
  live` builds. CI now runs clippy on both matrices.
- **`LiveCapture::next` → `next_packet`** to match `pcap::Capture`
  and stay clear of `Iterator::next`. Same rename across the
  `FrameSource` trait and every call site.
- **airodump CI step** now runs `cargo clippy -D warnings` on top of
  fmt + test, and a separate `bench-compile` job guarantees the
  criterion harness stays buildable.

### Fixed

- A handful of clippy lints (`needless_return`, `useless_format`,
  `needless_option_as_deref`, `unnecessary_cast`, `doc_overindented_list_items`,
  `should_implement_trait`, `redundant_guards`) that had accumulated
  in the first-pass implementation.

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
