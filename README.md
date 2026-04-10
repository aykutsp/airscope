<h1 align="center">airscope</h1>

<p align="center">
  <em>a wireless suite, reimagined in rust</em>
</p>

<p align="center">
  <a href="https://github.com/aykutsp/airscope/actions"><img alt="ci" src="https://img.shields.io/github/actions/workflow/status/aykutsp/airscope/ci.yml?branch=master&style=flat-square&label=ci&logo=github"></a>
  <a href="https://www.rust-lang.org/"><img alt="rust" src="https://img.shields.io/badge/rust-1.75%2B-dea584?style=flat-square&logo=rust&logoColor=white"></a>
  <img alt="platforms" src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-555?style=flat-square">
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square"></a>
  <img alt="version" src="https://img.shields.io/badge/version-0.2.0-78dce8?style=flat-square">
  <img alt="status" src="https://img.shields.io/badge/status-alpha-f5c06f?style=flat-square">
</p>

---

**airscope** is a six-tool Rust workspace that covers the same surface
as the classic aircrack-ng suite — monitor-mode setup, scanning,
injection, soft AP, and offline packet inspection — with a modern
terminal UI, a hand-rolled 802.11 parser, and a clean cross-platform
story. Every tool is its own binary so you can script them
individually, or drive them from the unified `airscope` launcher when
you just want a pretty menu.

```
  ▞▞▞  airscope  ▞▞▞
  ─────────────────────────────────────────
   ▶  airmon      monitor-mode manager
      airodump    real-time 802.11 scanner
      aireplay    frame builder + injector
      airbase     beacon / soft AP generator
      airview     offline pcap browser
  ─────────────────────────────────────────
   [↑/↓] navigate   [↵] launch   [q] quit
```

---

## requirements

There are **two build modes** with two different requirements profiles.
Pick the one that matches what you want to do:

### default build — no radio, no SDK

Everything in the suite that doesn't touch a physical Wi-Fi card
works here: the 802.11 parser, frame builders, pcap file replay,
pcap writer, the TUI launcher, and `airview`. This is also what CI
uses.

| thing you need     | how to get it |
|--------------------|---------------|
| **Rust ≥ 1.75**    | install via [rustup.rs](https://rustup.rs) |
| **git**            | any recent version |
| a terminal with 256-colour + unicode | Windows Terminal / iTerm2 / Alacritty / any modern emulator |

That's it. `cargo build --release` will produce every binary with
zero extra dependencies, and `airodump --read samples/demo-01.pcap`
will run on any OS.

### live-capture build — reading packets off a real radio

The moment you want `airodump -i wlan0`, `aireplay` to actually
inject, or `airbase` to hit the air, you need a packet-capture
library for your OS. Rebuild with the `live` feature after
installing the right native package.

| platform           | native dep                                                | monitor mode?            |
|--------------------|-----------------------------------------------------------|--------------------------|
| **Linux**          | `libpcap-dev` (apt) / `libpcap-devel` (dnf) / `libpcap` (pacman) | ✅ supported drivers     |
| **macOS**          | `brew install libpcap`                                    | ⚠️ via Wireless Diagnostics |
| **Windows (MSVC)** | [Npcap runtime](https://npcap.com) + Npcap SDK            | ⚠️ driver-dependent     |
| **Windows (mingw)**| Npcap runtime + SDK + one rename trick (see below)        | ⚠️ driver-dependent     |

Then:

```bash
# linux
sudo apt install libpcap-dev
cargo build --release --features "\
  airscope-airodump/live \
  airscope-airmon/live \
  airscope-aireplay/live \
  airscope-airbase/live"
sudo ./target/release/airmon start wlan0 --channel 6
sudo ./target/release/airodump -i wlan0
```

```powershell
# windows (msvc)
# 1. install Npcap runtime from https://npcap.com
#    (tick "install in WinPcap API-compatible mode")
# 2. download the Npcap SDK zip and extract to C:\npcap-sdk
$env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"
cargo build --release --features "airscope-airodump/live airscope-aireplay/live airscope-airbase/live"
.\target\release\airodump.exe -i "Wi-Fi"
```

```bash
# windows (mingw / git-bash)
# same Npcap runtime install, then:
cp /c/npcap-sdk/Lib/x64/wpcap.lib /c/npcap-sdk/Lib/x64/libwpcap.a
# the committed .cargo/config.toml already points rustflags at
# C:/npcap-sdk/Lib/x64 — adjust if your SDK lives elsewhere
cargo build --release --features "airscope-airodump/live airscope-aireplay/live airscope-airbase/live"
./target/release/airodump.exe -i "Wi-Fi"
```

When the feature is not enabled, live-capture code paths return a
long, actionable error pointing at [`docs/INSTALL.md`](docs/INSTALL.md)
instead of a cryptic one — that's not a bug, it's how the default
build stays portable.

> Full step-by-step (capabilities instead of sudo on Linux, macOS
> Sniffer mode, Windows driver notes, troubleshooting) is in
> [`docs/INSTALL.md`](docs/INSTALL.md).

---

## quick start

```bash
# clone and build
git clone https://github.com/aykutsp/airscope.git
cd airscope
cargo build --release

# try it with the checked-in sample pcap - no radio required
./target/release/airodump --no-tui --read samples/demo-01.pcap --duration 1 --rate 100

# or the offline browser
./target/release/airview samples/demo-01.pcap

# or the launcher
./target/release/airscope

# find capture targets without touching the live backend
./target/release/airodump --list-interfaces
./target/release/airmon list --json
```

---

## the tools

| binary     | in one line                                              | needs radio? |
|------------|----------------------------------------------------------|--------------|
| `airmon`   | flip a wireless interface into monitor mode and back     | yes (Linux)  |
| `airodump` | real-time scanner — APs, stations, signal bars, ENC      | live *or* `.pcap` replay |
| `aireplay` | craft / inspect / inject 802.11 management frames        | only for injection |
| `airbase`  | broadcast beacons for one or many fake SSIDs             | only for transmission |
| `airview`  | offline pcap browser with an 802.11-aware decoder        | no |
| `airscope` | unified launcher TUI that spawns the tool you pick       | no |

---

## cross-platform matrix

| feature                        | Linux | macOS | Windows |
|--------------------------------|:-----:|:-----:|:-------:|
| Build with `cargo build`       |  ✅  |  ✅   |   ✅    |
| Pcap file replay (`airodump --read`) |  ✅  |  ✅   |   ✅    |
| Offline browser (`airview`)    |  ✅  |  ✅   |   ✅    |
| Frame crafting (`aireplay` dry run) |  ✅  |  ✅   |   ✅    |
| `airscope` launcher TUI        |  ✅  |  ✅   |   ✅    |
| Live capture (`--features live`) |  ✅  |  ⚠️   |   ⚠️    |
| Monitor mode toggle (`airmon start`) | ✅ |  ❌   |   ❌    |
| Frame injection (`aireplay`, `airbase`) | ✅ |  ❌  |   ⚠️   |

Legend — ✅ works out of the box · ⚠️ works with vendor-supplied capture
drivers (Npcap on Windows; monitor mode on macOS requires
`Wireless Diagnostics` / SDK cards) · ❌ not supported by the OS
kernel / driver stack.

The default build needs nothing beyond `rustc`. Live capture pulls in
`libpcap` (Linux), `Npcap` (Windows), or the stock BPF device (macOS)
behind the opt-in `live` Cargo feature, so the basic tree still
builds on a machine with no SDK installed.

---

## comparison with aircrack-ng

| airscope binary | closest aircrack-ng tool | what airscope does differently |
|-----------------|--------------------------|---------------------------------|
| `airmon`        | `airmon-ng`              | Same mental model, but a single static binary. No shell-script wrapper over `lsusb`; interface discovery goes through `pcap::Device::list` so it agrees with what the rest of the suite sees. |
| `airodump`      | `airodump-ng`            | Modern ratatui TUI with real signal bars and a station table that follows the highlighted AP. Offline pcap replay is a first-class mode, so you can demo, test, and teach the tool without a radio. Headless `--format json` pipes straight into jq / dashboards. `--write` round-trips to a standard libpcap file. |
| `aireplay`      | `aireplay-ng`            | Split into `deauth`, `probe`, and `inspect` subcommands. Dry-run by default — frames are printed as hex and only transmitted when you pass `--interface`, which makes the tool safe to use in CI and docs. `inspect` parses a hex frame back into decoded fields, which aireplay-ng does not. |
| `airbase`       | `airbase-ng`             | Pure honeypot-beacon generator with deterministic BSSIDs per SSID so the same `--ssid` list gives the same frames every run. Stops cleanly on Ctrl-C or `--duration`. |
| `airview`       | `tshark` / `wireshark` (for 802.11) | Ultra-lean offline pcap browser scoped to 802.11. Tagged IEs are decoded for management bodies; the detail pane is a real hex+ASCII dump. One binary, no Qt, no Lua. |
| `airscope`      | *(no equivalent)*        | Unified launcher TUI that lists every tool, shows a description and an example invocation, and spawns the binary when you press `Enter`. |
|                 | `aircrack-ng`            | **Not implemented.** airscope is a visibility + analysis suite, not a key recovery tool. WEP / WPA-PSK cracking lives outside this project on purpose — see [`docs/SECURITY.md`](docs/SECURITY.md). |

### what airscope brings on top of aircrack-ng

- **Memory-safe end to end.** The 802.11 parser is hand-rolled in safe
  Rust. No `strcpy`, no manual buffer walks, and every frame test runs
  under the standard `cargo test` sanitisers.
- **Pcap-first workflow.** Every tool can work on a `.pcap` file. You
  don't need a radio to learn the codebase, run the tests, or ship
  bug reports.
- **Deterministic frame builders.** `wifi::builder::build_*` is pure
  CPU code, so unit tests can build a beacon, round-trip it through
  the parser, and assert on SSID / encryption without any I/O.
- **Single-process TUI.** ratatui + crossterm mean the scanner and the
  launcher render the same on every platform, without ncurses
  quirks.
- **Feature-gated native deps.** libpcap / Npcap are *optional*. The
  default build is portable; the power-user build pulls in the live
  backend with one extra flag.
- **Designed for CI.** `--no-tui`, `--format json`, `--duration N`,
  `--read file.pcap` — every tool has a scriptable, terminal-free
  path so the whole suite runs as part of a test job.
- **`airview` replaces a minimal wireshark.** For the 802.11
  workflows covered by airscope, `airview` is enough on its own — no
  need to install a 200 MB GUI.

---

## at the parser level

There are a lot of 802.11 parsing crates on crates.io. I chose to
write one from scratch because:

1. I wanted the frame format to be readable inside this repository,
   not through five layers of macros in a dependency.
2. The hand-rolled code is ~500 lines of safe Rust. That's
   auditable in an afternoon.
3. Keeping it in-tree means `cargo test` exercises the parser, the
   builders, and the pcap layer together — the round-trip tests
   catch regressions nobody would notice in isolation.

What the parser understands today:

- Frame control, To-DS / From-DS, all four address fields, sequence
  and fragment numbers.
- Management subtypes: beacon, probe request, probe response, auth,
  deauth, (dis)association, action.
- Fixed prelude for beacons / probe responses (timestamp, beacon
  interval, capabilities).
- Tagged IEs: SSID (0), supported rates (1), DS parameter set (3),
  RSN (48), vendor-specific WPA1 (221).
- RSN / WPA cipher suites: CCMP, GCMP, TKIP, WEP.
- RSN AKMs: PSK, EAP, FT-PSK, FT-EAP, SAE, OWE.

What it doesn't do *yet* (see [`docs/TODO.md`](docs/TODO.md)):
HT/VHT/HE operation elements, full action-frame decoding, encrypted
payload handling. These are additive, not structural changes.

---

## layout

```
airscope/
├── core/       shared types: MAC, channel, encryption, errors, OUI
├── wifi/       802.11 parser, radiotap, frame builders, pcap wrapper
├── ui/         shared ratatui widgets (theme, banner, signal bar)
├── airmon/     monitor-mode manager binary
├── airodump/   scanner binary
├── aireplay/   crafter + injector binary
├── airbase/    beacon / rogue AP binary
├── airview/    offline pcap browser binary
├── airscope/   unified launcher binary
├── samples/    demo pcap + README
└── docs/       architecture notes, security note, TODO
```

The split is deliberately hand-shaped rather than nest-everything-in
`apps/crates/`: each tool is a first-class directory you can `cd`
into and grep. Shared code lives next to the binaries that use it,
not two levels deeper.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the data-flow
diagrams and the reasoning behind the `live` feature split.

---

## responsible use

airscope lets you passively observe 802.11 traffic, craft management
frames, and — on Linux with a supported card — transmit those frames
on a real radio. That last bit is what makes it a security tool, and
it's what makes it something you should think about before you run it.

Run it on networks you own, under engagements you're authorised to
perform, or in an RF-isolated lab. airscope does not contain any key
recovery code, dictionary attacks, or EAPOL replay tooling — it's a
visibility suite. The deauth builder exists because deauth is also
the test harness you use when validating your own AP's roaming
behaviour. Full note in [`docs/SECURITY.md`](docs/SECURITY.md).

---

## development

```bash
# tests (cpu-only, no native deps)
cargo test --workspace

# regenerate the sample pcap if you change the frame builders
cargo run -p airscope-wifi --example make_sample

# format
cargo fmt --all

# build with live capture on linux
sudo apt install libpcap-dev
cargo build --workspace --features "airscope-airodump/live airscope-airmon/live"
```

CI runs `cargo fmt --check`, `cargo check --all-targets`, and `cargo
test` on Linux, macOS, and Windows. A separate Linux job installs
`libpcap-dev` and compiles the `live` feature so regressions in the
native path get caught before a release.

---

## license

[MIT](LICENSE) © Aykut Supurtulu. Contributions welcome — open an
issue before a large PR so we can agree on direction first.
