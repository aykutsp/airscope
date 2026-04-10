# Architecture notes

Rough layout of what lives where, written down before it all slipped out
of my head.

## Layout

```
airscope/
├── core/       shared types: MAC, Channel, Encryption, errors, tiny OUI table
├── wifi/       802.11 parser, radiotap decoder, frame builders, pcap wrapper
├── ui/         shared ratatui widgets (theme, banner, signal bar, status bar)
├── airmon/     monitor-mode toggler (Linux: wraps `ip`/`iw`)
├── airodump/   real-time scanner TUI
├── aireplay/   frame crafter + injector
├── airbase/    beacon / rogue AP tool
├── airview/    offline pcap browser TUI
├── airscope/   unified launcher TUI
├── assets/     logos, README screenshots
├── docs/       design notes (this folder)
└── samples/    sample pcaps for tests and demos
```

`core` and `wifi` are libraries. Everything else is a binary crate.

## Data flow (scanner case)

```
 ┌─────────────────┐     ┌─────────────┐
 │ monitor radio   │────▶│ LiveCapture │
 └─────────────────┘     └──────┬──────┘
                                │  CapturedPacket { ts, data }
                                ▼
                         ┌──────────────┐
                         │ FrameSource  │   trait, swappable
                         └──────┬───────┘
                                │
         radiotap header ──────▶│       Dot11Frame
                                ▼
                        ┌──────────────┐
                        │ ScanState    │   HashMap<MacAddr, AccessPoint>
                        └──────┬───────┘     HashMap<MacAddr, Station>
                               │
                               ▼
                        ┌──────────────┐
                        │ ratatui TUI  │
                        └──────────────┘
```

The `FrameSource` trait is deliberately tiny so the replay backend (for
pcap files) is a drop-in replacement for the live one. That's what lets
the scanner be demoed on a laptop with no Wi-Fi card.

## Why a hand-rolled 802.11 parser

There are crates for this on crates.io, but most of them either pull in
`nom` (fine, but a heavy transitive dep for what we need) or only decode
a subset that doesn't include what airodump cares about. Writing the
parser ourselves keeps `wifi` tight and means every byte on the wire
passes through code we control — which matters when you want to reason
about security claims.

## Why the `live` feature is opt-in

libpcap-sys (and the Windows `wpcap` import library) are not always
available in development environments. Keeping live capture behind a
Cargo feature means:

* `cargo build` / `cargo test` work on any machine that has rustc.
* CI runs without an Npcap SDK installed.
* `cargo build --features live` pulls the backend in for real work.

Tools that need live capture (`airmon`, `aireplay`, `airbase`, `airodump`
live mode) still compile without the feature — they return `Unsupported`
at runtime. `airview` and the pcap replay path don't touch libpcap at
all, so they work everywhere out of the box.
