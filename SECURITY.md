# security policy

See also [`docs/SECURITY.md`](docs/SECURITY.md) for the project's
responsible-use note.

## supported versions

| version | status              |
|---------|---------------------|
| 0.2.x   | ✅ actively maintained |
| 0.1.x   | ❌ superseded        |

## reporting a vulnerability

**Please do not open a public GitHub issue for a security bug.**

Report vulnerabilities privately via:

1. **GitHub Security Advisories** — preferred; use
   [`Security → Report a vulnerability`](https://github.com/aykutsp/airscope/security/advisories/new)
   on the repository.
2. **Email** — `aykut.supurtulu@gmail.com`. PGP not required but
   welcomed; ask and a key will be published in this file.

What to include:

- A description of the bug and its impact.
- Steps to reproduce (a pcap, a crashing input, a specific frame
  shape, etc.).
- The airscope version and the output of `rustc --version`.
- Whether you have a suggested fix.

Expected response time: acknowledgement within **72 hours**, with
a follow-up assessment and ETA for a fix within **7 days**. Fixes
for high-severity issues are cut as a patch release as soon as
they are ready.

## threat model

airscope parses untrusted 802.11 frames and pcap files. The parsers
are the largest attack surface and are the most worth your attention
if you want to hunt for bugs.

In scope:

- Out-of-bounds reads / panics in `wifi::frame` or `wifi::radiotap`.
- Out-of-bounds reads / panics in `wifi::capture::PcapFileReader`.
- Integer overflows / denial-of-service vectors reachable from a
  crafted `.pcap` file.
- Command-injection surface in `airmon` / `airodump`'s channel hopper
  (they shell out to `iw`).
- Anything that could cause `--features live` builds to crash a
  privileged process.

Out of scope (won't be treated as vulnerabilities):

- Running the tools against third-party networks without authorisation
  — that's a *you* problem, not a *tool* problem.
- The absence of cracking / key-recovery code. This is a deliberate
  design decision, not a missing feature.
- Windows consumer-driver limitations: if your adapter is in managed
  mode, airodump will show the sticky warning and empty tables. That
  is not a bug.
- Third-party crates reaching end-of-life. We track those via
  `cargo-audit` and `cargo-deny` in CI.
