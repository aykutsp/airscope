# contributing to airscope

Thanks for taking the time to look. This project is small and
opinionated, so a few things are worth knowing before you open a
pull request.

## philosophy

- **Every tool is its own binary.** The suite is held together by
  shared crates in `core/` and `wifi/`, not by a god-daemon. If your
  change couples two binaries through a side-channel, it's probably
  the wrong shape.
- **Safe by default.** We parse untrusted 802.11 frames, so the wifi
  crate carries `#![forbid(unsafe_code)]`. Anything that needs raw
  pointers belongs in a separate, narrowly-scoped crate with a
  `# Safety` doc on every function.
- **Cross-platform doesn't mean LCD.** The default build works on
  every platform with no native deps. Platform-specific goodies
  (libpcap, `iw`, etc.) live behind Cargo features or `cfg(...)`
  gates so the baseline stays portable.
- **No silent features.** If a feature is off, say so loudly and
  point at docs/INSTALL.md. If a runtime limitation bites the user,
  print a sticky warning, not a cryptic error code.

## local workflow

```bash
# the canonical "is everything healthy" check. same steps as CI.
cargo xtask ci

# run a single binary straight from source
cargo run -p airscope-airodump -- --list-interfaces

# build release artefacts for the host
cargo xtask dist

# refresh the checked-in sample pcap (after a builder change)
cargo xtask sample

# emit shell completions + man pages
cargo xtask completions --shell all
cargo xtask manpages

# benchmarks (criterion — HTML report under target/criterion/report/)
cargo bench -p airscope-wifi
```

Prefer the `cargo xtask` entry points to one-off shell scripts: they
are checked by the compiler and they work the same on Linux, macOS,
and Windows.

## coding rules we actually enforce

- `cargo fmt --all` is mandatory. CI fails otherwise.
- `cargo clippy --workspace --all-targets -- -D warnings` must pass.
  No `#[allow(clippy::...)]` without a one-line comment explaining
  why. No `#[allow(dead_code)]` on items that should just be
  deleted.
- `cargo test --workspace` must pass. If you add a new parser
  branch, add at least one happy-path test and one hostile-input
  test in `wifi/tests/fuzz_like.rs`.
- Public items should have a short doc comment that tells the
  caller *when* to reach for them, not just what the signature is.

## commit messages

One-line subject, lowercase, imperative. Body only when the why is
not obvious from the diff. Existing history is the style guide:

```
cross-platform polish: interface listing, fuzzy match, tui warning
docs: expand README with per-tool detail + aircrack-ng equivalents
fmt: rustfmt --all + drop duplicated doc comment
```

## licence

Contributions are accepted under the same terms as the project
([MIT](LICENSE)). By opening a pull request you confirm that you
wrote the change or otherwise have the right to submit it.

## conduct

Be kind. Assume good faith. If you spot something harmful, open a
private security advisory or email the maintainer instead of a
public issue. Full rules are in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
