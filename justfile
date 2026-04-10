# Aliases for common workflows. Install `just` from
# https://just.systems/ — otherwise run `cargo xtask <name>` instead.

_default:
    @just --list

# run the local equivalent of CI (fmt + clippy + tests)
ci:
    cargo xtask ci

# build release binaries for the host target
dist:
    cargo xtask dist

# regenerate samples/demo-01.pcap
sample:
    cargo xtask sample

# generate shell completions into dist/completions/
completions shell="all":
    cargo xtask completions --shell {{shell}}

# generate man pages into dist/man/
manpages:
    cargo xtask manpages

# run the criterion benchmark suite
bench:
    cargo bench -p airscope-wifi

# fix-up formatting
fmt:
    cargo fmt --all

# strict clippy across all targets
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# run all tests
test:
    cargo test --workspace

# tail the scanner over the checked-in sample pcap
demo:
    cargo run -p airscope-airodump -- --no-tui --read samples/demo-01.pcap --duration 1 --rate 100

# check for new security advisories + license drift
audit:
    cargo audit
    cargo deny check
