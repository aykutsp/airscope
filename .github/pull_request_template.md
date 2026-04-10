<!--
Thanks for the PR. A few boxes below — tick the ones that apply
and delete the rest.
-->

## what

<!-- One paragraph: what does this change and why. -->

## how to test

<!-- Exact commands a reviewer can paste. -->

```bash
cargo xtask ci
```

## checklist

- [ ] `cargo xtask ci` passes locally (fmt + clippy + test).
- [ ] New public APIs have a short doc comment.
- [ ] New parser branches have happy-path and hostile-input tests.
- [ ] `docs/INSTALL.md`, `docs/ARCHITECTURE.md`, or the README have
      been updated if user-visible behaviour changed.
- [ ] I have not committed any vendored SDKs, live pcaps, or local
      `.cargo/config.local.toml` overrides.

## related

<!-- Link issues, discussions, or prior PRs if any. -->
