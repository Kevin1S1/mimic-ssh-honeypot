## What / why

<!-- What changed, and why. Not just what — the diff already shows that. -->

## Checklist

- [ ] `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
      and `cargo test --workspace --all-targets` all pass locally.
- [ ] If this touches `src/shell/`, `src/vfs/`, or `src/commands/`: no new
      `std::process`, real `std::fs`, or socket I/O — `tests/escape_vectors.rs`
      enforces this and is included in the test run above.
- [ ] Docs updated in this PR, not after, if applicable: the matching page under
      `docs/` (behavior/config/commands), `SECURITY.md`
      (invariant/mitigation/bound), `deploy/mimic.toml` (config key
      added/renamed/removed).
- [ ] `CHANGELOG.md` entry added under `## [Unreleased]` (standard Keep a
      Changelog categories only; security-relevant fixes go under `Security`
      even if they'd also fit `Fixed`).
- [ ] No AI-attribution trailers in the commit messages or this description.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the reasoning behind these.
