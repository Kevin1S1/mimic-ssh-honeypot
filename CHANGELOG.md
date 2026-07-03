# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Daily automatic reset: wipes quarantine data and restarts the honeypot once
  per day at a random time within a configurable window (default 0–3 hours) so
  the restart is not predictable. Supported in Docker (sidecar container) and
  systemd (timer + oneshot service).
- `sensor_name` config key: an identifier included in every JSON log line so
  operators running multiple sensors can distinguish their streams (closes #3).

### Security
- Bounded per-session real-disk quarantine writes (`max_upload_bytes` × 32)
  so a flood of many distinct SCP-uploaded files can no longer grow the
  quarantine store without limit for the duration of a session; the
  in-memory VFS mirror (already bounded) is unaffected.

## [0.1.0] - 2026-07-02

Initial release.

### Added
- Escape-proof SSH honeypot emulating a Debian 12 server via a pure
  state-machine architecture — no `std::process`, no real filesystem access
  in the emulation layer, `#![forbid(unsafe_code)]` project-wide.
- ~30 emulated shell commands with readline-style line editing, history,
  MOTD, and `/proc` fakes.
- In-memory virtual filesystem bounded by node count (10k) and total
  content size (64 MiB).
- SCP upload support with configurable size cap (16 MiB default) and
  quarantine store for captured payloads.
- Structured JSON logging of sessions, credentials, and commands.
- Connection hardening: global and per-IP connection limits enforced
  before crypto, session and idle timeouts, bounded line/exec/output
  lengths.
- Docker deployment: distroless non-root runtime, read-only rootfs,
  dropped capabilities, resource limits.
- CI: clippy (`-D warnings`), full test suite, cargo-deny supply-chain
  audit with weekly scheduled run.

[Unreleased]: https://github.com/Kevin1S1/mimic-ssh-honeypot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Kevin1S1/mimic-ssh-honeypot/releases/tag/v0.1.0
