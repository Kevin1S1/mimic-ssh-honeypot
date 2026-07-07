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
- New emulated commands: `sudo` (transient elevation), `su` (persistent
  identity switch), `nproc`/`lscpu` (matching the existing fake `/proc/cpuinfo`),
  `tar` (create writes a placeholder archive; extract/list on a fake
  0-byte/garbage "download" reports the same corrupt-archive errors a real
  host would), and `pkill` (tab-completion already offered it; it previously
  fell through to "command not found"). `grep` and `find` — previously
  documented as "(stub)" in the README but not actually wired into the
  command dispatch table at all — now do real (if simplified) substring
  search and path traversal.

### Fixed
- `dpkg`/`apt` listed `sudo` as installed and `id` reported `sudo` group
  membership, but running `sudo` itself returned "command not found" — an
  inconsistency an attacker could notice. `sudo` is now implemented.

### Fixed
- `pty-req`, `env`, `window-change`, subsystem, and agent-forwarding channel
  requests were left unanswered (russh's default `Handler` impl neither
  succeeds nor fails them), unlike a real sshd which always replies. Most
  interactive `ssh` clients send `pty-req` before `shell` and tolerate the
  missing reply, but it's a cheap, passive fingerprinting signal for anything
  that checks it. Now replied to explicitly: `pty-req`/`window-change` always
  succeed; `env` succeeds only for `LANG`/`LC_*` (matching Debian's default
  `AcceptEnv`); subsystem and agent-forwarding requests fail cleanly, since
  neither is emulated.

### Security
- Bounded per-session real-disk quarantine writes (`max_upload_bytes` × 32)
  so a flood of many distinct SCP-uploaded files can no longer grow the
  quarantine store without limit for the duration of a session; the
  in-memory VFS mirror (already bounded) is unaffected.
- Host keys are now created with `0600` permissions atomically (via
  `OpenOptions` at file-creation time) instead of being chmod'd after a
  world/group-readable `std::fs::write`, closing a brief window where a
  newly generated private key was readable by other local users.
- Quarantined SCP uploads are now created `0600` atomically at file-creation
  time (same `OpenOptions` approach as host keys) instead of being chmod'd
  after a world/group-readable write, removing the brief window where a
  captured sample was readable by other local users. The `create_new` write
  also closes the previous exists()-then-write race between concurrent
  sessions storing the same content-addressed payload.
- `cat` and `grep` now enforce Unix read permissions (owner/group/other bits,
  root bypass) against the emulated VFS, matching real Debian instead of
  ignoring file modes entirely. Previously any unprivileged session could
  `cat`/`grep` a `0640` root-owned file like `/etc/shadow` — both an
  unrealistic tell (real Debian denies it) and, combined with the fake
  password hash literally containing the word "honeypot", an instant
  self-identifying giveaway. The fake `/etc/shadow` hash is also now a
  random-looking, non-identifying string.
- `tar -c` no longer writes a plaintext `MIMIC-FAKE-TAR-ARCHIVE` marker into
  its placeholder archive; an attacker who created and then `cat`ed the
  archive would see the product name directly. It now writes non-identifying
  binary-looking bytes (a gzip magic header followed by random data), and
  extract/list behavior on it is unchanged (still reports a corrupt archive).

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
