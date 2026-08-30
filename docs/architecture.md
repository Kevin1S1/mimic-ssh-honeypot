# Architecture

MIMIC is split into five strictly isolated layers. Only the network layer is
allowed to perform real I/O; everything below it operates entirely on in-memory
state.

```
┌──────────────────────────────────────────┐
│  1. Network Layer (TCP/SSH)              │  tokio TCP listener, accept-time
│     src/network/                         │  rate limiting, russh handshake
├──────────────────────────────────────────┤
│  2. SSH Protocol Engine                  │  KEX, auth capture, PTY / exec /
│     src/network/ssh.rs                   │  SCP / SFTP channel routing
├──────────────────────────────────────────┤
│  3. Shell Emulator (State Machine)       │  Line editing, pipes, env vars,
│     src/shell/                           │  $PS1, $?, $$, quoting, exit
├──────────────────────────────────────────┤
│  4. Virtual Filesystem (VFS)             │  In-memory inode tree, path
│     src/vfs/                             │  resolution, symlinks, /proc
├──────────────────────────────────────────┤
│  5. Command Registry                     │  ~100 emulated commands — each is
│     src/commands/                        │  a pure Rust function, no OS calls
└──────────────────────────────────────────┘
         ║                      ║
    ┌────╨────┐            ┌────╨────┐
    │ Logging │            │ Config  │
    │  (JSON) │            │ (TOML)  │
    └─────────┘            └─────────┘
```

## Security invariant

The emulation layers (3–5) have **zero access to the real OS**. This is enforced
by module visibility: only `src/network/` imports `std::fs` and `std::process`,
and only for permitted operations (persisting host keys, writing quarantined
uploads). The virtual filesystem is an entirely separate in-memory data
structure. The `tests/escape_vectors.rs` test fails the build if a forbidden API
leaks into the emulation layers.

The full threat model and attack-surface matrix live in [SECURITY.md](../SECURITY.md).

## Connection limiting

Limits are enforced at TCP **accept time** — before the SSH handshake — so a
connection flood never allocates crypto state. Two caps are configurable: a
global concurrent session cap (`max_sessions`) and a per-source-IP cap
(`per_ip_connections`). The shipped 32-session limit is simultaneous, not a daily
traffic quota, and is paired with the deployment's 1 GiB memory ceiling; raise
both together if a larger host needs more concurrency. Rejected connections are
logged as `connection_rejected` events.

## Host key persistence

An Ed25519 and an RSA host key are generated on first run and written to
`host_key_dir`. Subsequent starts load the same keys, so the server fingerprint
never changes — a rotating fingerprint is a classic honeypot tell.

## Project structure

```
mimic-ssh-honeypot/
├── src/
│   ├── main.rs              Entry point, config loading
│   ├── config.rs            TOML config parsing + validation
│   ├── lib.rs               Public crate root
│   ├── clock.rs             Fake boot time — the source of every timestamp
│   ├── persona.rs           Identity of the emulated box (hostname, kernel, …)
│   ├── network/
│   │   ├── mod.rs           TCP listener, accept loop, rate limiting
│   │   ├── ssh.rs           SSH protocol engine (russh), channel routing
│   │   ├── limiter.rs       Connection registry (global + per-IP caps, RAII guards)
│   │   ├── scp.rs           SCP sink — upload capture protocol
│   │   ├── sftp.rs          SFTP subsystem (v3) — upload capture & VFS operations
│   │   └── hostkey.rs       Persistent Ed25519 + RSA host keys
│   ├── shell/
│   │   ├── mod.rs           Shell state machine, expansion, dispatch, history
│   │   ├── line.rs          Readline-style line editor (cursor, history, Ctrl-R)
│   │   ├── complete.rs      Tab completion (command names + VFS paths)
│   │   ├── arith.rs         Integer arithmetic for $((…))
│   │   ├── parser.rs        Tokenizer (quoting, separators, pipes, redirects)
│   │   └── env.rs           Environment variables, $PS1
│   ├── vfs/
│   │   ├── mod.rs           Virtual filesystem tree (arena-based)
│   │   ├── nodes.rs         File / directory / symlink node types
│   │   └── snapshot.rs      Debian 12 filesystem snapshot
│   ├── commands/
│   │   ├── mod.rs           Command registry and dispatcher
│   │   ├── fs.rs            ls, cat, cd, pwd, touch, rm, mkdir, cp, mv, chmod
│   │   ├── system.rs        uname, whoami, id, ps, top, kill, df, history, recon
│   │   ├── text.rs          sed, awk, cut, tr, sort, base64, md5sum, vi, nano
│   │   ├── net.rs           wget, curl, ping, netstat, ss, ip, nc
│   │   ├── admin.rs         passwd, useradd, systemctl, service, getent
│   │   └── pkg.rs           apt, apt-get, dpkg stubs
│   └── logging/
│       ├── mod.rs           JSON logging initialisation (tracing)
│       └── event.rs         Typed forensic event helpers
├── tests/
│   ├── escape_vectors.rs    Asserts emulation layers contain no real-OS I/O
│   └── output_truncation.rs Verifies the per-command output cap holds under load
├── deploy/
│   ├── mimic.toml           Example / reference configuration
│   ├── mimic.service        Systemd unit (honeypot service)
│   ├── mimic-reset.service  Systemd unit (daily reset one-shot)
│   ├── mimic-reset.timer    Systemd timer (fires the daily reset)
│   └── daily-reset.sh       Reset script (wipe + restart with random jitter)
├── Dockerfile               Multi-stage: rust:1.88 → distroless/cc-debian12:nonroot
└── docker-compose.yml       Production-ready compose stack
```
