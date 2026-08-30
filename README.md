# MIMIC — SSH Honeypot

[![CI](https://github.com/Kevin1S1/mimic-ssh-honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/Kevin1S1/mimic-ssh-honeypot/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange)](https://www.rust-lang.org/)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success)](docs/architecture.md#security-invariant)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)

A medium-to-high interaction SSH honeypot written in Rust. MIMIC presents
attackers with a convincing Debian 12 shell — realistic prompt, MOTD, filesystem,
and ~100 emulated commands — while the entire session runs as a **pure in-memory
state machine**. No shell process is ever spawned, no real filesystem is ever
touched, and the Rust compiler statically enforces this through
`#![forbid(unsafe_code)]` and strict module-visibility boundaries.

Every attacker action — authentication attempts, commands, `wget`/`curl`
downloads, and SCP/SFTP uploads — is captured as a structured JSON event, ready
for SIEM ingestion or offline analysis.

### Interactive Shell & Forensic Event Stream
https://github.com/user-attachments/assets/d03d3be6-f769-4540-91d0-ec59b2556179

### SCP / SFTP File Upload & Quarantine
https://github.com/user-attachments/assets/9692197c-bdef-4169-b2fc-3fa849247016

## Why MIMIC?

Most SSH honeypots either wrap a real shell (introducing real execution risk) or
present such a thin emulation that automated scanners identify them immediately.
MIMIC takes a different approach:

- **No execution surface.** The emulation layers have zero access to
  `std::process` or real `std::fs`, enforced at the Rust module level and
  verified by a test that fails the build. There is no code path that can run a
  real OS command, regardless of what an attacker types.
- **Compiler-enforced memory safety.** `#![forbid(unsafe_code)]` project-wide.
- **OpenSSH-grade realism.** Banner, KEX order, cipher/MAC suite, host key types,
  coreutils error messages, `/proc` content and the `Last login` line are all
  modelled on Debian 12 OpenSSH 9.2 — the exact details honeypot-detection
  scanners probe.
- **A shell that feels real.** Full readline-style editing: cursor movement,
  history, `Ctrl-R` reverse search, kill/yank keys, Tab completion of commands
  and paths, `Ctrl-D` logout. A shell that can't do these is an easy tell.
- **Stable host key fingerprint** and randomised response jitter — two more
  passive honeypot signals, avoided.
- **Structured forensic logging.** One JSON line per event on stdout, optionally
  mirrored to daily-rotated files. Pipe into `jq`, Splunk, or Elastic.
- **Minimal footprint.** Single Rust binary, <50 MB RAM, distroless Docker image
  <20 MB, `cap_drop: ALL`, read-only root filesystem.

## Quick start

```bash
docker compose up -d      # host port 22 → container 2222
docker compose logs -f    # stream forensic JSON events
```

Host keys and captured uploads persist in the `/data` volume. Everything runs
with safe defaults; see [Configuration](docs/configuration.md) to tune limits,
authentication behaviour and logging, and [Deployment](docs/deployment.md) for
source builds and systemd.

> If something is already listening on port 22:
> `sudo systemctl stop ssh && sudo systemctl disable ssh`

## How it works

Five strictly isolated layers. Only the network layer performs real I/O;
everything below it operates entirely on in-memory state.

```
 1. Network Layer         src/network/        tokio listener, accept-time rate limiting
 2. SSH Protocol Engine   src/network/ssh.rs  KEX, auth capture, PTY/exec/SCP/SFTP routing
 ──────────────────────────────────────────── real I/O stops here ──────────────
 3. Shell Emulator        src/shell/          line editing, pipes, env vars, quoting
 4. Virtual Filesystem    src/vfs/            in-memory inode tree, symlinks, /proc
 5. Command Registry      src/commands/       ~100 commands, pure Rust, no OS calls
```

Full diagram, module map and the enforcement mechanism:
[Architecture](docs/architecture.md).

## Documentation

| Document | Contents |
|---|---|
| [Architecture](docs/architecture.md) | Layer model, security invariant, connection limiting, project structure |
| [Emulated Environment](docs/emulation.md) | Filesystem snapshot, full command list, session behaviour, where the emulation deliberately stops |
| [Configuration](docs/configuration.md) | Full `mimic.toml` reference and authentication modes |
| [Logging & SIEM](docs/logging.md) | Event catalogue, `jq` triage recipes, Splunk and Elastic/ECS ingestion |
| [Deployment](docs/deployment.md) | Docker, source builds, systemd, daily reset |
| [SECURITY.md](SECURITY.md) | Threat model, attack-surface matrix, vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Module-boundary rule, `// ponytail:` markers, local checks |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Contributing

Pull requests are welcome. Before submitting, run the same checks CI does:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the two conventions that are
load-bearing here: the build-enforced module boundary, and the `// ponytail:`
marker for deliberate emulation shortcuts.

## Disclaimer

> This software is provided **"as is"**, without warranty of any kind, express or
> implied. The authors and contributors are not responsible for any damage, data
> loss, security incidents, or legal consequences resulting from the use, misuse,
> or inability to use this software.

MIMIC is a security research tool. Deploying it carries legal and operational
responsibilities that rest entirely with the operator:

1. **Legal compliance** — ensure your deployment complies with all applicable
   local, national, and international laws, including data protection
   legislation (e.g. GDPR), wiretapping/monitoring statutes, and computer crime
   laws.
2. **Data handling** — honeypots collect third-party data (IP addresses,
   credentials, uploaded files). You are responsible for lawful handling,
   appropriate retention policies, and any breach notification obligations.
3. **Network isolation** — deploy in a dedicated, isolated environment.
   Misconfiguration can expose adjacent infrastructure. The authors assume no
   liability if the honeypot is used as a pivot point.
4. **Prohibited uses** — this tool must not be used for unauthorised
   surveillance, entrapment, or any form of offensive cyber operations.
5. **No security guarantees** — MIMIC is designed with defence-in-depth
   principles, but no software is immune to unknown vulnerabilities. Layer
   additional controls (firewalls, VLANs, monitoring) around any production
   deployment.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
