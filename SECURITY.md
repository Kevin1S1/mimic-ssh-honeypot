# Security Policy and Architecture

MIMIC is a high-interaction SSH honeypot. Because it is designed to be intentionally attacked by malicious actors, its internal security model is its most critical feature. 

This document explains the security architecture that guarantees the safety of the host system, and outlines how to report any vulnerabilities.

## Security Architecture

MIMIC is built on a philosophy of **Strict Architectural Isolation**. By rebuilding the shell and filesystem from scratch in memory using a memory-safe language, the attack surface is effectively eliminated. An attacker isn't in a "jail" they can escape from; they are interacting with a simulated terminal environment.

### 1. Zero `unsafe` Code (Compiler Enforced)
The `mimic` binary is written in pure Rust. At the root of the project (`main.rs` and `lib.rs`), we use `#![forbid(unsafe_code)]`. This ensures the Rust compiler physically guarantees that there are no raw pointer dereferences, no unchecked memory access, and no buffer overflows anywhere in the codebase.

### 2. Physical Impossibility of Command Execution
When an attacker connects and types a command, they are not interacting with a real UNIX shell. The entire emulation layer (including `src/commands/`) never imports or uses `std::process::Command`. Because the capability to spawn a real process literally does not exist in the code that handles user input, it is impossible for an attacker to achieve Remote Code Execution (RCE) on the host.

### 3. The Virtual Filesystem (VFS) is a Pure-Memory Sandbox
All emulated commands (`ls`, `cat`, `rm`, `touch`, etc.) operate purely on the `Vfs` struct (`src/vfs/mod.rs`), which is a collection of `BTreeMap` and `Vec` objects in RAM.
- An attacker running `rm -rf /` will only delete the fake structs in their session's memory.
- There are no symlink traversal vulnerabilities to the real host because the real host's filesystem is completely decoupled from the VFS.

### 4. Fake Networking (`wget`, `curl`, `ping`)
When an attacker attempts to download a malicious payload via `wget` or `curl`, the honeypot fakes the download progress, generates a fake IP resolution, and drops a 0-byte placeholder into the in-memory VFS. It never actually opens a network socket to fetch the file, preventing the honeypot from being used in DDoS amplification attacks or as an open proxy.

### 5. Safe SCP Quarantining
The only time the honeypot touches the real disk based on attacker input is during an SCP upload. This is heavily sanitized:
- Path separators (`/`, `\`) and `..` are replaced with `_` in that order — separators first, so the dotless replacement can never let `..` re-form after the collapse.
- Control bytes (including NUL) are stripped to prevent log/VFS injection.
- Files are deduplicated and saved by their SHA-256 hash, so the attacker-supplied name never influences the stored path on disk.
- The upload size is strictly capped to prevent disk exhaustion.
- A per-session cap on cumulative real-disk quarantine writes (`max_upload_bytes` × 32) bounds disk growth from a flood of many distinct small files within one session — content-addressed dedup alone only bounds *repeated* payloads. Files past the cap still land safely in the in-memory VFS (which has its own independent bounds); only the real-disk copy is skipped.
Even if thousands of malware samples are uploaded, they are safely written as inert blobs into the `quarantine` folder and cannot overwrite system files.

### 6. Denial of Service (DoS) Resilience
MIMIC is protected against resource exhaustion attacks:
- **Connection limits** shed TCP floods before SSH crypto is even negotiated.
- **VFS limits** cap each filesystem tree to 2,000 nodes and 8 MiB of total file content, preventing RAM exhaustion from recursive `mkdir` loops or `cp`-amplifying an SCP upload (the quarantine store keeps the configured upload capture, so no forensic data is lost).
- **Environment and Process limits** strictly cap string lengths, variable counts, and prevent memory leaks.
- **Per-command output cap** (`MAX_COMMAND_OUTPUT_BYTES = 1 MiB`) truncates any single command's output at the dispatch layer, preventing memory amplification from `cat`/`find`/`grep` on large VFS content.
- **One active channel per connection** prevents SSH channel floods from bypassing the connection limiter and keeps connection-scoped shell/SCP state isolated. A new channel may open after the active one closes.
- **Idle timeouts** ensure dead connections are reaped aggressively.
- **Absolute session lifetime cap** (`max_session_secs`) wraps every session, so a client cannot hold resources indefinitely with periodic keep-alive traffic.
- **Line-editor bounds** cap the interactive input line (4096 bytes) and per-session command history (1000 entries), so the readline emulation cannot be driven into unbounded memory growth. One-shot `exec` commands are capped at the same 4096 bytes, so an oversized exec request cannot bloat the logs or parser.
- **Per-session crash isolation**: each connection runs in its own task; a panic in one session cannot take down the listener.

### 7. Daily Reset (Ephemeral State Hygiene)
A deployment-level daily reset mechanism restarts the honeypot and wipes accumulated quarantine data once per day. This serves multiple security purposes:
- **Limits quarantine disk growth** — captured SCP uploads are purged daily, bounding the on-disk footprint without operator intervention.
- **Clears in-memory state** — VFS modifications, shell histories, and per-session artifacts from previous attackers are discarded, preventing one attacker's leftovers from confusing or alerting the next.
- **Randomised timing** — the restart occurs at a random time within a configurable window (default: 0–3 hours), so the reset is not predictable from `uptime` output or connection-drop patterns. Fixed-schedule restarts are a honeypot fingerprinting vector.
- **Host keys are preserved** — Ed25519 and RSA keys survive the reset so the SSH fingerprint stays stable (a rotating fingerprint is a classic honeypot tell).

In Docker deployments, this is handled by a lightweight sidecar container. For systemd, a timer + one-shot service unit pair is provided. See the README's [Daily Reset](README.md#daily-reset) section for configuration.

---

## Threat Model

### Assets to protect
1. **The host / container** — must never execute attacker code or suffer real filesystem, network, or process compromise.
2. **Availability** — the listener must keep serving despite floods, malformed input, or a single misbehaving session.
3. **Captured intelligence** — credentials, commands, downloads, and quarantined uploads must be recorded faithfully and stored inertly.
4. **Deception** — the honeypot's nature should not be trivially detectable, or its intelligence value collapses.

### Trust boundary
Everything an attacker sends crosses a single trust boundary into the **network layer** (`src/network/`). Only that layer performs real I/O, and only for three tightly-scoped purposes: binding the listener, persisting host keys, and writing quarantined uploads. The **emulation layers** (`src/shell/`, `src/vfs/`, `src/commands/`) are downstream of the boundary and have **zero real-OS capability** — enforced at compile time by module structure and verified by `tests/escape_vectors.rs`, which fails the build if `std::process`, `std::fs`, `tokio::net`, `TcpStream`, and similar APIs appear in those modules.

```
   attacker  ──TCP/SSH──▶  Network layer (real I/O, the ONLY trusted boundary)
                                  │  in-memory state only, no OS access
                                  ▼
                     Shell ▶ VFS ▶ Commands   ← tests/escape_vectors.rs guards this
```

### Adversary model
- **Capabilities:** can open arbitrary TCP connections; speak SSH; attempt unlimited credentials; type arbitrary bytes (including malformed UTF-8, ANSI escapes, oversized lines, control floods); run any command string; upload arbitrary files via SCP.
- **Assumed goals:** RCE on the host, escaping the emulation, reading the real filesystem, using the host as a pivot/proxy/DDoS amplifier, exhausting host resources, or fingerprinting the honeypot.
- **Out of scope:** attacks on the host kernel/hypervisor, supply-chain compromise of the build toolchain, and a privileged operator misconfiguring the deployment (see the README Disclaimer).

### Attack surface → mitigation

| # | Attack | Vector | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | Remote code execution | Any typed command / exec request | No `std::process` reachable from emulation layers; build-enforced by `escape_vectors` test | None by design |
| T2 | Real filesystem read/write | `cat`, `rm`, `cp`, path traversal | All ops act on the in-memory `Vfs`; real FS decoupled | None by design |
| T3 | Memory-safety exploit | Malformed packets, parser edge cases | `#![forbid(unsafe_code)]`; Rust ownership; fuzz/robustness tests on the line editor | Unknown bug in a dependency |
| T4 | Pivot / DDoS amplification | `wget`/`curl`/`ping` to attacker host | Network commands are faked; no real socket opened | None by design |
| T5 | Disk exhaustion | SCP upload flood | Size-capped, SHA-256 content-addressed (dedup), filename sanitised (separators → `_`, then `..` → `_`, control bytes dropped), written `0600` non-exec, per-session quarantine disk-write cap (`max_upload_bytes` × 32) | Bounded per session; capped total across sessions only by the daily reset |
| T6 | RAM exhaustion | Recursive `mkdir`, `cp`-amplified uploads, huge env, long lines, history, large command output, SSH channel flood | Shipped defaults cap connections at 32 globally/4 per IP under a 1 GiB process ceiling; each connection permits one active channel; VFS ≤ 2k nodes and ≤ 8 MiB content bytes; uploads ≤ 8 MiB; bounded env, command line (4096, interactive and exec) and history (1000); per-command output capped at 1 MiB (`MAX_COMMAND_OUTPUT_BYTES`) in dispatch | Bounded per session and by deployment memory controls |
| T7 | Connection flood | TCP/SSH flood | Per-IP + global caps enforced at accept time, before crypto | Bounded by OS accept rate |
| T8 | Hung / zombie sessions | Slowloris, idle hold | Idle timeout + absolute `max_session_secs` cap | Bounded |
| T9 | Daemon crash via one session | Panic-inducing input | Each session isolated in its own task; listener survives | Bounded to one session |
| T10 | Honeypot fingerprinting | Banner/KEX/timing/`/proc`/missing-feature probes | Debian 12 OpenSSH-shaped handshake, persistent host key, readline emulation, response jitter, recon-command coverage, randomised daily restart (not at fixed time), explicit `SSH_MSG_CHANNEL_SUCCESS`/`FAILURE` replies to `pty-req`/`env`/`window-change`/subsystem/agent requests (matching real sshd instead of leaving them unanswered) | Ongoing — anti-detection is an evolving discipline; TCP/IP-stack fingerprinting (TTL, window sizes) is host-kernel territory, addressed by host `sysctl`/firewall tuning, not the application |
| T11 | Credential/payload leakage | Captured data at rest | Quarantine files inert (`0600`, no exec bit); logs are structured JSON the operator controls; quarantine purged daily | Operator data-handling duty |
| T12 | Accumulated state / forensic contamination | Previous attacker's files, history, or VFS artifacts visible to next attacker | Daily process restart clears all in-memory state; quarantine wiped on disk; random restart time prevents uptime-based detection | Bounded to one daily cycle |

### Security invariants (must always hold)
1. **No `unsafe`** anywhere (`#![forbid(unsafe_code)]`).
2. **No real process execution** reachable from attacker input.
3. **No real filesystem or network access** in `src/shell`, `src/vfs`, `src/commands` (test-enforced).
4. **Every attacker-controlled allocation is bounded** (connections, sessions, VFS nodes and content bytes, env, command length, history, upload size, per-command output).
5. **Real disk writes are confined** to host keys and the content-addressed, non-executable quarantine store.
6. **One session cannot affect another** or the listener (task isolation + RAII connection slots).
7. **Ephemeral state does not persist across daily resets** — quarantine data, VFS modifications, and session artifacts are wiped daily; only host keys survive to maintain fingerprint stability.

Any change that would weaken one of these invariants must be rejected — security takes priority over realism or features.

---

### Known / accepted dependency advisories

Security is a process: CI runs `cargo audit` and `cargo deny` on every push and weekly. One advisory is **explicitly accepted** because it cannot break the invariants above. It is documented here, in `deny.toml`, and in `.cargo/audit.toml`; any *new* advisory still fails CI.

| Advisory | Crate | Severity | Why accepted | Mitigation / fix |
|---|---|---|---|---|
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) | `rsa` | Medium (5.9) | Marvin timing sidechannel. Worst case is recovery of the SSH **host key**, which only allows *impersonating* the honeypot — harmless for a sacrificial decoy and **no escape** to the host. | **No fixed version exists** upstream. Accepted; revisit if a patched `rsa` ships. |

---

## Reporting a Vulnerability

While MIMIC is designed to be highly secure, no software is flawless. If you discover a vulnerability that allows an attacker to escape the emulation layer, crash the honeypot, or otherwise compromise the host system, please report it.

### How to Report
Please **do not** open a public issue for a security vulnerability. 

Instead, please report the issue privately using GitHub's built-in Private Vulnerability Reporting feature. This allows you to securely disclose vulnerabilities directly to the maintainer without any email addresses changing hands.

To report:
1. Go to the "Security" tab on the GitHub repository.
2. Click on "Report a vulnerability".
3. Fill out the secure form with the details of your finding.

### Scope
I am primarily interested in vulnerabilities that lead to:
- Remote Code Execution (RCE) on the host system or Docker container.
- Real filesystem access (reading or writing files outside the `quarantine` directory).
- Denial of Service (DoS) attacks that crash the honeypot or exhaust host resources despite the built-in limits (excluding the explicitly accepted advisory documented above).
- Information leaks about the real host system.

Please note that "vulnerabilities" affecting the *emulated* shell (e.g., a bug in the fake `ls` command that causes it to behave weirdly) are generally considered standard bugs unless they can be leveraged to escape the sandbox.
