# Emulated Environment

What an attacker sees after login, and where the emulation deliberately stops.

## Filesystem

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

Home directories for non-root attackers are created automatically under
`/home/<username>`.

`/usr/bin` and `/usr/sbin` list 400 real Debian 12 binary names, sourced from
package filelists, matching `dpkg -l`. Most are listed for realism only. Running
a listed-but-not-emulated name exits 0 with no output — the same outcome a real
kernel gives an empty-but-executable file (`ENOEXEC` falls back to `/bin/sh`, and
an empty script does nothing). An unlisted name still gets `command not found`.

## Emulated commands

| Category | Commands |
|---|---|
| **Navigation** | `ls` (`-a`/`-A`/`-d`/`-l`/`-h`/`-1`), `cd` (`~`/`-`/`..`), `pwd` |
| **File ops** | `cat`, `touch`, `mkdir` (`-p`), `rm` (`-r`/`-f`), `rmdir`, `cp` (`-r`), `mv`, `chmod` (octal + symbolic), `chown`/`chgrp` (`-R`, root-only), `ln` (`-s`/`-f`), `tar` (`-c`/`-x`/`-t`/`-v`, dashless bundled flags) |
| **Text** | `echo` (`-n`/`-e`), `printf`, `grep` (`-i`/`-v`/`-n`/`-c`/`-r`/`-q`/`-l`/`-w`/`-o`/`-s`/`-h`/`-H`/`-e`, with `-E`/`-F`/`-G`/`-P` accepted; literal substring match), `find` (`-name`/`-type`, glob `-name`), `head`/`tail` (`-n`/`-c`/`-N`), `wc` (`-l`/`-w`/`-c`), `stat` (`-c FORMAT`/`-t`), `du` (`-s`/`-h`/`-a`/`-k`/`-m`/`--max-depth`) |
| **Text plumbing** | `sed` (`s///`, `d`, `p`, any delimiter, literal patterns), `cut` (`-d`/`-f`/`-c`), `tr` (`-d`/`-s`, ranges, POSIX classes), `sort` (`-r`/`-n`/`-u`), `uniq` (`-c`/`-d`/`-u`), `xargs` (`-n`), `tee` (`-a`), `rev`, `nl`, `seq`, `basename`, `dirname`, `base64` (`-d`/`-w0`), `md5sum`, `sha1sum`, `sha256sum`, `sha512sum`, `awk`/`mawk` (`-F`/`-v`/`-f`) |
| **Accounts** | `passwd` (prompts twice, echo suppressed), `chpasswd`, `useradd`/`adduser` (`-m`/`-s`/`-u`), `userdel`/`deluser`, `groupadd`/`addgroup`, `getent` (`passwd`/`group`/`shadow`/`hosts`) |
| **Services** | `systemctl` (`status`/`is-active`/`is-enabled`/`list-units`/`start`/`stop`/`enable`/`disable`/`daemon-reload`), `service`, `nohup`, `chattr`, `lsattr`, `sleep`, `sync`, `nologin` |
| **Identity** | `whoami`, `id`, `groups`, `uname` (`-a`/`-s`/`-n`/`-r`/`-v`/`-m`/`-o`), `arch`, `hostname`, `nproc`, `lscpu`, `lsb_release` (`-a`/`-s`/`-i`/`-d`/`-r`/`-c`), `tty`, `date` (`+FORMAT`) |
| **Privilege** | `sudo` (transient elevation for one command; `-i`/`-s` hand over a root shell for the session), `su` (identity switch; prompts a non-root user for a password) |
| **Shells** | `bash`/`sh` (`-c LINE`, a script operand read from the VFS, or piped stdin), `scp` (local copy; remote operands fail as unreachable) |
| **Environment** | `env`, `export`, `unset`, `clear` |
| **Processes** | `ps` (`aux`/`-ef`), `top` (holds the screen and repaints until `q`; `-b`/`-n` dump once), `kill`, `pkill`, `killall`, `pidof`, `pgrep` (`-l`), `free`, `uptime` |
| **Editors** | `vi`, `nano` — read-only screen-holding stubs: show the target file (or a blank buffer), quit on `vi`'s `:q`/`:q!`/`:wq`/`:x` or `nano`'s Ctrl-X. Typed text is never inserted or saved |
| **Networking** | `wget`, `curl`, `ping`, `netstat`, `ss`, `ip`, `nc`/`netcat` (`-l` holds the terminal until Ctrl-C) |
| **Interpreters** | `python3`, `perl` — invocation only; nothing is ever interpreted |
| **Recon** | `history`, `which`, `w`, `last`, `df` (`-h`), `mount`, `crontab` (`-l`), `dmesg` (root-only, `dmesg_restrict`) |
| **Packages** | `apt`, `apt-get`, `dpkg` (stubs — install requires root, fake package DB) |
| **Built-ins** | `exit` (`[N]`), `logout` (`[N]`), `true`, `false`, `cd`, `export`, `unset` |
| **Line syntax** | `;`, `&&`, `\|\|` chaining, `\|` pipelines, `>`/`>>`/`2>`/`&>`/`2>&1` redirection (all quoting-aware), `#` comments, `$VAR`/`${VAR}`/`$?`/`$$`/`$#`/`$0` expansion, `$(…)`/`` `…` `` substitution, `$((…))` arithmetic, here-documents (`<<`, `<<-`, quoted delimiters), quotes and backslash escapes |

## Session behaviour

A session behaves according to whether it asked for a terminal. With a PTY it is
an interactive login shell: prompt, readline editing, and `logout` on the way
out. Without one (`ssh -T host < script`, or a one-shot `ssh host cmd`) it is
non-interactive, exactly as bash is when it finds a pipe on stdin — no prompt, no
echo, no erase sequences, no `logout`. The MOTD comes from the PAM session rather
than the terminal, so it arrives either way.

Commands write to stdout and stderr separately, as real ones do: a pipeline
carries only stdout onward, `$(…)` captures only stdout, `2>` catches only
stderr, and an `exec` channel without a PTY sends stderr as
`SSH_EXTENDED_DATA_STDERR`, so `ssh host nosuchcmd 2>/dev/null` is silent. A
channel that asked for a PTY gets the two merged onto the terminal, because a
real one has a single stream.

Directory listings honour Unix read permissions, so an unprivileged user running
`ls /root` gets `Permission denied` just like a real box — and so does
`cd /root`, which needs the directory's search bit.

## Where the emulation deliberately stops

**The interpreters run nothing.** `python3 -c` and `perl -e` are emulated at the
*invocation*: the payload is already captured verbatim in the `command` event,
which is where the intelligence is, and executing attacker code is the one thing
this box exists not to do. A one-liner that opens a socket gets the traceback a
failed connect produces — by far the most common real outcome, since the
attacker's listener is usually already gone — and anything else exits quietly.
`nc` behaves the same way: no socket is opened, a connect always reports
`Connection refused`, and `nc -l PORT` holds the terminal, since a real listener
blocks in `accept(2)` until a client connects, and nothing ever connects here.

**`awk` covers pipeline plumbing, not programming.** `{print $N}` rules,
`-F`/`-v FS`, bare `/pattern/` matches, `$N == "v"` comparisons and `NR`/`NF` —
the shapes awk actually takes in an attack script. Anything outside that subset
is a **syntax error with `status: 2`**, deliberately: printing nothing would make
awk look like it ran and matched nothing, which is a worse lie than an honest
refusal, and the non-zero status is the signal for what to implement next.

**Privilege escalation never fails.** A non-root `su` shows a realistic
`Password:` prompt (suppressing echo) and the typed secret is captured as an
`auth_attempt` event before the switch — but, like `sudo`, it never fails the
credential check. The attacker's session already authenticated at login, so
refusing escalation would be an inconsistent tell with no forensic upside.

**Nothing is compressed.** `tar` reads and writes real POSIX ustar archives, so
`tar czf t.tgz d && tar tzf t.tgz` round-trips inside the VFS; `-z`/`-j`/`-J` are
accepted and ignored, since no command in the emulator can tell the difference.

**Network calls are recorded, not made.** `wget`, `curl`, `nc` and a
`python3`/`perl` one-liner that reaches for the network all log a `download`
event naming the remote endpoint, so one query recovers every host a session
tried to contact. `wget` and `curl` additionally write a placeholder file into
the VFS. SCP and SFTP uploads are captured to a SHA-256-named quarantine store on
the real filesystem.

## SSH banner

```
Linux debian 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
...
Last login: Wed Aug 20 11:03:33 2026 from 10.0.0.5
```

The `Last login` timestamp is derived from the fake box's boot time at startup,
as are the snapshot's file mtimes and everything `uptime`, `w`, `last` and `ps`
report — so `date` can never contradict them.
