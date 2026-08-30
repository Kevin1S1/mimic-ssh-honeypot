# Deployment

## Docker (recommended)

`docker compose` handles volume permission initialisation, log rotation, and the
security hardening (read-only filesystem, dropped capabilities).

```bash
docker compose up -d      # build and run the stack
docker compose logs -f    # stream forensic logs
```

Host port `22` is mapped to the container's `2222`. A named volume at `/data`
persists host keys and the quarantine store across container restarts. The stack
also includes the [daily reset](#daily-reset) sidecar.

> If something is already running on port 22, stop it first:
> `sudo systemctl stop ssh && sudo systemctl disable ssh`

## Build from source

Requires a [Rust toolchain](https://rustup.rs/) (stable, MSRV 1.88).

```bash
git clone https://github.com/Kevin1S1/mimic-ssh-honeypot.git
cd mimic-ssh-honeypot

cargo run                          # dev build + run, defaults to 0.0.0.0:2222
cargo run -- deploy/mimic.toml     # with a config file

cargo build --release
./target/release/mimic deploy/mimic.toml

cargo test
```

## Systemd (non-Docker)

```bash
cargo build --release
sudo install -m0755 target/release/mimic /usr/local/bin/mimic
sudo install -Dm0644 deploy/mimic.toml /etc/mimic/mimic.toml
sudo install -Dm0644 deploy/mimic.service /etc/systemd/system/mimic.service

sudo systemctl daemon-reload
sudo systemctl enable --now mimic

sudo journalctl -u mimic -f
```

The unit runs under a transient unprivileged user (`DynamicUser=yes`) with a
fully sandboxed filesystem and `CAP_NET_BIND_SERVICE`, so it can optionally bind
port 22 directly.

## Daily reset

MIMIC wipes quarantine data and restarts the honeypot once a day, so each day
begins with a clean slate. The restart time is **randomised** within a
configurable window (default: 0–3 hours after midnight UTC) so attackers cannot
predict exactly when the service bounces.

### Docker

The `mimic-reset` sidecar in [docker-compose.yml](../docker-compose.yml) handles
this automatically — no extra setup. Tune it with environment variables:

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

> **Privilege tradeoff:** the sidecar needs the host's Docker socket to restart
> the honeypot container. The `:ro` flag makes the socket *file* read-only but
> does **not** restrict Docker API calls, so that container effectively has root
> on the host daemon. It is isolated (`network_mode: none`, no attacker input,
> separate container from the honeypot), but if you would rather not grant it,
> use the systemd timer below — it needs no Docker socket. See
> [SECURITY.md](../SECURITY.md#7-daily-reset-ephemeral-state-hygiene).

### Systemd

```bash
sudo install -Dm0755 deploy/daily-reset.sh      /usr/local/lib/mimic/daily-reset.sh
sudo install -Dm0644 deploy/mimic-reset.service /etc/systemd/system/mimic-reset.service
sudo install -Dm0644 deploy/mimic-reset.timer   /etc/systemd/system/mimic-reset.timer
sudo systemctl daemon-reload
sudo systemctl enable --now mimic-reset.timer
```

The timer fires at midnight UTC; the script then sleeps for a random duration
within the window before performing the reset.

### What gets wiped

- **Quarantine store** (`quarantine/`) — captured SCP and SFTP uploads.
- **In-memory state** — the restart clears all VFS modifications, shell
  histories, and session state.
- **Host keys are preserved** — the SSH fingerprint stays stable across resets
  (a changing fingerprint is a honeypot tell).
