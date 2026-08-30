# Configuration

All settings are optional — MIMIC runs with safe defaults if no config file is
provided. Pass the config path as the first argument:

```bash
mimic /path/to/mimic.toml

# or via Docker
docker run ... -v ./deploy/mimic.toml:/etc/mimic/mimic.toml:ro \
  mimic-honeypot:latest /etc/mimic/mimic.toml
```

## Full reference

[deploy/mimic.toml](../deploy/mimic.toml) is the reference example and is kept in
sync with the code.

```toml
# Network
listen_addr        = "0.0.0.0"  # bind address
port               = 2222       # port inside the container; map host 22 → 2222
server_id          = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
hostname           = "debian"   # appears in the shell prompt and uname
sensor_name        = "mimic"    # identifier in every log line (multi-sensor setups)

# Limits
max_sessions       = 32         # global concurrent connection cap
per_ip_connections = 4          # per-source-IP concurrent cap
idle_timeout_secs  = 300        # drop idle sessions after 5 minutes
max_session_secs   = 1800       # absolute per-session lifetime cap

# Capture
quarantine_dir     = "/data/quarantine" # SCP/SFTP uploads land here (SHA-256 named)
max_upload_bytes   = 8388608            # truncate stored files at 8 MiB
host_key_dir       = "/data/host_keys"  # persisted Ed25519 + RSA keys

[logging]
# Events always go to stdout. When `dir` is set they are additionally written to
# a daily-rotated file there, for log shippers and manual reads.
dir            = "/data/logs"
# retention_days = 30           # omit to keep logs forever

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

## Authentication modes

| Mode | Behaviour | Best for |
|---|---|---|
| `accept_all` | Every password works on the first try | Maximum attacker interaction, capturing commands |
| `reject_all` | Always rejects — captures creds but never grants a shell | Passive credential harvesting only |
| `accept_after` | Rejects the first N−1 attempts and accepts the Nth (`accept_after = 2` → the second password works) | Realistic; attackers expect a few tries |
| `credentials` | Only specific pairs succeed | Targeted studies |

`accept_after` must be `1..=6`. `0` would silently mean `accept_all`, and the
server enforces Debian's `MaxAuthTries 6`, so a larger value disconnects the
client before the accepting attempt is ever reached.
