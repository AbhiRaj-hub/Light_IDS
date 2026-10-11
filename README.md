# Lightweight IDS (C port)

A C port of the Python Lightweight IDS: signature matching (POSIX ERE), sliding-window
anomaly detection (port scans, SYN floods, traffic spikes via z-score), JSON-lines
logging, and email/Slack/webhook alerting — built on libpcap, POSIX regex, libcurl,
and pthreads. No JSON library dependency: `src/json.c` is a small self-contained parser.

## ⚠️ Authorized Use Only

Only run this against networks/traffic you own or are explicitly authorized to
monitor. Run with `sudo` only when you mean to capture live traffic.

## Build

```bash
sudo apt install libpcap-dev libcurl4-openssl-dev build-essential   # Debian/Ubuntu
make
```

## Run

```bash
sudo ./ids -i eth0
sudo ./ids -i eth0 -f "tcp or udp"
./ids --pcap sample.pcap        # no root needed for offline replay
```

Flags mirror the Python version: `-i/--interface`, `-f/--filter`, `--pcap`, `--rules`,
`--config`, `--log-dir`, `-q/--quiet`, `-h/--help`.

## Differences from the Python version

- **Regex dialect**: `config/rules.json` patterns are POSIX Extended Regular
  Expressions (compiled with `REG_ICASE`), not Python's PCRE-style `re`. Inline
  `(?i)` and `\b` word boundaries aren't supported by `regex.h` and were
  rewritten/dropped — see the rules file for the current patterns before adding
  new ones.
- **Alert dispatch**: one worker thread per alert handles all enabled channels
  sequentially, rather than one thread per channel. Still fully non-blocking
  relative to packet capture, just a simpler threading model.
- **Email**: plaintext SMTP only — no STARTTLS/TLS. `use_tls` in `alerting.json`
  is accepted (for config compatibility with the Python version) but logged as a
  warning and ignored. Point `smtp_host` at a local relay/MTA that doesn't require
  TLS, or extend `send_email()` in `src/alert_sender.c` with OpenSSL.
- **Webhook headers**: the Python version supports arbitrary custom headers per
  channel; this build sends `Content-Type: application/json` only.
- **IPv4 only**, same as the Python version — no IPv6 support.
- **No packet reassembly** across fragmented IP datagrams (also true of the
  Python version).
- **Anomaly state never expires**: per-host tracking state (`ad_host_state_t`)
  accumulates in a hash table for the life of the process — fine for a lab/host
  segment, not meant for unattended multi-day runs against high-cardinality
  traffic without adding an eviction policy.
- Payload matching copies packet bytes into a bounded, NUL-terminated buffer
  (4096 bytes) before running `regexec`/`strcasestr`, since C string functions
  can't scan past an embedded `\0`. Embedded NUL bytes in payload are replaced
  with a space before matching. Payloads longer than 4096 bytes are truncated
  for signature purposes only (the full packet is still counted for anomaly
  detection).

## Adding a Signature Rule

Same schema as the Python version, but the pattern must be valid POSIX ERE:

```json
{
  "id": "SIG-2001",
  "name": "Log4Shell JNDI Lookup Attempt",
  "description": "JNDI injection string in HTTP payload (CVE-2021-44228)",
  "severity": "critical",
  "protocol": "tcp",
  "match_type": "payload_regex",
  "pattern": "\\$\\{jndi:(ldap|rmi|dns)://",
  "mitre_attack": "T1190"
}
```

No `(?i)` needed — `payload_regex` rules are always compiled case-insensitive.

## Logs

Same JSON-lines format as the Python version, written to `logs/ids_events.jsonl`.

## Known Limitations

- Single-process, in-memory state (same scope limitation as the Python version).
- No IPv6, no TLS-encrypted payload inspection, no fragment reassembly.
