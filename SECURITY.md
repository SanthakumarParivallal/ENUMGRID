# Security Policy

## Authorized use

ENUMGRID is an offensive-capable enumeration tool. **Scan only systems and
networks you own or are explicitly authorized, in writing, to test.**
Unauthorized scanning may be illegal where you live. The project enforces
guardrails by default — it refuses loopback, multicast, broadcast, link-local
and reserved space, and refuses public/internet-routable targets unless you
opt in (`ENUMGRID_ALLOW_PUBLIC=1`) — but **you** remain responsible for using it
lawfully.

## Reporting a vulnerability

If you discover a security vulnerability **in ENUMGRID itself** (not in a host
you scanned with it), please report it privately:

- Open a [GitHub Security Advisory](https://github.com/SanthakumarParivallal/ENUMGRID/security/advisories/new)
  (preferred), or
- Open a regular issue **without** sensitive details and ask for a private
  channel.

Please do not disclose publicly until a fix is available. I aim to acknowledge
reports within 5 days.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅        |

## Handling of secrets

Credentials supplied to ENUMGRID (SSH/AD passwords, cloud keys, the NVD API key)
are used **in memory only** — they are never written to disk or logs by the
application. The audit log records *that* an action happened, never the secret.
