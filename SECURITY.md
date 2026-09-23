# Security Policy

## Authorized use

ENUMGRID is an offensive-capable enumeration tool. **Scan only systems and
networks you own or are explicitly authorized, in writing, to test.**
Unauthorized scanning may be illegal where you live. The project enforces
guardrails by default: it refuses loopback, multicast, broadcast, link-local
and reserved space, and refuses public and internet-routable targets unless you
opt in with `ENUMGRID_ALLOW_PUBLIC=1`. You remain responsible for using it
lawfully.

## Reporting a vulnerability

If you discover a security vulnerability in ENUMGRID itself, rather than in a host
you scanned with it, please report it privately:

- Open a [GitHub Security Advisory](https://github.com/SanthakumarParivallal/ENUMGRID/security/advisories/new)
  (preferred), or
- Open a regular issue without sensitive details and ask for a private channel.

Please do not disclose publicly until a fix is available. I aim to acknowledge
reports within 5 days.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅        |

## Deploying the API safely

The backend is localhost-only by default; `start.sh` binds `127.0.0.1`. The
zero-config "open" mode, where no token is configured, is fail-closed to local
clients: a request to `/api/*` from a non-loopback peer, or one carrying a non-local
`Host` header (DNS-rebinding), is refused with `401`. Even a `0.0.0.0` bind, such as
Docker `--network host`, therefore does not expose the scanner to the LAN unless you
explicitly enable authenticated remote access.

To allow remote or authenticated access:

- Set `ENUMGRID_ADMIN_TOKEN`, and optionally `ENUMGRID_VIEWER_TOKEN` for read-only
  access. With a token configured, every scan and admin action requires it.
- Send the token in the `Authorization: Bearer <token>` header rather than the
  `?token=` query parameter, because query strings can leak into access logs, proxy
  logs and browser history. The `?token=` form is retained for local convenience.
- Front the API with TLS (`./start.sh --tls`, or a reverse proxy) before exposing
  it, and keep `ENUMGRID_ALLOW_PUBLIC` unset unless you have written authorization
  to scan public ranges.

## Hardening notes

- The history DB, the CVE/KEV/EPSS caches and the audit log are operator data
  written to the working directory. On a shared host, restrict that directory's
  permissions. The NVD key file is written owner-only, `0600`.
- The credentialed endpoints (`/api/host/credscan` over SSH, `/api/ad/enum` over
  LDAP) are admin-gated. A client-supplied key path or DC host is trusted because
  the caller is already an authenticated admin operating on assets they administer
  with their own credentials.

## Handling of secrets

Credentials supplied to ENUMGRID (SSH and AD passwords, cloud keys) are used in
memory only, and the application never writes them to disk or logs. The NVD API key
is the one exception: when entered in the dashboard it is persisted to an
owner-only (`0600`), git-ignored file so it survives a restart. It is still never
logged. The audit log records that an action happened, never the secret value.

The sudo password used by the dashboard's Privilege and Elevate control
(`POST /api/privilege/elevate`, admin-gated and local-only) follows the in-memory
rule with no exception. It is validated against `sudo`, held only in the backend
process for the session, and never written to disk, logged, or returned. Drop
(`POST /api/privilege/drop`), a restart, or `ENUMGRID_AUTO_SUDO=0` clears or
forbids it.
