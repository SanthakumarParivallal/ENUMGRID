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

## Deploying the API safely

The backend is **localhost-only by default** (`start.sh` binds `127.0.0.1`). The
zero-config "open" mode (no token configured) is **fail-closed to local clients**:
a request to `/api/*` from a non-loopback peer — or with a non-local `Host`
header (DNS-rebinding) — is refused with `401`. This means even a `0.0.0.0` bind
(e.g. Docker `--network host`) does **not** expose the scanner to the LAN unless
you explicitly enable authenticated remote access.

To allow remote/authenticated access:

- Set **`ENUMGRID_ADMIN_TOKEN`** (and optionally `ENUMGRID_VIEWER_TOKEN` for
  read-only). With a token configured, every scan/admin action requires it.
- **Send the token via the `Authorization: Bearer <token>` header**, not the
  `?token=` query parameter — query strings can leak into access logs, proxy logs
  and browser history. The `?token=` form is retained for local convenience only.
- **Front the API with TLS** (`./start.sh --tls`, or a reverse proxy) before
  exposing it, and keep `ENUMGRID_ALLOW_PUBLIC` unset unless you have written
  authorization to scan public ranges.

## Hardening notes

- The history DB, CVE/KEV/EPSS caches and the audit log are **operator data**
  written to the working directory; on a shared host, restrict that directory's
  permissions. (The NVD key file is written owner-only, `0600`.)
- The credentialed endpoints (`/api/host/credscan` over SSH, `/api/ad/enum` over
  LDAP) are **admin-gated**; a client-supplied key path / DC host is trusted
  because the caller is already an authenticated admin operating on assets they
  administer with their own credentials.

## Handling of secrets

Credentials supplied to ENUMGRID (SSH/AD passwords, cloud keys) are used
**in memory only** — never written to disk or logs by the application. The
**NVD API key**, when entered in the dashboard, is the one exception: it is
persisted to an owner-only (`0600`), git-ignored file so it survives a restart —
it is still never logged. The audit log records *that* an action happened, never
the secret value.
