# Getting help with ENUMGRID

ENUMGRID is maintained by one person alongside other work. This page says where to
send each kind of question so it reaches the right place and gets answered once.

## Read these first

Most setup questions are already covered:

| Question | Where |
| --- | --- |
| How do I install and run it? | [Quickstart](README.md#quickstart) |
| How do I run only the CLI? | [Or just the CLI](README.md#or-just-the-cli) |
| Why does it not ask for my password? | [Enabling privileged scans](README.md#enabling-privileged-scans) |
| What does it actually scan, and how? | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| How accurate is it, and how was that measured? | [`docs/ACCURACY.md`](docs/ACCURACY.md), [`docs/EVALUATION.md`](docs/EVALUATION.md) |
| How do I reproduce a number from the README? | [`docs/REPRODUCE.md`](docs/REPRODUCE.md) |
| How do I set up the AI copilot without paying for a key? | [`docs/COPILOT.md`](docs/COPILOT.md) |
| How do I contribute a change? | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

## Where to raise what

| Kind | Where | Notes |
| --- | --- | --- |
| Security vulnerability in ENUMGRID | [Private advisory](https://github.com/SanthakumarParivallal/ENUMGRID/security/advisories/new) | Never open a public issue for this. See [`SECURITY.md`](SECURITY.md) |
| Something is broken | [Bug report](https://github.com/SanthakumarParivallal/ENUMGRID/issues/new?template=bug_report.md) | Include the checks below |
| Missing capability | [Feature request](https://github.com/SanthakumarParivallal/ENUMGRID/issues/new?template=feature_request.md) | Say what you are trying to find out about a network, not just what UI you want |
| A measured claim looks wrong | Bug report | Quote the number and the artifact under `evaluation/results/` that disagrees. This is a real bug class, not a nuisance |

Blank issues are turned off on purpose, so please pick a template.

## Before filing a bug

Four checks resolve most reports:

1. **Run the gate.** `make test` should finish with `✓ all checks passed`. If it does
   not, paste that output rather than describing it.
2. **Confirm nmap is installed.** `nmap --version`. The launcher offers to install it,
   but a broken or sandboxed nmap looks like an ENUMGRID bug from the UI.
3. **Check whether it is a privilege difference.** ENUMGRID runs unprivileged by default
   and rewrites root-only techniques to equivalents. If results differ from raw nmap,
   the adaptation notes shown next to the scan explain what was substituted.
4. **Check your Python.** The project needs 3.10 or newer (`python3 --version`).

Then include your OS and version, how you started it (`./start.sh`, `make dev`, or the
CLI), the exact command or click sequence, what you expected, and what happened.

## Please do not include scan output from networks you do not own

ENUMGRID is for authorized assessment only. Issue threads are public and permanent, so
pasting a scan of a network you are not authorized to test exposes that network and may
expose you. Reproduce against the bundled docker testbed under `evaluation/` and paste
that output instead, or redact addresses and hostnames before posting.

## What to expect

Security reports are acknowledged within 5 days, as stated in [`SECURITY.md`](SECURITY.md).
Everything else is handled in whatever time is available, so there is no response target
for general issues. A clear reproduction is the single thing most likely to get a fix.

ENUMGRID is research software built for a dissertation. It is offered as is under the
[MIT licence](LICENSE), with no support contract and no warranty.
