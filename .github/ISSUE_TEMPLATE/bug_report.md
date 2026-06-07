---
name: Bug report
about: Report a defect in ENUMGRID (the tool itself — not a host you scanned)
title: "[bug] "
labels: bug
---

<!--
⚠️ Only report bugs in ENUMGRID itself. Do NOT paste scan output from systems
you don't own or aren't authorized to test. For a security vulnerability in
ENUMGRID, follow SECURITY.md instead of opening a public issue.
-->

**What happened**
A clear description of the bug.

**Steps to reproduce**
1. …
2. …

**Expected behavior**
What you expected instead.

**Environment**
- ENUMGRID version / commit:
- OS:
- Python version (`python --version`):
- Node version (`node --version`):
- Started with: `./start.sh` / `--no-sudo` / `--tls` / manual
- Privilege tier from `/api/health` (`capability`): root / sudo / unprivileged

**Logs**
Relevant lines from `.backend.log` or the browser console (redact anything sensitive).
