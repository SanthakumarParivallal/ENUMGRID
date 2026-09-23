<!-- Keep the quality gate green. -->

## What and why
Briefly describe the change and the problem it solves.

## Changes
-

## Checklist
- [ ] Tests added/updated and the full gate passes locally:
      `ruff` · `bandit -c pyproject.toml` · `pip-audit` · `pytest` · `npm test` · `npm run build` · `npm audit`
- [ ] `CHANGELOG.md` updated
- [ ] Docs updated if behavior/flags changed
- [ ] Results stay real (no simulated scan data) and scope guards are intact
- [ ] No secrets, tokens, or unauthorized scan output committed
