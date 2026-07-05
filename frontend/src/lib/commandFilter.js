/**
 * commandFilter.js — pure ranking for the ⌘K command palette.
 * ---------------------------------------------------------------------------
 * Kept dependency-free so the match/rank logic is unit-testable in isolation.
 * A command is `{ id, label, keywords?, ... }`; only label + keywords are read
 * here. Ranking: label prefix > label substring > keyword substring > fuzzy
 * subsequence. Ties keep the original (curated) order via a stable sort.
 */

/** True if every char of `needle` appears in `hay` in order (fuzzy match). */
export function isSubsequence(needle, hay) {
  if (!needle) return true;
  let i = 0;
  for (const ch of hay) {
    if (ch === needle[i]) i += 1;
    if (i === needle.length) return true;
  }
  return false;
}

/** Match score for a command against a lowercased query (0 = no match). */
export function scoreCommand(cmd, q) {
  if (!q) return 1;
  const label = (cmd.label || '').toLowerCase();
  const kw = (cmd.keywords || []).join(' ').toLowerCase();
  if (label.startsWith(q)) return 100;
  if (label.includes(q)) return 60;
  if (kw.includes(q)) return 30;
  if (isSubsequence(q, label)) return 10;
  return 0;
}

/** Filter + rank commands for a query, preserving order on ties. */
export function filterCommands(commands, query) {
  const q = (query || '').trim().toLowerCase();
  if (!q) return commands.slice();
  return commands
    .map((c, i) => ({ c, i, score: scoreCommand(c, q) }))
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score || a.i - b.i)
    .map((x) => x.c);
}
