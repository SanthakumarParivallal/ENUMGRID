/**
 * privilege.js — pure presentation logic for the scan-privilege control.
 * ---------------------------------------------------------------------------
 * The backend reports a capability tier (see /api/privilege). These helpers turn
 * that tier + the runtime-elevated flag into the label / tone / note the command
 * bar's Privilege pill and the Engine panel render. Kept dependency-free and
 * icon-free (the component maps `raw` → an icon) so it's unit-testable in
 * isolation, like the other lib modules.
 *
 *   capability : 'root' | 'sudo' | 'unprivileged'
 *   elevated   : raised to sudo at runtime via the dashboard this session
 */

// Tiers that give real raw-socket scans (-sS / -sU / -O).
export const RAW_TIERS = Object.freeze(['root', 'sudo']);

/** True when the current tier can run raw-socket scans (root or sudo). */
export function rawScanAvailable(capability) {
  return RAW_TIERS.includes(capability);
}

/**
 * Visual identity for a privilege tier.
 * @returns {{ label: string, tone: 'matrix'|'slate', raw: boolean, note: string }}
 */
export function privMeta(capability, elevated = false) {
  if (capability === 'root') {
    return {
      label: 'Root',
      tone: 'matrix',
      raw: true,
      note: 'running as root — full nmap (SYN/UDP/OS)',
    };
  }
  if (capability === 'sudo') {
    return {
      label: elevated ? 'Elevated' : 'Sudo',
      tone: 'matrix',
      raw: true,
      note: elevated
        ? 'elevated this session — full nmap (SYN/UDP/OS)'
        : 'passwordless sudo — full nmap (SYN/UDP/OS)',
    };
  }
  // Anything else (incl. 'unprivileged' or an unknown/empty value) is treated as
  // unprivileged — scans still run, auto-adapted.
  return {
    label: 'Unprivileged',
    tone: 'slate',
    raw: false,
    note: 'root-only scans auto-adapt to unprivileged equivalents',
  };
}

/**
 * Whether the command-bar pill should invite elevation (show the ⚡ affordance):
 * only when we're not already raw-capable but the backend says we could elevate.
 */
export function canOfferElevation(capability, canElevate) {
  return !rawScanAvailable(capability) && !!canElevate;
}
