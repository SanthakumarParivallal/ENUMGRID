/**
 * shortcuts.js — global keyboard-shortcut metadata + a pure guard.
 * ---------------------------------------------------------------------------
 * Deliberately safe: no shortcut triggers a network action (an accidental scan
 * would be harmful), only navigation/appearance. The list is rendered by the
 * "?" help overlay; `isEditableTarget` keeps single-key shortcuts from firing
 * while the user is typing in a field.
 */

export const SHORTCUTS = Object.freeze([
  { keys: '/', label: 'Focus the search box' },
  { keys: 't', label: 'Toggle light / dark theme' },
  { keys: 'd', label: 'Toggle compact / cozy density' },
  { keys: '?', label: 'Show / hide this shortcuts help' },
  { keys: 'Esc', label: 'Close any open dialog, menu, or this help' },
]);

/** True when keystrokes belong to the focused control, not a global shortcut. */
export function isEditableTarget(el) {
  if (!el) return false;
  const tag = (el.tagName || '').toLowerCase();
  return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable === true;
}
