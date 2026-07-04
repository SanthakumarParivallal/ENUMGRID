import { describe, it, expect } from 'vitest';
import { privMeta, rawScanAvailable, canOfferElevation, RAW_TIERS } from './privilege.js';

describe('rawScanAvailable', () => {
  it('is true only for root and sudo tiers', () => {
    expect(rawScanAvailable('root')).toBe(true);
    expect(rawScanAvailable('sudo')).toBe(true);
    expect(rawScanAvailable('unprivileged')).toBe(false);
    expect(rawScanAvailable('')).toBe(false);
    expect(rawScanAvailable(undefined)).toBe(false);
  });

  it('RAW_TIERS is exactly root + sudo', () => {
    expect([...RAW_TIERS].sort()).toEqual(['root', 'sudo']);
  });
});

describe('privMeta', () => {
  it('root → raw-capable matrix tier', () => {
    const m = privMeta('root', false);
    expect(m).toMatchObject({ label: 'Root', tone: 'matrix', raw: true });
    expect(m.note).toMatch(/root/i);
  });

  it('sudo (auto, not runtime-elevated) → "Sudo", raw-capable', () => {
    const m = privMeta('sudo', false);
    expect(m).toMatchObject({ label: 'Sudo', tone: 'matrix', raw: true });
    expect(m.note).toMatch(/passwordless sudo/i);
  });

  it('sudo elevated at runtime → "Elevated" with a distinct note', () => {
    const m = privMeta('sudo', true);
    expect(m).toMatchObject({ label: 'Elevated', tone: 'matrix', raw: true });
    expect(m.note).toMatch(/elevated this session/i);
    // The elevated note differs from the passwordless-sudo note.
    expect(m.note).not.toBe(privMeta('sudo', false).note);
  });

  it('unprivileged → slate tier, not raw-capable', () => {
    const m = privMeta('unprivileged', false);
    expect(m).toMatchObject({ label: 'Unprivileged', tone: 'slate', raw: false });
    expect(m.note).toMatch(/auto-adapt/i);
  });

  it('defaults elevated to false and treats unknown tiers as unprivileged', () => {
    expect(privMeta('unprivileged')).toEqual(privMeta('unprivileged', false));
    expect(privMeta('something-weird').label).toBe('Unprivileged');
  });

  it('the elevated flag only matters for the sudo tier', () => {
    // root ignores `elevated`; unprivileged ignores it too.
    expect(privMeta('root', true)).toEqual(privMeta('root', false));
    expect(privMeta('unprivileged', true)).toEqual(privMeta('unprivileged', false));
  });
});

describe('canOfferElevation', () => {
  it('offers elevation only when not raw-capable AND the backend says it can elevate', () => {
    expect(canOfferElevation('unprivileged', true)).toBe(true);
    expect(canOfferElevation('unprivileged', false)).toBe(false); // no sudo on host
    expect(canOfferElevation('sudo', true)).toBe(false); // already raw-capable
    expect(canOfferElevation('root', true)).toBe(false); // already root
  });
});
