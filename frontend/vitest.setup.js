/**
 * vitest.setup.js — test environment shims.
 * ---------------------------------------------------------------------------
 * jsdom 25 (as wired by vitest) doesn't instantiate window.localStorage, so
 * the bare `localStorage` global would fall through to Node's flag-gated one
 * and read as undefined. The dashboard targets a real browser, where
 * localStorage always exists, so we install a minimal in-memory Storage that
 * behaves like the browser's. Tests that need the "storage unavailable" path
 * stub it away explicitly (vi.stubGlobal('localStorage', undefined)).
 *
 * Storage is exposed as a class so `vi.spyOn(Storage.prototype, 'setItem')`
 * (used to simulate a throwing / quota-exceeded store) works as it would in a
 * browser.
 */
class Storage {
  #data = new Map();

  get length() {
    return this.#data.size;
  }

  key(index) {
    return [...this.#data.keys()][index] ?? null;
  }

  getItem(key) {
    return this.#data.has(String(key)) ? this.#data.get(String(key)) : null;
  }

  setItem(key, value) {
    this.#data.set(String(key), String(value));
  }

  removeItem(key) {
    this.#data.delete(String(key));
  }

  clear() {
    this.#data.clear();
  }
}

if (typeof globalThis.localStorage === 'undefined') {
  const storage = new Storage();
  const descriptor = { value: storage, writable: true, configurable: true };
  globalThis.Storage = Storage;
  Object.defineProperty(globalThis, 'localStorage', descriptor);
  if (typeof window !== 'undefined') {
    Object.defineProperty(window, 'localStorage', descriptor);
    window.Storage = Storage;
  }
}
