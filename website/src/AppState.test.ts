import { describe, expect, it, beforeEach } from 'vitest';
import { autorun } from 'mobx';

// AppState.ts evaluates window.matchMedia at module load time, but jsdom does
// not implement matchMedia. Stub it before (dynamically) importing the module.
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  configurable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});

const { AppState } = await import('./AppState');

describe('AppState loadingError', () => {
  beforeEach(() => {
    AppState.clearLoadingError();
  });

  it('is undefined initially / after reset', () => {
    expect(AppState.loadingError).toBeUndefined();
  });

  it('setLoadingError stores the error message', () => {
    AppState.setLoadingError('boom');
    expect(AppState.loadingError).toBe('boom');
  });

  it('setLoadingError overwrites a previous error', () => {
    AppState.setLoadingError('first failure');
    AppState.setLoadingError('second failure');
    expect(AppState.loadingError).toBe('second failure');
  });

  it('clearLoadingError clears a previously set error (successful load self-recovers)', () => {
    // simulate a failed poll...
    AppState.setLoadingError('network unreachable');
    expect(AppState.loadingError).toBe('network unreachable');

    // ...followed by a successful poll, which clears the error
    AppState.clearLoadingError();
    expect(AppState.loadingError).toBeUndefined();
  });

  it('clearLoadingError is a no-op when no error is set', () => {
    expect(AppState.loadingError).toBeUndefined();
    expect(() => AppState.clearLoadingError()).not.toThrow();
    expect(AppState.loadingError).toBeUndefined();
  });

  it('set and clear notify mobx observers (mutations go through actions)', () => {
    const seen: Array<string | undefined> = [];
    const dispose = autorun(() => {
      seen.push(AppState.loadingError);
    });
    try {
      AppState.setLoadingError('transient failure');
      AppState.clearLoadingError();
      expect(seen).toEqual([undefined, 'transient failure', undefined]);
    } finally {
      dispose();
    }
  });
});
