import { describe, expect, it } from 'vitest';
import { getPlatform, isMobile, Platform } from './Platform';

interface NavigatorMock {
  platform: string;
  userAgent?: string;
  maxTouchPoints?: number;
}

// getPlatform() reads window.navigator at call time, so overriding the
// (configurable) navigator getters per test case is sufficient.
function mockNavigator({ platform, userAgent = '', maxTouchPoints }: NavigatorMock) {
  Object.defineProperty(window.navigator, 'platform', { value: platform, configurable: true });
  Object.defineProperty(window.navigator, 'userAgent', { value: userAgent, configurable: true });
  Object.defineProperty(window.navigator, 'maxTouchPoints', { value: maxTouchPoints, configurable: true });
}

describe('getPlatform', () => {
  it('detects a classic iPhone as iOS', () => {
    mockNavigator({
      platform: 'iPhone',
      userAgent:
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
      maxTouchPoints: 5,
    });
    expect(getPlatform()).toBe(Platform.Ios);
  });

  it('detects a classic iPad (pre-iPadOS-13 UA) as iOS', () => {
    mockNavigator({
      platform: 'iPad',
      userAgent:
        'Mozilla/5.0 (iPad; CPU OS 12_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1',
      maxTouchPoints: 5,
    });
    expect(getPlatform()).toBe(Platform.Ios);
  });

  it('detects iPadOS 13+ masquerading as a Mac (MacIntel + touch) as iOS', () => {
    mockNavigator({
      platform: 'MacIntel',
      userAgent:
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15',
      maxTouchPoints: 5,
    });
    expect(getPlatform()).toBe(Platform.Ios);
  });

  it('detects a real Mac (MacIntel, no touch points) as Mac', () => {
    mockNavigator({
      platform: 'MacIntel',
      userAgent:
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15',
      maxTouchPoints: 0,
    });
    expect(getPlatform()).toBe(Platform.Mac);
  });

  it('treats MacIntel with maxTouchPoints === 1 as Mac (needs > 1)', () => {
    mockNavigator({ platform: 'MacIntel', maxTouchPoints: 1 });
    expect(getPlatform()).toBe(Platform.Mac);
  });

  it('falls back to Mac when maxTouchPoints is unavailable (older browsers)', () => {
    mockNavigator({ platform: 'MacIntel', maxTouchPoints: undefined });
    expect(getPlatform()).toBe(Platform.Mac);
  });

  it('detects Android via the user agent', () => {
    mockNavigator({
      platform: 'Linux armv8l',
      userAgent:
        'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36',
      maxTouchPoints: 5,
    });
    expect(getPlatform()).toBe(Platform.Android);
  });

  it('detects Windows', () => {
    mockNavigator({
      platform: 'Win32',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      maxTouchPoints: 0,
    });
    expect(getPlatform()).toBe(Platform.Windows);
  });
});

describe('isMobile', () => {
  it('treats an iPadOS-masquerading-as-Mac device as mobile', () => {
    mockNavigator({ platform: 'MacIntel', maxTouchPoints: 5 });
    expect(isMobile()).toBe(true);
  });

  it('does not treat a real Mac as mobile', () => {
    mockNavigator({ platform: 'MacIntel', maxTouchPoints: 0 });
    expect(isMobile()).toBe(false);
  });
});
