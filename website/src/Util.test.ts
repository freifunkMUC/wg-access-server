import { describe, expect, it } from 'vitest';
import { errorMessage, lastSeen } from './Util';
import { dateToTimestamp } from './Api';

describe('errorMessage', () => {
  // gRPC-web errors are plain objects with a message, not Error instances
  it('reads the message of an error-like object', () => {
    expect(errorMessage({ code: 2, message: 'Device name already taken.' })).toBe('Device name already taken.');
  });

  it('reads the message of an Error', () => {
    expect(errorMessage(new Error('boom'))).toBe('boom');
  });

  it('falls back to the string form of anything else', () => {
    expect(errorMessage('plain string')).toBe('plain string');
    expect(errorMessage(undefined)).toBe('undefined');
  });
});

describe('lastSeen', () => {
  it('reports a device that never connected', () => {
    expect(lastSeen(undefined)).toBe('Never');
  });

  it('describes how long ago the handshake was', () => {
    const anHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    expect(lastSeen(dateToTimestamp(anHourAgo))).toMatch(/hour ago$/);
  });
});
