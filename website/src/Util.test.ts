import { describe, expect, it } from 'vitest';
import { accessRank, deviceAccess, errorMessage, lastSeen } from './Util';
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

describe('deviceAccess', () => {
  it('says nothing about a device that may connect and stays that way', () => {
    expect(deviceAccess({ disabled: false })).toBeUndefined();
  });

  it('reports a device an admin blocked', () => {
    expect(deviceAccess({ disabled: true })).toEqual({ blocked: true, label: 'Blocked' });
  });

  // a blocked device is blocked, whatever its expiry says
  it('prefers the block over the expiry date', () => {
    const inAnHour = new Date(Date.now() + 60 * 60 * 1000);
    expect(deviceAccess({ disabled: true, expiresAt: dateToTimestamp(inAnHour) })?.label).toBe('Blocked');
  });

  it('reports an expiry date that has passed', () => {
    const anHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    expect(deviceAccess({ expiresAt: dateToTimestamp(anHourAgo) })).toEqual({ blocked: true, label: 'Expired' });
  });

  // still connecting, but the admin should see it coming
  it('says when access is going to end', () => {
    const inTwoDays = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
    const access = deviceAccess({ expiresAt: dateToTimestamp(inTwoDays) });
    expect(access?.blocked).toBe(false);
    expect(access?.label).toMatch(/^Expires in 2 days$/);
  });
});

describe('accessRank', () => {
  // sorting the column descending has to bring the devices that cannot
  // connect to the top
  it('ranks blocked devices above the ones that only expire later', () => {
    const anHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const inTwoDays = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);

    expect(accessRank({ disabled: false })).toBe(0);
    expect(accessRank({ expiresAt: dateToTimestamp(inTwoDays) })).toBe(1);
    expect(accessRank({ expiresAt: dateToTimestamp(anHourAgo) })).toBe(2);
    expect(accessRank({ disabled: true })).toBe(2);
  });
});
