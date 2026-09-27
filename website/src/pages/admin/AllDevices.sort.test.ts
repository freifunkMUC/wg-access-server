import { describe, expect, it, vi } from 'vitest';
import { sortDevices } from './AllDevices';
import { Device } from '../../sdk/devices_pb';

vi.mock('../../Api', () => ({ grpc: {}, toDate: (t: { seconds: number }) => new Date(t.seconds * 1000) }));

function device(overrides: Partial<Device.AsObject>): Device.AsObject {
  return { name: 'device', ownerName: 'owner', connected: false, ...overrides } as Device.AsObject;
}

describe('sortDevices', () => {
  it('has nothing to sort without devices', () => {
    expect(sortDevices(undefined, 'name', 'asc')).toEqual([]);
    expect(sortDevices(null, 'name', 'asc')).toEqual([]);
  });

  it('sorts by a column of the device, in both directions', () => {
    const devices = ['laptop', 'iPhone', 'Home PC'].map((name) => device({ name }));
    expect(sortDevices(devices, 'name', 'asc').map((d) => d.name)).toEqual(['Home PC', 'iPhone', 'laptop']);
    expect(sortDevices(devices, 'name', 'desc').map((d) => d.name)).toEqual(['laptop', 'iPhone', 'Home PC']);
  });

  it('leaves the devices it was given alone', () => {
    const devices = [device({ name: 'b' }), device({ name: 'a' })];
    sortDevices(devices, 'name', 'asc');
    expect(devices.map((d) => d.name)).toEqual(['b', 'a']);
  });

  it('sorts the connected ones together, although the column is a boolean', () => {
    const devices = [device({ name: 'off' }), device({ name: 'on', connected: true })];
    expect(sortDevices(devices, 'connected', 'desc').map((d) => d.name)).toEqual(['on', 'off']);
  });

  it('sorts by the traffic columns, which are not the column names', () => {
    const devices = [
      device({ name: 'quiet', transmitBytes: 10, receiveBytes: 900 }),
      device({ name: 'busy', transmitBytes: 100, receiveBytes: 9 }),
    ];
    expect(sortDevices(devices, 'download', 'desc').map((d) => d.name)).toEqual(['busy', 'quiet']);
    expect(sortDevices(devices, 'upload', 'desc').map((d) => d.name)).toEqual(['quiet', 'busy']);
  });

  it('treats a device that never connected as the oldest handshake', () => {
    const devices = [
      device({ name: 'never' }),
      device({ name: 'recent', lastHandshakeTime: { seconds: 100, nanos: 0 } }),
    ];
    expect(sortDevices(devices, 'lastHandshakeTime', 'desc').map((d) => d.name)).toEqual(['recent', 'never']);
  });

  // A device without a value for the column sorts to the end of an ascending
  // table and to the top of a descending one, like an empty string would.
  it('sorts a device without a value for the column to the end of the ascending table', () => {
    const devices = [device({ name: 'a', endpoint: undefined }), device({ name: 'b', endpoint: '10.0.0.1:51820' })];
    expect(sortDevices(devices, 'endpoint', 'asc').map((d) => d.name)).toEqual(['b', 'a']);
    expect(sortDevices(devices, 'endpoint', 'desc').map((d) => d.name)).toEqual(['a', 'b']);
  });
});
