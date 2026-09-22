import { describe, expect, it, vi } from 'vitest';
import { sortByName } from './Devices';
import { Device } from '../sdk/devices_pb';

vi.mock('../Api', () => ({ grpc: {} }));

describe('sortByName', () => {
  it('sorts alphabetically, not by character code', () => {
    const devices = ['Tablet', 'iPhone', 'Home PC', 'laptop 10', 'laptop 2'].map(
      (name) => ({ name }) as Device.AsObject,
    );
    expect(sortByName(devices).map((d) => d.name)).toEqual(['Home PC', 'iPhone', 'laptop 2', 'laptop 10', 'Tablet']);
  });
});
