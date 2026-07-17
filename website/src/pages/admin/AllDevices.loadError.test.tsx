import { cleanup, render, screen } from '@testing-library/react';
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// AppState reads window.matchMedia at module load time; jsdom does not
// implement it, so stub it before any imports are evaluated.
vi.hoisted(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
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
});

vi.mock('../../Api', () => ({
  grpc: {
    server: { info: vi.fn() },
    users: { listUsers: vi.fn(), deleteUser: vi.fn() },
    devices: { listAllDevices: vi.fn(), listDevices: vi.fn(), addDevice: vi.fn(), deleteDevice: vi.fn() },
  },
  toDate: (t: { seconds: number }) => new Date(t.seconds * 1000),
  dateToTimestamp: (d: Date) => ({ seconds: Math.round(d.getTime() / 1000), nanos: 0 }),
}));

import { grpc } from '../../Api';
import { AppState } from '../../AppState';
import { AllDevices } from './AllDevices';
import { Device } from '../../sdk/devices_pb';

const listUsers = vi.mocked(grpc.users.listUsers);
const listAllDevices = vi.mocked(grpc.devices.listAllDevices);

function makeDevice(overrides: Partial<Device.AsObject> = {}): Device.AsObject {
  return {
    name: 'test-device',
    owner: 'alice',
    ownerName: 'Alice',
    ownerEmail: 'alice@example.com',
    ownerProvider: 'basic',
    publicKey: 'pubkey',
    presharedKey: '',
    address: '10.44.0.2/32',
    endpoint: '203.0.113.1:51820',
    connected: true,
    receiveBytes: 1024,
    transmitBytes: 2048,
    createdAt: undefined,
    updatedAt: undefined,
    lastHandshakeTime: undefined,
    ...overrides,
  } as Device.AsObject;
}

describe('AllDevices initial load', () => {
  beforeEach(() => {
    AppState.clearLoadingError();
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    AppState.clearLoadingError();
  });

  it('shows an error instead of the spinner when the device list fetch fails', async () => {
    listUsers.mockRejectedValue(new Error('rpc unavailable'));
    listAllDevices.mockRejectedValue(new Error('rpc unavailable'));

    render(<AllDevices />);

    // While the requests are in flight the loading state is shown.
    expect(screen.getByText('Loading...')).toBeTruthy();

    // Once the fetch rejects the error UI must replace the spinner.
    expect(await screen.findByText('Error loading the page')).toBeTruthy();
    expect(screen.getByText('rpc unavailable')).toBeTruthy();
    expect(screen.queryByText('Loading...')).toBeNull();
  });

  it('renders the device and user tables when the fetch succeeds', async () => {
    listUsers.mockResolvedValue({
      items: [{ name: 'alice', displayName: 'Alice Doe' }],
    });
    listAllDevices.mockResolvedValue({
      items: [
        makeDevice({ name: 'work-laptop', connected: true }),
        makeDevice({ name: 'phone', connected: false }),
      ],
    });

    render(<AllDevices />);

    expect(await screen.findByText('work-laptop')).toBeTruthy();
    expect(screen.getByText('phone')).toBeTruthy();
    expect(screen.getByText('Alice Doe')).toBeTruthy();
    // 1 of the 2 devices is connected.
    expect(screen.getByText(/\(1 of 2 online\)/)).toBeTruthy();
    // Neither the spinner nor the error UI is shown.
    expect(screen.queryByText('Loading...')).toBeNull();
    expect(screen.queryByText('Error loading the page')).toBeNull();
  });
});
