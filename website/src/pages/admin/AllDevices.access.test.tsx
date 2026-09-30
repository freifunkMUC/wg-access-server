import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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
    devices: {
      listAllDevices: vi.fn(),
      listDevices: vi.fn(),
      addDevice: vi.fn(),
      deleteDevice: vi.fn(),
      setDeviceAccess: vi.fn(),
    },
  },
  toDate: (t: { seconds: number }) => new Date(t.seconds * 1000),
  dateToTimestamp: (d: Date) => ({ seconds: Math.round(d.getTime() / 1000), nanos: 0 }),
}));

vi.mock('../../components/Present', () => ({
  confirm: vi.fn(),
  present: vi.fn(),
}));

vi.mock('../../components/Toast', () => ({ toast: vi.fn() }));

import { grpc } from '../../Api';
import { AppState } from '../../AppState';
import { toast } from '../../components/Toast';
import { Device } from '../../sdk/devices_pb';
import { AllDevices, endOfDay, isoDay } from './AllDevices';

const listUsers = vi.mocked(grpc.users.listUsers);
const listAllDevices = vi.mocked(grpc.devices.listAllDevices);
const setDeviceAccess = vi.mocked(grpc.devices.setDeviceAccess);
const toastMock = vi.mocked(toast);

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
    connected: false,
    receiveBytes: 1024,
    transmitBytes: 2048,
    disabled: false,
    ...overrides,
  } as Device.AsObject;
}

function clickInRowWith(text: string, button: string) {
  const row = screen.getByText(text).closest('tr')!;
  fireEvent.click(within(row).getByRole('button', { name: button }));
}

describe('AllDevices access', () => {
  beforeEach(() => {
    AppState.clearLoadingError();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    listUsers.mockResolvedValue({ items: [{ name: 'alice', displayName: 'Alice', policies: [], twoFactor: false }] });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    AppState.clearLoadingError();
  });

  it('blocks a device without touching its expiry date', async () => {
    const device = makeDevice({ name: 'device-a' });
    listAllDevices.mockResolvedValue({ items: [device] });
    setDeviceAccess.mockResolvedValue(device);

    render(<AllDevices />);
    await screen.findByText('device-a');
    clickInRowWith('device-a', 'Block');

    await waitFor(() => {
      expect(setDeviceAccess).toHaveBeenCalledWith({
        name: 'device-a',
        owner: { value: 'alice' },
        clearExpiresAt: false,
        disabled: { value: true },
      });
    });
  });

  it('offers to unblock a device that is blocked, and shows why it cannot connect', async () => {
    const device = makeDevice({ name: 'device-a', disabled: true });
    listAllDevices.mockResolvedValue({ items: [device] });
    setDeviceAccess.mockResolvedValue({ ...device, disabled: false });

    render(<AllDevices />);
    await screen.findByText('device-a');
    expect(screen.getByText('Blocked')).toBeTruthy();

    clickInRowWith('device-a', 'Unblock');

    await waitFor(() => {
      expect(setDeviceAccess).toHaveBeenCalledWith({
        name: 'device-a',
        owner: { value: 'alice' },
        clearExpiresAt: false,
        disabled: { value: false },
      });
    });
  });

  it('sends the end of the picked day as the expiry date', async () => {
    const device = makeDevice({ name: 'device-a' });
    listAllDevices.mockResolvedValue({ items: [device] });
    setDeviceAccess.mockResolvedValue(device);

    render(<AllDevices />);
    await screen.findByText('device-a');
    clickInRowWith('device-a', 'Expiry');

    const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000);
    fireEvent.change(await screen.findByLabelText('Access ends'), { target: { value: isoDay(tomorrow) } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(setDeviceAccess).toHaveBeenCalledTimes(1);
    });
    const request = setDeviceAccess.mock.calls[0][0];
    expect(request.name).toBe('device-a');
    expect(request.clearExpiresAt).toBe(false);
    expect(request.expiresAt?.seconds).toBe(Math.round(endOfDay(isoDay(tomorrow))!.getTime() / 1000));
  });

  it('removes an expiry date that is set', async () => {
    const inTwoDays = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
    const device = makeDevice({
      name: 'device-a',
      expiresAt: { seconds: Math.round(inTwoDays.getTime() / 1000), nanos: 0 },
    });
    listAllDevices.mockResolvedValue({ items: [device] });
    setDeviceAccess.mockResolvedValue(makeDevice({ name: 'device-a' }));

    render(<AllDevices />);
    await screen.findByText('device-a');
    expect(screen.getByText(/^Expires in 2 days$/)).toBeTruthy();

    clickInRowWith('device-a', 'Expiry');
    fireEvent.click(await screen.findByRole('button', { name: 'Remove expiry' }));

    await waitFor(() => {
      expect(setDeviceAccess).toHaveBeenCalledWith({
        name: 'device-a',
        owner: { value: 'alice' },
        clearExpiresAt: true,
      });
    });
  });

  it('tells the admin when the change was refused', async () => {
    const device = makeDevice({ name: 'device-a' });
    listAllDevices.mockResolvedValue({ items: [device] });
    setDeviceAccess.mockRejectedValue(new Error('permission denied'));

    render(<AllDevices />);
    await screen.findByText('device-a');
    clickInRowWith('device-a', 'Block');

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith({
        text: 'Failed to change the access of the device: permission denied',
        intent: 'error',
      });
    });
    // the list is not refreshed as if the change had worked
    expect(listAllDevices).toHaveBeenCalledTimes(1);
  });
});

describe('endOfDay', () => {
  it('turns the picked day into its last second in local time', () => {
    const at = endOfDay('2030-03-01')!;
    expect([at.getFullYear(), at.getMonth(), at.getDate()]).toEqual([2030, 2, 1]);
    expect([at.getHours(), at.getMinutes(), at.getSeconds()]).toEqual([23, 59, 59]);
  });

  // the server refuses an expiry in the past, so the dialog must not offer it
  it('rejects a day that has passed, and anything that is not a day', () => {
    expect(endOfDay('')).toBeUndefined();
    expect(endOfDay('tomorrow')).toBeUndefined();
    expect(endOfDay('2020-01-01')).toBeUndefined();
  });
});

describe('isoDay', () => {
  // toISOString would name the previous day west of UTC
  it('formats a date in local time', () => {
    expect(isoDay(new Date(2030, 0, 1, 0, 30))).toBe('2030-01-01');
    expect(isoDay(new Date(2030, 11, 31, 23, 30))).toBe('2030-12-31');
  });
});
