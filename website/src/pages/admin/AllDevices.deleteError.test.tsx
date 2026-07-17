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
    devices: { listAllDevices: vi.fn(), listDevices: vi.fn(), addDevice: vi.fn(), deleteDevice: vi.fn() },
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
import { confirm } from '../../components/Present';
import { toast } from '../../components/Toast';
import { Device } from '../../sdk/devices_pb';
import { AllDevices } from './AllDevices';

const listUsers = vi.mocked(grpc.users.listUsers);
const deleteUser = vi.mocked(grpc.users.deleteUser);
const listAllDevices = vi.mocked(grpc.devices.listAllDevices);
const deleteDevice = vi.mocked(grpc.devices.deleteDevice);
const confirmMock = vi.mocked(confirm);
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
    ...overrides,
  } as Device.AsObject;
}

const deviceA = makeDevice({ name: 'device-a' });
const deviceB = makeDevice({ name: 'device-b' });

async function clickDeleteInRowWith(text: string) {
  const cell = await screen.findByText(text);
  const row = cell.closest('tr')!;
  fireEvent.click(within(row).getByRole('button', { name: 'Delete' }));
}

describe('AllDevices deletion', () => {
  beforeEach(() => {
    AppState.clearLoadingError();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    confirmMock.mockResolvedValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    AppState.clearLoadingError();
  });

  it('removes the device row after a successful delete', async () => {
    listUsers.mockResolvedValue({ items: [{ name: 'alice', displayName: 'Alice' }] });
    listAllDevices.mockResolvedValueOnce({ items: [deviceA, deviceB] }).mockResolvedValue({ items: [deviceB] });
    deleteDevice.mockResolvedValue({});

    render(<AllDevices />);
    await clickDeleteInRowWith('device-a');

    await waitFor(() => {
      expect(deleteDevice).toHaveBeenCalledWith({ name: 'device-a', owner: { value: 'alice' } });
    });
    await waitFor(() => {
      expect(screen.queryByText('device-a')).toBeNull();
    });
    expect(screen.getByText('device-b')).toBeTruthy();
    expect(toastMock).not.toHaveBeenCalled();
  });

  it('tells the admin and keeps the device row when the delete fails', async () => {
    listUsers.mockResolvedValue({ items: [{ name: 'alice', displayName: 'Alice' }] });
    listAllDevices.mockResolvedValue({ items: [deviceA, deviceB] });
    deleteDevice.mockRejectedValue(new Error('permission denied'));

    render(<AllDevices />);
    await clickDeleteInRowWith('device-a');

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith({
        text: 'Failed to delete the device: permission denied',
        intent: 'error',
      });
    });
    // no silent success: the device is still listed
    expect(screen.getByText('device-a')).toBeTruthy();
    // and the failed delete does not refresh the list as if it had worked
    expect(listAllDevices).toHaveBeenCalledTimes(1);
  });

  it('removes the user row after a successful user delete', async () => {
    listUsers
      .mockResolvedValueOnce({
        items: [
          { name: 'alice', displayName: 'Alice Doe' },
          { name: 'bob', displayName: 'Bob Roe' },
        ],
      })
      .mockResolvedValue({ items: [{ name: 'bob', displayName: 'Bob Roe' }] });
    listAllDevices.mockResolvedValue({ items: [deviceB] });
    deleteUser.mockResolvedValue({});

    render(<AllDevices />);
    await clickDeleteInRowWith('Alice Doe');

    await waitFor(() => {
      expect(deleteUser).toHaveBeenCalledWith({ name: 'alice' });
    });
    await waitFor(() => {
      expect(screen.queryByText('Alice Doe')).toBeNull();
    });
    expect(screen.getByText('Bob Roe')).toBeTruthy();
    expect(toastMock).not.toHaveBeenCalled();
  });

  it('tells the admin and keeps the user row when the user delete fails', async () => {
    listUsers.mockResolvedValue({ items: [{ name: 'alice', displayName: 'Alice Doe' }] });
    listAllDevices.mockResolvedValue({ items: [deviceB] });
    deleteUser.mockRejectedValue(new Error('backend down'));

    render(<AllDevices />);
    await clickDeleteInRowWith('Alice Doe');

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith({ text: 'Failed to delete the user: backend down', intent: 'error' });
    });
    expect(screen.getByText('Alice Doe')).toBeTruthy();
    expect(listUsers).toHaveBeenCalledTimes(1);
  });
});
