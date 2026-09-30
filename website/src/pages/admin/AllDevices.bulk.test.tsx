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
    users: { listUsers: vi.fn(), deleteUser: vi.fn(), revokeAccess: vi.fn() },
    devices: {
      listAllDevices: vi.fn(),
      listDevices: vi.fn(),
      addDevice: vi.fn(),
      deleteDevice: vi.fn(),
      setDeviceAccess: vi.fn(),
      setDeviceRoutes: vi.fn(),
    },
  },
  toDate: (t: { seconds: number }) => new Date(t.seconds * 1000),
  dateToTimestamp: (d: Date) => ({ seconds: Math.round(d.getTime() / 1000), nanos: 0 }),
}));

vi.mock('../../components/Present', () => ({ confirm: vi.fn(), present: vi.fn() }));
vi.mock('../../components/Toast', () => ({ toast: vi.fn() }));

import { grpc } from '../../Api';
import { AppState } from '../../AppState';
import { confirm } from '../../components/Present';
import { toast } from '../../components/Toast';
import { Device } from '../../sdk/devices_pb';
import { User } from '../../sdk/users_pb';
import { AllDevices, deviceKey, runAll } from './AllDevices';

const listUsers = vi.mocked(grpc.users.listUsers);
const listAllDevices = vi.mocked(grpc.devices.listAllDevices);
const setDeviceAccess = vi.mocked(grpc.devices.setDeviceAccess);
const deleteDevice = vi.mocked(grpc.devices.deleteDevice);
const asked = vi.mocked(confirm);
const toasted = vi.mocked(toast);

function makeDevice(overrides: Partial<Device.AsObject> = {}): Device.AsObject {
  return {
    name: 'device',
    owner: 'alice',
    ownerName: 'Alice Example',
    ownerEmail: 'alice@example.com',
    ownerProvider: 'basic',
    publicKey: 'pubkey',
    presharedKey: '',
    address: '10.44.0.2/32',
    endpoint: '',
    connected: false,
    receiveBytes: 0,
    transmitBytes: 0,
    disabled: false,
    routes: [],
    ...overrides,
  } as Device.AsObject;
}

describe('deviceKey', () => {
  // two users may both call a device "laptop", and a bulk action must not act
  // on the wrong one of them
  it('tells the devices of two users apart', () => {
    expect(deviceKey({ owner: 'alice', name: 'laptop' })).not.toBe(deviceKey({ owner: 'bob', name: 'laptop' }));
  });
});

describe('runAll', () => {
  it('reports what worked and what did not, and does not stop at a failure', async () => {
    const seen: number[] = [];
    const result = await runAll([1, 2, 3, 4, 5], async (n) => {
      seen.push(n);
      if (n % 2 === 0) throw new Error('no');
    });

    expect(result).toEqual({ done: 3, failed: 2 });
    expect(seen.sort()).toEqual([1, 2, 3, 4, 5]);
  });

  it('keeps only a few requests in flight at a time', async () => {
    let running = 0;
    let most = 0;
    await runAll(
      Array.from({ length: 20 }, (_, i) => i),
      async () => {
        running++;
        most = Math.max(most, running);
        await new Promise((r) => setTimeout(r, 1));
        running--;
      },
      5,
    );

    expect(most).toBeLessThanOrEqual(5);
  });

  it('does nothing with nothing', async () => {
    const action = vi.fn();
    expect(await runAll([], action)).toEqual({ done: 0, failed: 0 });
    expect(action).not.toHaveBeenCalled();
  });
});

describe('acting on several devices at once', () => {
  const devices = [
    makeDevice({ name: 'alice-laptop', owner: 'alice' }),
    makeDevice({ name: 'bob-phone', owner: 'bob', ownerName: 'Bob Roe', ownerEmail: 'bob@example.com' }),
    makeDevice({ name: 'carol-tablet', owner: 'carol', ownerName: 'Carol', ownerEmail: 'carol@example.com' }),
  ];

  beforeEach(() => {
    AppState.clearLoadingError();
    AppState.setInfo({ isAdmin: true, subject: 'admin' } as never);
    vi.spyOn(console, 'error').mockImplementation(() => {});
    listUsers.mockResolvedValue({ items: [{ name: 'alice', displayName: 'Alice Example' } as User.AsObject] });
    listAllDevices.mockResolvedValue({ items: devices });
    setDeviceAccess.mockResolvedValue(makeDevice());
    deleteDevice.mockResolvedValue({});
    asked.mockResolvedValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    AppState.clearLoadingError();
  });

  const select = (name: string) => fireEvent.click(screen.getByLabelText(new RegExp(`^Select ${name} `)));

  it('offers nothing until something is ticked', async () => {
    render(<AllDevices />);
    await screen.findByText('alice-laptop');

    expect(screen.queryByText(/selected/)).toBeNull();

    select('alice-laptop');

    expect(screen.getByText('1 device selected')).toBeTruthy();
  });

  it('blocks everything that is ticked and says how many', async () => {
    render(<AllDevices />);
    await screen.findByText('alice-laptop');

    select('alice-laptop');
    select('carol-tablet');
    fireEvent.click(screen.getByRole('button', { name: 'Block selected' }));

    await waitFor(() => expect(setDeviceAccess).toHaveBeenCalledTimes(2));
    expect(setDeviceAccess).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'alice-laptop', owner: { value: 'alice' }, disabled: { value: true } }),
    );
    expect(setDeviceAccess).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'carol-tablet', owner: { value: 'carol' }, disabled: { value: true } }),
    );
    // the one that was not ticked is left alone
    expect(setDeviceAccess).not.toHaveBeenCalledWith(expect.objectContaining({ name: 'bob-phone' }));

    expect(toasted).toHaveBeenCalledWith(expect.objectContaining({ text: '2 devices blocked', intent: 'success' }));
    // and the selection is gone, so the next click cannot repeat it by accident
    await waitFor(() => expect(screen.queryByText(/selected/)).toBeNull());
  });

  it('unblocks what is ticked', async () => {
    render(<AllDevices />);
    await screen.findByText('alice-laptop');

    select('bob-phone');
    fireEvent.click(screen.getByRole('button', { name: 'Unblock selected' }));

    await waitFor(() =>
      expect(setDeviceAccess).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'bob-phone', disabled: { value: false } }),
      ),
    );
    expect(toasted).toHaveBeenCalledWith(expect.objectContaining({ text: '1 device unblocked' }));
  });

  it('deletes what is ticked, after saying that it cannot be undone', async () => {
    render(<AllDevices />);
    await screen.findByText('alice-laptop');

    select('alice-laptop');
    fireEvent.click(screen.getByRole('button', { name: 'Delete selected' }));

    await waitFor(() => expect(deleteDevice).toHaveBeenCalledWith({ name: 'alice-laptop', owner: { value: 'alice' } }));
    expect(asked.mock.calls[0][0]).toMatch(/cannot be undone/);
  });

  it('does nothing when the question is declined', async () => {
    asked.mockResolvedValue(false);
    render(<AllDevices />);
    await screen.findByText('alice-laptop');

    select('alice-laptop');
    fireEvent.click(screen.getByRole('button', { name: 'Block selected' }));

    await waitFor(() => expect(asked).toHaveBeenCalled());
    expect(setDeviceAccess).not.toHaveBeenCalled();
    // ... and what was ticked stays ticked, so it can be acted on after all
    expect(screen.getByText('1 device selected')).toBeTruthy();
  });

  it('says how many did not work instead of claiming they all did', async () => {
    setDeviceAccess.mockRejectedValueOnce(new Error('gone')).mockResolvedValue(makeDevice());
    render(<AllDevices />);
    await screen.findByText('alice-laptop');

    fireEvent.click(screen.getByLabelText('Select every device shown'));
    fireEvent.click(screen.getByRole('button', { name: 'Block selected' }));

    await waitFor(() => expect(setDeviceAccess).toHaveBeenCalledTimes(3));
    expect(toasted).toHaveBeenCalledWith(
      expect.objectContaining({ text: '2 devices blocked, 1 failed', intent: 'error' }),
    );
  });

  it('ticks everything the search leaves, not only what is on the page', async () => {
    const many = Array.from({ length: 60 }, (_, i) => makeDevice({ name: `device-${String(i).padStart(2, '0')}` }));
    listAllDevices.mockResolvedValue({ items: many });
    render(<AllDevices />);
    await screen.findByText('device-00');

    fireEvent.click(screen.getByLabelText('Select every device shown'));

    // 60 devices, 25 rows on the page
    expect(screen.getByText('60 devices selected')).toBeTruthy();
  });

  it('forgets what was ticked when the search changes', async () => {
    render(<AllDevices />);
    await screen.findByText('alice-laptop');

    select('alice-laptop');
    expect(screen.getByText('1 device selected')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Search devices'), { target: { value: 'bob' } });

    await waitFor(() => expect(screen.queryByText(/selected/)).toBeNull());
  });

  it('clears the selection on request', async () => {
    render(<AllDevices />);
    await screen.findByText('alice-laptop');

    select('alice-laptop');
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));

    await waitFor(() => expect(screen.queryByText(/selected/)).toBeNull());
  });

  // the row buttons are still there for a single device
  it('leaves the single-device actions alone', async () => {
    render(<AllDevices />);
    await screen.findByText('alice-laptop');

    const row = screen.getAllByRole('row').find((r) => within(r).queryByText('alice-laptop'));
    expect(within(row!).getByRole('button', { name: 'Block' })).toBeTruthy();
    expect(within(row!).getByRole('button', { name: 'Expiry' })).toBeTruthy();
  });
});
