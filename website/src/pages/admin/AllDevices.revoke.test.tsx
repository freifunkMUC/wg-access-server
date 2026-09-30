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
import { InfoRes } from '../../sdk/server_pb';
import { AllDevices, count } from './AllDevices';

const listUsers = vi.mocked(grpc.users.listUsers);
const listAllDevices = vi.mocked(grpc.devices.listAllDevices);
const revokeAccess = vi.mocked(grpc.users.revokeAccess);
const deleteUser = vi.mocked(grpc.users.deleteUser);
const asked = vi.mocked(confirm);
const toasted = vi.mocked(toast);

const alice = {
  name: 'alice',
  displayName: 'Alice Example',
  policies: ['staff'],
} as User.AsObject;

const device = {
  name: 'laptop',
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
} as Device.AsObject;

function userRow() {
  const rows = screen.getAllByRole('row');
  const row = rows.find((r) => within(r).queryByRole('button', { name: 'Revoke access' }));
  if (!row) throw new Error('no user row with a revoke button');
  return row;
}

describe('count', () => {
  // "1 devices blocked" in a toast is the sort of thing people notice
  it('writes one thing in the singular and everything else in the plural', () => {
    expect(count(1, 'device')).toBe('1 device');
    expect(count(2, 'device')).toBe('2 devices');
    expect(count(0, 'session')).toBe('0 sessions');
    expect(count(1, 'API token')).toBe('1 API token');
  });
});

describe('revoking somebody"s access', () => {
  beforeEach(() => {
    AppState.clearLoadingError();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    AppState.setInfo({ isAdmin: true, subject: 'admin' } as InfoRes.AsObject);
    listUsers.mockResolvedValue({ items: [alice] });
    listAllDevices.mockResolvedValue({ items: [device] });
    revokeAccess.mockResolvedValue({ devicesBlocked: 2, tokensDeleted: 1, sessionsEnded: 3 });
    asked.mockResolvedValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    AppState.clearLoadingError();
  });

  it('asks first, then takes every way in and says what it took', async () => {
    render(<AllDevices />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Revoke access' })).toBeTruthy());

    fireEvent.click(within(userRow()).getByRole('button', { name: 'Revoke access' }));

    await waitFor(() => expect(revokeAccess).toHaveBeenCalledWith({ name: 'alice' }));
    // the question has to say that nothing is deleted, or nobody dares press it
    expect(asked.mock.calls[0][0]).toMatch(/Nothing is deleted/);
    expect(toasted).toHaveBeenCalledWith(
      expect.objectContaining({
        intent: 'success',
        text: 'Alice Example: 2 devices blocked, 1 API token revoked, 3 sessions ended',
      }),
    );
  });

  it('does nothing when the question is declined', async () => {
    asked.mockResolvedValue(false);
    render(<AllDevices />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Revoke access' })).toBeTruthy());

    fireEvent.click(within(userRow()).getByRole('button', { name: 'Revoke access' }));

    await waitFor(() => expect(asked).toHaveBeenCalled());
    expect(revokeAccess).not.toHaveBeenCalled();
  });

  it('shows the blocked devices without the page being reloaded', async () => {
    render(<AllDevices />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Revoke access' })).toBeTruthy());
    listAllDevices.mockResolvedValue({ items: [{ ...device, disabled: true }] });

    fireEvent.click(within(userRow()).getByRole('button', { name: 'Revoke access' }));

    await waitFor(() => expect(screen.getAllByText('Blocked').length).toBeGreaterThan(0));
  });

  it('says what went wrong instead of claiming success', async () => {
    revokeAccess.mockRejectedValue(new Error('the storage is gone'));
    render(<AllDevices />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Revoke access' })).toBeTruthy());

    fireEvent.click(within(userRow()).getByRole('button', { name: 'Revoke access' }));

    await waitFor(() =>
      expect(toasted).toHaveBeenCalledWith(
        expect.objectContaining({ intent: 'error', text: expect.stringContaining('the storage is gone') }),
      ),
    );
  });

  // pressing it on your own row would block your own devices and sign you out
  // halfway through, so it is not offered - the server refuses it as well
  it('does not offer to revoke your own access', async () => {
    listUsers.mockResolvedValue({
      items: [alice, { name: 'admin', displayName: 'The Admin', policies: [], twoFactor: false } as User.AsObject],
    });
    render(<AllDevices />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Revoke access' })).toBeTruthy());

    // alice's row offers it, the admin's own row does not - but deleting a
    // user stays on both
    expect(screen.getAllByRole('button', { name: 'Revoke access' })).toHaveLength(1);
    const ownRow = screen.getAllByRole('row').find((r) => within(r).queryByText('The Admin'));
    if (!ownRow) throw new Error('the admin has no row of their own');
    expect(within(ownRow).queryByRole('button', { name: 'Revoke access' })).toBeNull();
    expect(within(ownRow).queryByRole('button', { name: 'Delete' })).toBeTruthy();
  });

  it('keeps deleting a user a separate button', async () => {
    render(<AllDevices />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Revoke access' })).toBeTruthy());

    fireEvent.click(within(userRow()).getByRole('button', { name: 'Delete' }));

    await waitFor(() => expect(deleteUser).toHaveBeenCalledWith({ name: 'alice' }));
    expect(revokeAccess).not.toHaveBeenCalled();
  });
});
