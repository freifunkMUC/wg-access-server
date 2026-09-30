import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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
    users: { listUsers: vi.fn(), deleteUser: vi.fn(), revokeAccess: vi.fn(), resetTwoFactor: vi.fn() },
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
import { User } from '../../sdk/users_pb';
import { AllDevices } from './AllDevices';

const listUsers = vi.mocked(grpc.users.listUsers);
const listAllDevices = vi.mocked(grpc.devices.listAllDevices);
const resetTwoFactor = vi.mocked(grpc.users.resetTwoFactor);
const asked = vi.mocked(confirm);
const toasted = vi.mocked(toast);

const withTwoFactor = { name: 'alice', displayName: 'Alice Example', policies: [], twoFactor: true } as User.AsObject;
const without = { name: 'bob', displayName: 'Bob Roe', policies: [], twoFactor: false } as User.AsObject;

const rowOf = (name: string) => {
  const row = screen.getAllByRole('row').find((r) => within(r).queryByText(name));
  if (!row) throw new Error(`no row for ${name}`);
  return row;
};

describe('the second factor in the admin user list', () => {
  beforeEach(() => {
    AppState.clearLoadingError();
    AppState.setInfo({ isAdmin: true, subject: 'admin' } as never);
    vi.spyOn(console, 'error').mockImplementation(() => {});
    listUsers.mockResolvedValue({ items: [withTwoFactor, without] });
    listAllDevices.mockResolvedValue({ items: [] });
    resetTwoFactor.mockResolvedValue({});
    asked.mockResolvedValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    AppState.clearLoadingError();
  });

  it('shows who has one, and offers the reset only for them', async () => {
    render(<AllDevices />);
    await screen.findByText('Alice Example');

    expect(within(rowOf('Alice Example')).getByText('On')).toBeTruthy();
    expect(within(rowOf('Alice Example')).getByRole('button', { name: 'Reset 2FA' })).toBeTruthy();
    expect(within(rowOf('Bob Roe')).queryByRole('button', { name: 'Reset 2FA' })).toBeNull();
  });

  it('resets it after asking, and says what that means', async () => {
    render(<AllDevices />);
    await screen.findByText('Alice Example');

    fireEvent.click(within(rowOf('Alice Example')).getByRole('button', { name: 'Reset 2FA' }));

    await waitFor(() => expect(resetTwoFactor).toHaveBeenCalledWith({ name: 'alice' }));
    // the question has to say that a password alone then signs them in
    expect(asked.mock.calls[0][0]).toMatch(/password alone/);
    expect(toasted).toHaveBeenCalledWith(expect.objectContaining({ intent: 'success' }));
  });

  it('does nothing when the question is declined', async () => {
    asked.mockResolvedValue(false);
    render(<AllDevices />);
    await screen.findByText('Alice Example');

    fireEvent.click(within(rowOf('Alice Example')).getByRole('button', { name: 'Reset 2FA' }));

    await waitFor(() => expect(asked).toHaveBeenCalled());
    expect(resetTwoFactor).not.toHaveBeenCalled();
  });

  it('says what went wrong instead of claiming it worked', async () => {
    resetTwoFactor.mockRejectedValue(new Error('this user has no second factor'));
    render(<AllDevices />);
    await screen.findByText('Alice Example');

    fireEvent.click(within(rowOf('Alice Example')).getByRole('button', { name: 'Reset 2FA' }));

    await waitFor(() =>
      expect(toasted).toHaveBeenCalledWith(
        expect.objectContaining({ intent: 'error', text: expect.stringContaining('no second factor') }),
      ),
    );
  });
});
