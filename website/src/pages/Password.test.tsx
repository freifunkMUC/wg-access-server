import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
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

vi.mock('../Api', () => ({
  grpc: { users: { changePassword: vi.fn() } },
}));

vi.mock('../components/Toast', () => ({ toast: vi.fn() }));

import { grpc } from '../Api';
import { AppState } from '../AppState';
import { toast } from '../components/Toast';
import { InfoRes } from '../sdk/server_pb';
import { Password } from './Password';

const changePassword = vi.mocked(grpc.users.changePassword);
const toasted = vi.mocked(toast);

// anchored: "New password" is also the start of nothing else, but
// "Repeat the new password" contains it
const field = (label: string) => screen.getByLabelText(new RegExp(`^${label}`, 'i'));

const fill = (label: string, value: string) => fireEvent.change(field(label), { target: { value } });

const button = () => screen.getByRole('button', { name: 'Change password' });

describe('changing your password', () => {
  beforeEach(() => {
    AppState.setInfo({ passwordChangeEnabled: true } as InfoRes.AsObject);
    changePassword.mockResolvedValue({ sessionsEnded: 0 });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('sends the two passwords once they are filled in', async () => {
    render(<Password />);

    fill('Current password', 'the-old-one');
    fill('New password', 'a-longer-new-one');
    fill('Repeat the new password', 'a-longer-new-one');
    fireEvent.click(button());

    await waitFor(() =>
      expect(changePassword).toHaveBeenCalledWith({
        currentPassword: 'the-old-one',
        newPassword: 'a-longer-new-one',
      }),
    );
    expect(toasted).toHaveBeenCalledWith(expect.objectContaining({ text: 'Password changed', intent: 'success' }));
  });

  it('says how many other browsers were signed out', async () => {
    changePassword.mockResolvedValue({ sessionsEnded: 2 });
    render(<Password />);

    fill('Current password', 'the-old-one');
    fill('New password', 'a-longer-new-one');
    fill('Repeat the new password', 'a-longer-new-one');
    fireEvent.click(button());

    await waitFor(() =>
      expect(toasted).toHaveBeenCalledWith(
        expect.objectContaining({ text: 'Password changed - 2 other sessions signed out' }),
      ),
    );
  });

  // the server refuses a short one, but being told before sending is kinder
  it('will not send a password that is too short', () => {
    render(<Password />);

    fill('Current password', 'the-old-one');
    fill('New password', 'short');
    fill('Repeat the new password', 'short');

    expect(screen.getByText(/At least 10 characters/)).toBeTruthy();
    expect(button()).toHaveProperty('disabled', true);
  });

  it('will not send two passwords that differ', () => {
    render(<Password />);

    fill('Current password', 'the-old-one');
    fill('New password', 'a-longer-new-one');
    fill('Repeat the new password', 'a-longer-other-one');

    expect(screen.getByText(/do not match/)).toBeTruthy();
    expect(button()).toHaveProperty('disabled', true);
  });

  it('shows what the server said and keeps what was typed', async () => {
    changePassword.mockRejectedValue(new Error('that is not your current password'));
    render(<Password />);

    fill('Current password', 'not-it');
    fill('New password', 'a-longer-new-one');
    fill('Repeat the new password', 'a-longer-new-one');
    fireEvent.click(button());

    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/not your current password/));
    // the form is still filled in, so nobody has to type it all again
    expect(field('New password')).toHaveProperty('value', 'a-longer-new-one');
  });

  it('empties the form once it worked, so the password is not left on screen', async () => {
    render(<Password />);

    fill('Current password', 'the-old-one');
    fill('New password', 'a-longer-new-one');
    fill('Repeat the new password', 'a-longer-new-one');
    fireEvent.click(button());

    await waitFor(() => expect(field('Current password')).toHaveProperty('value', ''));
    expect(field('New password')).toHaveProperty('value', '');
  });

  // with an identity provider there is nothing here to change
  it('says so when the server keeps no password for this account', () => {
    AppState.setInfo({ passwordChangeEnabled: false } as InfoRes.AsObject);
    render(<Password />);

    expect(screen.getByText(/not kept by this server/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Change password' })).toBeNull();
  });
});
