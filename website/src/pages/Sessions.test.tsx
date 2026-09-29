import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../Api', () => ({
  grpc: {
    sessions: { listSessions: vi.fn(), deleteSession: vi.fn(), deleteOtherSessions: vi.fn() },
  },
  toDate: (t: { seconds: number }) => new Date(t.seconds * 1000),
}));

vi.mock('../components/Present', () => ({ confirm: vi.fn() }));
vi.mock('../components/Toast', () => ({ toast: vi.fn() }));

import { grpc } from '../Api';
import { confirm } from '../components/Present';
import { toast } from '../components/Toast';
import { Session } from '../sdk/sessions_pb';
import { describeAgent, Sessions } from './Sessions';

const listSessions = vi.mocked(grpc.sessions.listSessions);
const deleteSession = vi.mocked(grpc.sessions.deleteSession);
const deleteOtherSessions = vi.mocked(grpc.sessions.deleteOtherSessions);
const asked = vi.mocked(confirm);
const toasted = vi.mocked(toast);

const seconds = (date: string) => ({ seconds: Math.round(new Date(date).getTime() / 1000), nanos: 0 });

function makeSession(overrides: Partial<Session.AsObject> = {}): Session.AsObject {
  return {
    id: 'session-1',
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/128.0',
    remoteAddr: '192.0.2.10',
    createdAt: seconds('2026-09-01T10:00:00Z'),
    lastSeenAt: seconds('2026-09-01T10:00:00Z'),
    expiresAt: seconds('2026-10-01T10:00:00Z'),
    current: false,
    ...overrides,
  } as Session.AsObject;
}

const here = makeSession({ id: 'here', current: true });
const phone = makeSession({
  id: 'phone',
  userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Safari/604.1',
  remoteAddr: '198.51.100.7',
});

describe('describeAgent', () => {
  // the browser is what somebody matches against the devices in front of them,
  // and every one of these strings claims to be something it is not
  it.each([
    ['Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0', 'Firefox on Linux'],
    [
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/127.0 Safari/537.36',
      'Chrome on macOS',
    ],
    [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/127.0 Safari/537.36 Edg/127.0',
      'Edge on Windows',
    ],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Safari/604.1', 'Safari on iPhone'],
    ['Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/127.0 Mobile Safari/537.36', 'Chrome on Android'],
  ])('names the browser and the platform: %s', (agent, want) => {
    expect(describeAgent(agent)).toBe(want);
  });

  it('says so when there is no user agent at all', () => {
    expect(describeAgent('')).toBe('Unknown browser');
    expect(describeAgent('   ')).toBe('Unknown browser');
  });

  it('shows an agent it does not know as it came', () => {
    expect(describeAgent('curl/8.5.0')).toBe('curl/8.5.0');
  });

  it('shortens a long unknown agent instead of filling the row', () => {
    const long = 'x'.repeat(200);
    const shown = describeAgent(long);
    expect(shown.length).toBeLessThan(long.length);
    expect(shown.endsWith('…')).toBe(true);
  });
});

describe('Sessions', () => {
  beforeEach(() => {
    listSessions.mockResolvedValue({ items: [here, phone] });
    deleteSession.mockResolvedValue({});
    deleteOtherSessions.mockResolvedValue({ ended: 1 });
    asked.mockResolvedValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('marks the session doing the asking and offers no button for it', async () => {
    render(<Sessions />);
    await screen.findByText('Safari on iPhone');

    const rows = screen.getAllByRole('row');
    const current = rows.find((row) => within(row).queryByText('This browser'));
    expect(current).toBeTruthy();
    expect(within(current!).queryByRole('button')).toBeNull();

    expect(screen.getByRole('button', { name: /Sign out of Safari on iPhone/ })).toBeTruthy();
    expect(screen.getByText('198.51.100.7')).toBeTruthy();
  });

  it('ends one session after asking, and reloads', async () => {
    render(<Sessions />);
    await screen.findByText('Safari on iPhone');

    fireEvent.click(screen.getByRole('button', { name: /Sign out of Safari on iPhone/ }));

    await waitFor(() => expect(deleteSession).toHaveBeenCalledWith({ id: 'phone' }));
    expect(asked).toHaveBeenCalled();
    expect(listSessions).toHaveBeenCalledTimes(2);
  });

  it('ends nothing when the question is declined', async () => {
    asked.mockResolvedValue(false);
    render(<Sessions />);
    await screen.findByText('Safari on iPhone');

    fireEvent.click(screen.getByRole('button', { name: /Sign out of Safari on iPhone/ }));

    await waitFor(() => expect(asked).toHaveBeenCalled());
    expect(deleteSession).not.toHaveBeenCalled();
  });

  it('signs out everywhere else and says how many that was', async () => {
    deleteOtherSessions.mockResolvedValue({ ended: 3 });
    render(<Sessions />);
    await screen.findByText('Safari on iPhone');

    fireEvent.click(screen.getByRole('button', { name: /Sign out everywhere else/ }));

    await waitFor(() => expect(deleteOtherSessions).toHaveBeenCalled());
    expect(toasted).toHaveBeenCalledWith(expect.objectContaining({ text: 'Signed out of 3 other sessions' }));
  });

  it('has nothing to sign out of with only this browser left', async () => {
    listSessions.mockResolvedValue({ items: [here] });
    render(<Sessions />);
    await screen.findByText('This browser');

    expect(screen.getByRole('button', { name: /Sign out everywhere else/ })).toHaveProperty('disabled', true);
  });

  it('shows what went wrong instead of an empty page', async () => {
    listSessions.mockRejectedValue(new Error('no'));
    render(<Sessions />);

    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('no'));
  });

  it('tells a failed sign-out apart from a successful one', async () => {
    deleteSession.mockRejectedValue(new Error('gone wrong'));
    render(<Sessions />);
    await screen.findByText('Safari on iPhone');

    fireEvent.click(screen.getByRole('button', { name: /Sign out of Safari on iPhone/ }));

    await waitFor(() =>
      expect(toasted).toHaveBeenCalledWith(
        expect.objectContaining({ intent: 'error', text: expect.stringContaining('gone wrong') }),
      ),
    );
  });
});
