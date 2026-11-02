import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { ApiTokens, expiryFor, lifetimesWithin } from './ApiTokens';
import { grpc } from '../Api';
import { AppState } from '../AppState';
import { InfoRes } from '../sdk/server_pb';

vi.mock('../Api', async () => {
  const actual = await vi.importActual<typeof import('../Api')>('../Api');
  return {
    ...actual,
    grpc: {
      tokens: {
        listTokens: vi.fn(),
        listAllTokens: vi.fn(),
        createToken: vi.fn(),
        deleteToken: vi.fn(),
      },
    },
  };
});

vi.mock('../components/Toast', () => ({ toast: vi.fn() }));

const token = {
  id: 'abc',
  name: 'backup script',
  owner: 'alice',
  ownerName: 'Alice',
  createdAt: { seconds: 1_700_000_000, nanos: 0 },
};

function asAdmin(isAdmin: boolean) {
  AppState.setInfo({ isAdmin, apiTokensEnabled: true } as InfoRes.AsObject);
}

beforeEach(() => {
  vi.mocked(grpc.tokens.listTokens).mockResolvedValue({ items: [token] });
  vi.mocked(grpc.tokens.listAllTokens).mockResolvedValue({ items: [token, { ...token, id: 'def', owner: 'bob', ownerName: 'Bob' }] });
  vi.mocked(grpc.tokens.createToken).mockReset();
  asAdmin(false);
});

describe('expiryFor', () => {
  it('adds the lifetime in days', () => {
    const now = new Date('2026-01-01T00:00:00Z');
    expect(expiryFor(30, now)).toEqual(new Date('2026-01-31T00:00:00Z'));
  });

  it('has no expiry for "never"', () => {
    expect(expiryFor(0)).toBeUndefined();
  });
});

describe('lifetimesWithin', () => {
  const day = 24 * 60 * 60;

  it('offers everything without a cap', () => {
    expect(lifetimesWithin(undefined).map((l) => l.label)).toEqual(['30 days', '90 days', '1 year', 'Never']);
    expect(lifetimesWithin(0)).toHaveLength(4);
  });

  it('drops what is beyond the cap, and never', () => {
    expect(lifetimesWithin(100 * day).map((l) => l.label)).toEqual(['30 days', '90 days', '100 days']);
  });

  it('does not repeat a lifetime that is the cap', () => {
    expect(lifetimesWithin(90 * day).map((l) => l.label)).toEqual(['30 days', '90 days']);
  });

  it('offers the cap alone when it is short', () => {
    expect(lifetimesWithin(24 * 3600).map((l) => l.label)).toEqual(['1 day']);
    expect(lifetimesWithin(12 * 3600).map((l) => l.label)).toEqual(['12 hours']);
  });
});

describe('ApiTokens', () => {
  it('lists the own tokens', async () => {
    render(<ApiTokens />);
    expect(await screen.findByText('backup script')).toBeTruthy();
    expect(screen.getAllByText('Never')).toHaveLength(2); // does not expire, was never used
    expect(grpc.tokens.listAllTokens).not.toHaveBeenCalled();
  });

  it('shows admins every token with its owner', async () => {
    asAdmin(true);
    render(<ApiTokens />);
    expect(await screen.findByText('Bob')).toBeTruthy();
  });

  it('creates a token that expires in 90 days and shows its secret once', async () => {
    vi.mocked(grpc.tokens.createToken).mockResolvedValue({ secret: 'wgas_secret', token: undefined });
    render(<ApiTokens />);
    await screen.findByText('backup script');

    fireEvent.click(screen.getByRole('button', { name: /create token/i }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/name/i), { target: { value: 'ci' } });

    const before = Date.now();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }));

    expect(await screen.findByTestId('token-secret')).toHaveProperty('textContent', 'wgas_secret');
    const request = vi.mocked(grpc.tokens.createToken).mock.calls[0][0];
    expect(request.name).toBe('ci');
    const days = (request.expiresAt!.seconds * 1000 - before) / (24 * 60 * 60 * 1000);
    expect(Math.round(days)).toBe(90);

    fireEvent.click(screen.getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(screen.queryByTestId('token-secret')).toBeNull());
  });

  it('creates a token without expiry', async () => {
    vi.mocked(grpc.tokens.createToken).mockResolvedValue({ secret: 'wgas_secret', token: undefined });
    render(<ApiTokens />);
    await screen.findByText('backup script');

    fireEvent.click(screen.getByRole('button', { name: /create token/i }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/name/i), { target: { value: 'forever' } });
    fireEvent.mouseDown(within(dialog).getByRole('combobox'));
    fireEvent.click(await screen.findByRole('option', { name: 'Never' }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }));

    await screen.findByTestId('token-secret');
    expect(vi.mocked(grpc.tokens.createToken).mock.calls[0][0].expiresAt).toBeUndefined();
  });

  it('offers only lifetimes within the cap of the server', async () => {
    AppState.setInfo({ isAdmin: false, apiTokensEnabled: true, apiTokenMaxLifetime: { seconds: 7 * 24 * 3600, nanos: 0 } } as InfoRes.AsObject);
    vi.mocked(grpc.tokens.createToken).mockResolvedValue({ secret: 'wgas_secret', token: undefined });
    render(<ApiTokens />);
    await screen.findByText('backup script');

    fireEvent.click(screen.getByRole('button', { name: /create token/i }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.mouseDown(within(dialog).getByRole('combobox'));
    expect((await screen.findAllByRole('option')).map((o) => o.textContent)).toEqual(['7 days']);
    fireEvent.click(screen.getByRole('option', { name: '7 days' }));
    fireEvent.change(within(dialog).getByLabelText(/name/i), { target: { value: 'ci' } });

    const before = Date.now();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    await screen.findByTestId('token-secret');
    const request = vi.mocked(grpc.tokens.createToken).mock.calls[0][0];
    expect(Math.round((request.expiresAt!.seconds * 1000 - before) / (24 * 3600 * 1000))).toBe(7);
  });

  it('keeps the dialog open and shows why creating failed', async () => {
    vi.mocked(grpc.tokens.createToken).mockRejectedValue(new Error('a token needs a name'));
    render(<ApiTokens />);
    await screen.findByText('backup script');

    fireEvent.click(screen.getByRole('button', { name: /create token/i }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/name/i), { target: { value: ' ' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }));

    expect(await within(dialog).findByText('a token needs a name')).toBeTruthy();
    expect(screen.queryByTestId('token-secret')).toBeNull();
  });
});
