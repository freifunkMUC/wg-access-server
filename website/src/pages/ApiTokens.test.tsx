import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { ApiTokens, expiryFor } from './ApiTokens';
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
