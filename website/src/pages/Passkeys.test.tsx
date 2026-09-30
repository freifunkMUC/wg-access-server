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
  grpc: {
    server: { info: vi.fn() },
    users: {
      listPasskeys: vi.fn(),
      beginPasskey: vi.fn(),
      finishPasskey: vi.fn(),
      renamePasskey: vi.fn(),
      deletePasskey: vi.fn(),
    },
  },
  toDate: (t: { seconds: number }) => new Date(t.seconds * 1000),
}));

vi.mock('../components/Present', () => ({ confirm: vi.fn(), prompt: vi.fn(), present: vi.fn() }));
vi.mock('../components/Toast', () => ({ toast: vi.fn() }));

import { grpc } from '../Api';
import { AppState } from '../AppState';
import { confirm, prompt } from '../components/Present';
import { toast } from '../components/Toast';
import { InfoRes } from '../sdk/server_pb';
import { Passkey } from '../sdk/users_pb';
import { Passkeys } from './Passkeys';

const list = vi.mocked(grpc.users.listPasskeys);
const begin = vi.mocked(grpc.users.beginPasskey);
const finish = vi.mocked(grpc.users.finishPasskey);
const renamed = vi.mocked(grpc.users.renamePasskey);
const remove = vi.mocked(grpc.users.deletePasskey);
const asked = vi.mocked(confirm);
const askedForName = vi.mocked(prompt);
const toasted = vi.mocked(toast);

const options = JSON.stringify({
  publicKey: {
    challenge: 'AQID',
    rp: { id: 'vpn.example.com', name: 'wg-access-server' },
    user: { id: 'BAUG', name: 'alice', displayName: 'Alice' },
  },
});

const aPasskey = (overrides: Partial<Passkey.AsObject> = {}): Passkey.AsObject =>
  ({
    id: 'passkey-1',
    name: 'The key on my keyring',
    createdAt: { seconds: Math.round(Date.now() / 1000), nanos: 0 },
    ...overrides,
  }) as Passkey.AsObject;

// what the browser would make
const made = {
  id: 'made-id',
  rawId: new Uint8Array([1, 2, 3]).buffer,
  type: 'public-key',
  response: {
    clientDataJSON: new Uint8Array([4, 5, 6]).buffer,
    attestationObject: new Uint8Array([7, 8, 9]).buffer,
  },
};

function setInfo(overrides: Partial<InfoRes.AsObject> = {}) {
  AppState.setInfo({
    passwordChangeEnabled: true,
    twoFactorEnabled: false,
    passkeys: 0,
    ...overrides,
  } as InfoRes.AsObject);
}

describe('passkeys', () => {
  beforeEach(() => {
    setInfo();
    list.mockResolvedValue({ items: [] });
    begin.mockResolvedValue({ options });
    finish.mockResolvedValue(aPasskey());
    renamed.mockResolvedValue(aPasskey({ name: 'My phone' }));
    remove.mockResolvedValue({});
    asked.mockResolvedValue(true);
    askedForName.mockResolvedValue('My phone');
    vi.mocked(grpc.server.info).mockImplementation(async () => AppState.info!);

    Object.defineProperty(window, 'isSecureContext', { writable: true, value: true });
    Object.defineProperty(window, 'PublicKeyCredential', { writable: true, value: function () {} });
    Object.defineProperty(navigator, 'credentials', {
      writable: true,
      configurable: true,
      value: { create: vi.fn().mockResolvedValue(made), get: vi.fn() },
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('adds one, sending what the browser made under the name given', async () => {
    render(<Passkeys />);
    await waitFor(() => expect(list).toHaveBeenCalled());

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'The key on my keyring' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add a passkey' }));

    await waitFor(() => expect(finish).toHaveBeenCalled());
    const sent = finish.mock.calls[0][0];
    expect(sent.name).toBe('The key on my keyring');
    expect(JSON.parse(sent.credential)).toEqual({
      id: 'made-id',
      rawId: 'AQID',
      type: 'public-key',
      response: { clientDataJSON: 'BAUG', attestationObject: 'BwgJ' },
    });

    // the browser was asked with the challenge decoded into bytes
    const create = vi.mocked(navigator.credentials.create);
    const asked = create.mock.calls[0][0]!.publicKey!;
    expect(new Uint8Array(asked.challenge as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(toasted).toHaveBeenCalledWith(expect.objectContaining({ text: 'Passkey added', intent: 'success' }));
  });

  it('shows what went wrong when the browser refuses', async () => {
    vi.mocked(navigator.credentials.create).mockRejectedValue(new Error('The operation was cancelled'));
    render(<Passkeys />);
    await waitFor(() => expect(list).toHaveBeenCalled());

    fireEvent.click(screen.getByRole('button', { name: 'Add a passkey' }));

    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/cancelled/));
    expect(finish).not.toHaveBeenCalled();
  });

  it('lists what is registered and removes one after asking', async () => {
    list.mockResolvedValue({ items: [aPasskey(), aPasskey({ id: 'passkey-2', name: 'My phone' })] });
    render(<Passkeys />);

    await screen.findByText('My phone');
    fireEvent.click(screen.getByRole('button', { name: 'Remove My phone' }));

    await waitFor(() => expect(remove).toHaveBeenCalledWith({ id: 'passkey-2' }));
    // two are registered, so removing one is not the last word on signing in
    expect(asked.mock.calls[0][0]).not.toMatch(/last one/);
  });

  it('renames one, offering the current name to edit', async () => {
    list.mockResolvedValue({ items: [aPasskey()] });
    render(<Passkeys />);

    await screen.findByText('The key on my keyring');
    fireEvent.click(screen.getByRole('button', { name: 'Rename The key on my keyring' }));

    await waitFor(() => expect(renamed).toHaveBeenCalledWith({ id: 'passkey-1', name: 'My phone' }));
    expect(askedForName.mock.calls[0][1]).toBe('The key on my keyring');
    // the list is read again, so the row shows the stored name rather than
    // what was typed
    expect(list).toHaveBeenCalledTimes(2);
  });

  it('asks nothing of the server when the rename is cancelled', async () => {
    askedForName.mockResolvedValue(null);
    list.mockResolvedValue({ items: [aPasskey()] });
    render(<Passkeys />);

    await screen.findByText('The key on my keyring');
    fireEvent.click(screen.getByRole('button', { name: 'Rename The key on my keyring' }));

    await waitFor(() => expect(askedForName).toHaveBeenCalled());
    expect(renamed).not.toHaveBeenCalled();
  });

  // a dialog somebody confirmed without typing is not a change worth a round
  // trip, and the toast would claim something happened
  it('asks nothing of the server when the name is unchanged', async () => {
    askedForName.mockResolvedValue('The key on my keyring');
    list.mockResolvedValue({ items: [aPasskey()] });
    render(<Passkeys />);

    await screen.findByText('The key on my keyring');
    fireEvent.click(screen.getByRole('button', { name: 'Rename The key on my keyring' }));

    await waitFor(() => expect(askedForName).toHaveBeenCalled());
    expect(renamed).not.toHaveBeenCalled();
    expect(toasted).not.toHaveBeenCalled();
  });

  it('says so when the rename fails', async () => {
    renamed.mockRejectedValue(new Error('no such passkey'));
    list.mockResolvedValue({ items: [aPasskey()] });
    render(<Passkeys />);

    await screen.findByText('The key on my keyring');
    fireEvent.click(screen.getByRole('button', { name: 'Rename The key on my keyring' }));

    await waitFor(() =>
      expect(toasted).toHaveBeenCalledWith(
        expect.objectContaining({ text: expect.stringMatching(/Failed to rename/), intent: 'error' }),
      ),
    );
  });

  // removing the last one takes the second factor away entirely, which the
  // question has to say
  it('warns when the last passkey is the last second factor', async () => {
    list.mockResolvedValue({ items: [aPasskey()] });
    render(<Passkeys />);

    await screen.findByText('The key on my keyring');
    fireEvent.click(screen.getByRole('button', { name: 'Remove The key on my keyring' }));

    await waitFor(() => expect(asked).toHaveBeenCalled());
    expect(asked.mock.calls[0][0]).toMatch(/last one/);
  });

  it('does not warn about the last one when an authenticator app is set up too', async () => {
    setInfo({ twoFactorEnabled: true });
    list.mockResolvedValue({ items: [aPasskey()] });
    render(<Passkeys />);

    await screen.findByText('The key on my keyring');
    fireEvent.click(screen.getByRole('button', { name: 'Remove The key on my keyring' }));

    await waitFor(() => expect(asked).toHaveBeenCalled());
    expect(asked.mock.calls[0][0]).not.toMatch(/last one/);
  });

  // over plain HTTP no browser will make a passkey, and a button that cannot
  // work is worse than one that explains itself
  it('says so when the browser cannot make a passkey here', async () => {
    Object.defineProperty(window, 'isSecureContext', { writable: true, value: false });
    render(<Passkeys />);
    await waitFor(() => expect(list).toHaveBeenCalled());

    expect(screen.getByText(/served over HTTPS/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Add a passkey' })).toHaveProperty('disabled', true);
  });

  it('shows nothing when the server keeps no sign-in for this account', () => {
    setInfo({ passwordChangeEnabled: false });
    const { container } = render(<Passkeys />);

    expect(container.textContent).toBe('');
  });
});
