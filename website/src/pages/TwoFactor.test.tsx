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
      startTwoFactor: vi.fn(),
      confirmTwoFactor: vi.fn(),
      disableTwoFactor: vi.fn(),
      newRecoveryCodes: vi.fn(),
    },
  },
}));

vi.mock('../components/Toast', () => ({ toast: vi.fn() }));
// drawing a QR code needs a canvas; what matters here is what goes into it
vi.mock('../components/QRCode', () => ({
  QRCode: ({ content }: { content: string }) => <div data-testid="qr">{content}</div>,
}));

import { grpc } from '../Api';
import { AppState } from '../AppState';
import { InfoRes } from '../sdk/server_pb';
import { TwoFactor } from './TwoFactor';

const start = vi.mocked(grpc.users.startTwoFactor);
const confirm = vi.mocked(grpc.users.confirmTwoFactor);
const disable = vi.mocked(grpc.users.disableTwoFactor);
const newCodes = vi.mocked(grpc.users.newRecoveryCodes);
const info = vi.mocked(grpc.server.info);

const secret = 'JBSWY3DPEHPK3PXP';
const uri = `otpauth://totp/vpn.example.com:alice?secret=${secret}&issuer=vpn.example.com`;

function setInfo(overrides: Partial<InfoRes.AsObject> = {}) {
  AppState.setInfo({
    passwordChangeEnabled: true,
    twoFactorEnabled: false,
    recoveryCodesLeft: 0,
    ...overrides,
  } as InfoRes.AsObject);
}

describe('two-factor authentication', () => {
  beforeEach(() => {
    setInfo();
    start.mockResolvedValue({ secret, uri });
    confirm.mockResolvedValue({ recoveryCodes: ['AAAA-BBBB', 'CCCC-DDDD'] });
    disable.mockResolvedValue({});
    info.mockImplementation(async () => AppState.info!);
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('offers the setup and shows the QR code and the secret', async () => {
    render(<TwoFactor />);

    fireEvent.click(screen.getByRole('button', { name: 'Set up two-factor' }));

    await waitFor(() => expect(screen.getByTestId('qr').textContent).toBe(uri));
    // for a phone that cannot scan
    expect(screen.getByTestId('totp-secret').textContent).toBe(secret);
    // nothing is on yet, so nobody is locked out by walking away here
    expect(screen.queryByRole('button', { name: 'Turn it off' })).toBeNull();
  });

  it('turns it on with a code and shows the recovery codes once', async () => {
    info.mockImplementation(async () => {
      setInfo({ twoFactorEnabled: true, recoveryCodesLeft: 2 });
      return AppState.info!;
    });
    render(<TwoFactor />);

    fireEvent.click(screen.getByRole('button', { name: 'Set up two-factor' }));
    await screen.findByTestId('qr');

    fireEvent.change(screen.getByLabelText(/Code from the app/), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Turn it on' }));

    await waitFor(() => expect(confirm).toHaveBeenCalledWith({ code: '123456' }));
    const codes = await screen.findByTestId('recovery-codes');
    expect(codes.textContent).toContain('AAAA-BBBB');
    expect(codes.textContent).toContain('CCCC-DDDD');
    expect(codes.textContent).toMatch(/only time they are shown/);
  });

  it('will not send a code that is too short', async () => {
    render(<TwoFactor />);
    fireEvent.click(screen.getByRole('button', { name: 'Set up two-factor' }));
    await screen.findByTestId('qr');

    fireEvent.change(screen.getByLabelText(/Code from the app/), { target: { value: '123' } });

    expect(screen.getByRole('button', { name: 'Turn it on' })).toHaveProperty('disabled', true);
  });

  it('shows what the server said about a wrong code', async () => {
    confirm.mockRejectedValue(new Error('that code is not right'));
    render(<TwoFactor />);
    fireEvent.click(screen.getByRole('button', { name: 'Set up two-factor' }));
    await screen.findByTestId('qr');

    fireEvent.change(screen.getByLabelText(/Code from the app/), { target: { value: '000000' } });
    fireEvent.click(screen.getByRole('button', { name: 'Turn it on' }));

    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/not right/));
    // still on the setup, so the code can be typed again
    expect(screen.getByTestId('qr')).toBeTruthy();
  });

  it('asks for the password to turn it off', async () => {
    setInfo({ twoFactorEnabled: true, recoveryCodesLeft: 7 });
    render(<TwoFactor />);

    expect(screen.getByText(/7 recovery codes left/)).toBeTruthy();

    fireEvent.change(screen.getByLabelText(/Your password/), { target: { value: 'the-password' } });
    fireEvent.click(screen.getByRole('button', { name: 'Turn it off' }));

    await waitFor(() => expect(disable).toHaveBeenCalledWith({ password: 'the-password' }));
  });

  it('says when the recovery codes are running out, and offers a fresh set', () => {
    setInfo({ twoFactorEnabled: true, recoveryCodesLeft: 2 });
    render(<TwoFactor />);

    expect(screen.getByText(/2 recovery codes left/)).toBeTruthy();
    expect(screen.getByText(/A fresh set of ten replaces them/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'New recovery codes' })).toBeTruthy();
  });

  // this used to mean turning the second factor off and on again, with the
  // authenticator app to set up a second time
  it('replaces the recovery codes and shows the new ones', async () => {
    newCodes.mockResolvedValue({ recoveryCodes: ['EEEE-FFFF', 'GGGG-HHHH'] });
    setInfo({ twoFactorEnabled: true, recoveryCodesLeft: 1 });
    render(<TwoFactor />);

    fireEvent.change(screen.getByLabelText(/^Password/), { target: { value: 'the-password' } });
    fireEvent.click(screen.getByRole('button', { name: 'New recovery codes' }));

    await waitFor(() => expect(newCodes).toHaveBeenCalledWith({ password: 'the-password' }));
    const shown = await screen.findByTestId('recovery-codes');
    expect(shown.textContent).toMatch(/EEEE-FFFF/);
    expect(shown.textContent).toMatch(/GGGG-HHHH/);
    // the second factor is still on: nothing was turned off to get here
    expect(screen.getByRole('button', { name: 'Turn it off' })).toBeTruthy();
  });

  it('says so when the password for new codes is wrong', async () => {
    newCodes.mockRejectedValue(new Error('that is not your password'));
    setInfo({ twoFactorEnabled: true, recoveryCodesLeft: 1 });
    render(<TwoFactor />);

    fireEvent.change(screen.getByLabelText(/^Password/), { target: { value: 'not-it' } });
    fireEvent.click(screen.getByRole('button', { name: 'New recovery codes' }));

    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/not your password/));
    expect(screen.queryByTestId('recovery-codes')).toBeNull();
  });

  // two password fields sit in this section; the one by "Turn it off" must not
  // be the one the new-codes button submits
  it('keeps the two password fields apart', async () => {
    newCodes.mockResolvedValue({ recoveryCodes: ['EEEE-FFFF'] });
    setInfo({ twoFactorEnabled: true, recoveryCodesLeft: 7 });
    render(<TwoFactor />);

    fireEvent.change(screen.getByLabelText(/^Password/), { target: { value: 'for-new-codes' } });
    fireEvent.change(screen.getByLabelText(/Your password/), { target: { value: 'for-turning-it-off' } });

    fireEvent.click(screen.getByRole('button', { name: 'New recovery codes' }));
    await waitFor(() => expect(newCodes).toHaveBeenCalledWith({ password: 'for-new-codes' }));
    expect(disable).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'Turn it off' }));
    await waitFor(() => expect(disable).toHaveBeenCalledWith({ password: 'for-turning-it-off' }));
  });

  it('says when there are none left at all', () => {
    setInfo({ twoFactorEnabled: true, recoveryCodesLeft: 0 });
    render(<TwoFactor />);

    expect(screen.getByText(/No recovery codes left/)).toBeTruthy();
  });

  // with an identity provider the second factor belongs there
  it('shows nothing when the server keeps no sign-in for this account', () => {
    setInfo({ passwordChangeEnabled: false });
    const { container } = render(<TwoFactor />);

    expect(container.textContent).toBe('');
  });
});
