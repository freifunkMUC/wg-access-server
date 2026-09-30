import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import React from 'react';
import { DeviceListItem } from './DeviceListItem';
import { AppState } from '../AppState';
import { Device } from '../sdk/devices_pb';
import { InfoRes } from '../sdk/server_pb';
import { grpc } from '../Api';
import { toast } from './Toast';

vi.mock('../Api', async () => {
  const actual = await vi.importActual<typeof import('../Api')>('../Api');
  return {
    ...actual,
    grpc: {
      devices: {
        deleteDevice: vi.fn().mockResolvedValue({}),
        renameDevice: vi.fn().mockResolvedValue({}),
        rotateDeviceKey: vi.fn(),
      },
    },
  };
});

vi.mock('./Toast', () => ({ toast: vi.fn() }));

// the configuration is a download and a QR code, so what the card hands over
// is shown as text here - that is what these tests are about
vi.mock('./GetConnected', () => ({
  GetConnected: ({ configFile }: { configFile: string }) => <pre data-testid="config">{configFile}</pre>,
}));

const rotate = vi.mocked(grpc.devices.rotateDeviceKey);
const toasted = vi.mocked(toast);

function testDevice(overrides: Partial<Device.AsObject> = {}): Device.AsObject {
  return {
    name: 'laptop',
    owner: 'alice',
    publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    presharedKey: '',
    address: '10.44.0.2/32',
    connected: false,
    receiveBytes: 0,
    transmitBytes: 0,
    endpoint: '',
    ownerName: 'Alice',
    ownerEmail: '',
    ownerProvider: 'simple',
    ...overrides,
  } as Device.AsObject;
}

async function confirmDialog() {
  const dialog = await screen.findByRole('dialog');
  fireEvent.click(within(dialog).getByText('OK'));
}

describe('giving a device a new key', () => {
  beforeEach(() => {
    AppState.setInfo({
      publicKey: 'serverkey',
      allowedIps: '0.0.0.0/0',
      port: 51820,
      host: { value: 'vpn.example.com' },
      dnsEnabled: false,
      clientConfigMtu: 0,
      clientConfigPersistentKeepalive: 0,
    } as InfoRes.AsObject);
    rotate.mockResolvedValue({ ...testDevice(), publicKey: 'the-new-one' });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('sends a new key and hands back a configuration to install', async () => {
    const onChange = vi.fn();
    render(<DeviceListItem device={testDevice()} onChange={onChange} />);

    fireEvent.click(screen.getByTitle('Give the device a new key'));
    await confirmDialog();

    await waitFor(() => expect(rotate).toHaveBeenCalled());
    const sent = rotate.mock.calls[0][0];
    expect(sent.name).toBe('laptop');
    // a real WireGuard key: 32 bytes, base64
    expect(sent.publicKey).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    // the device had no pre-shared key, so it does not get one now
    expect(sent.presharedKey).toBe('');

    // the private half never went to the server, but has to reach the user -
    // with the address the device keeps, and without the public half in it
    const shown = await screen.findByTestId('config');
    expect(shown.textContent).toMatch(/PrivateKey = [A-Za-z0-9+/]{43}=/);
    expect(shown.textContent).toContain('Address = 10.44.0.2/32');
    expect(shown.textContent).not.toContain(sent.publicKey);
    expect(screen.getByText(/The new configuration for/)).toBeTruthy();
    expect(onChange).toHaveBeenCalled();
  });

  it('gives a device that uses a pre-shared key a new one of those too', async () => {
    render(<DeviceListItem device={testDevice({ presharedKey: 'old-preshared-key' })} onChange={() => {}} />);

    fireEvent.click(screen.getByTitle('Give the device a new key'));
    await confirmDialog();

    await waitFor(() => expect(rotate).toHaveBeenCalled());
    const sent = rotate.mock.calls[0][0];
    expect(sent.presharedKey).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(sent.presharedKey).not.toBe('old-preshared-key');
  });

  // the device stops working until the new configuration is installed, so
  // nobody should be able to do this by mistake
  it('does nothing when the question is cancelled', async () => {
    render(<DeviceListItem device={testDevice()} onChange={() => {}} />);

    fireEvent.click(screen.getByTitle('Give the device a new key'));
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toMatch(/stops connecting until you install the new configuration/);
    fireEvent.click(within(dialog).getByText('Cancel'));

    await waitFor(() => expect(rotate).not.toHaveBeenCalled());
  });

  it('says what went wrong and shows no configuration', async () => {
    rotate.mockRejectedValue(new Error('another device already uses this key'));
    render(<DeviceListItem device={testDevice()} onChange={() => {}} />);

    fireEvent.click(screen.getByTitle('Give the device a new key'));
    await confirmDialog();

    await waitFor(() =>
      expect(toasted).toHaveBeenCalledWith(
        expect.objectContaining({ intent: 'error', text: expect.stringContaining('another device already uses') }),
      ),
    );
    expect(screen.queryByTestId('config')).toBeNull();
  });
});
