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
    users: { listUsers: vi.fn(), deleteUser: vi.fn() },
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

vi.mock('../../components/Present', () => ({
  confirm: vi.fn(),
  present: vi.fn(),
}));

vi.mock('../../components/Toast', () => ({ toast: vi.fn() }));

import { grpc } from '../../Api';
import { AppState } from '../../AppState';
import { toast } from '../../components/Toast';
import { Device } from '../../sdk/devices_pb';
import { AllDevices, parseRoutes } from './AllDevices';

const listUsers = vi.mocked(grpc.users.listUsers);
const listAllDevices = vi.mocked(grpc.devices.listAllDevices);
const setDeviceRoutes = vi.mocked(grpc.devices.setDeviceRoutes);
const toastMock = vi.mocked(toast);

function makeDevice(overrides: Partial<Device.AsObject> = {}): Device.AsObject {
  return {
    name: 'site',
    owner: 'alice',
    ownerName: 'Alice',
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

describe('AllDevices routes', () => {
  beforeEach(() => {
    AppState.clearLoadingError();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    listUsers.mockResolvedValue({ items: [{ name: 'alice', displayName: 'Alice' }] });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    AppState.clearLoadingError();
  });

  it('lists the networks a device carries', async () => {
    listAllDevices.mockResolvedValue({ items: [makeDevice({ routes: ['192.168.5.0/24', '2001:db8:5::/48'] })] });

    render(<AllDevices />);
    await screen.findByText('site');
    expect(screen.getByText('192.168.5.0/24, 2001:db8:5::/48')).toBeTruthy();
  });

  it('sends what was typed as separate networks', async () => {
    const device = makeDevice();
    listAllDevices.mockResolvedValue({ items: [device] });
    setDeviceRoutes.mockResolvedValue({ ...device, routes: ['192.168.5.0/24'] });

    render(<AllDevices />);
    await screen.findByText('site');
    const row = screen.getByText('site').closest('tr')!;
    fireEvent.click(within(row).getByRole('button', { name: 'Networks' }));

    fireEvent.change(await screen.findByLabelText('Networks'), {
      target: { value: '192.168.5.0/24,\n 2001:db8:5::/48 ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(setDeviceRoutes).toHaveBeenCalledWith({
        name: 'site',
        owner: { value: 'alice' },
        routes: ['192.168.5.0/24', '2001:db8:5::/48'],
      });
    });
  });

  it('starts from the networks the device already carries, and can empty them', async () => {
    const device = makeDevice({ routes: ['192.168.5.0/24'] });
    listAllDevices.mockResolvedValue({ items: [device] });
    setDeviceRoutes.mockResolvedValue(makeDevice());

    render(<AllDevices />);
    await screen.findByText('site');
    const row = screen.getByText('site').closest('tr')!;
    fireEvent.click(within(row).getByRole('button', { name: 'Networks' }));

    const field = (await screen.findByLabelText('Networks')) as HTMLInputElement;
    expect(field.value).toBe('192.168.5.0/24');

    fireEvent.change(field, { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(setDeviceRoutes).toHaveBeenCalledWith({ name: 'site', owner: { value: 'alice' }, routes: [] });
    });
  });

  // the server decides what may be routed; when it says no, the admin should
  // be able to correct the network instead of typing them all again
  it('keeps the dialog open when the server refuses a network', async () => {
    listAllDevices.mockResolvedValue({ items: [makeDevice()] });
    setDeviceRoutes.mockRejectedValue(new Error("'10.44.0.0/24' overlaps the VPN network"));

    render(<AllDevices />);
    await screen.findByText('site');
    const row = screen.getByText('site').closest('tr')!;
    fireEvent.click(within(row).getByRole('button', { name: 'Networks' }));

    fireEvent.change(await screen.findByLabelText('Networks'), { target: { value: '10.44.0.0/24' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith({
        text: "Failed to change the networks: '10.44.0.0/24' overlaps the VPN network",
        intent: 'error',
      });
    });
    expect(screen.getByLabelText('Networks')).toBeTruthy();
  });
});

describe('parseRoutes', () => {
  it('splits on commas and new lines and drops what is empty', () => {
    expect(parseRoutes(' 192.168.5.0/24 ,\n\n2001:db8:5::/48,, ')).toEqual(['192.168.5.0/24', '2001:db8:5::/48']);
  });

  it('is empty for an empty field', () => {
    expect(parseRoutes('   ')).toEqual([]);
  });
});
