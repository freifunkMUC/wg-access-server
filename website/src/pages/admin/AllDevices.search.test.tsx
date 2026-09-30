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

vi.mock('../../components/Present', () => ({ confirm: vi.fn(), present: vi.fn() }));
vi.mock('../../components/Toast', () => ({ toast: vi.fn() }));

import { grpc } from '../../Api';
import { AppState } from '../../AppState';
import { Device } from '../../sdk/devices_pb';
import { User } from '../../sdk/users_pb';
import { AllDevices, filterDevices, filterUsers } from './AllDevices';

const listUsers = vi.mocked(grpc.users.listUsers);
const listAllDevices = vi.mocked(grpc.devices.listAllDevices);

function makeDevice(overrides: Partial<Device.AsObject> = {}): Device.AsObject {
  return {
    name: 'device',
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
    ...overrides,
  } as Device.AsObject;
}

function makeUser(overrides: Partial<User.AsObject> = {}): User.AsObject {
  return { name: 'alice', displayName: 'Alice Example', policies: [], ...overrides } as User.AsObject;
}

describe('filterDevices', () => {
  // every device belongs to somebody else, down to the email address: the
  // search looks at all of those, and a fixture that shares one would make a
  // test pass for the wrong reason
  const devices = [
    makeDevice({
      name: 'alice-laptop',
      owner: 'alice',
      ownerName: 'Alice Example',
      ownerEmail: 'alice@example.com',
      connected: true,
    }),
    makeDevice({ name: 'bob-phone', owner: 'bob', ownerName: 'Bob Roe', ownerEmail: 'bob@example.com' }),
    makeDevice({
      name: 'blocked-one',
      owner: 'carol',
      ownerName: 'Carol',
      ownerEmail: 'carol@example.com',
      disabled: true,
    }),
    makeDevice({
      name: 'the-site',
      owner: 'dave',
      ownerName: 'Dave',
      ownerEmail: 'dave@example.com',
      routes: ['192.168.5.0/24'],
    }),
  ];
  const names = (result: Device.AsObject[]) => result.map((d) => d.name);

  it('keeps everything without a search', () => {
    expect(filterDevices(devices, '', 'all')).toHaveLength(4);
    expect(filterDevices(devices, '   ', 'all')).toHaveLength(4);
  });

  it('searches the device name, the owner however they are named, and the networks', () => {
    expect(names(filterDevices(devices, 'laptop', 'all'))).toEqual(['alice-laptop']);
    expect(names(filterDevices(devices, 'Bob Roe', 'all'))).toEqual(['bob-phone']);
    expect(names(filterDevices(devices, 'bob@example.com', 'all'))).toEqual(['bob-phone']);
    expect(names(filterDevices(devices, 'carol', 'all'))).toEqual(['blocked-one']);
    expect(names(filterDevices(devices, '192.168.5', 'all'))).toEqual(['the-site']);
  });

  it('ignores case', () => {
    expect(names(filterDevices(devices, 'ALICE', 'all'))).toEqual(['alice-laptop']);
  });

  it('narrows down to a state', () => {
    expect(names(filterDevices(devices, '', 'connected'))).toEqual(['alice-laptop']);
    expect(names(filterDevices(devices, '', 'blocked'))).toEqual(['blocked-one']);
    expect(names(filterDevices(devices, '', 'routing'))).toEqual(['the-site']);
  });

  it('applies the search and the state together', () => {
    expect(filterDevices(devices, 'alice', 'blocked')).toHaveLength(0);
    expect(names(filterDevices(devices, 'alice', 'connected'))).toEqual(['alice-laptop']);
  });

  it('counts a device past its expiry as blocked', () => {
    const anHourAgo = { seconds: Math.round(Date.now() / 1000) - 3600, nanos: 0 };
    const expired = makeDevice({ name: 'expired', expiresAt: anHourAgo });
    expect(names(filterDevices([expired, ...devices], '', 'blocked'))).toEqual(['expired', 'blocked-one']);
  });
});

describe('filterUsers', () => {
  const users = [
    makeUser({ name: 'alice', displayName: 'Alice Example', policies: ['staff'] }),
    makeUser({ name: 'bob', displayName: 'Bob Roe', policies: ['contractors'] }),
    makeUser({ name: 'carol', displayName: 'Carol', policies: [], twoFactor: false }),
  ];
  const names = (result: User.AsObject[]) => result.map((u) => u.name);

  it('keeps everything without a search', () => {
    expect(filterUsers(users, '')).toHaveLength(3);
  });

  it('searches the name and the policies', () => {
    expect(names(filterUsers(users, 'Bob'))).toEqual(['bob']);
    expect(names(filterUsers(users, 'contractors'))).toEqual(['bob']);
    expect(names(filterUsers(users, 'staff'))).toEqual(['alice']);
  });
});

describe('AllDevices with many devices', () => {
  const many = Array.from({ length: 60 }, (_, i) =>
    makeDevice({ name: `device-${String(i).padStart(2, '0')}`, address: `10.44.0.${i + 2}/32` }),
  );

  beforeEach(() => {
    AppState.clearLoadingError();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    listUsers.mockResolvedValue({ items: [makeUser()] });
    listAllDevices.mockResolvedValue({ items: many });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    AppState.clearLoadingError();
  });

  // 300 devices in one table is what this is about: the page has to stay
  // readable and a device has to be findable.
  it('shows a page of devices and moves to the next', async () => {
    render(<AllDevices />);
    await screen.findByText('device-00');

    expect(screen.queryByText('device-24')).toBeTruthy();
    expect(screen.queryByText('device-25')).toBeNull();

    const pagination = screen.getAllByRole('button', { name: /next page/i })[0];
    fireEvent.click(pagination);

    await waitFor(() => expect(screen.queryByText('device-25')).toBeTruthy());
    expect(screen.queryByText('device-00')).toBeNull();
  });

  it('searches through everything that was loaded, not only the page', async () => {
    render(<AllDevices />);
    await screen.findByText('device-00');

    // device-42 is on the second page
    fireEvent.change(screen.getByLabelText('Search devices'), { target: { value: 'device-42' } });

    await waitFor(() => expect(screen.queryByText('device-42')).toBeTruthy());
    expect(screen.queryByText('device-00')).toBeNull();
    expect(screen.getByText(/1 shown/)).toBeTruthy();
  });

  it('starts at the front again when the search changes', async () => {
    render(<AllDevices />);
    await screen.findByText('device-00');

    fireEvent.click(screen.getAllByRole('button', { name: /next page/i })[0]);
    await waitFor(() => expect(screen.queryByText('device-25')).toBeTruthy());

    fireEvent.change(screen.getByLabelText('Search devices'), { target: { value: 'device' } });

    // back on the first page, not on an empty second one
    await waitFor(() => expect(screen.queryByText('device-00')).toBeTruthy());
  });

  it('says so when nothing matches', async () => {
    render(<AllDevices />);
    await screen.findByText('device-00');

    fireEvent.change(screen.getByLabelText('Search devices'), { target: { value: 'nothing-like-this' } });

    await waitFor(() => expect(screen.getByText(/No device matches/)).toBeTruthy());
  });

  it('keeps the owner column stable while searching', async () => {
    listAllDevices.mockResolvedValue({
      items: [makeDevice({ name: 'one', ownerProvider: 'basic' }), makeDevice({ name: 'two', ownerProvider: 'oidc' })],
    });
    render(<AllDevices />);
    await screen.findByText('one');

    const header = screen.getAllByRole('table')[0];
    expect(within(header).queryByText('Auth provider')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Search devices'), { target: { value: 'one' } });

    await waitFor(() => expect(screen.queryByText('two')).toBeNull());
    expect(within(screen.getAllByRole('table')[0]).queryByText('Auth provider')).toBeTruthy();
  });
});
