import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { DeviceListItem } from './DeviceListItem';
import { Device } from '../sdk/devices_pb';
import { grpc } from '../Api';

// The real client would talk to the server on import, so the whole module is
// replaced - except for the helpers the components use for formatting.
vi.mock('../Api', async () => {
  const actual = await vi.importActual<typeof import('../Api')>('../Api');
  return {
    ...actual,
    grpc: {
      devices: {
        deleteDevice: vi.fn().mockResolvedValue({}),
      },
    },
  };
});

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

describe('DeviceListItem', () => {
  it('shows the device name and its public key', () => {
    render(<DeviceListItem device={testDevice()} onRemove={() => {}} />);

    expect(screen.getByText('laptop')).toBeDefined();
    expect(screen.getByText('Public key')).toBeDefined();
  });

  it('reports a device that has never connected as never seen', () => {
    render(<DeviceListItem device={testDevice()} onRemove={() => {}} />);

    expect(screen.getByText(/Last seen: Never/)).toBeDefined();
  });

  it('deletes the device once the question is confirmed', async () => {
    const onRemove = vi.fn();
    render(<DeviceListItem device={testDevice()} onRemove={onRemove} />);

    fireEvent.click(screen.getByTitle('Delete Device'));
    fireEvent.click(await screen.findByText('Ok'));

    await waitFor(() => expect(grpc.devices.deleteDevice).toHaveBeenCalledWith({ name: 'laptop' }));
    await waitFor(() => expect(onRemove).toHaveBeenCalled());
  });

  // deleting a device cannot be undone, so a cancelled dialog must do nothing
  it('keeps the device when the question is cancelled', async () => {
    const onRemove = vi.fn();
    render(<DeviceListItem device={testDevice()} onRemove={onRemove} />);

    fireEvent.click(screen.getByTitle('Delete Device'));
    fireEvent.click(await screen.findByText('Cancel'));

    await waitFor(() => expect(grpc.devices.deleteDevice).not.toHaveBeenCalled());
    expect(onRemove).not.toHaveBeenCalled();
  });
});
