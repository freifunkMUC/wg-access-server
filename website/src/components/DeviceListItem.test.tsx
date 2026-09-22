import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
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
        renameDevice: vi.fn().mockResolvedValue({}),
      },
    },
  };
});

vi.mock('./Toast', () => ({ toast: vi.fn() }));

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
    render(<DeviceListItem device={testDevice()} onChange={() => {}} />);

    expect(screen.getByText('laptop')).toBeDefined();
    expect(screen.getByText('Public key')).toBeDefined();
  });

  it('reports a device that has never connected as never seen', () => {
    render(<DeviceListItem device={testDevice()} onChange={() => {}} />);

    expect(screen.getByText(/Last seen: Never/)).toBeDefined();
  });

  it('deletes the device once the question is confirmed', async () => {
    const onChange = vi.fn();
    render(<DeviceListItem device={testDevice()} onChange={onChange} />);

    fireEvent.click(screen.getByTitle('Delete device'));
    fireEvent.click(within(await screen.findByRole('dialog')).getByText('OK'));

    await waitFor(() => expect(grpc.devices.deleteDevice).toHaveBeenCalledWith({ name: 'laptop' }));
    await waitFor(() => expect(onChange).toHaveBeenCalled());
  });

  // deleting a device cannot be undone, so a cancelled dialog must do nothing
  it('keeps the device when the question is cancelled', async () => {
    const onChange = vi.fn();
    render(<DeviceListItem device={testDevice()} onChange={onChange} />);

    fireEvent.click(screen.getByTitle('Delete device'));
    fireEvent.click(within(await screen.findByRole('dialog')).getByText('Cancel'));

    await waitFor(() => expect(grpc.devices.deleteDevice).not.toHaveBeenCalled());
    expect(onChange).not.toHaveBeenCalled();
  });

  it('renames the device and reloads the list', async () => {
    const onChange = vi.fn();
    render(<DeviceListItem device={testDevice()} onChange={onChange} />);

    fireEvent.click(screen.getByTitle('Rename device'));

    // the dialog title and the field carry the same text, so query by role
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByRole('textbox'), { target: { value: 'work laptop' } });
    fireEvent.click(within(dialog).getByText('OK'));

    await waitFor(() =>
      expect(grpc.devices.renameDevice).toHaveBeenCalledWith({ name: 'laptop', newName: 'work laptop' }),
    );
    await waitFor(() => expect(onChange).toHaveBeenCalled());
  });

  // an unchanged name is not worth a request
  it('does not rename when the name is left as it is', async () => {
    const onChange = vi.fn();
    render(<DeviceListItem device={testDevice()} onChange={onChange} />);

    fireEvent.click(screen.getByTitle('Rename device'));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByText('OK'));

    await waitFor(() => expect(grpc.devices.renameDevice).not.toHaveBeenCalled());
    expect(onChange).not.toHaveBeenCalled();
  });

  it('does not rename when the dialog is cancelled', async () => {
    render(<DeviceListItem device={testDevice()} onChange={() => {}} />);

    fireEvent.click(screen.getByTitle('Rename device'));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByText('Cancel'));

    await waitFor(() => expect(grpc.devices.renameDevice).not.toHaveBeenCalled());
  });
});
