import { cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../Api', () => ({
  grpc: {
    server: { info: vi.fn() },
    users: { listUsers: vi.fn(), deleteUser: vi.fn() },
    devices: { listAllDevices: vi.fn(), listDevices: vi.fn(), addDevice: vi.fn(), deleteDevice: vi.fn() },
  },
  toDate: (t: { seconds: number }) => new Date(t.seconds * 1000),
  dateToTimestamp: (d: Date) => ({ seconds: Math.round(d.getTime() / 1000), nanos: 0 }),
}));

vi.mock('./Toast', () => ({
  toast: vi.fn(),
}));

vi.mock('./Present', () => ({
  confirm: vi.fn(),
  present: vi.fn(),
}));

import { grpc } from '../Api';
import { toast } from './Toast';
import { ImportExportDelete } from './ImportExportDelete';
import { Device } from '../sdk/devices_pb';

const addDevice = vi.mocked(grpc.devices.addDevice);
const toastMock = vi.mocked(toast);

const DEVICES_JSON = JSON.stringify([{ name: 'imported-device', publicKey: 'pubkey-1' }]);

function makeImportFile(content: string = DEVICES_JSON): File {
  const file = new File([content], 'vpn-devices.json', { type: 'application/json' });
  // Guarantee File#text() regardless of the jsdom version in use.
  Object.defineProperty(file, 'text', { value: () => Promise.resolve(content) });
  return file;
}

function getFileInput(): HTMLInputElement {
  // The menu is rendered keepMounted, so the hidden input is always in the DOM
  // (inside a MUI portal, hence document-level lookup).
  const input = document.querySelector<HTMLInputElement>('input[type="file"]');
  expect(input).not.toBeNull();
  return input!;
}

function selectFile(input: HTMLInputElement, file: File) {
  // jsdom forbids assigning a non-empty value to a file input, so shadow the
  // `value` property with a writable one carrying the fake path a browser
  // would report. The component's reset (`event.target.value = ''`) writes to
  // this property, letting us observe whether the input was actually cleared.
  Object.defineProperty(input, 'value', {
    configurable: true,
    writable: true,
    value: 'C:\\fakepath\\vpn-devices.json',
  });
  Object.defineProperty(input, 'files', {
    configurable: true,
    value: [file],
  });
  fireEvent.change(input);
}

describe('ImportExportDelete import input reset', () => {
  beforeEach(() => {
    addDevice.mockResolvedValue({} as Device.AsObject);
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('runs the import and clears the input value so the same file can be re-selected', async () => {
    const onRefresh = vi.fn();
    render(<ImportExportDelete onRefresh={onRefresh} />);

    const input = getFileInput();
    selectFile(input, makeImportFile());

    // The value is reset synchronously at the start of the handler, before
    // the file is read, so selecting the same file again re-fires onChange.
    expect(input.value).toBe('');

    // The captured File reference is still imported successfully.
    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith({ text: 'Devices imported successfully', intent: 'success' });
    });
    expect(addDevice).toHaveBeenCalledTimes(1);
    expect(addDevice).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'imported-device', publicKey: 'pubkey-1' }),
    );
    expect(onRefresh).toHaveBeenCalledTimes(1);
  });

  it('imports again when the same file is selected a second time', async () => {
    const onRefresh = vi.fn();
    render(<ImportExportDelete onRefresh={onRefresh} />);

    const input = getFileInput();
    const file = makeImportFile();

    selectFile(input, file);
    await waitFor(() => expect(addDevice).toHaveBeenCalledTimes(1));
    expect(input.value).toBe('');

    selectFile(input, file);
    await waitFor(() => expect(addDevice).toHaveBeenCalledTimes(2));
    expect(input.value).toBe('');
    expect(onRefresh).toHaveBeenCalledTimes(2);
  });

  it('clears the input even when the import fails, so a retry with the same file works', async () => {
    render(<ImportExportDelete />);

    const input = getFileInput();
    selectFile(input, makeImportFile('not valid json'));

    expect(input.value).toBe('');
    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ intent: 'error', text: expect.stringContaining('Failed to import devices') }),
      );
    });
    expect(addDevice).not.toHaveBeenCalled();
  });
});
