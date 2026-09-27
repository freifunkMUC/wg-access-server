import { formatDistance } from 'date-fns';
import timestamp_pb from 'google-protobuf/google/protobuf/timestamp_pb';
import { toDate } from './Api';
import { toast } from './components/Toast';

// Errors reaching the UI are either gRPC-web errors, plain Errors or - in
// theory - anything a rejected promise carries, so narrow instead of casting.
export function errorMessage(error: unknown): string {
  if (typeof error === 'object' && error !== null && 'message' in error) {
    return String((error as { message: unknown }).message);
  }
  return String(error);
}

export function sleep(seconds: number) {
  return new Promise<void>((resolve) => {
    setTimeout(() => {
      resolve();
    }, seconds * 1000);
  });
}

export function lastSeen(timestamp: timestamp_pb.Timestamp.AsObject | undefined): string {
  if (timestamp === undefined) {
    return 'Never';
  }
  return formatDistance(toDate(timestamp), new Date(), {
    addSuffix: true,
  });
}

// A device the server has no peer for, or one that is about to lose it. What
// the UI needs is the same in both places it shows a device, so it is decided
// here rather than in each of them.
export interface DeviceAccess {
  // blocked: the device cannot connect at all - an admin disabled it, or its
  // expiry date has passed.
  blocked: boolean;
  label: string;
}

// deviceAccess describes what stands between a device and the VPN. It returns
// undefined for a device that may connect and keeps it that way, which is the
// normal case and needs no explaining.
export function deviceAccess(
  device: { disabled?: boolean; expiresAt?: timestamp_pb.Timestamp.AsObject },
  now: Date = new Date(),
): DeviceAccess | undefined {
  if (device.disabled) {
    return { blocked: true, label: 'Blocked' };
  }
  if (!device.expiresAt) {
    return undefined;
  }
  const at = toDate(device.expiresAt);
  if (at <= now) {
    return { blocked: true, label: 'Expired' };
  }
  return { blocked: false, label: 'Expires ' + formatDistance(at, now, { addSuffix: true }) };
}

// accessRank orders devices by how much attention their access needs: the ones
// that cannot connect last, so that sorting the column descending brings them
// to the top.
export function accessRank(device: { disabled?: boolean; expiresAt?: timestamp_pb.Timestamp.AsObject }): number {
  const access = deviceAccess(device);
  if (!access) {
    return 0;
  }
  return access.blocked ? 2 : 1;
}

export function setClipboard(text: string) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  document.body.removeChild(textarea);
  toast({
    intent: 'success',
    text: 'Added to clipboard',
  });
}

export interface DownloadOpts {
  filename: string;
  content: string;
}

export function download(opts: DownloadOpts) {
  const anchor = document.createElement('a');
  anchor.href = URL.createObjectURL(new File([opts.content], opts.filename));
  anchor.download = opts.filename;
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
}
