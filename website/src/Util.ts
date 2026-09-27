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
