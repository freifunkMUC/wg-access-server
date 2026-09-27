import { formatDistance } from 'date-fns';
import timestamp_pb from 'google-protobuf/google/protobuf/timestamp_pb';
import { toDate } from './Api';
import { observable, runInAction } from 'mobx';
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

// lazy defers cb until `current` is read for the first time, then hands the
// result to any observer that read it. Replaces mobx-utils' lazyObservable,
// which is stuck on mobx 6.
export function lazy<T>(cb: () => Promise<T>) {
  const value = observable.box<T | undefined>(undefined, { deep: false });
  let started = false;

  const fetch = () => {
    started = true;
    // cb is async, so the write always lands in a later tick and never inside
    // the render that triggered it - no need for mobx's internal
    // _allowStateChanges escape hatch.
    void cb().then((next) => runInAction(() => value.set(next)));
  };

  return {
    get current(): T | undefined {
      if (!started) {
        fetch();
      }
      return value.get();
    },
    refresh: async () => {
      if (started) {
        fetch();
      }
    },
  };
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
