import { useCallback, useEffect, useRef, useState } from 'react';
import { sleep } from './Util';

// usePolling loads a value now and then again every `seconds`, for as long as
// the component is on screen. `refresh` loads it once in between, which is
// what a component calls after it changed something.
export function usePolling<T>(seconds: number, load: () => Promise<T>) {
  const [current, setCurrent] = useState<T | undefined>(undefined);
  // the callback is usually written out in the render, so it is a new
  // function every time - the loop reads the latest one instead of restarting
  const latest = useRef(load);
  useEffect(() => {
    latest.current = load;
  });

  const refresh = useCallback(async () => {
    setCurrent(await latest.current());
  }, []);

  useEffect(() => {
    let onScreen = true;
    void (async () => {
      while (onScreen) {
        const next = await latest.current();
        if (!onScreen) {
          return;
        }
        setCurrent(next);
        await sleep(seconds);
      }
    })();
    return () => {
      onScreen = false;
    };
  }, [seconds]);

  return { current, refresh };
}
