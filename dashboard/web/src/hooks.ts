import { useEffect, useRef, useState } from "react";

/**
 * Turns "work is in flight" into "an indicator should be on screen".
 *
 * Two thresholds, both about perception rather than latency. Under `delay`
 * the answer feels instant and an indicator would only flash, so none is
 * shown. Once one is shown it stays for at least `minVisible`, so a response
 * that lands just after the delay does not make it blink.
 */
export function useDelayedFlag(
  flag: boolean,
  {
    delay = 300,
    minVisible = 400,
  }: { delay?: number; minVisible?: number } = {},
): boolean {
  const [visible, setVisible] = useState(false);
  const shownAt = useRef(0);

  useEffect(() => {
    if (flag) {
      if (visible) return;
      const timer = setTimeout(() => {
        shownAt.current = Date.now();
        setVisible(true);
      }, delay);
      return () => clearTimeout(timer);
    }

    if (!visible) return;
    const remaining = minVisible - (Date.now() - shownAt.current);
    if (remaining <= 0) {
      setVisible(false);
      return;
    }
    const timer = setTimeout(() => setVisible(false), remaining);
    return () => clearTimeout(timer);
  }, [flag, visible, delay, minVisible]);

  return visible;
}

/**
 * The three things a data view needs to know about a load:
 *
 *  - `placeholder`: there is no data yet, so the final shape is reserved with
 *    skeleton blocks — hidden while `skeleton` is false, so a fast first
 *    response does not flash them.
 *  - `skeleton`: the first load has run long enough to show the skeleton.
 *  - `refreshing`: data is on screen and a newer version is on its way; the
 *    old data stays, dimmed, rather than being swapped for a skeleton.
 */
export function useLoadPhase(loading: boolean, hasData: boolean) {
  const initial = loading && !hasData;
  const skeleton = useDelayedFlag(initial);
  const refreshing = useDelayedFlag(loading && hasData);
  return { placeholder: initial || skeleton, skeleton, refreshing };
}

/**
 * The value, once it has stopped changing for `delay` ms. For free-text
 * filters: one request when the operator finishes typing, not one per key.
 */
export function useDebounced<T>(value: T, delay = 300): T {
  const [settled, setSettled] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);

  return settled;
}

/** Whole seconds since `running` became true; 0 while it is false. */
export function useElapsedSeconds(running: boolean): number {
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    setSeconds(0);
    if (!running) return;
    const started = Date.now();
    const timer = setInterval(
      () => setSeconds(Math.floor((Date.now() - started) / 1000)),
      1000,
    );
    return () => clearInterval(timer);
  }, [running]);

  return seconds;
}
