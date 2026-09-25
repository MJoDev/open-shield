import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useDebounced, useDelayedFlag, useLoadPhase } from "./hooks";

// These hooks are the whole wait-time policy of the dashboard. If they drift,
// every screen starts flashing indicators on fast responses or firing one
// request per keystroke, and no single component test would say why.

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("useDelayedFlag", () => {
  it("never shows an indicator for work that finishes under the delay", () => {
    const { result, rerender } = renderHook(
      ({ flag }) => useDelayedFlag(flag),
      {
        initialProps: { flag: true },
      },
    );

    act(() => vi.advanceTimersByTime(250));
    expect(result.current).toBe(false);

    rerender({ flag: false });
    act(() => vi.advanceTimersByTime(1000));
    expect(result.current).toBe(false);
  });

  it("shows the indicator once the delay has passed", () => {
    const { result } = renderHook(() => useDelayedFlag(true));

    act(() => vi.advanceTimersByTime(300));
    expect(result.current).toBe(true);
  });

  // The anti-flicker half: an indicator that appears at 300 ms and vanishes at
  // 320 ms is a blink, which is worse than no indicator at all.
  it("keeps a shown indicator up for the minimum time", () => {
    const { result, rerender } = renderHook(
      ({ flag }) => useDelayedFlag(flag),
      {
        initialProps: { flag: true },
      },
    );

    act(() => vi.advanceTimersByTime(300));
    expect(result.current).toBe(true);

    act(() => vi.advanceTimersByTime(20));
    rerender({ flag: false });
    act(() => vi.advanceTimersByTime(300));
    expect(result.current).toBe(true);

    act(() => vi.advanceTimersByTime(100));
    expect(result.current).toBe(false);
  });
});

describe("useLoadPhase", () => {
  it("reserves space on a first load without showing the skeleton yet", () => {
    const { result } = renderHook(() => useLoadPhase(true, false));

    expect(result.current.placeholder).toBe(true);
    expect(result.current.skeleton).toBe(false);

    act(() => vi.advanceTimersByTime(300));
    expect(result.current.skeleton).toBe(true);
  });

  it("marks a slow reload of data already on screen as a refresh", () => {
    const { result } = renderHook(() => useLoadPhase(true, true));

    expect(result.current.placeholder).toBe(false);
    act(() => vi.advanceTimersByTime(300));
    expect(result.current.refreshing).toBe(true);
  });
});

describe("useDebounced", () => {
  it("settles on the last value once typing stops", () => {
    const { result, rerender } = renderHook(
      ({ value }) => useDebounced(value, 300),
      {
        initialProps: { value: "" },
      },
    );

    for (const value of ["2", "20", "203", "203.0"]) {
      rerender({ value });
      act(() => vi.advanceTimersByTime(100));
    }
    expect(result.current).toBe("");

    act(() => vi.advanceTimersByTime(300));
    expect(result.current).toBe("203.0");
  });
});
