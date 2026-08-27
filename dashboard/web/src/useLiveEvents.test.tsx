import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useLiveEvents } from "./useLiveEvents";
import { FakeSocket, installFakeSocket } from "./test/fakeSocket";
import type { AuditEntry } from "./types";

// The live feed is the one screen an operator leaves open, and its failure mode
// is silence: a dropped socket looks exactly like quiet traffic. Everything
// below is about telling those two apart.

function entry(id: string): AuditEntry {
  return {
    id,
    request_id: `req-${id}`,
    timestamp: "2026-08-25T12:00:00Z",
    kind: "traffic",
    payload: { ip: "203.0.113.7", verdict: "block", rule: "sqli" },
    prev_hash: "0".repeat(64),
    hash: `hash-${id}`,
  };
}

describe("useLiveEvents", () => {
  beforeEach(() => {
    installFakeSocket();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("connects and reports the connection state", async () => {
    const { result } = renderHook(() => useLiveEvents(true));

    expect(result.current.state).toBe("connecting");

    act(() => FakeSocket.latest().open());
    await waitFor(() => expect(result.current.state).toBe("open"));
  });

  it("does not connect at all when disabled", () => {
    const { result } = renderHook(() => useLiveEvents(false));

    expect(FakeSocket.instances).toHaveLength(0);
    expect(result.current.state).toBe("closed");
  });

  it("delivers events newest first", async () => {
    const { result } = renderHook(() => useLiveEvents(true));
    act(() => FakeSocket.latest().open());

    act(() => {
      FakeSocket.latest().emit(entry("a"));
      FakeSocket.latest().emit(entry("b"));
    });

    await waitFor(() => expect(result.current.events).toHaveLength(2));
    expect(result.current.events.map((e) => e.id)).toEqual(["b", "a"]);
  });

  // The feed is unbounded input into a page that may stay open for days.
  // Without the cap, a busy site turns the dashboard into a memory leak.
  it("keeps at most 200 events", async () => {
    const { result } = renderHook(() => useLiveEvents(true));
    act(() => FakeSocket.latest().open());

    act(() => {
      for (let i = 0; i < 260; i++) {
        FakeSocket.latest().emit(entry(String(i)));
      }
    });

    await waitFor(() => expect(result.current.events).toHaveLength(200));
    // The newest is kept and the oldest dropped, not the other way round.
    expect(result.current.events[0]?.id).toBe("259");
    expect(result.current.events.at(-1)?.id).toBe("60");
  });

  // Anything that can publish to the events channel can publish nonsense.
  // Losing the feed to it would be a denial of service against the operator's
  // own view.
  it("survives a frame that is not valid JSON", async () => {
    const { result } = renderHook(() => useLiveEvents(true));
    act(() => FakeSocket.latest().open());

    act(() => {
      FakeSocket.latest().emitRaw("no es json");
      FakeSocket.latest().emit(entry("after"));
    });

    await waitFor(() => expect(result.current.events).toHaveLength(1));
    expect(result.current.events[0]?.id).toBe("after");
  });

  // The reason this hook is not the four-line version in §7.3 of the technical
  // document. A dashboard left open overnight outlives at least one engine
  // restart; a feed that never reconnects goes silent and looks idle.
  it("reconnects after the connection drops", async () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useLiveEvents(true));

    act(() => FakeSocket.latest().open());
    await vi.waitFor(() => expect(result.current.state).toBe("open"));

    act(() => FakeSocket.latest().drop());
    await vi.waitFor(() => expect(result.current.state).toBe("closed"));
    expect(FakeSocket.instances).toHaveLength(1);

    // First retry is after one second.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(FakeSocket.instances).toHaveLength(2);

    act(() => FakeSocket.latest().open());
    await vi.waitFor(() => expect(result.current.state).toBe("open"));
  });

  // Backoff, so an engine that is down for an hour is not hammered once a
  // second for an hour.
  it("backs off exponentially between attempts", async () => {
    vi.useFakeTimers();
    renderHook(() => useLiveEvents(true));

    // Attempt 1 fails immediately: retry after 1s.
    act(() => FakeSocket.latest().drop());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(999);
    });
    expect(FakeSocket.instances).toHaveLength(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(FakeSocket.instances).toHaveLength(2);

    // Attempt 2 fails: retry after 2s, not 1s.
    act(() => FakeSocket.latest().drop());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(FakeSocket.instances).toHaveLength(2);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(FakeSocket.instances).toHaveLength(3);
  });

  // A successful reconnection resets the backoff, so the next outage is again
  // noticed within a second rather than half a minute.
  it("resets the backoff once a connection succeeds", async () => {
    vi.useFakeTimers();
    renderHook(() => useLiveEvents(true));

    act(() => FakeSocket.latest().drop());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    act(() => FakeSocket.latest().open());

    act(() => FakeSocket.latest().drop());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(FakeSocket.instances).toHaveLength(3);
  });

  it("closes the socket when the component goes away", async () => {
    const { unmount } = renderHook(() => useLiveEvents(true));
    act(() => FakeSocket.latest().open());

    const socket = FakeSocket.latest();
    unmount();

    expect(socket.closed).toBe(true);
    // And it must not reconnect after unmounting.
    act(() => socket.drop());
    expect(FakeSocket.instances).toHaveLength(1);
  });

  it("clears the buffer on request", async () => {
    const { result } = renderHook(() => useLiveEvents(true));
    act(() => FakeSocket.latest().open());
    act(() => FakeSocket.latest().emit(entry("a")));
    await waitFor(() => expect(result.current.events).toHaveLength(1));

    act(() => result.current.clear());
    await waitFor(() => expect(result.current.events).toHaveLength(0));
  });

  // The SPA is served from the same origin as the API, so the feed follows the
  // page's scheme. Hardcoding ws: would break the dashboard the day TLS is
  // enabled (RF-04, deferred to v1.1) and nothing else would.
  it("uses the page's scheme and host", () => {
    renderHook(() => useLiveEvents(true));

    const url = FakeSocket.latest().url;
    expect(url).toContain(window.location.host);
    expect(url).toMatch(/^ws:/);
    expect(url).toContain("/ws/live");
  });
});
