import { useEffect, useRef, useState } from "react";
import type { AuditEntry } from "./types";

export type ConnectionState = "connecting" | "open" | "closed";

const MAX_EVENTS = 200;

/**
 * Subscribes to the live decision feed.
 *
 * The technical document sketches this hook in §7.3. Two things are added here
 * that a deployment needs and the sketch left out:
 *
 *  - Reconnection with exponential backoff. A dashboard left open overnight
 *    will outlive at least one engine restart, and the sketch's version goes
 *    permanently silent the first time the socket drops — with no visible
 *    difference from "no traffic", which is the worst possible failure for a
 *    monitoring tool.
 *  - A reported connection state, so the operator can tell an idle system from
 *    a broken one.
 */
export function useLiveEvents(enabled: boolean) {
  const [events, setEvents] = useState<AuditEntry[]>([]);
  const [state, setState] = useState<ConnectionState>("connecting");
  const attemptRef = useRef(0);

  useEffect(() => {
    if (!enabled) {
      setState("closed");
      return;
    }

    let socket: WebSocket | null = null;
    let retryTimer: number | undefined;
    let cancelled = false;

    const connect = () => {
      if (cancelled) return;

      setState("connecting");
      const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(`${scheme}//${window.location.host}/ws/live`);

      socket.onopen = () => {
        attemptRef.current = 0;
        setState("open");
      };

      socket.onmessage = (message) => {
        try {
          const entry = JSON.parse(message.data) as AuditEntry;
          setEvents((previous) => [entry, ...previous].slice(0, MAX_EVENTS));
        } catch {
          // A malformed frame is not worth tearing the feed down for.
        }
      };

      socket.onclose = () => {
        if (cancelled) return;
        setState("closed");

        // Backoff caps at 30s: an engine that is down for an hour should not be
        // hammered, but the feed should recover within half a minute of it
        // coming back.
        const delay = Math.min(1000 * 2 ** attemptRef.current, 30_000);
        attemptRef.current += 1;
        retryTimer = window.setTimeout(connect, delay);
      };

      socket.onerror = () => socket?.close();
    };

    connect();

    return () => {
      cancelled = true;
      window.clearTimeout(retryTimer);
      socket?.close();
    };
  }, [enabled]);

  return { events, state, clear: () => setEvents([]) };
}
