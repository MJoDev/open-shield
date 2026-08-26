import { vi } from "vitest";

/**
 * A stand-in for the browser's WebSocket, so the live feed can be driven from a
 * test.
 *
 * useLiveEvents exists mostly to survive a connection that drops — a dashboard
 * left open overnight outlives at least one engine restart, and the version
 * sketched in §7.3 of the technical document goes permanently silent the first
 * time that happens, with no visible difference from "no traffic". That is the
 * worst failure a monitoring tool has, and it is only testable if a test can
 * close the socket itself.
 */
export class FakeSocket {
  static instances: FakeSocket[] = [];

  readonly url: string;
  readyState = 0;
  closed = false;

  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(url: string) {
    this.url = url;
    FakeSocket.instances.push(this);
  }

  /** The server accepting the connection. */
  open() {
    this.readyState = 1;
    this.onopen?.();
  }

  /** One event arriving on the feed. */
  emit(payload: unknown) {
    this.onmessage?.({ data: JSON.stringify(payload) });
  }

  /** A frame that is not valid JSON, which must not tear the feed down. */
  emitRaw(data: string) {
    this.onmessage?.({ data });
  }

  /** The connection dropping, as an engine restart would. */
  drop() {
    this.readyState = 3;
    this.onclose?.();
  }

  close() {
    this.closed = true;
    this.readyState = 3;
  }

  static latest(): FakeSocket {
    const socket = FakeSocket.instances.at(-1);
    if (!socket) {
      throw new Error("no WebSocket was opened");
    }
    return socket;
  }

  static reset() {
    FakeSocket.instances = [];
  }
}

/** Installs FakeSocket as the global WebSocket for the current test. */
export function installFakeSocket() {
  FakeSocket.reset();
  vi.stubGlobal("WebSocket", FakeSocket as unknown as typeof WebSocket);
}
