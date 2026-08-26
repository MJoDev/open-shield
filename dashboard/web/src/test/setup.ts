import "@testing-library/jest-dom/vitest";
import { afterEach, expect } from "vitest";
import { cleanup } from "@testing-library/react";

// jsdom keeps the document between tests in the same file; without this a query
// that should find one element finds three and the failure looks like a bug in
// the component.
afterEach(cleanup);

// jsdom has no WebSocket. Rather than leave `new WebSocket(...)` throwing a
// ReferenceError that a test would have to interpret, the failure is made
// explicit: a test that reaches the live feed without installing the fake
// socket from useLiveEvents.test.tsx gets told so.
if (!("WebSocket" in globalThis)) {
  Object.defineProperty(globalThis, "WebSocket", {
    writable: true,
    configurable: true,
    value: class {
      constructor() {
        throw new Error(
          "this test opened a WebSocket without installing the fake; see src/test/fakeSocket.ts",
        );
      }
    },
  });
}

// Nothing in the suite may reach the network.
Object.defineProperty(globalThis, "fetch", {
  writable: true,
  configurable: true,
  value: () => {
    throw new Error("a test called fetch() without stubbing it");
  },
});

expect.extend({});
