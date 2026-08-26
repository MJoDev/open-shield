import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Kept separate from vite.config.ts rather than merged into it: the build
// configuration is what ships inside the dashboard binary, and nothing about
// the test runner belongs in it.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // The suite must not reach the network. Every test that needs the API
    // stubs fetch explicitly; one that forgets should fail loudly rather than
    // quietly hit a dashboard that happens to be running on this machine.
    restoreMocks: true,
    clearMocks: true,
  },
});
