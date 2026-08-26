import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The built output is embedded in the dashboard API binary, which serves it
// from the same origin as the API — so every request is same-origin in
// production and no CORS handling exists anywhere in this system.
//
// In development Vite serves the SPA instead, and proxies the API and the
// WebSocket to a locally running dashboard-api so the same relative paths work.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Hashed filenames under assets/ are what let the Go handler cache them
    // immutably while keeping index.html uncacheable.
    assetsDir: "assets",
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8081", changeOrigin: true },
      "/ws": { target: "ws://localhost:8081", ws: true },
    },
  },
});
