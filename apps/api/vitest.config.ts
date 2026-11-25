import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    alias: {
      "@siidekick/engine": path.resolve(__dirname, "../../packages/engine/src/index.ts"),
    },
    environment: "node",
  },
});
