import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Point at another API port with SIIDEKICK_API=http://localhost:8790 npm run dev -w apps/web
      "/api": process.env.SIIDEKICK_API ?? "http://localhost:8787",
    },
  },
});
