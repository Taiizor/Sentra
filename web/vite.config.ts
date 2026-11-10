import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

const bridgePort = process.env.SENTRA_WEB_PORT ?? "3001"

/** Package name of the innermost node_modules entry in a module id, or null for application code. */
function packageName(moduleId: string): string | null {
  const parts = moduleId.replaceAll("\\", "/").split("/node_modules/")
  if (parts.length < 2) return null
  const segments = parts[parts.length - 1].split("/")
  return segments[0].startsWith("@") ? `${segments[0]}/${segments[1] ?? ""}` : segments[0]
}

function packageGroup(name: string, priority: number, packages: RegExp) {
  return {
    name,
    priority,
    test: (moduleId: string) => {
      const pkg = packageName(moduleId)
      return pkg !== null && packages.test(pkg)
    },
  }
}

/**
 * Vendor chunks for the production build. The console loads every tab eagerly, so this does not
 * change what is downloaded at start-up; it keeps each chunk under Vite's size advisory and lets
 * browsers cache the libraries separately from the application code. Each group also captures
 * the dependencies of its modules that a higher-priority group has not taken (Rolldown's
 * default), which keeps the chunk graph free of cycles; React is therefore taken first.
 */
const VENDOR_GROUPS = [
  packageGroup("react", 40, /^(react|react-dom|scheduler)$/),
  packageGroup("ui", 30, /^(@base-ui\/[^/]+|@floating-ui\/[^/]+|lucide-react|cmdk|sonner|tabbable)$/),
  packageGroup("charts", 20, /^(recharts|victory-vendor|d3-[a-z-]+|internmap|decimal\.js-light|es-toolkit|eventemitter3|immer|redux|redux-thunk|react-redux|reselect|@reduxjs\/toolkit|tiny-invariant)$/),
  packageGroup("vendor", 10, /./),
]

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: VENDOR_GROUPS,
        },
      },
    },
  },
  server: {
    host: "localhost",
    port: 5173,
    strictPort: true,
    proxy: {
      // The bridge binds to IPv4 loopback by default; target it explicitly so "localhost"
      // resolving to ::1 cannot break the proxy.
      "/api": {
        target: `http://127.0.0.1:${bridgePort}`,
        changeOrigin: true,
      },
    },
  },
})
