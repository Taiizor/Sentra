/**
 * Development launcher: starts the bridge (server.ts, default 127.0.0.1:3001) and the Vite dev
 * server (127.0.0.1:5173, proxying /api to the bridge). For production use `bun run start`
 * after `bun run build`, which serves the built UI and the API from a single origin.
 */
const cwd = import.meta.dirname
const bridgePort = process.env.SENTRA_WEB_PORT ?? '3001'

console.log(`[sentra-web] starting bridge on 127.0.0.1:${bridgePort} and Vite on http://localhost:5173`)

const bridge = Bun.spawn(['bun', 'run', 'server.ts'], { cwd, stdout: 'inherit', stderr: 'inherit', env: process.env })
const vite = Bun.spawn(['bun', 'run', 'vite'], { cwd, stdout: 'inherit', stderr: 'inherit', env: process.env })

let stopping = false
async function stop(code: number) {
  if (stopping) return
  stopping = true
  for (const child of [bridge, vite]) {
    try {
      child.kill()
    } catch {
      // already exited
    }
  }
  await Promise.allSettled([bridge.exited, vite.exited])
  process.exit(code)
}

process.on('SIGINT', () => void stop(0))
process.on('SIGTERM', () => void stop(0))

// If either process exits, stop the other one too.
const exitCode = await Promise.race([bridge.exited, vite.exited])
await stop(typeof exitCode === 'number' ? exitCode : 1)
