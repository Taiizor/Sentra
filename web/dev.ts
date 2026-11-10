console.log('[Sentra Web] Launching API bridge (port 3001) and Vite dev server (port 5173)...')

const cwd = import.meta.dirname

// 1. Start Bun API Backend on port 3001
const apiProcess = Bun.spawn(['bun', 'run', 'server.ts'], {
  cwd,
  stdout: 'inherit',
  stderr: 'inherit',
})

// 2. Start Vite Dev Server on port 5173
const viteProcess = Bun.spawn(['bun', 'run', 'vite'], {
  cwd,
  stdout: 'inherit',
  stderr: 'inherit',
})

function handleExit() {
  try {
    apiProcess.kill()
  } catch {}
  try {
    viteProcess.kill()
  } catch {}
  process.exit(0)
}

process.on('SIGINT', handleExit)
process.on('SIGTERM', handleExit)

// Exit if either process terminates unexpectedly
await Promise.race([apiProcess.exited, viteProcess.exited])
handleExit()
