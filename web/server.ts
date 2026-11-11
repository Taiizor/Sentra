/**
 * Sentra web bridge entry point. See web/README.md for configuration.
 *
 *   bun run server.ts               # development (pair with the Vite dev server)
 *   bun run server.ts --production  # serve web/dist and the API from one origin
 */
import { startServer } from "./server/main.ts";

startServer();
