import type { AppContext } from "../app-context.ts";
import type { Router } from "../http.ts";
import { registerCoreRoutes } from "./core-routes.ts";
import { registerGitHubRoutes } from "./github.ts";
import { registerIntelRoutes } from "./intel.ts";
import { registerPatchRoutes } from "./patches.ts";
import { registerPluginRoutes } from "./plugins.ts";
import { registerPromptRoutes } from "./prompts.ts";
import { registerResearchRoutes } from "./research.ts";
import { registerScanRoutes } from "./scans.ts";
import { registerAiSettingsRoutes } from "./ai-settings.ts";
import { registerWebhookRoutes } from "./webhooks.ts";

export function registerRoutes(router: Router, app: AppContext): void {
  registerCoreRoutes(router, app);
  registerScanRoutes(router, app);
  registerIntelRoutes(router, app);
  registerPatchRoutes(router, app);
  registerAiSettingsRoutes(router, app);
  registerPromptRoutes(router, app);
  registerGitHubRoutes(router, app);
  registerWebhookRoutes(router, app);
  registerResearchRoutes(router, app);
  registerPluginRoutes(router, app);
}
