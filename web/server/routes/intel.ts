import type { AppContext } from "../app-context.ts";
import { HttpError, json, type Router } from "../http.ts";
import { osvDisabledError } from "../services/osv.ts";
import { optionalString, requiredString } from "../validate.ts";
import { actorOf, audited } from "./helpers.ts";

/** OSV ecosystem identifiers, including release-qualified forms such as `Debian:12`. */
const ECOSYSTEM_PATTERN = /^[A-Za-z][A-Za-z0-9.+_-]{0,39}(?::[A-Za-z0-9.+_ -]{1,40})?$/;

export function registerIntelRoutes(router: Router, app: AppContext): void {
  router.get("/api/intel/status", { auth: "session", permission: "read" }, () => json(app.osv.status()));

  router.put("/api/settings/intel", { auth: "session", permission: "settings:write" }, async (ctx) => {
    const body = await ctx.readJson();
    if (typeof body.osvEnabled !== "boolean") {
      throw new HttpError(400, "invalid_request", "'osvEnabled' is required and must be a boolean");
    }
    const osvEnabled = body.osvEnabled;
    const previous = app.osv.enabled();
    const status = await audited(
      app,
      ctx.principal,
      { action: "intel_settings_updated", target: "intel.osv", details: { osvEnabled, previous } },
      () => app.osv.setEnabled(osvEnabled, actorOf(ctx.principal)),
    );
    return json(status);
  });

  router.post("/api/intel/osv/query", { auth: "session", permission: "intel:query" }, async (ctx) => {
    const body = await ctx.readJson();
    const pkg = requiredString(body, "package", { max: 256 });
    const ecosystem = requiredString(body, "ecosystem", { max: 81, pattern: ECOSYSTEM_PATTERN });
    const version = optionalString(body, "version", { max: 128 }) ?? null;
    // oxlint-disable-next-line no-control-regex -- intentional: rejects control characters in the package name and version
    if (/[\u0000-\u001f]/.test(pkg) || (version !== null && /[\u0000-\u001f]/.test(version))) {
      throw new HttpError(400, "invalid_request", "'package' and 'version' must not contain control characters");
    }
    if (!app.osv.enabled()) throw osvDisabledError();
    // Recorded because the query discloses a package name (and version) to OSV.dev.
    const result = await audited(
      app,
      ctx.principal,
      { action: "osv_query", target: `${ecosystem}/${pkg}`, details: { package: pkg, ecosystem, version } },
      () => app.osv.query(pkg, ecosystem, version),
      (response) => ({ vulnerabilities: response.vulnerabilities.length }),
    );
    return json(result);
  });
}
