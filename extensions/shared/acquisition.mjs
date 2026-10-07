import { AcquisitionError, validateCapsule } from "./protocol.mjs";
import { ADAPTERS, getAdapter } from "./adapters.mjs";

export function projectCookieChange(changeInfo, { allowFixture = false } = {}) {
  const enabled = [...Object.values(ADAPTERS), ...(allowFixture ? [getAdapter("fixture", { allowFixture: true })] : [])].filter(adapter => adapter.grantExport === "enabled");
  if (!enabled.length) return null;
  const cookie = changeInfo?.cookie;
  if (!cookie || typeof changeInfo.removed !== "boolean" || typeof cookie.storeId !== "string" || !cookie.storeId || cookie.storeId.length > 128) return null;
  const adapter = enabled.find(candidate => candidate.cookies.some(rule => rule.name === cookie.name && rule.domain === cookie.domain && rule.path === cookie.path));
  if (!adapter) return null;
  if (adapter.browserContext.partition === "unpartitioned" && cookie.partitionKey) return null;
  if (adapter.browserContext.partition === "origin" && cookie.partitionKey?.topLevelSite !== adapter.origin) return null;
  if ((cookie.firstPartyDomain ?? "") !== adapter.browserContext.firefoxFirstPartyDomain) return null;
  // Deliberately do not touch cookie.value, even when deciding to reject work.
  return { adapter: adapter.id, storeId: cookie.storeId, removed: changeInfo.removed };
}

// Raw values exist only in this function's ephemeral capsule and native message.
export async function acquireGrant({ adapter, storeId, cookies, readStorage, now, browserKind = "chromium" }) {
  if (adapter.grantExport !== "enabled") throw new AcquisitionError("grant_export_unproven");
  if (!["chromium", "firefox"].includes(browserKind) || !["unpartitioned", "origin"].includes(adapter.browserContext?.partition) || typeof adapter.browserContext.firefoxFirstPartyDomain !== "string") throw new AcquisitionError("browser_context_unproven");
  const capturedAt = Math.floor(now());
  const exportedCookies = [];
  for (const rule of adapter.cookies) {
    const query = { url: `${adapter.origin}${rule.path}`, name: rule.name, storeId };
    if (adapter.browserContext.partition === "origin") query.partitionKey = { topLevelSite: adapter.origin };
    if (browserKind === "firefox") query.firstPartyDomain = adapter.browserContext.firefoxFirstPartyDomain;
    const values = await cookies.getAll(query);
    for (const cookie of values) {
      if (cookie.name !== rule.name || cookie.domain !== rule.domain || cookie.path !== rule.path || cookie.storeId !== storeId) continue;
      if (adapter.browserContext.partition === "unpartitioned" && cookie.partitionKey) continue;
      if (adapter.browserContext.partition === "origin" && cookie.partitionKey?.topLevelSite !== adapter.origin) continue;
      if ((cookie.firstPartyDomain ?? "") !== adapter.browserContext.firefoxFirstPartyDomain) continue;
      if (!cookie.session && cookie.expirationDate <= capturedAt) continue;
      const exported = {};
      for (const key of ["name", "value", "domain", "path", "secure", "httpOnly", "hostOnly", "session", "sameSite", "storeId", "expirationDate", "firstPartyDomain"]) {
        if (Object.hasOwn(cookie, key)) exported[key] = cookie[key];
      }
      if (cookie.partitionKey) {
        exported.partitionKey = { topLevelSite: cookie.partitionKey.topLevelSite };
        if (Object.hasOwn(cookie.partitionKey, "hasCrossSiteAncestor")) exported.partitionKey.hasCrossSiteAncestor = cookie.partitionKey.hasCrossSiteAncestor;
      }
      exportedCookies.push(exported);
    }
  }
  const storage = adapter.storageKeys.length ? await readStorage(adapter.origin, adapter.storageKeys, { storeId, browserKind, browserContext: adapter.browserContext }) : [];
  const capsule = { kind: "browser_session", purpose: "identity_observation", renewalAuthority: "external", browserBound: adapter.browserBound, capturedAt, cookies: exportedCookies, storage };
  const expiries = exportedCookies.filter(cookie => !cookie.session).map(cookie => Math.floor(cookie.expirationDate));
  if (expiries.length) capsule.expiresAt = Math.min(...expiries);
  return validateCapsule(capsule, adapter);
}
