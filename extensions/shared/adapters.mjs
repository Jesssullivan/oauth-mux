// Browser permissions and acquisition schemas are a reviewed adapter boundary.
// Production grants remain blocked until identity/schema evidence is committed.
const productionAdapters = {
  codex: { id: "codex", label: "Codex / ChatGPT", origin: "https://chatgpt.com" },
  claude: { id: "claude", label: "Claude", origin: "https://claude.ai" },
  github: { id: "github", label: "GitHub", origin: "https://github.com" },
};

export const ADAPTERS = Object.freeze(Object.fromEntries(
  Object.entries(productionAdapters).map(([id, descriptor]) => [id, Object.freeze({
    ...descriptor,
    grantExport: "blocked_pending_schema_proof",
    browserBound: false,
    cookies: Object.freeze([]),
    storageKeys: Object.freeze([]),
    browserContext: Object.freeze({ partition: "unpartitioned", firefoxFirstPartyDomain: "" }),
  })]),
));

const FIXTURE = Object.freeze({
  id: "fixture",
  label: "Test fixture",
  origin: "https://fixture.invalid",
  grantExport: "enabled",
  browserBound: false,
  cookies: Object.freeze([Object.freeze({ name: "omux_fixture_session", domain: "fixture.invalid", path: "/" })]),
  storageKeys: Object.freeze(["omux_fixture_state"]),
  browserContext: Object.freeze({ partition: "unpartitioned", firefoxFirstPartyDomain: "" }),
});

export function getAdapter(id, { allowFixture = false } = {}) {
  if (allowFixture && id === "fixture") return FIXTURE;
  if (Object.hasOwn(ADAPTERS, id)) return ADAPTERS[id];
  throw new Error("unsupported_adapter");
}

export function hostPermission(adapter) {
  return `${adapter.origin}/*`;
}
