#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const marker = "OMUX_CODEX_SHIM";
const self = fs.realpathSync(__filename);
const oauthMuxJs = path.join(__dirname, "oauth-mux.js");
const pathEntries = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
const candidateNames = process.platform === "win32"
  ? ["codex.exe", "codex.cmd", "codex.bat", "codex"]
  : ["codex"];

function isShim(candidate) {
  try {
    const real = fs.realpathSync(candidate);
    if (real === self) return true;
    const sample = fs.readFileSync(candidate, { encoding: "utf8", flag: "r" }).slice(0, 4096);
    return sample.includes(marker);
  } catch {
    return false;
  }
}

function findNativeCodex() {
  for (const dir of pathEntries) {
    for (const name of candidateNames) {
      const candidate = path.join(dir, name);
      if (!fs.existsSync(candidate)) continue;
      try {
        const stat = fs.statSync(candidate);
        if (!stat.isFile() && !stat.isSymbolicLink()) continue;
      } catch {
        continue;
      }
      if (isShim(candidate)) continue;
      return candidate;
    }
  }
  return null;
}

function shouldPassNative(firstArg) {
  return new Set([
    "--help",
    "-h",
    "help",
    "--version",
    "-V",
    "version",
    "login",
    "logout",
    "auth",
    "mcp",
    "completion",
    "completions",
  ]).has(firstArg || "");
}

function exitFromResult(prefix, result) {
  if (result.error) {
    console.error(`${prefix}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.signal) {
    process.kill(process.pid, result.signal);
  }
  process.exit(result.status ?? 1);
}

const nativeCodex = process.env.OMUX_CODEX_BIN || findNativeCodex();
if (!nativeCodex) {
  console.error("codex: native Codex CLI not found; set OMUX_CODEX_BIN to the upstream Codex executable");
  process.exit(127);
}

const forwardedArgs = process.argv.slice(2);
if (shouldPassNative(forwardedArgs[0])) {
  exitFromResult(
    "codex: failed to launch native Codex",
    spawnSync(nativeCodex, forwardedArgs, {
      stdio: "inherit",
      env: process.env,
    }),
  );
}

const env = {
  ...process.env,
  OMUX_CODEX_BIN: nativeCodex,
  OMUX_CODEX_SHIM: "1",
  OMUX_COMMAND_SPELLING: "codex",
};
const result = spawnSync(process.execPath, [oauthMuxJs, "codex", ...forwardedArgs], {
  stdio: "inherit",
  env,
});

exitFromResult("codex: failed to launch oauth-mux", result);
