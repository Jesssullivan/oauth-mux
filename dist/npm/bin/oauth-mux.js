#!/usr/bin/env node
const { spawnSync } = require("child_process");
const path = require("path");

const binary = process.platform === "win32" ? "oauth-mux.exe" : "oauth-mux";
const binPath = path.join(__dirname, binary);

const result = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  console.error(`oauth-mux: failed to launch ${binPath}: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  process.kill(process.pid, result.signal);
}

process.exit(result.status ?? 1);
