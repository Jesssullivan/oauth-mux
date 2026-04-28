#!/usr/bin/env node
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

const PLATFORM_MAP = {
  "darwin-arm64": "oauth-mux-darwin-arm64",
  "darwin-x64": "oauth-mux-darwin-x64",
  "linux-arm64": "oauth-mux-linux-arm64",
  "linux-x64": "oauth-mux-linux-x64",
  "win32-arm64": "oauth-mux-win32-arm64",
  "win32-x64": "oauth-mux-win32-x64",
};

const key = `${os.platform()}-${os.arch()}`;
const pkg = PLATFORM_MAP[key];

if (!pkg) {
  console.error(`oauth-mux: unsupported platform ${key}`);
  process.exit(1);
}

try {
  const pkgDir = path.dirname(require.resolve(`${pkg}/package.json`));
  const binary = os.platform() === "win32" ? "oauth-mux.exe" : "oauth-mux";
  const src = path.join(pkgDir, "bin", binary);
  const dest = path.join(__dirname, "bin", binary);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
  fs.chmodSync(dest, 0o755);
} catch (e) {
  console.error(`oauth-mux: failed to install binary: ${e.message}`);
  process.exit(1);
}
