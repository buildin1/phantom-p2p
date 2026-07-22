#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const statePath = path.join(root, "version.json");
const localPackages = new Set([
  "phantom-core",
  "phantom-mobile",
  "phantom-p2p",
  "phantom-p2p-web",
  "phantom-protocol",
  "phantom-server",
]);

function fail(message) {
  console.error(`version: ${message}`);
  process.exit(1);
}

function parseVersion(value) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(value);
  if (!match) fail(`invalid version '${value}', expected x.x.x`);
  const parts = match.slice(1).map(Number);
  if (parts[1] > 10 || parts[2] > 10) {
    fail(`invalid version '${value}', minor and patch must be between 0 and 10`);
  }
  return parts;
}

function formatVersion(parts) {
  return parts.join(".");
}

function nextVersion(value) {
  let [major, minor, patch] = parseVersion(value);
  patch += 1;
  if (patch > 10) {
    patch = 0;
    minor += 1;
  }
  if (minor > 10) {
    minor = 0;
    major += 1;
  }
  return formatVersion([major, minor, patch]);
}

function buildNumber(value) {
  const [major, minor, patch] = parseVersion(value);
  return major * 121 + minor * 11 + patch;
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function jsonText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function replaceRequired(text, pattern, replacement, label) {
  if (!pattern.test(text)) fail(`cannot find ${label}`);
  pattern.lastIndex = 0;
  return text.replace(pattern, replacement);
}

function syncCargoManifest(text, version, relativePath) {
  return replaceRequired(
    text,
    /(\[package\][\s\S]*?^version\s*=\s*")[^"]+("\s*$)/m,
    `$1${version}$2`,
    `package version in ${relativePath}`,
  );
}

function syncCargoLock(text, version, relativePath) {
  let found = 0;
  const output = text.replace(
    /(\[\[package\]\]\r?\nname = "([^"]+)"\r?\nversion = ")[^"]+("\r?\n)/g,
    (match, prefix, name, suffix) => {
      if (!localPackages.has(name)) return match;
      found += 1;
      return `${prefix}${version}${suffix}`;
    },
  );
  if (found === 0) fail(`cannot find local packages in ${relativePath}`);
  return output;
}

function desiredFiles(version) {
  const number = buildNumber(version);
  const files = new Map();

  files.set("version.json", jsonText({ version, buildNumber: number }));

  const packageJson = readJson("package.json");
  packageJson.version = version;
  files.set("package.json", jsonText(packageJson));

  const packageLock = readJson("package-lock.json");
  packageLock.version = version;
  if (packageLock.packages?.[""]) packageLock.packages[""].version = version;
  files.set("package-lock.json", jsonText(packageLock));

  const tauriConfig = readJson("src-tauri/tauri.conf.json");
  tauriConfig.version = version;
  files.set("src-tauri/tauri.conf.json", jsonText(tauriConfig));

  const manifests = [
    "src-tauri/Cargo.toml",
    "crates/core/Cargo.toml",
    "crates/mobile/Cargo.toml",
    "crates/protocol/Cargo.toml",
    "server/Cargo.toml",
    "src-web/Cargo.toml",
  ];
  for (const relativePath of manifests) {
    const text = fs.readFileSync(path.join(root, relativePath), "utf8");
    files.set(relativePath, syncCargoManifest(text, version, relativePath));
  }

  for (const relativePath of ["Cargo.lock", "src-tauri/Cargo.lock"]) {
    const text = fs.readFileSync(path.join(root, relativePath), "utf8");
    files.set(relativePath, syncCargoLock(text, version, relativePath));
  }

  let html = fs.readFileSync(path.join(root, "index.html"), "utf8");
  html = replaceRequired(
    html,
    /(<div class="brand-version" id="appVersion")(?: data-build="\d+")?(>)[^<]+(<\/div>)/,
    `$1 data-build="${number}"$2v${version} (${number})$3`,
    "frontend appVersion",
  );
  files.set("index.html", html);

  let gradle = fs.readFileSync(path.join(root, "android/app/build.gradle.kts"), "utf8");
  gradle = replaceRequired(
    gradle,
    /(versionCode\s*=\s*)\d+/,
    `$1${number}`,
    "Android versionCode",
  );
  gradle = replaceRequired(
    gradle,
    /(versionName\s*=\s*")[^"]+("\s*)/,
    `$1${version}$2`,
    "Android versionName",
  );
  files.set("android/app/build.gradle.kts", gradle);

  let installer = fs.readFileSync(path.join(root, "build/windows-installer.nsi"), "utf8");
  installer = replaceRequired(
    installer,
    /(!define APP_VERSION ")[^"]+("\s*)/,
    `$1${version}$2`,
    "NSIS APP_VERSION",
  );
  files.set("build/windows-installer.nsi", installer);

  return { files, number };
}

function synchronize(version, checkOnly) {
  const { files, number } = desiredFiles(version);
  const changed = [];
  for (const [relativePath, desired] of files) {
    const absolutePath = path.join(root, relativePath);
    const current = fs.readFileSync(absolutePath, "utf8");
    if (current === desired) continue;
    changed.push(relativePath);
    if (!checkOnly) fs.writeFileSync(absolutePath, desired, "utf8");
  }
  if (checkOnly && changed.length > 0) {
    fail(`version metadata is out of sync:\n  ${changed.join("\n  ")}`);
  }
  return { changed, number };
}

function loadState() {
  const state = readJson("version.json");
  parseVersion(state.version);
  const expected = buildNumber(state.version);
  if (state.buildNumber !== expected) {
    fail(`buildNumber ${state.buildNumber} does not match ${state.version} (expected ${expected})`);
  }
  return state;
}

function selfTest() {
  const cases = new Map([
    ["1.0.0", "1.0.1"],
    ["1.0.10", "1.1.0"],
    ["1.10.9", "1.10.10"],
    ["1.10.10", "2.0.0"],
    ["10.10.10", "11.0.0"],
  ]);
  for (const [input, expected] of cases) {
    const actual = nextVersion(input);
    if (actual !== expected) fail(`self-test: ${input} produced ${actual}, expected ${expected}`);
  }
  if (buildNumber("1.10.10") + 1 !== buildNumber("2.0.0")) {
    fail("self-test: build number is not monotonic at major rollover");
  }
  console.log("version self-test: OK");
}

const command = process.argv[2] ?? "check";
if (command === "self-test") {
  selfTest();
  process.exit(0);
}

const state = loadState();
if (command === "current") {
  console.log(state.version);
} else if (command === "build-number") {
  console.log(state.buildNumber);
} else if (command === "check") {
  synchronize(state.version, true);
  console.log(`version ${state.version} (build ${state.buildNumber}): synchronized`);
} else if (command === "sync") {
  const result = synchronize(state.version, false);
  console.log(`version ${state.version} (build ${result.number}): synchronized ${result.changed.length} file(s)`);
} else if (command === "bump") {
  const version = nextVersion(state.version);
  const result = synchronize(version, false);
  console.log(`version ${state.version} -> ${version} (build ${result.number})`);
} else {
  fail(`unknown command '${command}' (use bump, sync, check, current, build-number, or self-test)`);
}
