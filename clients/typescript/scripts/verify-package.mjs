import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const scratch = mkdtempSync(join(tmpdir(), "fivedrisk-gateway-package-"));
const cache = join(scratch, "npm-cache");
mkdirSync(cache);

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, npm_config_cache: cache },
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result.stdout;
}

const packed = JSON.parse(run("npm", ["pack", "--json", "--silent"], root));
assert.equal(packed.length, 1, "npm pack must produce exactly one tarball");
const metadata = packed[0];
const files = new Set(metadata.files.map((entry) => entry.path));
for (const required of ["dist/index.js", "dist/index.d.ts", "README.md", "package.json"]) {
  assert.ok(files.has(required), `packed tarball is missing ${required}`);
}

const tarball = resolve(root, metadata.filename);
const consumer = join(scratch, "consumer");
mkdirSync(consumer);
try {
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({ name: "fivedrisk-gateway-consumer", private: true, type: "module" }),
  );
  run(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
    consumer,
  );
  writeFileSync(
    join(consumer, "smoke.mjs"),
    "import { bandToSentinel } from 'fivedrisk-gateway';\n"
      + "if (bandToSentinel('RED') !== 'block') throw new Error('public API smoke failed');\n",
  );
  run(process.execPath, ["smoke.mjs"], consumer);

  const installed = JSON.parse(
    readFileSync(join(consumer, "node_modules", "fivedrisk-gateway", "package.json"), "utf8"),
  );
  assert.equal(installed.name, "fivedrisk-gateway");
} finally {
  rmSync(tarball, { force: true });
  rmSync(scratch, { recursive: true, force: true });
}

console.log("packed package contains runtime/types and imports from a clean consumer");
