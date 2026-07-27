import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  parseCanonicalJson,
  validateTrust,
  verifyRegistrySignature,
} from "./registry-lib.mjs";

const root = resolve(import.meta.dirname, "..");
const allowed = [
  /^\.gitattributes$/,
  /^\.github\/workflows\/validate-license-registry\.yml$/,
  /^README\.md$/,
  /^LICENSE-REGISTRY\.md$/,
  /^package\.json$/,
  /^license-registry\/README\.md$/,
  /^license-registry\/trust\.json$/,
  /^license-registry\/registry\.json$/,
  /^license-registry\/registry\.sig\.json$/,
  /^schemas\/[a-z0-9.-]+\.schema\.json$/,
  /^scripts\/[a-z0-9.-]+\.mjs$/,
  /^tests\/[a-z0-9.-]+\.test\.mjs$/,
];

const tracked = execFileSync(
  "git",
  ["ls-files", "--cached", "--others", "--exclude-standard"],
  { cwd: root, encoding: "utf8" },
)
  .split(/\r?\n/)
  .filter(Boolean);
const disallowed = tracked.filter((path) => !allowed.some((pattern) => pattern.test(path)));
if (disallowed.length) throw new Error(`disallowed tracked paths: ${disallowed.join(", ")}`);

for (const schema of tracked.filter((path) => path.startsWith("schemas/"))) {
  JSON.parse(readFileSync(resolve(root, schema), "utf8"));
}

const trustBytes = readFileSync(resolve(root, "license-registry/trust.json"));
const trust = parseCanonicalJson(trustBytes, "trust.json", { allowFinalLf: true });
validateTrust(trust);

const hasRegistry = tracked.includes("license-registry/registry.json");
const hasSignature = tracked.includes("license-registry/registry.sig.json");
if (hasRegistry !== hasSignature) throw new Error("registry payload and signature must both be present or absent");
if (trust.status === "active" && !hasRegistry) throw new Error("active trust requires a signed registry");
if (trust.status === "unprovisioned" && hasRegistry) throw new Error("unprovisioned trust cannot publish a registry");

if (hasRegistry) {
  const registryBytes = readFileSync(resolve(root, "license-registry/registry.json"));
  const registry = parseCanonicalJson(registryBytes, "registry.json");
  const signature = parseCanonicalJson(
    readFileSync(resolve(root, "license-registry/registry.sig.json")),
    "registry.sig.json",
  );
  verifyRegistrySignature(registryBytes, registry, signature, trust);
}

console.log(`validated ${tracked.length} allowlisted files; registry status: ${trust.status}`);
