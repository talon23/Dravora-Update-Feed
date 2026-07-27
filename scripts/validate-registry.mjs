import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  canonicalize,
  historyRegistryPath,
  parseCanonicalJson,
  sha256Label,
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
  /^license-registry\/history\/[0-9]{16}-[0-9a-f]{64}\/registry\.json$/,
  /^license-registry\/history\/[0-9]{16}-[0-9a-f]{64}\/registry\.sig\.json$/,
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
  const latestDigest = verifyRegistrySignature(registryBytes, registry, signature, trust);
  const historyPayloads = tracked
    .filter((path) => /^license-registry\/history\/[^/]+\/registry\.json$/.test(path))
    .sort();
  const historySignatures = tracked.filter((path) => /^license-registry\/history\/[^/]+\/registry\.sig\.json$/.test(path));
  if (historyPayloads.length !== historySignatures.length) throw new Error("every history payload requires one signature");
  let previous = null;
  for (const historyPath of historyPayloads) {
    const historyBytes = readFileSync(resolve(root, historyPath));
    const historyRegistry = parseCanonicalJson(historyBytes, historyPath);
    const digest = sha256Label(historyBytes);
    if (historyPath !== historyRegistryPath(historyRegistry.sequence, digest)) throw new Error(`history path does not bind payload: ${historyPath}`);
    const signaturePath = historyPath.replace(/registry\.json$/, "registry.sig.json");
    if (!historySignatures.includes(signaturePath)) throw new Error(`missing history signature: ${signaturePath}`);
    const historySignature = parseCanonicalJson(readFileSync(resolve(root, signaturePath)), signaturePath);
    verifyRegistrySignature(historyBytes, historyRegistry, historySignature, trust);
    if (previous === null) {
      if (historyRegistry.sequence !== 1) throw new Error("history must begin at genesis");
    } else if (
      historyRegistry.sequence !== previous.sequence + 1 ||
      historyRegistry.previous_sequence !== previous.sequence ||
      historyRegistry.previous_payload_sha256 !== previous.digest
    ) {
      throw new Error("history chain is not contiguous");
    }
    previous = { sequence: historyRegistry.sequence, digest };
  }
  if (previous === null || previous.sequence !== registry.sequence || previous.digest !== latestDigest || canonicalize(registry) !== canonicalize(parseCanonicalJson(readFileSync(resolve(root, historyRegistryPath(registry.sequence, latestDigest))), "latest history payload"))) {
    throw new Error("latest registry must exactly match the history tip");
  }
}

console.log(`validated ${tracked.length} allowlisted files; registry status: ${trust.status}`);
