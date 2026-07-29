import { createHash } from "node:crypto";
import { createReadStream, statSync } from "node:fs";
import { basename, resolve } from "node:path";

const exactKeys = (value, expected, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
};

const digestPattern = /^[0-9A-F]{64}$/;
const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
const addonPattern = /^[a-z]+ops$/;
const environments = new Set(["development", "test", "staging", "production"]);
const channels = new Set(["developer", "test", "staging", "stable"]);
const addonStatuses = new Set(["active", "suspended", "revoked", "retired"]);
const packageStatuses = new Set(["available", "withdrawn", "revoked"]);
const forbiddenText = /customer|testerName|email|phone|address|passphrase|privateKey|bearer|DRVA1\.|HSE record/i;

export function validateAddonStatusRegistry(registry) {
  exactKeys(registry, ["schemaVersion", "kind", "registryEpoch", "sequence", "issuedAtUtc", "expiresAtUtc", "entries"], "status registry");
  if (JSON.stringify(registry).match(forbiddenText)) throw new Error("status registry contains forbidden private data");
  if (registry.schemaVersion !== 1 || registry.kind !== "dravora-addon-licence-status-registry") throw new Error("status registry identity mismatch");
  if (!uuidPattern.test(registry.registryEpoch) || !Number.isSafeInteger(registry.sequence) || registry.sequence < 1) throw new Error("status registry sequence identity mismatch");
  if (Date.parse(registry.issuedAtUtc) >= Date.parse(registry.expiresAtUtc)) throw new Error("status registry expiry must be after issue time");
  if (!Array.isArray(registry.entries)) throw new Error("status registry entries must be an array");
  const seen = new Set();
  for (const [index, entry] of registry.entries.entries()) {
    exactKeys(entry, ["entitlementId", "addOnId", "licenceSha256", "status", "notBeforeUtc", "expiresAtUtc", "reasonCode"], `entries[${index}]`);
    const key = `${entry.entitlementId}:${entry.addOnId}`;
    if (seen.has(key)) throw new Error("duplicate entitlement/add-on status entry");
    seen.add(key);
    if (!uuidPattern.test(entry.entitlementId) || !addonPattern.test(entry.addOnId)) throw new Error("invalid status entry identity");
    if (!digestPattern.test(entry.licenceSha256)) throw new Error("licenceSha256 must be uppercase SHA-256");
    if (!addonStatuses.has(entry.status)) throw new Error("unsupported add-on status");
    if (Date.parse(entry.notBeforeUtc) >= Date.parse(entry.expiresAtUtc)) throw new Error("entry expiry must be after not-before");
    if (!(entry.reasonCode === null || (typeof entry.reasonCode === "string" && entry.reasonCode.length <= 80))) throw new Error("invalid reasonCode");
  }
  return registry;
}

export function validateAddonPackageCatalogue(catalogue) {
  exactKeys(catalogue, ["schemaVersion", "kind", "catalogueEpoch", "sequence", "issuedAtUtc", "expiresAtUtc", "environment", "channel", "packages"], "package catalogue");
  if (JSON.stringify(catalogue).match(forbiddenText)) throw new Error("package catalogue contains forbidden private data");
  if (catalogue.schemaVersion !== 1 || catalogue.kind !== "dravora-addon-package-catalogue") throw new Error("package catalogue identity mismatch");
  if (!uuidPattern.test(catalogue.catalogueEpoch) || !Number.isSafeInteger(catalogue.sequence) || catalogue.sequence < 1) throw new Error("package catalogue sequence identity mismatch");
  if (!environments.has(catalogue.environment) || !channels.has(catalogue.channel)) throw new Error("unsupported package catalogue lane");
  if (Date.parse(catalogue.issuedAtUtc) >= Date.parse(catalogue.expiresAtUtc)) throw new Error("package catalogue expiry must be after issue time");
  if (!Array.isArray(catalogue.packages) || catalogue.packages.length < 1 || catalogue.packages.length > 12) throw new Error("package catalogue must contain one to twelve packages");
  const addOns = new Set();
  for (const [index, entry] of catalogue.packages.entries()) {
    exactKeys(entry, ["addOnId", "addOnVersion", "packageFileName", "packageUri", "packageSha256", "packageLength", "descriptorSha256", "registrySha256", "immutableIdentity", "processor", "payloadNamespace", "status"], `packages[${index}]`);
    if (addOns.has(entry.addOnId)) throw new Error("duplicate add-on package entry");
    addOns.add(entry.addOnId);
    if (!addonPattern.test(entry.addOnId) || !/^1\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/.test(entry.addOnVersion)) throw new Error("invalid add-on package identity");
    const expectedFile = `Dravora-addon-${entry.addOnId}-${entry.addOnVersion}-${catalogue.environment}-${catalogue.channel}.dravup`;
    if (entry.packageFileName !== expectedFile) throw new Error("package file name mismatch");
    if (entry.immutableIdentity !== `addon/${entry.addOnId}/${catalogue.environment}/${catalogue.channel}/${entry.addOnVersion}`) throw new Error("immutable identity mismatch");
    if (entry.processor !== "dravora.addon.v1" || entry.payloadNamespace !== `addons/${entry.addOnId}/`) throw new Error("processor or payload namespace mismatch");
    for (const field of ["packageSha256", "descriptorSha256", "registrySha256"]) {
      if (!digestPattern.test(entry[field])) throw new Error(`${field} must be uppercase SHA-256`);
    }
    if (!Number.isSafeInteger(entry.packageLength) || entry.packageLength < 1 || entry.packageLength > 1073741824) throw new Error("package length must be one byte to one GiB");
    if (!packageStatuses.has(entry.status)) throw new Error("unsupported package status");
    validatePackageUri(entry.packageUri, expectedFile);
  }
  return catalogue;
}

export function validatePackageUri(value, expectedFile) {
  let uri;
  try {
    uri = new URL(value);
  } catch {
    throw new Error("packageUri must be a URL");
  }
  if (uri.protocol !== "https:" || uri.hostname !== "github.com" || uri.username || uri.password || uri.search || uri.hash) {
    throw new Error("packageUri must be credential-free GitHub HTTPS without query or fragment");
  }
  const segments = uri.pathname.split("/").filter(Boolean).map(decodeURIComponent);
  if (segments.length !== 6 || segments[0] !== "talon23" || segments[1] !== "Dravora-Update-Feed" || segments[2] !== "releases" || segments[3] !== "download" || !segments[4] || segments[5] !== expectedFile) {
    throw new Error("packageUri must be an exact Dravora Update Feed release asset URL");
  }
}

export async function sha256File(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex").toUpperCase();
}

export async function verifyLocalAddonPackages(catalogue, assetsDirectory) {
  for (const entry of catalogue.packages) {
    const assetPath = resolve(assetsDirectory, entry.packageFileName);
    if (basename(assetPath) !== entry.packageFileName) throw new Error("add-on package path escaped the assets directory");
    const stat = statSync(assetPath);
    if (!stat.isFile() || stat.size !== entry.packageLength) throw new Error(`${entry.packageFileName} length mismatch`);
    if ((await sha256File(assetPath)) !== entry.packageSha256) throw new Error(`${entry.packageFileName} SHA-256 mismatch`);
  }
}
