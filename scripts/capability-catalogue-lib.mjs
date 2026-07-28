import { createHash } from "node:crypto";
import { statSync, createReadStream } from "node:fs";
import { basename, resolve } from "node:path";

const exactKeys = (value, expected, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
};

const assetPattern =
  /^Dravora-runtime-[0-9A-Za-z._-]+-(development|test|staging|production)-(developer|test|staging|stable)\.dravup$/;
const digestPattern = /^[0-9A-F]{64}$/;
const allowedEditions = new Map([
  ["professional", { predecessorEdition: "standalone", moduleSet: ["professional"] }],
  ["business", { predecessorEdition: "professional", moduleSet: ["business"] }],
]);

export function validateCatalogue(catalogue) {
  exactKeys(catalogue, ["schemaVersion", "kind", "packages"], "catalogue");
  if (catalogue.schemaVersion !== 1 || catalogue.kind !== "dravora-capability-catalogue") {
    throw new Error("catalogue identity mismatch");
  }
  if (!Array.isArray(catalogue.packages) || catalogue.packages.length < 1 || catalogue.packages.length > 2) {
    throw new Error("packages must contain one or two supported edition records");
  }

  const editions = new Set();
  for (const [index, entry] of catalogue.packages.entries()) {
    exactKeys(
      entry,
      ["edition", "predecessorEdition", "moduleSet", "assetName", "assetUri", "sha256", "length"],
      `packages[${index}]`,
    );
    const expected = allowedEditions.get(entry.edition);
    if (!expected || editions.has(entry.edition)) throw new Error("unsupported or duplicate edition");
    editions.add(entry.edition);
    if (
      entry.predecessorEdition !== expected.predecessorEdition ||
      JSON.stringify(entry.moduleSet) !== JSON.stringify(expected.moduleSet)
    ) {
      throw new Error(`${entry.edition} capability chain mismatch`);
    }
    if (!assetPattern.test(entry.assetName)) throw new Error("invalid capability asset name");
    if (!digestPattern.test(entry.sha256)) throw new Error("sha256 must be 64 uppercase hexadecimal characters");
    if (!Number.isSafeInteger(entry.length) || entry.length < 1 || entry.length > 1073741824) {
      throw new Error("length must be an integer from 1 to 1073741824");
    }

    let uri;
    try {
      uri = new URL(entry.assetUri);
    } catch {
      throw new Error("assetUri must be a valid URL");
    }
    if (
      uri.protocol !== "https:" ||
      uri.hostname !== "github.com" ||
      uri.username ||
      uri.password ||
      uri.search ||
      uri.hash
    ) {
      throw new Error("assetUri must be credential-free GitHub HTTPS without query or fragment");
    }
    const segments = uri.pathname.split("/").filter(Boolean);
    if (
      segments.length !== 6 ||
      segments[0] !== "talon23" ||
      segments[1] !== "Dravora-Update-Feed" ||
      segments[2] !== "releases" ||
      segments[3] !== "download" ||
      !segments[4] ||
      decodeURIComponent(segments[5] ?? "") !== entry.assetName
    ) {
      throw new Error("assetUri must be an exact Dravora Update Feed release asset URL");
    }
  }

  if (editions.has("business") && !editions.has("professional")) {
    throw new Error("Business catalogue requires the Professional predecessor record");
  }
  return catalogue;
}

export async function sha256File(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex").toUpperCase();
}

export async function verifyLocalAssets(catalogue, assetsDirectory) {
  for (const entry of catalogue.packages) {
    const assetPath = resolve(assetsDirectory, entry.assetName);
    if (basename(assetPath) !== entry.assetName) throw new Error("asset path escaped the assets directory");
    const stat = statSync(assetPath);
    if (!stat.isFile() || stat.size !== entry.length) throw new Error(`${entry.assetName} length mismatch`);
    if ((await sha256File(assetPath)) !== entry.sha256) throw new Error(`${entry.assetName} SHA-256 mismatch`);
  }
}
