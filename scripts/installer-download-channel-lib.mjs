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
const releaseTagPattern = /^dravora-standalone-[0-9]+\.[0-9]+\.[0-9]+-external-test\.[0-9]+$/;
const timestampPattern = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const commitPattern = /^[0-9a-f]{40}$/;
const privateDataPattern = /customer|testerName|email|phone|address|passphrase|privateKey|bearer|DRVA1\.|HSE record|keyDirectory|licen[cs]ePath|licen[cs]eKey|diagnostic|backup/i;
const packageOrder = ["professional", "business", "enterprise"];

function parseUtc(value, label) {
  if (typeof value !== "string" || !timestampPattern.test(value)) throw new Error(`${label} must be a UTC timestamp`);
  const millis = Date.parse(value);
  if (!Number.isFinite(millis) || new Date(millis).toISOString() !== value.replace("Z", ".000Z")) {
    throw new Error(`${label} is not a real UTC timestamp`);
  }
}

function validateDigest(value, label) {
  if (!digestPattern.test(value)) throw new Error(`${label} must be 64 uppercase hexadecimal characters`);
}

function validateReleaseAssetUri(value, releaseTag, expectedFile, label) {
  let uri;
  try {
    uri = new URL(value);
  } catch {
    throw new Error(`${label} must be a URL`);
  }
  if (uri.protocol !== "https:" || uri.hostname !== "github.com" || uri.username || uri.password || uri.search || uri.hash) {
    throw new Error(`${label} must be credential-free GitHub HTTPS without query or fragment`);
  }
  const segments = uri.pathname.split("/").filter(Boolean).map(decodeURIComponent);
  if (
    segments.length !== 6 ||
    segments[0] !== "talon23" ||
    segments[1] !== "Dravora-Update-Feed" ||
    segments[2] !== "releases" ||
    segments[3] !== "download" ||
    segments[4] !== releaseTag ||
    segments[5] !== expectedFile
  ) {
    throw new Error(`${label} must be an exact Dravora Update Feed release asset URL`);
  }
}

export function validateInstallerDownloadChannel(channel) {
  exactKeys(channel, ["schemaVersion", "kind", "channelId", "environment", "packageChannel", "releaseTag", "issuedAtUtc", "productionPublication", "installer", "runtimePackages", "source", "trust", "validation"], "channel");
  if (JSON.stringify(channel).match(privateDataPattern)) throw new Error("channel contains forbidden private data");
  if (channel.schemaVersion !== 1 || channel.kind !== "dravora-external-tester-installer-channel") throw new Error("channel identity mismatch");
  if (channel.channelId !== "external-testing" || channel.environment !== "test" || channel.packageChannel !== "test") throw new Error("only the external-testing test lane is supported");
  if (!releaseTagPattern.test(channel.releaseTag) || /production|stable|latest/i.test(channel.releaseTag)) throw new Error("releaseTag must be external-test only");
  parseUtc(channel.issuedAtUtc, "issuedAtUtc");

  exactKeys(channel.productionPublication, ["status", "reason"], "productionPublication");
  if (channel.productionPublication.status !== "blocked" || !/production/i.test(channel.productionPublication.reason)) {
    throw new Error("production publication must remain blocked with an explicit reason");
  }

  const installer = channel.installer;
  exactKeys(installer, ["product", "version", "runtime", "installerTechnology", "fileName", "downloadUri", "sha256", "length", "authenticodeStatus", "allowedUnsignedReason", "buildReceipt"], "installer");
  if (installer.product !== "dravora-standalone" || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(installer.version)) throw new Error("installer identity mismatch");
  if (installer.runtime !== "native-csharp-dotnet-10" || installer.installerTechnology !== "NSIS-3") throw new Error("installer runtime or technology mismatch");
  if (installer.fileName !== `Dravora-Standalone-${installer.version}-Tester-Setup.exe`) throw new Error("installer file name mismatch");
  validateReleaseAssetUri(installer.downloadUri, channel.releaseTag, installer.fileName, "installer.downloadUri");
  validateDigest(installer.sha256, "installer.sha256");
  if (!Number.isSafeInteger(installer.length) || installer.length < 1 || installer.length > 2147483648) throw new Error("installer length is out of range");
  if (!["valid", "not_signed_test_only"].includes(installer.authenticodeStatus)) throw new Error("unsupported Authenticode status");
  if (installer.authenticodeStatus === "not_signed_test_only" && !/test/i.test(installer.allowedUnsignedReason)) throw new Error("unsigned installer reason must be test-only");

  exactKeys(installer.buildReceipt, ["fileName", "downloadUri", "sha256", "length"], "installer.buildReceipt");
  if (installer.buildReceipt.fileName !== `Dravora-Standalone-${installer.version}-Tester-Setup.build-receipt.json`) throw new Error("build receipt file name mismatch");
  validateReleaseAssetUri(installer.buildReceipt.downloadUri, channel.releaseTag, installer.buildReceipt.fileName, "installer.buildReceipt.downloadUri");
  validateDigest(installer.buildReceipt.sha256, "installer.buildReceipt.sha256");
  if (!Number.isSafeInteger(installer.buildReceipt.length) || installer.buildReceipt.length < 1 || installer.buildReceipt.length > 1048576) throw new Error("build receipt length is out of range");

  if (!Array.isArray(channel.runtimePackages) || channel.runtimePackages.length > 3) throw new Error("runtimePackages must contain no more than three records");
  let previousIndex = -1;
  const seen = new Set();
  for (const [index, entry] of channel.runtimePackages.entries()) {
    exactKeys(entry, ["edition", "fileName", "downloadUri", "sha256", "length", "trustPublicKeySha256", "status"], `runtimePackages[${index}]`);
    const orderIndex = packageOrder.indexOf(entry.edition);
    if (orderIndex < 0 || seen.has(entry.edition) || orderIndex <= previousIndex) throw new Error("runtime packages must be unique and ordered by edition");
    if ((entry.edition === "business" && !seen.has("professional")) || (entry.edition === "enterprise" && !seen.has("business"))) {
      throw new Error("runtime package predecessors are missing");
    }
    seen.add(entry.edition);
    previousIndex = orderIndex;
    const expectedFile = `Dravora-runtime-${installer.version}-matched20260802T183349Z-${entry.edition}-test-test.dravup`;
    if (entry.fileName !== expectedFile) throw new Error("runtime package file name mismatch");
    validateReleaseAssetUri(entry.downloadUri, channel.releaseTag, entry.fileName, `runtimePackages[${index}].downloadUri`);
    validateDigest(entry.sha256, `runtimePackages[${index}].sha256`);
    validateDigest(entry.trustPublicKeySha256, `runtimePackages[${index}].trustPublicKeySha256`);
    if (entry.trustPublicKeySha256 !== channel.trust.updatePublicKeySha256) throw new Error("runtime package trust does not match installer trust");
    if (!Number.isSafeInteger(entry.length) || entry.length < 1 || entry.length > 1073741824) throw new Error("runtime package length is out of range");
    if (!["available", "withdrawn", "revoked"].includes(entry.status)) throw new Error("unsupported runtime package status");
  }

  exactKeys(channel.source, ["repository", "branch", "commit", "trackedClean"], "source");
  if (channel.source.repository !== "talon23/DravoraHSE" || channel.source.branch !== "develop" || !commitPattern.test(channel.source.commit) || channel.source.trackedClean !== true) {
    throw new Error("source binding mismatch");
  }

  exactKeys(channel.trust, ["updateTrustRootId", "updatePublicKeySha256", "licencePublicKeySha256"], "trust");
  if (channel.trust.updateTrustRootId !== "dravora-test-update") throw new Error("only the Dravora test update trust root is supported");
  validateDigest(channel.trust.updatePublicKeySha256, "trust.updatePublicKeySha256");
  validateDigest(channel.trust.licencePublicKeySha256, "trust.licencePublicKeySha256");

  exactKeys(channel.validation, ["vmEditionMatrix", "vmEditionTransitionMatrix", "forbiddenAssistantBrandHits", "vmSnapshotsPresent", "windowsUpdatesDisabled"], "validation");
  if (channel.validation.vmEditionMatrix !== "passed" || channel.validation.vmEditionTransitionMatrix !== "passed") throw new Error("VM edition validation must be passed");
  if (channel.validation.forbiddenAssistantBrandHits !== 0 || channel.validation.vmSnapshotsPresent !== false || channel.validation.windowsUpdatesDisabled !== true) {
    throw new Error("VM safety validation mismatch");
  }

  return channel;
}

export async function sha256File(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex").toUpperCase();
}

async function verifyFile(directory, fileName, length, sha256, label) {
  const path = resolve(directory, fileName);
  if (basename(path) !== fileName) throw new Error(`${label} path escaped the asset directory`);
  const stat = statSync(path);
  if (!stat.isFile() || stat.size !== length) throw new Error(`${fileName} length mismatch`);
  if ((await sha256File(path)) !== sha256) throw new Error(`${fileName} SHA-256 mismatch`);
}

export async function verifyLocalInstallerDownloadAssets(channel, { installerDirectory = null, packageDirectory = null } = {}) {
  if (installerDirectory) {
    await verifyFile(installerDirectory, channel.installer.fileName, channel.installer.length, channel.installer.sha256, "installer");
    await verifyFile(installerDirectory, channel.installer.buildReceipt.fileName, channel.installer.buildReceipt.length, channel.installer.buildReceipt.sha256, "build receipt");
  }
  if (packageDirectory) {
    for (const entry of channel.runtimePackages) {
      await verifyFile(packageDirectory, entry.fileName, entry.length, entry.sha256, `runtime package ${entry.edition}`);
    }
  }
}
