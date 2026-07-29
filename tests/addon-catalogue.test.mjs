import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  validateAddonPackageCatalogue,
  validateAddonStatusRegistry,
  verifyLocalAddonPackages,
} from "../scripts/addon-catalogue-lib.mjs";

const digest = "A".repeat(64);
const issuedAtUtc = "2026-07-29T00:00:00Z";
const expiresAtUtc = "2026-08-05T00:00:00Z";

const statusRegistry = {
  schemaVersion: 1,
  kind: "dravora-addon-licence-status-registry",
  registryEpoch: "11111111-1111-4111-8111-111111111111",
  sequence: 1,
  issuedAtUtc,
  expiresAtUtc,
  entries: [{
    entitlementId: "22222222-2222-4222-8222-222222222222",
    addOnId: "assetops",
    licenceSha256: digest,
    status: "active",
    notBeforeUtc: issuedAtUtc,
    expiresAtUtc,
    reasonCode: null,
  }],
};

const packageEntry = {
  addOnId: "assetops",
  addOnVersion: "1.0.0",
  packageFileName: "Dravora-addon-assetops-1.0.0-test-test.dravup",
  packageUri: "https://github.com/talon23/Dravora-Update-Feed/releases/download/addon-test-1.0.0/Dravora-addon-assetops-1.0.0-test-test.dravup",
  packageSha256: digest,
  packageLength: 1024,
  descriptorSha256: digest,
  registrySha256: digest,
  immutableIdentity: "addon/assetops/test/test/1.0.0",
  processor: "dravora.addon.v1",
  payloadNamespace: "addons/assetops/",
  status: "available",
};

const packageCatalogue = {
  schemaVersion: 1,
  kind: "dravora-addon-package-catalogue",
  catalogueEpoch: "33333333-3333-4333-8333-333333333333",
  sequence: 1,
  issuedAtUtc,
  expiresAtUtc,
  environment: "test",
  channel: "test",
  packages: [packageEntry],
};

test("accepts privacy-minimised add-on status registry", () => {
  assert.equal(validateAddonStatusRegistry(statusRegistry), statusRegistry);
});

test("rejects status duplicates and raw licence material", () => {
  assert.throws(() => validateAddonStatusRegistry({ ...statusRegistry, entries: [statusRegistry.entries[0], statusRegistry.entries[0]] }), /duplicate/);
  assert.throws(() => validateAddonStatusRegistry({ ...statusRegistry, customerEmail: "founder@example.com" }), /unexpected/);
  assert.throws(() => validateAddonStatusRegistry({ ...statusRegistry, entries: [{ ...statusRegistry.entries[0], licenceSha256: "DRVA1.secret" }] }), /forbidden private data|uppercase/);
});

test("accepts add-on package catalogue with exact GitHub release asset URI", () => {
  assert.equal(validateAddonPackageCatalogue(packageCatalogue), packageCatalogue);
});

test("rejects add-on package catalogue dangerous URI variants", () => {
  for (const packageUri of [
    packageEntry.packageUri.replace("https://", "https://token@"),
    `${packageEntry.packageUri}?token=secret`,
    `${packageEntry.packageUri}#fragment`,
    packageEntry.packageUri.replace("github.com", "example.com"),
  ]) {
    assert.throws(() => validateAddonPackageCatalogue({ ...packageCatalogue, packages: [{ ...packageEntry, packageUri }] }), /packageUri/);
  }
});

test("rejects duplicate package ids and mismatched immutable identity", () => {
  assert.throws(() => validateAddonPackageCatalogue({ ...packageCatalogue, packages: [packageEntry, packageEntry] }), /duplicate/);
  assert.throws(() => validateAddonPackageCatalogue({ ...packageCatalogue, packages: [{ ...packageEntry, immutableIdentity: "addon/fleetops/test/test/1.0.0" }] }), /immutable/);
});

test("binds declared add-on package length and digest to local bytes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "dravora-addon-feed-"));
  try {
    const bytes = Buffer.from("signed-addon-dravup-fixture");
    await writeFile(join(directory, packageEntry.packageFileName), bytes);
    const local = {
      ...packageCatalogue,
      packages: [{
        ...packageEntry,
        packageLength: bytes.length,
        packageSha256: createHash("sha256").update(bytes).digest("hex").toUpperCase(),
      }],
    };
    await verifyLocalAddonPackages(validateAddonPackageCatalogue(local), directory);
    await assert.rejects(() => verifyLocalAddonPackages({ ...local, packages: [{ ...local.packages[0], packageLength: bytes.length + 1 }] }, directory), /length mismatch/);
    await assert.rejects(() => verifyLocalAddonPackages({ ...local, packages: [{ ...local.packages[0], packageSha256: "B".repeat(64) }] }, directory), /SHA-256 mismatch/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("requires current Node LTS tooling floor for add-on feed validation", () => {
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(manifest.engines.node, ">=24.18.0");
});
