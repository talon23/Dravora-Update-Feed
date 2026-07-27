import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  validateCatalogue,
  verifyLocalAssets,
} from "../scripts/capability-catalogue-lib.mjs";

const digest = "A".repeat(64);
const professional = {
  edition: "professional",
  predecessorEdition: "standalone",
  moduleSet: ["professional"],
  assetName: "Dravora-runtime-1.0.0-test-test.dravup",
  assetUri:
    "https://github.com/talon23/Dravora-Update-Feed/releases/download/capability-test-1.0.0/Dravora-runtime-1.0.0-test-test.dravup",
  sha256: digest,
  length: 1024,
};
const business = {
  edition: "business",
  predecessorEdition: "professional",
  moduleSet: ["business"],
  assetName: "Dravora-runtime-1.0.0-business-test-test.dravup",
  assetUri:
    "https://github.com/talon23/Dravora-Update-Feed/releases/download/capability-test-1.0.0/Dravora-runtime-1.0.0-business-test-test.dravup",
  sha256: digest,
  length: 2048,
};
const catalogue = {
  schemaVersion: 1,
  kind: "dravora-capability-catalogue",
  packages: [professional, business],
};

test("accepts the Professional then Business capability chain", () => {
  assert.equal(validateCatalogue(catalogue), catalogue);
});

test("rejects Business without Professional", () => {
  assert.throws(
    () => validateCatalogue({ ...catalogue, packages: [business] }),
    /requires the Professional/,
  );
});

test("rejects credentials, query strings, and wrong hosts", () => {
  for (const assetUri of [
    professional.assetUri.replace("https://", "https://token@"),
    `${professional.assetUri}?token=secret`,
    professional.assetUri.replace("github.com", "example.com"),
  ]) {
    assert.throws(
      () =>
        validateCatalogue({
          ...catalogue,
          packages: [{ ...professional, assetUri }],
        }),
      /assetUri/,
    );
  }
});

test("rejects lowercase digests and unexpected fields", () => {
  assert.throws(
    () => validateCatalogue({ ...catalogue, packages: [{ ...professional, sha256: digest.toLowerCase() }] }),
    /uppercase/,
  );
  assert.throws(
    () => validateCatalogue({ ...catalogue, secret: "forbidden" }),
    /unexpected or missing/,
  );
});

test("binds catalogue length and digest to exact local package bytes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "dravora-capability-"));
  try {
    const bytes = Buffer.from("signed-dravup-fixture");
    await writeFile(join(directory, professional.assetName), bytes);
    const local = {
      ...catalogue,
      packages: [{
        ...professional,
        length: bytes.length,
        sha256: createHash("sha256").update(bytes).digest("hex").toUpperCase(),
      }],
    };
    await verifyLocalAssets(validateCatalogue(local), directory);
    await assert.rejects(
      () => verifyLocalAssets({ ...local, packages: [{ ...local.packages[0], length: bytes.length + 1 }] }, directory),
      /length mismatch/,
    );
    await assert.rejects(
      () => verifyLocalAssets({ ...local, packages: [{ ...local.packages[0], sha256: "B".repeat(64) }] }, directory),
      /SHA-256 mismatch/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
