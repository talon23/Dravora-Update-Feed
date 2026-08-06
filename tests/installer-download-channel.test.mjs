import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  validateInstallerDownloadChannel,
  verifyLocalInstallerDownloadAssets,
} from "../scripts/installer-download-channel-lib.mjs";

const digest = "A".repeat(64);
const releaseTag = "dravora-standalone-1.2.6-external-test.1";
const assetUrl = (name) => `https://github.com/talon23/Dravora-Update-Feed/releases/download/${releaseTag}/${name}`;

const channel = {
  schemaVersion: 1,
  kind: "dravora-external-tester-installer-channel",
  channelId: "external-testing",
  environment: "test",
  packageChannel: "test",
  releaseTag,
  issuedAtUtc: "2026-08-03T00:00:00Z",
  productionPublication: { status: "blocked", reason: "Production remains blocked for external testing." },
  installer: {
    product: "dravora-standalone",
    version: "1.2.6",
    runtime: "native-csharp-dotnet-10",
    installerTechnology: "NSIS-3",
    fileName: "Dravora-Standalone-1.2.6-Tester-Setup.exe",
    downloadUri: assetUrl("Dravora-Standalone-1.2.6-Tester-Setup.exe"),
    sha256: digest,
    length: 11,
    authenticodeStatus: "not_signed_test_only",
    allowedUnsignedReason: "Unsigned only in the test lane.",
    buildReceipt: {
      fileName: "Dravora-Standalone-1.2.6-Tester-Setup.build-receipt.json",
      downloadUri: assetUrl("Dravora-Standalone-1.2.6-Tester-Setup.build-receipt.json"),
      sha256: digest,
      length: 7,
    },
  },
  runtimePackages: [
    {
      edition: "professional",
      fileName: "Dravora-runtime-1.2.6-matched20260802T183349Z-professional-test-test.dravup",
      downloadUri: assetUrl("Dravora-runtime-1.2.6-matched20260802T183349Z-professional-test-test.dravup"),
      sha256: digest,
      length: 12,
      trustPublicKeySha256: digest,
      status: "available",
    },
    {
      edition: "business",
      fileName: "Dravora-runtime-1.2.6-matched20260802T183349Z-business-test-test.dravup",
      downloadUri: assetUrl("Dravora-runtime-1.2.6-matched20260802T183349Z-business-test-test.dravup"),
      sha256: digest,
      length: 8,
      trustPublicKeySha256: digest,
      status: "available",
    },
  ],
  source: {
    repository: "talon23/DravoraHSE",
    branch: "develop",
    commit: "a".repeat(40),
    trackedClean: true,
  },
  trust: {
    updateTrustRootId: "dravora-test-update",
    updatePublicKeySha256: digest,
    licencePublicKeySha256: "B".repeat(64),
  },
  validation: {
    vmEditionMatrix: "passed",
    vmEditionTransitionMatrix: "passed",
    forbiddenAssistantBrandHits: 0,
    vmSnapshotsPresent: false,
    windowsUpdatesDisabled: true,
  },
};

test("accepts the external-testing installer channel", () => {
  assert.equal(validateInstallerDownloadChannel(channel), channel);
});

test("rejects production, stable, and private URL variants", () => {
  assert.throws(() => validateInstallerDownloadChannel({ ...channel, environment: "production" }), /external-testing test lane/);
  assert.throws(() => validateInstallerDownloadChannel({ ...channel, releaseTag: "dravora-standalone-1.2.6-stable.1" }), /external-test/);
  for (const downloadUri of [
    channel.installer.downloadUri.replace("https://", "https://token@"),
    `${channel.installer.downloadUri}?token=secret`,
    `${channel.installer.downloadUri}#fragment`,
    channel.installer.downloadUri.replace("github.com", "example.com"),
  ]) {
    assert.throws(() => validateInstallerDownloadChannel({ ...channel, installer: { ...channel.installer, downloadUri } }), /downloadUri/);
  }
});

test("rejects private data, lowercase digest, and unsafe VM evidence", () => {
  assert.throws(() => validateInstallerDownloadChannel({ ...channel, customerEmail: "person@example.com" }), /unexpected|forbidden/);
  assert.throws(() => validateInstallerDownloadChannel({ ...channel, installer: { ...channel.installer, sha256: digest.toLowerCase() } }), /uppercase/);
  assert.throws(() => validateInstallerDownloadChannel({ ...channel, validation: { ...channel.validation, forbiddenAssistantBrandHits: 1 } }), /VM safety/);
});

test("requires package predecessors in edition order", () => {
  const businessOnly = { ...channel, runtimePackages: [channel.runtimePackages[1]] };
  assert.throws(() => validateInstallerDownloadChannel(businessOnly), /predecessors/);
  const reversed = { ...channel, runtimePackages: [channel.runtimePackages[1], channel.runtimePackages[0]] };
  assert.throws(() => validateInstallerDownloadChannel(reversed), /predecessors|ordered/);
});

test("binds local installer, receipt, and package bytes", async () => {
  const installerDirectory = await mkdtemp(join(tmpdir(), "dravora-installer-feed-"));
  const packageDirectory = await mkdtemp(join(tmpdir(), "dravora-package-feed-"));
  try {
    const installerBytes = Buffer.from("installer-ok");
    const receiptBytes = Buffer.from("receipt");
    const professionalBytes = Buffer.from("professional");
    const businessBytes = Buffer.from("business");
    const local = {
      ...channel,
      installer: {
        ...channel.installer,
        sha256: createHash("sha256").update(installerBytes).digest("hex").toUpperCase(),
        length: installerBytes.length,
        buildReceipt: {
          ...channel.installer.buildReceipt,
          sha256: createHash("sha256").update(receiptBytes).digest("hex").toUpperCase(),
          length: receiptBytes.length,
        },
      },
      runtimePackages: [
        {
          ...channel.runtimePackages[0],
          sha256: createHash("sha256").update(professionalBytes).digest("hex").toUpperCase(),
          length: professionalBytes.length,
        },
        {
          ...channel.runtimePackages[1],
          sha256: createHash("sha256").update(businessBytes).digest("hex").toUpperCase(),
          length: businessBytes.length,
        },
      ],
    };
    await writeFile(join(installerDirectory, local.installer.fileName), installerBytes);
    await writeFile(join(installerDirectory, local.installer.buildReceipt.fileName), receiptBytes);
    await writeFile(join(packageDirectory, local.runtimePackages[0].fileName), professionalBytes);
    await writeFile(join(packageDirectory, local.runtimePackages[1].fileName), businessBytes);
    await verifyLocalInstallerDownloadAssets(validateInstallerDownloadChannel(local), { installerDirectory, packageDirectory });
    await assert.rejects(
      () => verifyLocalInstallerDownloadAssets({ ...local, installer: { ...local.installer, length: local.installer.length + 1 } }, { installerDirectory, packageDirectory }),
      /length mismatch/,
    );
  } finally {
    await rm(installerDirectory, { recursive: true, force: true });
    await rm(packageDirectory, { recursive: true, force: true });
  }
});
