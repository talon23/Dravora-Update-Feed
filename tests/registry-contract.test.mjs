import assert from "node:assert/strict";
import { constants, createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  ALGORITHM,
  REGISTRY_EPOCH,
  canonicalize,
  historyRegistryPath,
  parseCanonicalJson,
  sha256Label,
  signingBytes,
  validateReplay,
  validateTrust,
  verifyRegistrySignature,
} from "../scripts/registry-lib.mjs";

function toBase64Url(value) {
  return value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
}

function fixture(now = new Date("2030-01-01T00:00:00Z")) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 0x10001 });
  const jwk = publicKey.export({ format: "jwk" });
  const xml = `<RSAKeyValue><Modulus>${toBase64Url(jwk.n)}</Modulus><Exponent>${toBase64Url(jwk.e)}</Exponent></RSAKeyValue>`;
  const keyId = "registry-test-2030";
  const trust = {
    contract: "dravora-license-registry-trust/v1",
    keys: [{
      algorithm: ALGORITHM,
      key_id: keyId,
      not_after: null,
      not_before: "2029-01-01T00:00:00Z",
      public_key_fingerprint: sha256Label(Buffer.from(xml)),
      public_key_format: "dotnet-rsa-xml",
      public_key_xml: xml,
      purpose: "license-status-registry",
      status: "active",
    }],
    minimum_sequence: 1,
    policy: { max_future_skew_seconds: 300, max_validity_seconds: 604800 },
    registry_epoch: REGISTRY_EPOCH,
    registry_id: "dravora-production",
    status: "active",
  };
  const registry = {
    contract: "dravora-license-registry/v1",
    expires_at: "2030-01-02T00:00:00Z",
    issued_at: "2030-01-01T00:00:00Z",
    previous_payload_sha256: null,
    previous_sequence: 0,
    records: [{
      edition: "professional",
      license_expires_at: null,
      license_ref: `sha256:${"1".repeat(64)}`,
      not_before: "2030-01-01T00:00:00Z",
      revision: 1,
      status: "active",
      status_changed_at: "2030-01-01T00:00:00Z",
    }],
    registry_epoch: REGISTRY_EPOCH,
    registry_id: "dravora-production",
    sequence: 1,
  };
  const bytes = Buffer.from(canonicalize(registry));
  const signature = sign("sha256", signingBytes(bytes), { key: privateKey, padding: constants.RSA_PKCS1_PADDING });
  const envelope = {
    algorithm: ALGORITHM,
    contract: "dravora-license-registry-signature/v1",
    key_id: keyId,
    payload_sha256: sha256Label(bytes),
    registry_epoch: REGISTRY_EPOCH,
    registry_path: "license-registry/registry.json",
    sequence: 1,
    signature_base64: signature.toString("base64"),
  };
  return { now, trust, registry, bytes, envelope };
}

test("canonical signing bytes have the frozen domain", () => {
  const prefix = signingBytes(Buffer.from("{}")).subarray(0, -2);
  assert.equal(prefix.toString("hex"), "445241564f52412d4c4943454e53452d52454749535452592d56310a");
});

test("a correctly linked RSA-SHA256 registry verifies", () => {
  const data = fixture();
  validateTrust(data.trust);
  const digest = verifyRegistrySignature(data.bytes, data.registry, data.envelope, data.trust, data.now);
  assert.equal(digest, data.envelope.payload_sha256);
  assert.equal(validateReplay(data.registry, digest, data.trust), "bootstrap");
});

test("tampering is rejected", () => {
  const data = fixture();
  const tampered = { ...data.registry, sequence: 2, previous_sequence: 1, previous_payload_sha256: data.envelope.payload_sha256 };
  const bytes = Buffer.from(canonicalize(tampered));
  assert.throws(() => verifyRegistrySignature(bytes, tampered, { ...data.envelope, sequence: 2, payload_sha256: sha256Label(bytes) }, data.trust, data.now), /verification failed/);
});

test("rollback, equivocation, and chain gaps are rejected", () => {
  const data = fixture();
  const checkpoint = { registry_epoch: REGISTRY_EPOCH, sequence: 2, payload_sha256: `sha256:${"2".repeat(64)}` };
  assert.throws(() => validateReplay(data.registry, data.envelope.payload_sha256, data.trust, checkpoint), /rollback/);
  const same = { ...data.registry, sequence: 2, previous_sequence: 1, previous_payload_sha256: `sha256:${"3".repeat(64)}` };
  assert.throws(() => validateReplay(same, `sha256:${"4".repeat(64)}`, data.trust, checkpoint), /equivocation/);
  const gap = { ...same, sequence: 4 };
  assert.throws(() => validateReplay(gap, `sha256:${"5".repeat(64)}`, data.trust, checkpoint), /discontinuity/);
});

test("immutable history paths bind sequence and payload digest", () => {
  const digest = `sha256:${"a".repeat(64)}`;
  assert.equal(
    historyRegistryPath(42, digest),
    `license-registry/history/0000000000000042-${"a".repeat(64)}/registry.json`,
  );
});

test("an offline client can advance through a verified contiguous history", () => {
  const checkpoint = { registry_epoch: REGISTRY_EPOCH, sequence: 1, payload_sha256: `sha256:${"1".repeat(64)}` };
  const second = { sequence: 2, previous_sequence: 1, previous_payload_sha256: checkpoint.payload_sha256 };
  const secondDigest = `sha256:${"2".repeat(64)}`;
  assert.equal(validateReplay(second, secondDigest, { minimum_sequence: 1 }, checkpoint), "advanced");
  const nextCheckpoint = { registry_epoch: REGISTRY_EPOCH, sequence: 2, payload_sha256: secondDigest };
  const third = { sequence: 3, previous_sequence: 2, previous_payload_sha256: secondDigest };
  assert.equal(validateReplay(third, `sha256:${"3".repeat(64)}`, { minimum_sequence: 1 }, nextCheckpoint), "advanced");
});

test("non-canonical JSON and unexpected fields fail closed", () => {
  assert.throws(() => parseCanonicalJson(Buffer.from('{ "a":1}'), "fixture"), /canonical/);
  const data = fixture();
  assert.throws(() => validateTrust({ ...data.trust, secret: "forbidden" }), /unexpected or missing/);
});

test("the public reference is a digest, not the usable token", () => {
  const token = "DRV-TEST-THIS-IS-NOT-PUBLISHED";
  const reference = `sha256:${createHash("sha256").update(Buffer.from(token, "utf8")).digest("hex")}`;
  assert.match(reference, /^sha256:[0-9a-f]{64}$/);
  assert.equal(reference.includes(token), false);
});
