import {
  constants,
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";

export const CONTRACT = "dravora-license-registry/v1";
export const TRUST_CONTRACT = "dravora-license-registry-trust/v1";
export const SIGNATURE_CONTRACT = "dravora-license-registry-signature/v1";
export const REGISTRY_ID = "dravora-production";
export const REGISTRY_EPOCH = "63d1c863-c23a-4a8c-9cd0-8e1274a9f423";
export const ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256";
export const DOMAIN = Buffer.from("DRAVORA-LICENSE-REGISTRY-V1\n", "ascii");
export const REGISTRY_PATH = "license-registry/registry.json";
export const MAX_VALIDITY_SECONDS = 604800;
export const MAX_FUTURE_SKEW_SECONDS = 300;

const timestampPattern =
  /^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const keyIdPattern = /^[a-z0-9][a-z0-9._-]{2,63}$/;
const editionPattern = /^[a-z0-9][a-z0-9._-]{0,31}$/;
const xmlPattern =
  /^<RSAKeyValue><Modulus>([A-Za-z0-9+/]+={0,2})<\/Modulus><Exponent>([A-Za-z0-9+/]+={0,2})<\/Exponent><\/RSAKeyValue>$/;

function fail(message) {
  throw new Error(message);
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} has unexpected or missing fields`);
  }
}

function isSafeUint(value, minimum = 0) {
  return Number.isSafeInteger(value) && value >= minimum;
}

function parseTimestamp(value, label) {
  if (typeof value !== "string" || !timestampPattern.test(value)) {
    fail(`${label} must be an RFC 3339 UTC timestamp with whole seconds`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value.replace("Z", ".000Z")) {
    fail(`${label} is not a real calendar timestamp`);
  }
  return milliseconds;
}

function validBase64(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    fail(`${label} must be canonical base64`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length === 0 || bytes.toString("base64") !== value) {
    fail(`${label} must be canonical base64`);
  }
  return bytes;
}

export function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) fail("only non-negative safe integers are permitted");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("unsupported JSON value");
}

export function parseCanonicalJson(bytes, label, { allowFinalLf = false } = {}) {
  const raw = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (raw.length >= 3 && raw.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))) {
    fail(`${label} must not contain a UTF-8 BOM`);
  }
  const decoded = raw.toString("utf8");
  if (!Buffer.from(decoded, "utf8").equals(raw)) fail(`${label} is not valid UTF-8`);
  const text = allowFinalLf && decoded.endsWith("\n") ? decoded.slice(0, -1) : decoded;
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
  const expected = canonicalize(value) + (allowFinalLf ? "\n" : "");
  if (expected !== decoded) fail(`${label} must be exact canonical JSON bytes`);
  return value;
}

export function sha256Label(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function signingBytes(canonicalRegistryBytes) {
  return Buffer.concat([DOMAIN, Buffer.from(canonicalRegistryBytes)]);
}

export function validateTrust(trust) {
  exactKeys(trust, ["contract", "registry_id", "registry_epoch", "status", "minimum_sequence", "policy", "keys"], "trust");
  if (trust.contract !== TRUST_CONTRACT || trust.registry_id !== REGISTRY_ID || trust.registry_epoch !== REGISTRY_EPOCH) fail("trust identity mismatch");
  if (!["unprovisioned", "active"].includes(trust.status)) fail("invalid trust status");
  if (!isSafeUint(trust.minimum_sequence, 1)) fail("invalid minimum_sequence");
  exactKeys(trust.policy, ["max_validity_seconds", "max_future_skew_seconds"], "trust.policy");
  if (trust.policy.max_validity_seconds !== MAX_VALIDITY_SECONDS || trust.policy.max_future_skew_seconds !== MAX_FUTURE_SKEW_SECONDS) fail("trust policy mismatch");
  if (!Array.isArray(trust.keys)) fail("trust.keys must be an array");
  if (trust.status === "unprovisioned" && trust.keys.length !== 0) fail("unprovisioned trust must have no keys");
  if (trust.status === "active" && trust.keys.length === 0) fail("active trust must have a key");
  const ids = new Set();
  let previousKeyId = "";
  let activeKeyCount = 0;
  for (const [index, key] of trust.keys.entries()) {
    exactKeys(key, ["key_id", "purpose", "algorithm", "public_key_format", "public_key_xml", "public_key_fingerprint", "not_before", "not_after", "status"], `trust.keys[${index}]`);
    if (!keyIdPattern.test(key.key_id) || ids.has(key.key_id) || key.key_id <= previousKeyId) fail("key IDs must be valid, unique, and sorted");
    ids.add(key.key_id);
    previousKeyId = key.key_id;
    if (key.purpose !== "license-status-registry" || key.algorithm !== ALGORITHM || key.public_key_format !== "dotnet-rsa-xml") fail("key purpose, algorithm, or format mismatch");
    const match = xmlPattern.exec(key.public_key_xml);
    if (!match) fail("public_key_xml is not canonical .NET RSA XML");
    const modulus = validBase64(match[1], "RSA modulus");
    const exponent = validBase64(match[2], "RSA exponent");
    if (modulus.length < 256 || (modulus.length === 256 && (modulus[0] & 0x80) === 0)) fail("RSA modulus must be at least 2048 bits");
    const exponentValue = exponent.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
    if (exponent.length > 8 || exponentValue < 3n || (exponentValue & 1n) === 0n) fail("RSA exponent must be a small odd integer");
    if (key.public_key_fingerprint !== sha256Label(Buffer.from(key.public_key_xml, "utf8"))) fail("public key fingerprint mismatch");
    const keyNotBefore = parseTimestamp(key.not_before, "key.not_before");
    if (key.not_after !== null && parseTimestamp(key.not_after, "key.not_after") <= keyNotBefore) fail("key validity interval is invalid");
    if (!["active", "retired"].includes(key.status)) fail("invalid key status");
    if (key.status === "active") activeKeyCount += 1;
  }
  if (trust.status === "active" && activeKeyCount === 0) fail("active trust requires an active key");
}

export function validateRegistry(registry, now = new Date()) {
  exactKeys(registry, ["contract", "registry_id", "registry_epoch", "sequence", "issued_at", "expires_at", "previous_sequence", "previous_payload_sha256", "records"], "registry");
  if (registry.contract !== CONTRACT || registry.registry_id !== REGISTRY_ID || registry.registry_epoch !== REGISTRY_EPOCH) fail("registry identity mismatch");
  if (!isSafeUint(registry.sequence, 1) || !isSafeUint(registry.previous_sequence)) fail("invalid sequence");
  if (registry.sequence === 1) {
    if (registry.previous_sequence !== 0 || registry.previous_payload_sha256 !== null) fail("invalid genesis link");
  } else if (registry.previous_sequence !== registry.sequence - 1 || !digestPattern.test(registry.previous_payload_sha256)) {
    fail("invalid previous registry link");
  }
  const issued = parseTimestamp(registry.issued_at, "issued_at");
  const expires = parseTimestamp(registry.expires_at, "expires_at");
  const nowMs = now.getTime();
  if (issued > nowMs + MAX_FUTURE_SKEW_SECONDS * 1000) fail("registry issued too far in the future");
  if (expires <= issued || expires - issued > MAX_VALIDITY_SECONDS * 1000) fail("registry validity interval is invalid");
  if (expires <= nowMs) fail("registry is expired");
  if (!Array.isArray(registry.records) || registry.records.length > 1000000) fail("invalid records array");
  let previousRef = "";
  for (const [index, record] of registry.records.entries()) {
    exactKeys(record, ["license_ref", "status", "edition", "not_before", "license_expires_at", "status_changed_at", "revision"], `records[${index}]`);
    if (!digestPattern.test(record.license_ref) || record.license_ref <= previousRef) fail("license_ref values must be unique and sorted");
    previousRef = record.license_ref;
    if (!["active", "consumed", "recalled", "expired"].includes(record.status)) fail("invalid record status");
    if (!editionPattern.test(record.edition)) fail("invalid edition");
    const notBefore = parseTimestamp(record.not_before, "record.not_before");
    const licenseExpires = record.license_expires_at === null
      ? null
      : parseTimestamp(record.license_expires_at, "record.license_expires_at");
    const statusChanged = parseTimestamp(record.status_changed_at, "record.status_changed_at");
    if (licenseExpires !== null && licenseExpires <= notBefore) fail("record licence validity interval is invalid");
    if (statusChanged > issued) fail("record status cannot change after registry issuance");
    if (record.status === "expired" && (licenseExpires === null || licenseExpires > issued)) fail("expired record must have reached its licence expiry");
    if (record.status === "active" && licenseExpires !== null && licenseExpires <= issued) fail("active record cannot already be expired");
    if (!isSafeUint(record.revision, 1)) fail("invalid record revision");
  }
}

export function validateSignatureEnvelope(signature) {
  exactKeys(signature, ["contract", "registry_path", "registry_epoch", "sequence", "payload_sha256", "algorithm", "key_id", "signature_base64"], "signature");
  if (signature.contract !== SIGNATURE_CONTRACT || signature.registry_path !== REGISTRY_PATH || signature.registry_epoch !== REGISTRY_EPOCH || signature.algorithm !== ALGORITHM) fail("signature envelope identity mismatch");
  if (!isSafeUint(signature.sequence, 1) || !digestPattern.test(signature.payload_sha256) || !keyIdPattern.test(signature.key_id)) fail("invalid signature envelope value");
  validBase64(signature.signature_base64, "signature_base64");
}

function xmlKeyToJwk(xml) {
  const match = xmlPattern.exec(xml);
  if (!match) fail("invalid RSA XML");
  const base64url = (value) => value.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return { kty: "RSA", n: base64url(match[1]), e: base64url(match[2]) };
}

export function verifyRegistrySignature(registryBytes, registry, envelope, trust, now = new Date()) {
  validateTrust(trust);
  validateRegistry(registry, now);
  validateSignatureEnvelope(envelope);
  const digest = sha256Label(registryBytes);
  if (envelope.registry_epoch !== registry.registry_epoch || envelope.sequence !== registry.sequence || envelope.payload_sha256 !== digest) fail("signature envelope does not bind this payload");
  const key = trust.keys.find((candidate) => candidate.key_id === envelope.key_id);
  if (!key || key.status !== "active") fail("signature key is not active");
  const nowMs = now.getTime();
  if (parseTimestamp(key.not_before, "key.not_before") > nowMs || (key.not_after !== null && parseTimestamp(key.not_after, "key.not_after") <= nowMs)) fail("signature key is outside its validity window");
  const publicKey = createPublicKey({ key: xmlKeyToJwk(key.public_key_xml), format: "jwk" });
  const verified = verifySignature("sha256", signingBytes(registryBytes), { key: publicKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(envelope.signature_base64, "base64"));
  if (!verified) fail("registry signature verification failed");
  return digest;
}

export function validateReplay(registry, digest, trust, checkpoint = null) {
  if (!checkpoint) {
    if (registry.sequence < trust.minimum_sequence) fail("registry sequence is below the pinned minimum");
    return "bootstrap";
  }
  if (checkpoint.registry_epoch !== REGISTRY_EPOCH || !isSafeUint(checkpoint.sequence, 1) || !digestPattern.test(checkpoint.payload_sha256)) fail("invalid local checkpoint");
  if (registry.sequence < checkpoint.sequence) fail("registry rollback detected");
  if (registry.sequence === checkpoint.sequence) {
    if (digest !== checkpoint.payload_sha256) fail("same-sequence equivocation detected");
    return "unchanged";
  }
  if (registry.sequence !== checkpoint.sequence + 1 || registry.previous_sequence !== checkpoint.sequence || registry.previous_payload_sha256 !== checkpoint.payload_sha256) fail("registry chain discontinuity detected");
  return "advanced";
}
