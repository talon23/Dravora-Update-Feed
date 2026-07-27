# Licence status registry contract

Version 1 defines a public, metadata-only status registry. It never contains a
usable licence token, private key, customer identity, site identity, device
identity, contact detail, diagnostic, or signing-ceremony record.

## Fixed identity and paths

- Repository: `talon23/Dravora-Update-Feed`
- Branch: `License-Checker`
- Registry ID: `dravora-production`
- Registry epoch: `63d1c863-c23a-4a8c-9cd0-8e1274a9f423`
- Trust metadata: `license-registry/trust.json`
- Payload: `license-registry/registry.json`
- Detached signature: `license-registry/registry.sig.json`
- Immutable history:
  `license-registry/history/<sequence16>-<payloadhex>/registry.json` and
  `registry.sig.json`

The schemas in `schemas/` are authoritative for field shape. Production JSON
must use RFC 8785 JSON Canonicalization Scheme (JCS) bytes and UTF-8 without a
BOM or insignificant whitespace. `trust.json` has one final LF for normal Git
text handling. The signed `registry.json` and `registry.sig.json` have no final
newline. The schemas deliberately restrict numbers to non-negative integers and
contract strings to ASCII-compatible formats.

## Licence reference

`license_ref` is:

```text
sha256:<lowercase hexadecimal SHA-256 of the exact UTF-8 usable licence token>
```

The token is hashed exactly as issued; no trimming, case folding, decoding, or
line-ending conversion is allowed. Tokens must contain sufficient
cryptographically random entropy to resist offline guessing. The usable token
is never published.

Records are sorted by ascending ordinal `license_ref` and each value is unique.
Only public edition slugs and the states `active`, `consumed`, `recalled`, and
`expired` are allowed.

## Signature

The dedicated licence-status key has purpose `license-status-registry`. It is
separate from usable licence material and all other signing roles.

The exact signing bytes are:

```text
UTF8("DRAVORA-LICENSE-REGISTRY-V1\n") || canonical_registry_json
```

The domain prefix hexadecimal bytes are:

```text
445241564f52412d4c4943454e53452d52454749535452592d56310a
```

The algorithm is `RSASSA-PKCS1-v1_5-SHA256`. `payload_sha256` is SHA-256 over
the canonical registry JSON only, excluding the domain prefix, encoded as
`sha256:` followed by lowercase hexadecimal.

The public key uses canonical .NET RSA XML:

```xml
<RSAKeyValue><Modulus>BASE64</Modulus><Exponent>BASE64</Exponent></RSAKeyValue>
```

There is no XML declaration or whitespace. `public_key_fingerprint` is SHA-256
over the exact UTF-8 XML bytes, with the same lowercase `sha256:` encoding.
Consumers must pin the epoch, key ID, and fingerprint outside this repository.
`trust.json` is public discovery metadata, not a trust root.

## Freshness, rollback, and replay

A bootstrap client requires `sequence >= max(trust.minimum_sequence,
externally_pinned_minimum_sequence)`. The branch value is discovery metadata;
it cannot lower a minimum bundled with or securely persisted by the client.
After a successful verification the client stores the epoch, highest sequence,
and payload digest in rollback-protected local state.

- A lower sequence is rejected.
- The current sequence is accepted only when its payload digest is identical.
- A new registry must be exactly the cached sequence plus one.
- `previous_sequence` and `previous_payload_sha256` must match the cached
  checkpoint.
- Genesis is sequence 1 with previous sequence 0 and a null previous digest.
- `issued_at` may be at most 300 seconds in the future.
- `expires_at` must be later than `issued_at` and no more than 604800 seconds
  later.
- An expired registry is rejected even when its signature is valid.

The payload and signature must be fetched from the same resolved Git commit,
never as separate moving-branch reads.

If the latest sequence is more than one ahead of the cached checkpoint, the
client verifies each missing immutable history entry in order before accepting
latest. `sequence16` is the zero-padded 16-digit decimal sequence and
`payloadhex` is the 64-character lowercase payload digest without `sha256:`.
Every history directory therefore binds its sequence and digest in its path.
There is no reset or gap-skipping path.

## Publication

The publisher reads and validates the current registry, creates the next linked
payload and signature, then writes latest plus the new immutable history pair in
one Git commit using compare-and-swap against the exact observed
`License-Checker` head. An existing history path is never overwritten or
deleted. A stale head, stale sequence, history collision, signature failure,
validation failure, or non-fast-forward update fails closed. The publisher must
not auto-rebase, force-push, or overwrite concurrent state.

Provisioning requires an independently generated dedicated private key outside
Git and an explicitly approved public-key pin. This repository contains no
private key and does not create one.

## Branch allowlist

Only these tracked paths are allowed:

- `.gitattributes`
- `.github/workflows/validate-license-registry.yml`
- `README.md`
- `LICENSE-REGISTRY.md`
- `package.json`
- `license-registry/README.md`
- `license-registry/trust.json`
- optional `license-registry/registry.json`
- optional `license-registry/registry.sig.json`
- optional immutable `license-registry/history/<sequence16>-<payloadhex>/registry.json`
  and `registry.sig.json` pairs
- `schemas/*.schema.json`
- `scripts/*.mjs`
- `tests/*.test.mjs`

The validator rejects every other tracked path.
