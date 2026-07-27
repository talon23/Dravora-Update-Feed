# Capability release contract

The `patches` branch contains public verification tooling and documentation.
Package bytes are published only as immutable GitHub Release assets after the
controlled build, signing and approval gates complete.

## Client catalogue

The installer-owned catalogue is:

`C:\ProgramData\Dravora\updates\capabilities\catalogue.json`

It has exactly these top-level fields:

```json
{
  "schemaVersion": 1,
  "kind": "dravora-capability-catalogue",
  "packages": []
}
```

Each package record has exactly:

- `edition`
- `predecessorEdition`
- `moduleSet`
- `assetName`
- `assetUri`
- `sha256`
- `length`

Professional follows Standalone and has module set `["professional"]`.
Business follows Professional and has module set `["business"]`. A Business
activation therefore acquires Professional before Business when Professional
is missing.

`assetUri` is an exact, credential-free URL of this form:

```text
https://github.com/talon23/Dravora-Update-Feed/releases/download/<tag>/<assetName>
```

The catalogue contains uppercase hexadecimal SHA-256 values and exact byte
lengths. It is installed by the controlled, signed Dravora build. Each
downloaded package is independently verified through the native `.dravup`
signature, descriptor, digest, length, edition, predecessor and module-set
checks before restart cutover.

The Console receipt and SHA sidecar are build evidence. They are not client
download assets and are not a substitute for the native `.dravup` signature.

## Validate before publication

```powershell
npm test
node scripts/validate-capability-catalogue.mjs <catalogue.json> --assets-dir <signed-package-directory>
```

Validation fails closed if the catalogue is structurally wrong, contains a
non-GitHub or credential-bearing URL, contains a duplicate edition, breaks the
edition chain, or does not match the exact local package digest and length.

Do not publish a package until its exact approved digest is available. Never
commit private keys, usable licence tokens, tester identity, customer data, or
unsigned package bytes.
