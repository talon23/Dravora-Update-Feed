# Dravora Update Feed

This is the public, metadata-only distribution surface for Dravora updates.

Allowed content:

- signed channel manifests and their detached signatures on protected service refs;
- immutable, signed `.dravup` packages attached to GitHub releases;
- public verification material only when explicitly approved for distribution.

Never publish application source, private signing keys, tokens, customer or site data, diagnostics, backups, unsigned packages, or signing-ceremony records here. The Dravora source repository remains private. Update clients must continue to verify every manifest, emergency control and package; public hosting is transport, not trust.

## Capability packages

Professional and Business edition capabilities are distributed as immutable,
natively signed `.dravup` GitHub Release assets. The client receives its
capability catalogue from the controlled Dravora installation, not from a
moving branch file in this repository.

See [`CAPABILITY-RELEASES.md`](CAPABILITY-RELEASES.md) for the frozen public
delivery contract and local pre-publication validation command.

## Add-on package catalogues

Native Dravora add-ons use dormant feed contracts only at this stage. This
repository can validate add-on status and package catalogue JSON before any
future publication, but this branch does not publish, sign, download or
activate add-ons.

Contract validation tooling targets Node.js 24.18.0 LTS or newer. Node remains
feed/developer tooling only and is not a Dravora native runtime dependency.

- `schemas/addon-licence-status-registry.v1.schema.json` defines the public
  add-on entitlement status registry shape.
- `schemas/addon-package-catalogue.v1.schema.json` defines signed `.dravup`
  add-on package catalogue entries.
- `scripts/addon-catalogue-lib.mjs` validates privacy-minimised status entries,
  exact GitHub release asset URLs, uppercase SHA-256 values, package lengths,
  duplicate add-on IDs and immutable package identity.

Business remains provisional until the exact `BUSINESS EXTERNAL-TEST READY`
handoff. `assuranceops` must not be published or activated as a Business add-on
before that gate.
