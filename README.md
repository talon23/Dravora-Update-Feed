# Dravora Update Feed

This is the public, metadata-only distribution surface for Dravora updates.

Allowed content:

- signed channel manifests and their detached signatures on protected service refs;
- immutable, signed `.dravup` packages attached to GitHub releases;
- public verification material only when explicitly approved for distribution.
- signed, metadata-only licence status registries on the `License-Checker`
  branch.

Never publish application source, private signing keys, tokens, customer or site data, diagnostics, backups, unsigned packages, or signing-ceremony records here. The Dravora source repository remains private. Update clients must continue to verify every manifest, emergency control and package; public hosting is transport, not trust.

The licence status registry contract is documented in
[`LICENSE-REGISTRY.md`](LICENSE-REGISTRY.md). The branch is intentionally
unprovisioned until an independently generated, dedicated public verification
key is approved and pinned in each consumer. No private key belongs in this
repository.
