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
