# External tester installer download contract

The installer download lane exists so external testers can fetch one exact
Dravora Standalone native build and its matched test runtime packages. It is
not the production feed, not a stable channel, and not a source publication
surface.

## Fixed lane

- Repository: `talon23/Dravora-Update-Feed`
- Branch: `codex/external-tester-download-feed-20260803`
- Channel file: `installer-downloads/external-testing/channel.json`
- Environment: `test`
- Package channel: `test`
- Release type: GitHub pre-release only

## Publication boundary

Allowed public assets for this lane are:

- `Dravora-Standalone-<version>-Tester-Setup.exe`
- that installer's public build receipt JSON
- matched signed `.dravup` runtime packages for the same test trust root
- the public channel JSON

The lane must never publish source, private keys, usable licence tokens,
customer data, site data, diagnostics, backups, signing-ceremony records,
or generated licence files. The usable tester licences are distributed through
a separate private handoff.

The current 1.2.6 tester installer is not Authenticode-signed. That is allowed
only because the manifest is locked to `environment: "test"` and declares
`authenticodeStatus: "not_signed_test_only"`. Any production or stable
publication must use the separate signed release-candidate process.

## Validate before upload

```powershell
npm test
node scripts/validate-installer-download-channel.mjs installer-downloads/external-testing/channel.json --installer-dir <installer-output-directory> --package-dir <signed-package-directory>
```

Validation fails closed on production or stable lanes, credential-bearing URLs,
query strings, fragments, non-GitHub hosts, lowercase digests, missing test
trust binding, missing VM evidence, missing package predecessors, local digest
mismatches, and any private-data-shaped field.
