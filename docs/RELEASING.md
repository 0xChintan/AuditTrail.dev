# Releasing (and verifying a release)

## Maintainers

1. Protect the npm account with **2FA**: publish only from CI, with provenance. Add the automation token as the `NPM_TOKEN` repo secret.
2. Bump the package versions (they share one version), update CHANGELOG, then push a signed tag: `git tag -s v0.2.0 && git push origin v0.2.0`.
3. `.github/workflows/release.yml` re-runs CI, then:
   - publishes `@audittrail/core`, `@audittrail/sdk` and `audittrail-mcp-proxy` with **npm provenance**;
   - builds the Go binaries (linux/darwin × amd64/arm64) and the WASM verifier with `-trimpath`, with SBOM + `SHA256SUMS`;
   - creates **GitHub build-provenance attestations** and a **Sigstore keyless signature** of `SHA256SUMS`.

The lockfile is enforced everywhere (`pnpm install --frozen-lockfile`), and Go dependencies are pinned in `go.sum`.

## Users: verify before you trust

```sh
# npm packages: provenance links the tarball to this repo's workflow run
npm audit signatures

# binaries: GitHub attestation + Sigstore signature over the checksums
gh attestation verify audittrail-verify-linux-amd64 --repo 0xChintan/AuditTrail.dev
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/0xChintan/AuditTrail.dev/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

An auditor verifying evidence should run a verifier binary they checked this way, not one supplied by the party whose logs are being verified.
