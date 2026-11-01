# Prepare and publish artifacts

This procedure prepares the research preview. It does not authorize a public
release. Public package-index uploads require explicit user approval, and the
single-public-release policy remains in force. Production qualification still
requires all seven [release gates](../ENGINEERING_PLAYBOOK.md#release-gate).

## Prepare an immutable candidate

Use a separate preview branch. Review the version, license, project URLs,
Python range, exact dependencies and extras in `pyproject.toml`. Keep demonstration
code and results in the separate application repository. `uv_build` remains the
build backend; its hashed requirements are in `qualification/build-backend`.

From a clean Cryptalis checkout with the locked development environment:

```console
uv sync --locked --all-extras
.venv/bin/python scripts/release_check.py --output /absolute/new/artifacts --receipt /absolute/new/release.json
```

The receipt binds source/build inputs and records exact wheel/sdist hashes,
repeat-build equality, metadata, RECORD checks, archive inspection and a
CycloneDX SBOM. It does not independently reproduce a different builder's output.
Choose new output and receipt paths for each candidate. Inspect package contents,
license, optional dependencies and CLI help; run fresh pip and uv installs
outside the checkout for CPython 3.12 and 3.13. Use the installed interpreter with
`scripts/release_check.py --python /absolute/environment/bin/python` to compare
installed bytes and CLI startup against the inspected wheel.

Run the mandatory wrapper and existing application/fresh-cluster harnesses with
`--installed-wheel` to bind lifecycle evidence to that artifact. Retain commands,
raw receipts, skips and failures. A clean installation is not a complete
application or security qualification.

Freeze the library and separate demonstration revisions only when the selected
acceptance work is complete. Bind measurements, hashes, dependency versions and
artifact provenance to those exact revisions. Subsequent reusable fixes return
to main after verification; preview and production work are branches of one
library.

## Draft the GitHub Release

Create a **draft**, marked prerelease, for the reviewed candidate tag. Attach the
already-inspected wheel, sdist, `SHA256SUMS`, SBOM, sanitized build/installation
receipts and a release note stating the exact admitted scope, missed targets,
external prerequisites and all production gates UNKNOWN. Link the demonstration
evidence without copying it into the library distribution. A draft is reviewable
preparation, not permission to publish it.

## Package-index workflow template

The reviewed workflow template is
[`package-publish.yml`](../release/package-publish.yml). It is stored outside
`.github/workflows`, so it cannot execute or publish until deliberately enabled.
Before enabling it:

1. Obtain explicit approval for this public preview; it counts as a public release.
2. Configure the `pypi` environment with required independent reviewers and branch/tag
   restrictions. Configure PyPI Trusted Publishing for this exact repository,
   workflow filename and environment. Verify publisher ownership and recovery.
3. Review and copy the template to `.github/workflows/package-publish.yml`.
   Review every immutable action/tool pin. The existing isolated build job has
   no upload authority; only the publication job receives short-lived OIDC.
4. Select the approved immutable tag and the exact reviewed build run when
   dispatching. The publication job downloads that run's already-built artifacts;
   it does not rebuild with publication authority.
5. Independently compare the downloaded distributions with the approved hashes
   and receipts before approving the protected job. Keep deployment secrets and
   package-index tokens out of build jobs, caches and artifacts.

Do not configure long-lived package-index tokens as a fallback. If environment
protection, publisher identity, independent review or provenance is missing,
publication remains blocked. Sigstore attestations identify artifacts and issuer
within their trust assumptions; they do not prove safe cryptography or code.
