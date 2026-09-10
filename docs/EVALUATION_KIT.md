# CERBERUS Cyber evaluation kit — 0.1.0rc1

A simulation-only research authorization layer for AI-assisted cybersecurity.
It validates proposed responses, constrains their authority, and produces
auditable simulated outcomes. **Not production protection or a containment tool.**

## Quick start

Use a fresh Python 3.10 or 3.12 virtual environment. From this reviewed checkout:

```bash
python -m venv .venv
# Linux / macOS:
. .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install .
cerberus-cyber demo
cerberus-cyber demo --json
```

Expected output reports four passed demo cases: one authenticated eligible
request produces an exact simulated receipt; forged evidence and forged approval
are denied; a new gateway reopening the same state database refuses replay.
JSON output exposes the request, reasons, policy/assurance digests and receipt.
It does not expose bearer tokens or private keys.

The demo uses only fabricated local identities and freshly generated ephemeral
keys. It takes no target, credential, policy or network-connector arguments. Its
temporary SQLite directory is removed on completion. That teardown is demo cleanup,
**not a recovery procedure** for a deployed authority store. No real containment,
network probing, external resource mutation or operational authentication occurs.

This package is a release candidate in GitHub, not a published PyPI package. Do
not substitute an unverified package with a similar name. Distribution name:
`cerberus-cyber-eval`; existing Python imports remain `cerberus` and `sdk`.
Use a dedicated environment to avoid collisions with those generic import names.

## Build and verify the actual installable artifact

```bash
python -m pip install -r requirements-dev.txt -r requirements-build.txt
python -m pytest -q
python -m build
python scripts/release_checksums.py
python -m venv /tmp/cerberus-clean-eval
/tmp/cerberus-clean-eval/bin/python -m pip install dist/cerberus_cyber_eval-0.1.0rc1-py3-none-any.whl
/tmp/cerberus-clean-eval/bin/python -I scripts/verify_installed.py --repo-root .
```

Choose a new writable temporary path for each clean environment. On Windows use
the environment's `Scripts/python.exe`. The verifier checks an installed package
from a separate working directory, rejects checkout imports, runs the console
entry point, and validates bundled schemas. `python -m build` builds an sdist
and then a wheel from that sdist. SHA256SUMS identifies those exact build artifacts;
it is not a cryptographic publisher signature or a reproducible-build claim.
Direct build/runtime dependencies are pinned; transitive resolution may differ.

## Contract and evidence

DecisionToken **1.3.0** is the single combined contract: exact envelope, policy and
assurance digests, action, target, scope, actor, idempotency and expiry. Both earlier
1.2.0 branch profiles are rejected, not guessed or silently upgraded. Obtain fresh
authority after migration. PolicyBundle 1.0.0 validates and hashes the evaluated
rules; evidence v2 and approval v1 attestations bind the full ActionEnvelope.

The full request carries a policy version, not the exact policy digest. Upstream
attestations therefore bind that version; the resulting decision/token/receipt
binds the exact evaluated policy digest. Trusted administrators must bump policy
versions when rules change. This kit does not supply remote policy distribution,
policy-signing authority or online policy-revocation enforcement.

Historical benchmark v1/v2/v3 records remain frozen. The combined-contract runner
is `benchmarks/release_candidate/run.py`; it reuses v3's exact request and proof
bytes with explicit PolicyBundle schema metadata and the 1.3.0 interface. Selected
tests are not a real-world attack rate, an independent holdout or a security score.

## Before any operational pilot

Independent adversarial review, authentic issuer provisioning, online revocation,
trusted clock/storage, operational key management, telemetry privacy, and connector
crash/recovery behavior remain deployment work. SQLite assumes one trusted host and
shared database/namespace, not distributed or rollback-resistant storage. Signatures
prove configured origin, not sensor truth. HMAC decision signing remains a prototype.

See [assurance assumptions](ASSURANCE_BOUNDARY.md),
[release contract](RELEASE_CANDIDATE.md) and the repository's security policy.

Packaging references: [PyPA build workflow](https://packaging.python.org/en/latest/tutorials/packaging-projects/)
and [setuptools package data](https://setuptools.pypa.io/en/latest/userguide/datafiles.html).
