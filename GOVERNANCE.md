# Governance

## Model

mcp-runtime-authz is a maintainer-led project with a single maintainer,
[@Wazza0](https://github.com/Wazza0), who makes the final decision on scope, design, merges and
releases.

Decisions are made in public, on issues and pull requests, where anyone can comment:

- Changes land as pull requests that pass CI and follow [CONTRIBUTING.md](CONTRIBUTING.md). The
  maintainer reviews and merges them.
- Changes to what the guard guarantees ([docs/security.md](docs/security.md)) or to the policy
  format are discussed in an issue before code is written.
- When people disagree, the maintainer decides and writes the reasoning on the issue or pull request.
- Security fixes are the one exception: they are developed privately until release, as described in
  [SECURITY.md](SECURITY.md).

## Roles and responsibilities

| Role | Who | Responsibilities |
| --- | --- | --- |
| Maintainer | [@Wazza0](https://github.com/Wazza0) | Review and merge pull requests; triage issues; handle vulnerability reports as described in SECURITY.md; publish releases (tag, release workflow, release notes); keep dependencies and CI actions patched; keep the documentation and the published evaluation numbers current; enforce the [code of conduct](CODE_OF_CONDUCT.md). |
| Contributor | Anyone | Follow CONTRIBUTING.md and the code of conduct; include tests with changes; keep discussion on issues and pull requests. |
| Security reporter | Anyone | Report privately, as SECURITY.md describes, and allow time for a fix before disclosing. |

## Becoming a maintainer

Contributors with a record of sustained, careful contributions, especially reviews and security
work, may be invited to become maintainers. A second maintainer is welcome: today the project has a
bus factor of one.

## Continuity

If the maintainer becomes unavailable, the project can still be continued:

- Everything needed to build, test, evaluate and release is in the repository: the CI and release
  workflows, the pinned toolchain (`rust-toolchain.toml`) and `Cargo.lock`.
- Releases are signed with keyless Sigstore build provenance tied to the repository's release
  workflow, so there are no private signing keys to hand over.
- The code is MIT OR Apache-2.0, so anyone can fork it and carry on.
