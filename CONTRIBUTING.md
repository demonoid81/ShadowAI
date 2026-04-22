# Contributing to ShadowAI Core

Thank you for your interest in contributing to ShadowAI Core. This document
describes the contribution process, code of conduct expectations, and the
**Developer Certificate of Origin (DCO)** sign-off requirement that applies
to all patches.

## Scope

This repository is **dual-licensed**:

- **ShadowAI Core** — most of the tree, licensed under the Apache
  License 2.0 (see `LICENSE`). Contributions follow the **DCO**
  workflow described below.
- **ShadowAI Enterprise Components** — directories and files listed
  in `ENTERPRISE.md`, licensed under a proprietary commercial license
  (see `LICENSE.enterprise`). Contributions to these paths
  additionally require a signed **Contributor License Agreement
  (CLA)** in addition to the DCO sign-off.

If you are unsure whether your contribution touches Enterprise
Components, consult `ENTERPRISE.md` and compare the paths you are
editing. When in doubt, open an issue before writing code.

## Developer Certificate of Origin (DCO)

All commits to ShadowAI Core must be signed off with the
[Developer Certificate of Origin (DCO) 1.1](https://developercertificate.org/).

By signing off on your commit, you certify the following:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### How to sign off

Append a `Signed-off-by:` trailer to every commit message using your real
name and a verifiable email address:

```
Signed-off-by: Jane Doe <jane@example.com>
```

Git can do this automatically:

```bash
git commit -s -m "your message"
```

Or append the line manually during `git commit --amend` if you forgot.

Pull requests containing any commit without a valid DCO sign-off will be
blocked by CI.

## Pull request workflow

1. Open an issue first for non-trivial changes so the scope and design can
   be discussed before implementation.
2. Fork the repository, create a feature branch, and commit with DCO
   sign-off.
3. Ensure tests pass: `cd backend && go test ./...` and
   `cd frontend && npm test`.
4. Open a pull request with:
   - a clear description of the change and motivation,
   - references to any related issues,
   - a test plan (what you ran, what passed).
5. At least one maintainer review is required before merge.

## Code style

- **Go**: `gofmt -s`, `go vet`, idiomatic error handling. Structured
  changes via `ast-grep` rather than sed/awk.
- **TypeScript/Vue**: follow the existing `eslint` / `prettier` config.
- **Comments**: write *why*, not *what*. Let well-named identifiers
  explain the *what*.
- **Tests**: add regression tests for every bug fix; add unit tests for
  new public functions.

## Reporting security issues

Do **not** open public issues for security vulnerabilities. See
`SECURITY.md` (to be added) for the private disclosure channel. Until
that document is published, email the maintainers directly with
`[security]` in the subject line.

## Licensing of contributions

### Core paths (Apache 2.0)

By submitting a contribution that only touches Core paths under DCO
sign-off, you agree that your contribution is licensed under the
Apache License, Version 2.0. No separate CLA is required for pure
Core contributions.

### Enterprise paths (proprietary)

By submitting a contribution that touches any path enumerated in
`ENTERPRISE.md`, you additionally agree to the terms of a signed
**Contributor License Agreement (CLA)** with the ShadowAI
Contributors. The CLA grants the maintainers the right to
distribute your contribution under `LICENSE.enterprise`
(proprietary, commercial). Without a signed CLA, PRs touching
Enterprise paths will not be merged.

This split is not retroactive: contributions accepted under DCO
before an ENTERPRISE.md path was introduced remain under Apache 2.0
in their original form.

## Trademark

Use of the name "ShadowAI" and the ShadowAI logo is governed by
`TRADEMARK.md`. You may not name a fork or a hosted service "ShadowAI"
without prior written permission from the trademark holder.
