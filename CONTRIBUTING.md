# Contributing to ShadowAI Core

Thank you for your interest in contributing to ShadowAI Core. This document
describes the contribution process, code of conduct expectations, and the
**Developer Certificate of Origin (DCO)** sign-off requirement that applies
to all patches.

## Scope

This repository contains **ShadowAI Core**, licensed under the
Apache License, Version 2.0 (see `LICENSE`).

Contributions to enterprise-only features (see `NOTICE`) are handled
through a separate private repository under a commercial license and are
not accepted here. If you are unsure whether a feature belongs in Core or
Enterprise, open an issue before writing code.

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

By submitting a contribution under DCO sign-off, you agree that your
contribution is licensed under the Apache License, Version 2.0, the same
license as the rest of ShadowAI Core. No separate Contributor License
Agreement (CLA) is required for Core contributions.

If a future need arises to dual-license specific modules (for example, to
include community contributions in ShadowAI Enterprise), a separate CLA
may be introduced at that time and will apply only going forward, never
retroactively.

## Trademark

Use of the name "ShadowAI" and the ShadowAI logo is governed by
`TRADEMARK.md`. You may not name a fork or a hosted service "ShadowAI"
without prior written permission from the trademark holder.
