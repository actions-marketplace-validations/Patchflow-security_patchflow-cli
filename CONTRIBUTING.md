# Contributing to PatchFlow CLI

Thank you for helping improve PatchFlow CLI. Contributions may include bug
fixes, false-positive reductions, framework rules, fixtures, documentation,
performance work, and product proposals.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) in every project space.
Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not a public
issue or pull request.

## Before you start

- Search [existing issues](https://github.com/Patchflow-security/patchflow-cli/issues)
  and pull requests.
- Use the issue chooser for a bug, false positive, rule request, feature request,
  or community question.
- For a large change, open an issue before implementation so maintainers can
  confirm the contract and review scope.
- Keep a pull request focused on one outcome. Generated formatting, unrelated
  cleanup, and behavior changes should not be mixed without explanation.

## Development setup

Prerequisites:

- Git;
- Go `1.26.4` as declared by `go.mod`;
- optional scanner binaries only when the affected integration requires them.

```bash
git clone https://github.com/Patchflow-security/patchflow-cli.git
cd patchflow-cli
go mod download
go build -o patchflow .
./patchflow version
```

Run the same core checks used by CI:

```bash
go mod tidy
git diff --exit-code -- go.mod go.sum
gofmt -w .
go vet ./...
go test ./... -timeout 10m
go build ./...
```

`go test ./...` includes integration packages that may be slower locally. When
iterating, run the affected package first, then run the complete suite before
requesting review. See [the development guide](docs/DEVELOPMENT.md) and
[developer guide](docs/DEVELOPER_GUIDE.md) for architecture and conventions.

## Pull-request workflow

1. Fork the repository or create a topic branch.
2. Add a focused regression test before or with the fix.
3. Update user-facing documentation when flags, output, rules, or behavior change.
4. Run the core checks above and record any intentional skip.
5. Complete every applicable section of the pull-request template.
6. Respond to review with follow-up commits; do not rewrite another contributor's
   branch without permission.

Pull requests should explain:

- the user-visible problem and expected outcome;
- compatibility or schema impact;
- security and privacy implications;
- runtime, binary-size, and benchmark impact;
- false-positive/false-negative or other noise impact;
- the exact commands used for verification.

## Adding or changing a security rule

Framework packs live under `internal/sast/frameworks/<framework>/`. Follow the
[framework pack contract](internal/sast/frameworks/README.md):

1. Declare the typed rule, source, sink, sanitizer, and safe patterns.
2. Register a new pack in `default_registry.go` and add detection signals when
   introducing a framework.
3. Start new rule packs as `experimental` until their fixture suite passes.
4. Add vulnerable, safe, and normal fixtures. A rule is incomplete if it only
   proves that a vulnerable example matches.
5. Assert stable rule ID, severity, location, message, and suppression behavior.
6. Measure changes in findings and runtime against the relevant benchmark or
   explain why no benchmark is applicable.

Do not include real credentials, private repositories, proprietary source, or
unredacted customer findings in fixtures. Use unmistakably synthetic secrets and
minimal source examples.

## Fixtures and false positives

- Put fixtures next to the package or in its existing test fixture directory.
- Include the smallest code needed to reproduce the behavior.
- Pair every vulnerable fixture with at least one safe control.
- Cover framework aliases, file extensions, sanitizers, and suppression comments
  when relevant.
- A false-positive fix must retain a test showing that the genuinely vulnerable
  pattern is still detected.

## Commit sign-off (DCO)

PatchFlow uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
instead of a separate Contributor License Agreement. Sign off each commit to
certify that you have the right to submit it:

```bash
git commit -s -m "fix: describe the change"
```

This adds a `Signed-off-by: Name <email>` trailer matching the commit author.
If a commit is missing the trailer, amend it before requesting review. A future
CLA or sign-off policy change requires the governance process in
[GOVERNANCE.md](GOVERNANCE.md); it will not apply silently.

## Review and merge

Passing automation is necessary but not sufficient. A maintainer reviews the
contract, tests, security impact, and documentation. Maintainers may request a
smaller scope, additional fixtures, or benchmark evidence. Merge and release
authority is defined in [GOVERNANCE.md](GOVERNANCE.md).

For help choosing the correct channel, see [SUPPORT.md](SUPPORT.md).
