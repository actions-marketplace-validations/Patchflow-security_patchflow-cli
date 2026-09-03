## Outcome

Describe the user/developer problem and the outcome delivered by this pull request.

## Scope

- Included:
- Explicitly not included:
- Compatibility or migration notes:

## Verification

List exact commands and results. Explain every intentional skip.

- [ ] `go mod tidy` leaves `go.mod` and `go.sum` unchanged.
- [ ] `gofmt` produces no diff.
- [ ] `go vet ./...` passes.
- [ ] Relevant focused tests pass.
- [ ] `go test ./... -timeout 10m` passes.
- [ ] `go build ./...` passes.
- [ ] User-facing documentation is updated when behavior or output changes.

## Rule, noise, and benchmark impact

- Finding/rule IDs affected:
- Vulnerable fixture added or updated:
- Safe control fixture added or updated:
- False-positive/false-negative impact:
- Runtime, memory, binary-size, or benchmark impact:
- If not applicable, explain why:

## Security and privacy

- [ ] No real secrets, tokens, private source, customer data, or personal data are included.
- [ ] New network calls, credential access, source upload, and trust-boundary changes are documented.
- [ ] Machine-readable output remains valid and logs do not corrupt stdout.
- [ ] Security-sensitive details were reported privately instead of included here.

## Contribution

- [ ] Commits include a DCO `Signed-off-by` trailer (`git commit -s`).
- [ ] I have read `CONTRIBUTING.md` and followed the Code of Conduct.
- [ ] Related issue(s):
