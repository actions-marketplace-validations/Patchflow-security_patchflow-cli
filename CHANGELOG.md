# Changelog

All notable changes to PatchFlow CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.6] — 2026-07-04

This release fixes critical silent-wrong-output bugs found during a systematic
evaluation of v0.1.5. Several of these bugs caused the tool to report "clean"
when vulnerabilities existed — the most dangerous class of defect in a
security tool. See the "Fixed" section below for details.

All fixes are backed by output-correctness regression tests in
`internal/integration/output_correctness_test.go`.

## [Unreleased]

### Fixed — Silent Wrong Output Bugs (Post-v0.1.5 Post-Mortem)

These fixes address bugs found during a systematic evaluation of v0.1.5.
Several of these were **silent wrong output** bugs — the most dangerous
class of defect in a security tool because the user believes they are
protected when they are not.

**P0: CycloneDX SBOM exported 0 vulnerabilities**
- `scan export --format cyclonedx-json` produced SBOMs with `"vulnerabilities": []`
  even when the scan found 42 CVEs. The vulnerabilities array was gated behind
  `IncludeVEX=true`, but VEX (reachability analysis) is the optional part —
  the vulnerabilities themselves must always be present.
- **Impact**: Any compliance audit or vulnerability management workflow using
  the CycloneDX export would believe the project had zero vulnerabilities.
- **Fix**: Vulnerabilities are now always populated from SCA findings.
  VEX analysis is only included when `--include-vex` is set.
- **Test**: `TestCycloneDXVulnerabilitiesPopulatedFromSCAFindings` in
  `internal/integration/output_correctness_test.go`

**P0: Standard profile crashed on Go projects (taint-ssa panic)**
- `scan run --profile standard` panicked with "no type for *ast.CallExpr"
  on Go projects with type errors in dependency packages. The SSA builder
  spawns internal goroutines that panic without recovery, and `defer/recover()`
  cannot catch panics from child goroutines.
- **Impact**: The standard profile (the default for CI) was unusable on
  real-world Go projects.
- **Fix**: SSA packages are now built individually with per-package
  `defer/recover()`. Packages with type errors are skipped in
  `collectAllPackages` before the build.
- **Test**: `TestStandardProfileNoCrashOnGoProject`

**P1: `--since` silently dropped all SCA findings**
- `scan run --since HEAD~1` set `scaAnalyzer.ChangedOnly = true`, which
  filtered SCA findings to only dependencies whose manifest file changed.
  A PR that didn't touch `go.mod`/`package.json` would show 0 vulnerabilities
  even if the project had 42 known CVEs.
- **Impact**: Developers using `--since` in PR CI believed their changes
  were clean when existing vulnerabilities were silently ignored.
- **Fix**: SCA always scans all dependencies regardless of `--changed-only`/
  `--since`. Vulnerabilities in existing deps are still relevant even if
  the manifest file wasn't changed in this PR.
- **Test**: `TestSinceDoesNotDropSCAFindings`

**P1: `deps licenses` showed 0% coverage but `scan run` showed 85%**
- `deps licenses` used only manifest-extracted licenses (no registry lookup),
  while `scan run` used the full enrichment pipeline (npm, PyPI, Maven, etc.).
- **Fix**: `deps licenses` now uses `registry.LicenseAnalyzer` with the same
  disk cache as `scan run`.

**P1: License enrichment cache was ineffective for empty results**
- The cache stored empty license strings (`"license":""`) but `Get()` returned
  `""` for both "not cached" and "cached as empty", causing re-fetching on
  every scan. A 40-dependency project took 29s on every scan, not just the first.
- **Fix**: Added `Cache.Has()` method to distinguish "not cached" from
  "cached as empty". Second scan now takes 1ms instead of 29s.

**P2: SCA findings lacked deterministic rule IDs**
- SCA findings showed `rule_id: "unknown"` or empty, making suppression
  (`//patchflow:ignore`) and mode overrides (`.patchflow/rules.yaml`) impossible.
- **Fix**: SCA findings now get `OSV-CVE-*`, `OSV-GHSA-*`, or `OSV-VULN-*` IDs.
- **Test**: `TestSCAFindingsHaveDeterministicRuleIDs`

**P2: `report` command re-ran the entire scan**
- `patchflow report` always re-ran SCA + SAST + reachability from scratch
  instead of using cached results.
- **Fix**: `scan run` now saves `last-scan.json` to `.patchflow/reports/`.
  `report` loads it by default; `--rescan` forces a fresh scan.

**P2: Dependency counts inconsistent across commands**
- `deps list`, `scan run` JSON, and `scan export cyclonedx` reported different
  dependency counts because `deps list` didn't resolve Maven transitives.
- **Fix**: All `deps` subcommands now resolve Maven transitives via
  `resolveMavenTransitivesIfNeeded()`.

**Minor: SAST logs leaked to stderr in JSON mode**
- SAST timing logs (e.g., `[sast] secrets-embedded total: 143ms`) were written
  to stderr even with `--json`, breaking parseable output for CI pipelines.
- **Fix**: Added `Runner.Quiet` field; redirects log output to `io.Discard`.
- **Test**: `TestJSONModeNoStderrLeak`

**Minor: G104 rule too noisy**
- G104 (unhandled errors) is idiomatic in Go (`_ =` pattern) but fired on
  every occurrence, flooding output with low-value findings.
- **Fix**: Downgraded G104 to `MaturityExperimental` — only appears in
  audit profile, not standard/CI scans. Users can re-enable via
  `.patchflow/rules.yaml`.

**Minor: `sbom` format alias missing**
- `scan export --format sbom` was not recognized; users had to type
  `cyclonedx-json`.
- **Fix**: Added `sbom`→`cyclonedx-json` alias, plus `cyclonedx`/`cdx`/`spdx`.

### Added — Output Correctness Test Suite

A new test suite (`internal/integration/output_correctness_test.go`) that
verifies **output correctness, not just "doesn't crash."** Each test
corresponds to a specific silent-wrong-output bug class:

- `TestCycloneDXVulnerabilitiesPopulatedFromSCAFindings` — asserts
  vulnerabilities array is populated when SCA findings exist, even without
  `--include-vex`
- `TestCycloneDXVulnerabilitiesEmptyWhenNoSCAFindings` — asserts the
  inverse: no vulns when no SCA findings
- `TestSinceDoesNotDropSCAFindings` — asserts SCA findings match between
  full scan and `--since` scan
- `TestStandardProfileNoCrashOnGoProject` — asserts exit code != 2 (panic)
  on a Go project with the switch+type pattern that triggered the original crash
- `TestSCAFindingsHaveDeterministicRuleIDs` — asserts all SCA findings have
  `OSV-*` rule IDs (not "unknown" or empty)
- `TestJSONModeNoStderrLeak` — asserts no SAST diagnostic logs in stderr
  when using `--json` mode

### Added — CI Dogfooding Workflow

The `.github/workflows/patchflow-scan.yml` workflow now:
- Runs `patchflow scan run` on every commit and PR (on the patchflow-cli repo itself)
- Generates SARIF, JSON, and CycloneDX outputs
- Validates all three outputs for correctness (vulns populated, rule IDs present,
  no silent-wrong-output)
- Uploads SARIF to GitHub Code Scanning
- Runs the output-correctness test suite
- Publishes a summary to the GitHub Actions run page

### Added — B12: CLI Release Hardening

**B12.0: RC1 Baseline Freeze**
- `PATCHFLOW_CLI_RC1_BASELINE.md` — frozen state at commit `e3716fc`
- 822 rules across 24 scanners + 18 framework packs
- All 62 packages passing, vet clean, no benchmark regressions

**B12.1: Enhanced Version Command**
- `patchflow version --json` now outputs full metadata: version, commit, built_at, go_version, ruleset_version, schema_version, sarif_version, osv_db_version
- New `FullInfo()` function in `pkg/version/version.go`
- New constants: `RulesetVersion`, `SchemaVersion`, `SARIFVersion`, `OSVDBVersion`

**B12.5: Config Validation and Migration**
- `patchflow config validate [path]` — validates config and warns about old schema
- `patchflow config migrate [path]` — migrates old config to current schema
  - Adds `schema_version: "1.0"` if missing
  - Suggests `framework_extensions` equivalents for `framework_overrides`
  - Writes to `.patchflow/rules.migrated.yaml` (does NOT overwrite original)

**B12.6: Schema Versioning**
- Added `schema_version` field to `rulesconfig.Config` struct
- `rules validate` warns if `schema_version` is missing
- `GetSchemaVersion()` method defaults to "1.0" if unset

**B12.7: CI Templates**
- `patchflow ci init github` — generates GitHub Actions workflow
- `patchflow ci init gitlab` — generates GitLab CI/CD pipeline
- `patchflow ci init circleci` — generates CircleCI config
- `patchflow ci init azure` — generates Azure Pipelines config
- `patchflow ci init pre-commit` — generates pre-commit hook
- Three profiles: `audit` (default, non-blocking), `starter`, `ci-blocking`

**B12.8: Enhanced Doctor Command**
- `patchflow doctor` now checks: version, config file found/valid, cache writable, SARIF output writable
- `patchflow doctor --json` includes all new fields
- Overall status: `ok`, `warning`, `error`

**B12.9: Golden Release Smoke Test**
- 5 smoke fixtures in `internal/testdata/release-smoke/`:
  - `spring-custom-extension` — tests CWE-scoped custom sinks + safe pattern suppression
  - `graphql-sqli` — tests GraphQL SQLi detection
  - `express-sqli` — tests Express SQLi detection
  - `clean-go` — tests zero false positives on safe Go code
  - `clean-python` — tests zero false positives on safe Python code
- `TestReleaseSmoke` in `internal/testdata/release_smoke_test.go`
- Copies fixtures to temp dirs to avoid git/module interference

### Already Existed (Verified Working)
- GoReleaser config (6 targets, checksums, SBOMs, cosign signing)
- Homebrew + Scoop publishing via GoReleaser
- Docker images (Dockerfile + Dockerfile.goreleaser)
- CI workflows (ci.yml, release.yml, patchflow-scan.yml)
- Makefile with release targets
- RELEASE.md with full release process

### Added — B11.5: Extension Hardening

**B11.5.1: Sink Scoping by CWE/Category**
- Custom sinks now carry optional `cwe` and `category` fields.
- A sink with `cwe: "CWE-89"` only attaches to SQLi rules, not SSRF/redirect/deser.
- A sink with no CWE/category attaches to all rules (backward compatible).
- `CategoryForCWE()` maps CWEs to categories (CWE-89→sql_injection, CWE-918→ssrf, etc.).
- `sinkMatchesRule()` and `sourceMatchesRule()` functions in `types.go`.
- Added `Category` field to `FrameworkRule` and `SinkPattern`.
- 11 tests in `sink_scoping_test.go`.

**B11.5.2: Source Category Scoping**
- Custom sources now carry optional `categories` field.
- A source with `categories: [sql_injection, path_traversal]` only attaches to matching rules.
- A source with no categories attaches to all rules (backward compatible).

**B11.5.3: Taint Safe Pattern Suppression**
- Safe patterns now suppress taint-mode findings when the pattern matches in the same function.
- New file `safepattern_taint.go` with `suppressTaintWithSafePatterns()` function.
- Uses function boundary detection from B10.9 to find the containing function.
- Checks if any safe pattern regex matches within the function's line range.
- 6 tests in `safepattern_taint_test.go`.

**B11.5.4: Config UX Cleanup**
- Added `--config` flag as the unified config entry point.
- `--rules` and `--rules-config` are now documented as legacy aliases.
- `--config` sets both `CustomRulesPath` and `RulesConfigPath` for a single config file.
- Backward compatible: existing `--rules` and `--rules-config` flags still work independently.

**B11.5.5: Strong Validation**
- `rules validate` now catches noisy extension mistakes:
  - Warning: sink with no CWE/category (will attach to all rules)
  - Warning: duplicate source/sink/sanitizer
  - Warning: unknown framework name
  - Warning: CWE format doesn't match CWE-NNN
  - Error: missing required fields (func, annotation, pattern)
  - Error: invalid regex patterns
- Added `Warnings` field to `rulesValidateResult` JSON output.
- Added `getKnownFrameworkNames()` helper.

**YAML Alias Support**
- `func` and `function` are now both accepted in YAML for sources, sinks, and sanitizers.
- `FuncName()` method on YAML types returns the correct value from either field.

### Added — B11: Custom Framework Extensions

**B11.1: Config Schema**
- Added `framework_extensions` section to `.patchflow/rules.yaml` (in `internal/rulesconfig/config.go`).
- New types: `rawFrameworkExtension`, `rawExtensionSink` (with CWE/category/severity), `rawSafePattern`.
- Extensions are parsed alongside `framework_overrides` and merged into the same pack override pipeline.
- `HasFrameworkExtensions()` method on `Config`.

**B11.2: Merge Extensions into Framework Packs**
- `customrules.Loader` converts `framework_extensions` to `PackOverride` entries.
- Extensions are merged with `framework_overrides` if both define entries for the same framework.
- `PackOverride` now includes `SafePatterns` field.
- `ApplyPackOverride` merges safe patterns into each rule's `SafePatterns` slice.

**B11.3: Taint Support**
- Custom sources (including annotations like `@TenantInput`) are added to all taint rules in the pack.
- Custom sinks (like `LegacySql.run`) are added to all taint rules.
- Custom sanitizers are added to all rules.
- Safe patterns are added to all rules (pattern/template mode only — taint mode is a known limitation).

**B11.4: Explain + Validate Support**
- `patchflow explain --rule <id>` now shows "Project extensions" section with additional sources, sinks, sanitizers, and safe patterns.
- `patchflow rules validate` now validates `framework_extensions` entries (sources, sinks, sanitizers, safe patterns, regex compilation).

**B11.5: Tests + Docs**
- 7 tests in `customrules/framework_extensions_test.go` (parse, merge, unknown framework, invalid regex, empty name, missing pattern, express).
- 3 tests in `rulesconfig/framework_extensions_test.go` (parse, empty config, has framework config).
- 3 tests in `frameworks/overrides_test.go` (safe patterns, full merge, severity overrides).
- New doc: `docs/CUSTOM_FRAMEWORK_EXTENSIONS.md` with schema reference, examples, and limitations.

### Added — B10.9: Function Boundary Grouping Refinement
- Spring annotation-based source modeling: the taint engine now recognizes
  `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`,
  `@CookieValue`, and `@ModelAttribute` as taint sources via
  `seedAnnotatedParams()` in the taint analyzer. Parameters with these
  annotations are pre-tainted before walking the function body.
- GraphQL resolver source modeling: Python functions named `resolve_*` or
  `mutate` with an `info` parameter are now recognized as GraphQL resolvers.
  Parameters after `root`/`parent`/`self` and `info` are pre-tainted as
  user-controlled resolver arguments via `seedGraphQLResolverParams()`.
- Direct source-to-sink detection: the taint engine now detects cases where
  a taint source is used inline in a sink argument without being assigned to
  a variable first (e.g., `query(`SELECT ... ${req.body.email}`)`).
  This is handled by `argContainsSource()` in both the intra-procedural and
  inter-procedural analyzers.
- TypeScript normalization: `.ts` and `.tsx` files are now normalized to
  "javascript" for taint rule matching. Previously, TypeScript files were
  skipped entirely by the taint engine because rules used `Language: "javascript"`.

### Changed
- `taintpatterns.SourcePattern` now has an `Annotation` field for Java/C#
  annotation-based sources. The `frameworks.ToTaintRules` conversion now
  transfers the `Annotation` field from framework pack sources.
- All built-in Java taint rules (TP-JAVA001 through TP-JAVA010) now include
  `javaAnnotationSources` in their source patterns.

### Enabled Strict Tests
- `TestWebGoat_SpringAnnotationSources_TaintRulesFire` — was pending, now
  enabled. WebGoat: 0 → 8 TP-JAVA* findings.
- `TestJuiceShop_ExpressSources_TaintRulesFire` — was pending, now enabled.
  Juice Shop: 0 → 66 TP-JS* findings.
- `TestDVGA_GraphQLSources_AreSeeded` — new test, enabled. Verifies GraphQL
  source model is active (Python findings produced).
- `TestDVGA_GraphQLSources_TaintRulesFire` — remains pending B7. Source
  seeding works but DVGA uses SQLAlchemy `text()` which is not yet a taint
  sink.

### Benchmark Impact
- WebGoat: 627 → 635 total findings (+8 TP-JAVA* taint findings)
- Juice Shop: 273 → 347 total findings (+66 TP-JS* taint findings, +8 from
  TypeScript files now being analyzed)
- Django (clean): 143 → 143 (no FP regression)
- Flask (clean): 43 → 43 (no FP regression)

### Added — B6.5e: Angular Source Model Closure
- Enhanced Angular sources: added `route.snapshot.paramMap`,
  `route.snapshot.queryParams`, `route.snapshot.params`, `route.data`,
  `route.fragment`, `FormControl.value`, `FormGroup.value`, `http.get`,
  `http.post`, `ElementRef.nativeElement` — matching real Angular code
  patterns (e.g., `this.route.snapshot.queryParams["html"]`).
- Enhanced Angular sinks: added `nativeElement.innerHTML`, `outerHTML`,
  `navigate`, `document.location`, `createComponent`,
  `ViewContainerRef.createComponent`.
- Enhanced Angular sanitizers: added `sanitizer.sanitize`, `validateUrl`.
- Added SafePatterns to PF-ANGULAR-XSS-001 (DOMPurify.sanitize,
  sanitizer.sanitize suppress).
- Added 2 MatchTaint rules:
  - `PF-ANGULAR-XSS-003`: route/form/@Input data → bypassSecurityTrust*/innerHTML (CWE-79)
  - `PF-ANGULAR-REDIRECT-002`: route data → navigateByUrl/navigate/window.location (CWE-601)
- New MatchTaint rules are `MaturityExperimental` (audit-only, non-blocking)
  until benchmark validation promotes them.
- 3 new Angular tests: taint rule count, source coverage, sink coverage.

### Added — B7.1: SQLAlchemy text() Sink
- Added `text` as a taint sink in TP-PY001 (SQL injection). This closes the
  DVGA gap: GraphQL resolver args (seeded by B6.5) now flow to `text()` and
  trigger TP-PY001.
- Fixed `seedGraphQLResolverParams()` to handle Python parameters with
  default values (`default_parameter` AST nodes). Previously, parameters like
  `filter=None` were missed because only `identifier` children of `parameters`
  were collected. Now `default_parameter`, `typed_parameter`, and
  `list_splat_pattern`/`dictionary_splat_pattern` are also handled.
- DVGA: 0 → 1 TP-PY001 finding (resolver arg `filter` → `text()` SQLi).
- `TestDVGA_GraphQLSources_TaintRulesFire` — enabled (was pending B7).
- Django clean: 143/3 taint — no FP regression from `text` sink.
- Flask clean: 43/0 taint — no FP regression.

### Added — B7.2: GraphQL Framework Pack
- New `graphql` framework pack with 5 rules:
  - `PF-GRAPHQL-SQLI-001` (MatchTaint, CWE-89, beta): resolver args → raw SQL
  - `PF-GRAPHQL-SSRF-001` (MatchTaint, CWE-918, beta): resolver args → HTTP requests
  - `PF-GRAPHQL-PATH-001` (MatchTaint, CWE-22, beta): resolver args → file operations
  - `PF-GRAPHQL-AUTH-001` (MatchPattern, CWE-639, beta): IDOR — filter_by(id=id) without ownership
  - `PF-GRAPHQL-DOS-001` (MatchPattern, CWE-400, experimental): missing depth/complexity limits
- GraphQL detection signature: detects graphene/ariadne/strawberry in requirements.txt
  or pyproject.toml, or .graphql schema files (MinSignals: 1).
- 12 GraphQL pack tests (contract, rule count, IDs, taint count, auth inform,
  DoS experimental, source/sink coverage, auth positive/safe, DoS positive/safe).
- DVGA: 91 → 99 total findings (+1 TP-PY001, +6 PF-GRAPHQL-AUTH-001, +1 PF-GRAPHQL-SQLI-001).

### Added — B7.3: Flask Pack Enhancement
- Added `PF-FLASK-PATH-001` (MatchPattern, CWE-22, beta): send_file/open with request input
- Added `PF-FLASK-CONFIG-001` (MatchPattern, CWE-489, beta): debug=True or hardcoded SECRET_KEY
- Added `PF-FLASK-SQLI-002` (MatchTaint, CWE-89, experimental): request → text()/execute
- Added `PF-FLASK-SSRF-002` (MatchTaint, CWE-918, experimental): request → requests/httpx
- Enhanced sources: added `request.json`, `request.files`, `request.data`
- Enhanced sinks: added `text`, `execute`, `session.execute`, `requests.post`,
  `httpx.get`, `httpx.post`, `send_from_directory`, `open`, `subprocess.run`, `os.system`

### Added — B7.4: FastAPI Pack Enhancement
- Added `PF-FASTAPI-AUTH-001` (MatchPattern, CWE-862, experimental): sensitive endpoint
  missing Depends(auth)
- Enhanced SQLi taint rule: added `text` and `session.execute` to sinks
- Enhanced sinks: added `text`, `session.execute`

### Benchmark Impact (B7 full)
- DVGA: 91 → 99 (+8 taint-confirmed findings: 1 TP-PY001 + 7 PF-GRAPHQL*)
- Django (clean): 143 → 143 (no FP regression)
- Flask (clean): 43 → 43 (no FP regression)
- WebGoat: 635 → 635 (stable)
- Juice Shop: 347 → 347 (stable)

### Added — B8: Documentation, Explainability, and Profiles

**B8.1: Framework Pack Documentation**
- Created `docs/rules/frameworks/` with per-pack documentation:
  - `graphql.md` — 5 rules, sources/sinks/sanitizers, vulnerable/safe examples
  - `flask.md` — 9 rules (7 pattern + 2 taint), enhanced sources/sinks
  - `fastapi.md` — 9 rules (7 pattern + 2 taint), AUTH rule
  - `spring.md` — Spring annotation source model, TP-JAVA* taint rules
  - `angular.md` — 5 rules (3 pattern + 2 taint), 25 source patterns
  - `express.md` — TypeScript normalization, direct source-to-sink
  - `django.md` — Built-in Python taint rules, conservative GraphQL detection
- Each doc includes: overview, detection signals, sources, sinks, sanitizers,
  rule tables, vulnerable/safe examples, override instructions, known limitations.

**B8.2: Rule Explain Improvements**
- `patchflow explain --rule <id>` now shows:
  - OWASP Top 10 category (mapped from CWE)
  - Default mode (computed from maturity + severity)
  - Safe patterns (with reasons)
  - Override instructions (`.patchflow/rules.yaml` snippet)
- JSON output includes `owasp`, `default_mode`, and `safe_patterns` fields.
- Added `owaspCategoryForCWE()` mapping for 15 common CWEs.

**B8.3: Rules Init Profiles**
- `patchflow rules init --profile <name>` generates pre-configured rules.yaml:
  - `starter` — stable high/critical block, rest inform
  - `strict` — stable + beta injection/auth-critical block, heuristics inform
  - `audit` — everything inform, nothing blocks
  - `framework-heavy` — enable framework packs, stable block
  - `ci-blocking` — block all high/critical (stable+beta), experimental off
  - `enterprise` — stable block, beta inform, experimental off
- 3 new tests: profile generation, invalid profile, profile list.

**B8.4: Rule Modes and CI Documentation**
- Created `docs/RULE_MODES_AND_CI.md` — documents block/inform/off policy,
  mode resolution, maturity defaults, JSON/SARIF fields, CI integration.

**B8.5: Framework Detection and CI Documentation**
- Created `docs/FRAMEWORK_DETECTION_AND_CI.md` — documents auto-detection,
  overrides, framework pack controls, CI examples (GitHub Actions, GitLab CI,
  pre-commit), suppression patterns.

### Added — B9: Benchmark Report Refresh

**B9.0: Frozen Baseline**
- Created `FRAMEWORK_RULES_V1_BASELINE.md` — frozen snapshot with commit hash,
  rule counts, environment, benchmark repo results.
- 777 total rules, 132 framework rules, 18 packs, 37 blocking-eligible.

**B9.1: Semgrep Comparison**
- Created `SEMGREP_COMPARISON_framework-rules-v1.md` — live comparison with
  Semgrep 1.168.0 on 7 vulnerable + 3 clean repos.
- PatchFlow taint-confirmed findings: 66 on Juice Shop (vs Semgrep's 10 ERROR).
- Clean repo: Django 143/0 blocking (vs Semgrep's 612/81 ERROR).

**B9.2: Clean Precision Report**
- Created `CLEAN_PRECISION_REPORT_framework-rules-v1.md` — documents zero
  blocking regressions and zero taint FP regressions from B1 to v1.

**B9.3: Framework Coverage Matrix**
- Created `FRAMEWORK_COVERAGE_MATRIX.md` — 18 packs with rules, taint counts,
  sources, sinks, sanitizers, detection signals, known limitations.

**B9.4: Framework Benchmark Report**
- Created `FRAMEWORK_RULES_BENCHMARK_v1.md` — per-repo findings with
  source-to-sink taint wins highlighted.
- Total vulnerable: 1546 → 1636 (+90 findings, +8 DVGA, +8 WebGoat, +74 Juice Shop).
- Clean repos: 0 delta.

**B9.5: Trivy Comparison (SCA Lane)**
- Created `TRIVY_COMPARISON_framework-rules-v1.md` — SCA-only comparison.
- PatchFlow OSV finds 68 vulns on Juice Shop (vs Trivy's 0).
- Trivy remains strongest for container/infra scanning.

**B9.6: Public Benchmark Report**
- Created `BENCHMARK_COMPARISON_framework-rules-v1.md` — polished report with
  executive summary, methodology, Semgrep/Trivy comparisons, clean precision
  baseline, framework source-model wins, output quality, known limitations,
  roadmap, and safe claims.

**B9.7: Manual Review of Heuristic Findings**
- Created `MANUAL_REVIEW_DVGA_AUTH_findings.md` — manual code review of all
  6 PF-GRAPHQL-AUTH-001 findings in DVGA.
- Result: all 6 are TRUE POSITIVES (IDOR vulnerabilities). Zero false positives.
- Finding #2 (views.py:148) is a same-function duplicate of #1 (views.py:141)
  — both in EditPaste.mutate on different filter_by(id=id) lines. B10 dedup target.
- Rule confidence (low) and default mode (inform) remain appropriate.

### Added — B10: Performance, Deduplication, and Output Quality

**B10.1: Stable Fingerprinting**
- Added `DedupFingerprint` field to Finding struct — groups base/IP taint variants.
- Added `IssueGroupID`, `OccurrenceCount`, `RelatedLocations` fields to Finding.
- Added `ComputeDedupFingerprint()` and `ComputeIssueGroupID()` functions.
- Added `ExtractFunctionName()` helper for function-aware grouping.
- `PopulateFingerprints()` now also sets `DedupFingerprint`.

**B10.2: Dedup/Grouping Engine**
- Added `dedupBaseVsInterprocedural()` — merges base taint findings with their
  interprocedural (-IP) counterparts on the same file+line. IP variant kept.
- Added `groupIssues()` — groups related findings in the same function using
  function-name extraction or line proximity (30-line window).
- Issue groups preserve all findings (no data loss) — primary finding carries
  `OccurrenceCount` and `RelatedLocations`.
- Phase 2e (base/IP dedup) and Phase 2f (issue grouping) added to SAST pipeline.

**B10.3: Dedup Applied Before Report Generation**
- Dedup and grouping run in the SAST runner before findings are returned to
  the scan command, ensuring all output formats benefit.

**B10.4: JSON/SARIF Output Updated**
- JSON output includes `dedup_fingerprint`, `issue_group_id`, `occurrence_count`,
  `related_locations` on each finding.
- SARIF properties include `dedup_fingerprint`, `issue_group_id`, `occurrence_count`.

**B10.5: Performance Timings**
- SAST runner now collects internal phase timings: `framework_detection`,
  `scanners`, `dedup_grouping`.
- Timings merged into `engine_timings` in JSON output.
- Dedup/grouping overhead: 0.4ms (negligible).

**B10.6: Rule Registry Optimization**
- Framework registry is now a package-level singleton (`sync.Once`), avoiding
  rebuild across multiple Runner instances.
- All regex patterns were already precompiled at scanner initialization —
  no recompilation on each scan.

**B10.7: Framework Detection Cache**
- Not needed — framework detection is 11.7ms and called once per scan.

**B10.8: Benchmark Comparison**
- Created `B10_BENCHMARK_COMPARISON.md` — before/after comparison.
- Juice Shop: 66→33 taint findings (50% reduction, zero signal loss).
- DVGA: 6 AUTH findings grouped into 5 issue groups (function-aware).
- Clean repos: 0 regression (cobra 18/0, flask 43/0, django 143/0).
- All 61 test packages pass.

**B10.9: Function Boundary Grouping Refinement**
- Added `internal/sast/funcboundaries.go` — detects function/method/class
  definitions in source files (Python, Go, JS/TS, Java, Ruby).
- `groupIssues` now uses function boundary detection as the primary grouping
  strategy: reads the source file, finds `def`/`class`/`function`/`func`
  patterns, and assigns each finding to its enclosing function.
- Proximity (10-line window, reduced from 30) is only used as a fallback when
  source code is unavailable or no function boundary is found.
- Methods with the same name in different classes (e.g., EditPaste.mutate vs
  DeletePaste.mutate) are correctly separated using `name@startLine` keys.
- DVGA result: 6 AUTH findings → 5 issue groups (was 2 with proximity-only).
  EditPaste.mutate (lines 141+148) correctly grouped; DeletePaste.mutate
  (line 167) correctly separate.
- Added tests: `TestGroupIssuesFunctionBoundaryDetection`,
  `TestDetectFunctionBoundaries`, `TestFindFunctionForLine`.

**B10 Tests Added**
- `TestDedupBaseVsInterprocedural` — base/IP merge keeps IP variant.
- `TestDedupBaseVsInterproceduralKeepsBaseWhenNoIP` — base kept when no IP.
- `TestGroupIssuesSameFunction` — same-function findings grouped.
- `TestGroupIssuesDifferentFunctionsNotGrouped` — different functions separate.
- `TestGroupIssuesDifferentRulesNotGrouped` — different rules separate.
- `TestGroupIssuesDifferentFilesNotGrouped` — different files separate.
- `TestDedupFingerprintBaseIPSameLine` — base/IP share dedup fingerprint.
- `TestDedupFingerprintDifferentLinesNotEqual` — different lines differ.
- `TestDedupFingerprintStableAcrossLineShift` — semantic FP stable.
- `TestIssueGroupIDSameFileSameRule` — same rule+file share group ID.
- `TestIssueGroupIDDifferentRules` — different rules differ.
- `TestExtractFunctionName` — function name extraction from titles.
- `TestPopulateFingerprintsIncludesDedup` — dedup FP populated.

## [0.1.2] - 2025-07-01

### Added
- Non-blocking update check notification — PatchFlow now checks for new releases
  on startup and prints a banner if a newer version is available
- GitHub Actions workflow for self-hosted PatchFlow scans
  (`.github/workflows/patchflow-scan.yml`)
- CI workflow with comprehensive test gates
  (`.github/workflows/ci.yml`)
- Release workflow with GoReleaser, Cosign signing, and SBOM generation
  (`.github/workflows/release.yml`)
- Engineering standards document (`ENGINEERING_STANDARDS.md`)
- Architecture decision records (`ARCHITECTURE_DECISION_RECORDS.md`)
- Product principles document (`PATCHFLOW_PRODUCT_PRINCIPLES.md`)
- Engineering manifesto (`PatchFlow_CLI_Engineering_Manifesto.md`)
- Embedded SAST roadmap (`EMBEDDED_SAST_ROADMAP.md`)
- Quickstart guide (`QUICKSTART.md`)
- Code of Conduct (`CODE_OF_CONDUCT.md`)
- NOTICE file for Apache 2.0 license compliance
- Makefile with common build, test, and release targets
- `.gitleaks.toml` for allowlist control
- `.pre-commit-hooks.yaml` for pre-commit integration

### Security
- Pinned all GitHub Actions to immutable SHA commits (prevents mutable-action
  supply-chain attacks)
- Removed `curl | sh` syft install in release workflow — replaced with pinned
  download script
- Fixed composite-action shell injection risk in `action.yml`
- Hardened Docker runtime: non-root user, read-only filesystem, minimal base
  image
- Token retrieval now uses OS keychain with 0600-permission file fallback
- Report file permissions set to 0600 (was 0644)
- Gitleaks behavior fixed: `.gitleaks.toml` added for allowlist control
- Secret rule IDs normalized for consistent SARIF reporting

### Changed
- GoReleaser pinned to v2.15.4 (avoids `brews` deprecation as failing config in
  newer versions)
- Go version updated to 1.26.4 in all workflows
- `scripts/install.sh` hardened with better error handling and checksum
  verification
- Container image validation improved in `internal/container/scanner.go`

### Fixed
- pnpm workspaces under `packages/` were skipped during manifest detection
- Golden tests expected stale rule IDs that no longer match the registry
- PR artifact tests wrote outside the validated project path
- Bare `return err` wrapped with context in critical paths (SAST runner, report
  generator, benchmark, OSV DB)
- Hardcoded `/usr/bin/time` path in benchmark now tries PATH first, then
  absolute fallback

## [0.1.1] - 2025-07-01

### Security
- Pinned all GitHub Actions to immutable SHA commits (preplies mutable-action supply-chain attacks)
- Removed `curl | sh` syft install in release workflow — replaced with pinned download script
- Fixed composite-action shell injection risk in `action.yml`
- Hardened Docker runtime: non-root user, read-only filesystem, minimal base image
- Token retrieval now uses OS keychain with 0600-permission file fallback
- Report file permissions set to 0600 (was 0644)
- Gitleaks behavior fixed: `.gitleaks.toml` added for allowlist control
- Secret rule IDs normalized for consistent SARIF reporting

### Changed
- GoReleaser pinned to v2.15.4 (avoids `brews` deprecation as failing config in newer versions)
- Go version updated to 1.26.4 in all workflows
- `scripts/install.sh` hardened with better error handling and checksum verification
- Container image validation improved in `internal/container/scanner.go`

### Fixed
- pnpm workspaces under `packages/` were skipped during manifest detection
- Golden tests expected stale rule IDs that no longer match the registry
- PR artifact tests wrote outside the validated project path
- Bare `return err` wrapped with context in critical paths (SAST runner, report generator, benchmark, OSV DB)
- Hardcoded `/usr/bin/time` path in benchmark now tries PATH first, then absolute fallback

## [0.1.0] - 2025-06-27

### Added
- GoReleaser config with multi-platform builds (linux/darwin/windows, amd64/arm64)
- Docker images with multi-arch manifests (buildx)
- Homebrew tap and Scoop bucket auto-publish
- Cosign image and blob signing
- SPDX SBOM generation via syft
- GitHub Action (`action.yml`) for composite security scan workflow
- Pre-commit hooks for scan and secret detection
- Install script (`scripts/install.sh`) with checksum verification
- Benchmark results: 100% recall on 18 vulnerable repos, 0.094 HC/KLOC on clean repos
- Embedded SAST engine: pattern scanner, taint analysis (tree-sitter), AST rules
- Framework pack system (Rails reference pack)
- Governance registry with maturity levels (experimental/beta/stable)
- Incremental scanning with mtime fast-path and git diff pre-filter
