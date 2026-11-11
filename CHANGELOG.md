# Changelog

Changes to **protestware-check** are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] — unreleased (2026-11-11)

- Align project documentation with 1.3.0, complete the CLI/options and report-field
  references, add the documentation index, development notes and explicit roadmap.
  Pin both CI examples to reviewed scanner code and preserve known detection gaps.
- Export baseline schema 2 with selected source, rules/backend, configuration,
  dependency graph and policy digests. Reopen known findings when this conservative
  project context changes, including added calls with identical evidence. Preserve
  fingerprint v1 and Python comment/line-shift stability. Reject legacy baseline
  filtering until reviewed migration; keep incomplete-analysis gate priority.
- Import explicit trusted Go listing JSON for production build profiles without
  invoking Go. Validate revisions, bounded local inputs/digests, embed scope, paths
  and package closure; retain selected used modules, replacements, relationships
  and build provenance. Add a data-only exporter and real Go CI round-trip.
- Add 12 attributed external source fragments from six projects, pinned revisions
  and licenses. Keep evaluation FP/FN visible separately from strict regression
  metrics; parser errors still fail CI. No production accuracy claim is made.
- Document migration, trusted producer responsibilities and unsupported Go profiles.

## [1.2.0] — unreleased (2026-11-11)

- Add source/artifact selection profiles and bounded file/directory coverage
  accounting, per-extension AST outcomes and resolved GitHub commit/tree IDs.
- Add explicit TOML policies, reviewed fingerprint baselines, new-finding gates,
  expiring owner/reason exceptions, retained findings and SARIF policy metadata.
  Expired exceptions cannot be hidden by baseline filtering.
- Add separate GitLab report/gate helpers with fresh output directories, report
  digests and fail-closed artifact checks. Preserve separate line-less package
  findings in GitLab SARIF without inventing source lines.
- Add Python sensitive-source-to-HTTP-payload findings and AST geographic deletion
  correlation for Go/C#/JavaScript/TypeScript. Fold literal dead branches; retain
  confidence and trace context without asserting malicious intent.
- Mask SQL quoted literals/identifier contents before keyword heuristics to avoid
  interpreting example text as destructive statements; retain dynamic SQL signals.
- Add 48 balanced inert corpus cases for six languages, rule-level quality metrics
  and resource measurements saved by CI. Reuse one parsed Python tree per file.
- Add bounded OSV page tokens/GitHub cursors, transient retries, advisory request/time
  budgets and an explicit expiring snapshot for offline positive/negative results.
  Cache hits retain retrieval times; stale/absent offline entries remain incomplete.
- Pin the Tree-sitter Python dependency and document operational limits and examples.

## Analysis integrity fixes — 2026-11-10 (unreleased)

- Report bounded Python/Tree-sitter taint, C/C++ helper and JavaScript network-path
  exhaustion as partial analysis; required AST mode fails with exit code 2.
- Invalidate reassigned Python geographic flags, fold literal Boolean conditions,
  and merge branch states without carrying unreachable geographic actions forward.
- Read Go requirements, indirect markers and replacements from go.mod. Keep
  missing requirements visible, distinguish module/archive checksums, and count
  unselected go.sum versions separately. A selected Go build list is not inferred.
- Preserve declared package origins, Git revisions and available checksums;
  distinguish equal coordinates from different sources in inventory and CycloneDX.
  Skip public advisory/enrichment queries for unverified, private, local and Git
  origins. Explicit public coordinates remain available through --package.
- Preserve package identity, advisory IDs, sources, references and matching basis
  in SARIF; attach manifest locations without inventing line numbers and expose
  incomplete enabled analyses in invocation coverage.
- Add regression fixtures for these cases and update documentation and API smoke
  inputs. Pinned detection regressions retain partial-analysis diagnostics while
  continuing to require the expected behavioral findings.

## Version-boundary and documentation fixes — 2026-11-10 (unreleased)

- Treat npm partial versions (`1`, `1.2`) as ranges, never as exact advisory
  coordinates; reject malformed npm SemVer identities as well.
- In lock mode, preserve incomplete inventory/advisory status and strict exit
  code 2. In registry mode, resolve partial ranges before versioned queries
  while retaining the approximate-inventory warning.
- Add inert regression cases for CLI strict gates, lockfiles, both advisory
  sources, registry resolution, prereleases and build metadata.
- Clarify that required AST mode applies to supported parser languages only;
  document actual smoke-workflow triggers and link historical release notes.

## Documentation alignment — 2026-11-09 (unreleased)

- Align README and release procedure with public repository status and 1.1.0 code.
- Complete CLI defaults, exit-code/completeness semantics, output safety and offline setup.
- Document advisory thresholds, limits and unexhausted pagination separately from inventory coverage.
- Refresh architecture, CI example prerequisites and historical release-note labeling.

## Security and reliability review — 2026-11-09 (unreleased)

- Bound local/remote reads and aggregate source budgets; reject special files and redirects.
- Preserve incomplete-scan status in exit codes, text reports and SARIF.
- Write reports atomically without following output symlinks or overwriting source files.
- Handle malformed dependency data, malformed source URLs and excessive analysis nesting.
- Keep version constraints out of exact-version advisory queries; resolve explicit ranges in registry mode.
- Preserve per-manifest registry enrichment and case-sensitive Go advisory identities.
- Use pre-cached AST grammars only during scans.
- Pin CI actions and run pinned behavioral regressions on main and pull requests.

## [1.1.0] — additional opt-in malware intelligence (unreleased)

- Query version-specific OpenSSF malicious-package records via the OSV API, and GitHub Advisory Database records with `type=malware`.
- Deduplicate OSV/GHSA aliases and preserve advisory provenance, affected package, locked version and dependency context.
- Do not treat political statements or external records as proof of malicious behavior; keep `code_risk` separate.
- Add bounded HTTPS requests, `--malware-strict`, transparency on partial checks, inert regression tests, and a manual public API smoke workflow.

## [1.0.0] — release candidate (unpublished)

First proposed public release. The scanner remains a **static triage tool**, not
a malware verdict engine or a guarantee against supply-chain compromise.

### Added
- Security reporting policy, Apache-2.0 license and contributor guidance.
- Reproducible release preparation, draft GitHub Release workflow and
  cryptographic checksums for the release archive.
- Gitleaks verification of Git history reachable from fetched refs, with
  version- and SHA-256-pinned scanner binary; no secret material in CI logs.
- Release checklist and pre-publication documentation checks.

### Included from the 0.x series
- AST-backed checks for Python, C/C++, Go, C#, JavaScript, TypeScript, SQL,
  HTML, CSS, SCSS, Less, and limited Sass structural parsing.
- Bounded single-file interprocedural taint flow and C/C++ call reachability.
- Rules for dynamic network URLs, suspicious filesystem operations,
  geo-dependent behavior, JavaScript request flooding and obfuscation.
- Opt-in `toxic-repos` and `black-mark` lookups; matched records are **contextual
  observations**, not proof of maliciousness.
- Lockfile/metadata dependency inventory, SARIF 2.1.0 and CycloneDX 1.6 exports.

### Known limitations
- No complete cross-file CFG, SSA or path-sensitive analysis; language and
  dependency coverage depends on parsers, formats and input size.
- No guarantee that a clean scan establishes benign behavior.
- Release candidate does **not** imply public repository access, a published
  GitHub Release, or a security-service SLA.

## 0.8.0 — 2026-11-04
- C/C++ single-file bounded call-graph analysis and `CPP_GEO_ACTION`
  reachability traces with SARIF `codeFlows`.

## 0.7.0 — 2026-11-04
- C/C++ Tree-sitter analysis, `NETWORK_FLOOD`, `OBFUSCATED_JS`, pinned
  positive/negative repository regression checks.

## 0.6.0 — 2026-11-04
- Named-function, bounded interprocedural URL taint and SARIF traces.

## 0.5.0 — 2026-11-03
- Multi-language Tree-sitter support and dynamic-URL taint tracking.

## 0.4.0 — 2026-11-03
- Language-specific heuristics, SARIF/CycloneDX export and NuGet inventory.

## 0.3.0 — 2026-11-03
- Transitive package discovery from lockfiles, opt-in registry enrichment.

## 0.2.0 — 2026-11-03
- Python AST and external watchlist integration.

## 0.1.0 — 2026-11-03
- First static heuristics, GitHub scanning, JSON/text reports and tests.

[1.0.0]: docs/releases/v1.0.0.md
