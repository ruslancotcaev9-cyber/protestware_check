# Changelog

Changes to **protestware-check** are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
