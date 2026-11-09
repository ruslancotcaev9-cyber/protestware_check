# Changelog

Changes to **protestware-check** are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/ruslancotcaev9-cyber/protestware_check/releases/tag/v1.0.0
