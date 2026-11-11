# Contributing to protestware-check

Contributions follow the repository owner's permissions and the review process below.

## Before contributing

- Read [SECURITY.md](SECURITY.md) for **private vulnerability disclosure**;
  do not publish working exploitation details or authentic credentials in issues.
- This is a defensive **triage** utility. Political text, membership of
  third-party lists or author nationality must not be used as a malware verdict.
- Never submit live malicious payloads, harmful traffic generators, real
  credentials, private code, or material that you cannot redistribute.
  Use inert string fixtures to simulate unsafe patterns.
- The project is licensed under [Apache-2.0](LICENSE). By submitting a
  contribution, you confirm you have rights to contribute it under that license.
  Preserve copyright and license notices for third-party dependencies.

## Environment

Python 3.11+ is required. Create an isolated virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-ast.txt -r requirements-resolver.txt
python -c 'from tree_sitter_language_pack import download; download(["go","csharp","javascript","typescript","tsx","sql","html","css","scss","less","c","cpp"])'
python -m compileall -q .
python -m unittest discover -s tests -v
```

Scanning never downloads missing grammars automatically. Prefetch them during trusted
environment preparation; optional dependencies are necessary for the full test suite.
A passing run with skipped parser classes does not validate multilingual AST coverage.

On Windows, activate `.venv\Scripts\Activate.ps1` instead.

## What a good pull request contains

1. A narrow description of the rule, the intended threat model and the
   expected severity. Prefer evidence of **behavior** over rhetoric.
2. Positive and negative tests for every new rule, demonstrating the absence
   of false positives on ordinary code. Add pinned integration regressions
   when practical; **never execute the tested repository's code**.
3. A note about affected languages, AST grammar requirements, resource
   limits, and expected precision/recall trade-offs.
4. Documentation updates for changed CLI flags, JSON/SARIF properties,
   dependency formats or reporting behavior.
5. A passing full test run. Do not disable or silently bypass security checks.

## Coding and design requirements

- Favor the Python standard library for core scanning. Optional parser
  dependencies must be declared, pinned and reviewed.
- Scan target content as **data**, never import or invoke it. Do not install
  or execute packages from repositories under examination.
- Restrict remote fetches to explicitly supported HTTPS domains; enforce
  size, recursion, depth and request limits; prevent redirect/SSRF abuse.
- Preserve the separation between contextual indicators, uncertain heuristics
  and confirmed executable behavior. The JSON risk rating is not a verdict.
- Fail clearly if AST or dependency coverage is incomplete, especially in
  `--ast-mode required` and `--dependency-strict`.
- Treat report excerpts as potentially confidential. No raw secret values
  should be logged by tests, workflows, or error handling.

## Workflow

Create a topic branch from `main`, make focused changes and run tests locally.
Open a pull request explaining the change and its safety implications.
A maintainer reviews the behavior, CI results, documentation and licensing
before merging. If a rule affects watchlist scoring, include examples
distinguishing a mention of a repository from malicious activity.

## Security findings

Report vulnerabilities in *this analyzer* through the private channel in
[SECURITY.md](SECURITY.md). For vulnerabilities in third-party packages,
contact those package maintainers through their private reporting channel.


## CI checks and documentation

`tests.yml` runs unit tests on pushes and pull requests. `pinned-regression.yml`
runs on main pushes, pull requests and manual dispatch; it checks the pinned
third-party sources as data only. `secret-history-scan.yml` checks fetched Git
history. `malware-advisory-smoke.yml` uses public API metadata and runs on
manual dispatch or pushes to `feature/malware-advisory-feeds-20261109`, not
on pushes to `main`.
See [release checklist](docs/RELEASE_CHECKLIST.md) for tag/release behavior.

For documentation changes, compare flags and defaults with `--help`, verify
relative Markdown links, and run the existing documentation/release checks.
Mark historical review results with their date and commit rather than implying
that they certify later versions.

Current development documentation covers 1.3.0 (unreleased). Keep the
[documentation index](docs/README.md), user guide, security support line, changelog
and release procedure consistent with `VERSION`. Do not create or publish a release
as a side effect of a documentation update.

`tests.yml` also runs a real Go listing round-trip on our own benign fixture and
two separate corpus evaluations. The 48-case regression gates on FP/FN. The
12-case external evaluation records FP/FN in report-only mode; parser errors
still fail. Retain source revisions, fragment hashes and third-party licenses.
When tuning a rule against an external example, move that example to regression
and add fresh evaluation data; do not report the tuned example as unseen evidence.
See the [corpus method](tests/corpus/README.md) and [open tasks](docs/ROADMAP.md).
