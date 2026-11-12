# Release checklist

**Status on 2026-11-12:** the repository is public, the code in `main`
reports `1.4.0` (unreleased), and no GitHub Releases were returned by the release listing.
Repository visibility, the version constant, a Git tag and a published GitHub
Release are distinct. `release.yml` creates a **draft** only; it does not change
repository visibility. `docs/releases/v1.0.0.md` is a historical candidate note,
not evidence of a published release.

[Documentation index](README.md) · [1.4.0 development notes](releases/v1.4.0.md).

## Before each release

- [ ] Confirm redistribution rights and licenses for code, fixtures and documents.
- [ ] Verify the monitored security contact/triage owner and the availability of
      GitHub Private vulnerability reporting; the policy link alone does not enable it.
- [ ] Review repository permissions, branch protection, workflows and credentials.
- [ ] Run the entire reachable Git history secret scan, including fetched branches
      and tags. Review failures privately; revoke/rotate exposed credentials.
      Deleting a file does not remove it from Git history.
- [ ] Check issue/PR content, previous artifacts and releases separately: Git
      history scanning does not cover them.
- [ ] Run unit tests with resolver dependencies and pre-cached AST grammars;
      verify no unexpected skips. Run the pinned behavioral regression and the
      optional live malware-advisory smoke test when applicable.
- [ ] Verify the real Go export/import job. Review all three corpus artifacts:
      strict regression FP/FN block the gate; external evaluation records FP/FN
      without blocking, while fatal/degraded evaluation errors still block.
      Inspect auto-mode partial/syntax-recovery diagnostics separately. Review
      known misses and the candidate-label ledger; do not call pending labels
      independently verified. See docs/CORPUS_REVIEW_GUIDE.md.
- [ ] Check baseline schema 2 migration and Go producer trust/profile limits;
      confirm that examples pin an existing reviewed scanner commit.
- [ ] Validate JSON schemas and frozen compatibility fixtures with
      requirements-contracts.txt installed; confirm no contract test skips.
      Review any format-version change and migration instructions.
- [ ] Review README, CLI reference, changelog, version and release-specific notes.
- [ ] Confirm that the exact release commit passed the required checks.

## Release procedure

1. Integrate reviewed changes into `main` and wait for CI. Preserve unrelated work.
2. Choose the intended release version. Match the literal `VERSION` in
   `protestware_check.py`, the changelog and the release notes to that version.
   Do not tag current 1.4.0 code as v1.0.0 or another mismatched version.
3. From a trusted clean checkout of the reviewed commit, create an annotated
   tag in `vMAJOR.MINOR.PATCH` form. For example, **only when 1.4.0 is approved**:

   ```bash
   git tag -a v1.4.0 -m 'protestware-check v1.4.0'
   git push origin v1.4.0
   ```

   Do not move an existing release tag or tag a commit with outstanding gates.
4. A tag push starts `release.yml`. It verifies that the commit belongs to
   `main`, checks tag/version equality, runs tests and secret scanning, then
   builds the source ZIP and SHA256SUMS and creates a draft release.
   A manual workflow run performs verification only; it does not create a release.
5. Review archive, checksum, source SHA and notes in the draft. The workflow
   uses `docs/releases/v1.0.0.md` only for tag v1.0.0; for other tags it generates
   notes automatically. For v1.4.0, copy the reviewed content of
   `docs/releases/v1.4.0.md` into the draft and update its unreleased status only
   as part of the approved release. The workflow does not automatically select
   that file. Review migration notes and limitations before manually publishing.
6. Monitor private vulnerability reports and issues after publication.

## History scanning on developer workstations

The CI installer pins Gitleaks v8.30.1 and checks the Linux x86_64 archive's
SHA-256. On that platform:

```bash
bash scripts/install_gitleaks.sh /tmp/protestware-security-bin
git fetch --all --tags --prune
/tmp/protestware-security-bin/gitleaks git --redact --log-opts='--all' \
  --report-format=json --report-path=/secure/reports/gitleaks-private.json .
```

Create a private report directory first and adapt the paths. On other platforms
use an independently verified Gitleaks installation. The bootstrap does not
support Windows/macOS. Keep detailed logs and JSON private. CI emits only
PASS or REVIEW REQUIRED and suppresses raw findings; a clean scan is not proof
that no secrets exist.
