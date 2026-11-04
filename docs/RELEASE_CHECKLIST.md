# Pre-publication and release checklist

**Status:** `v1.0.0` candidate; creating a tag does not automatically make a
private repository public. The release workflow creates a **draft** GitHub
Release, not a publicly published release.

## Before the first public release

- [ ] Confirm permissions to open-source every source file, test fixture,
      third-party extract and authored document under Apache-2.0.
- [ ] Assign an actual security contact/triage owner. Enable and test GitHub
      **Private vulnerability reporting** before making the repo public.
- [ ] Review repository and GitHub Actions permissions, branch protection,
      workflow dependencies and any external credentials.
- [ ] Run the **entire reachable Git history** secret scan, including all
      fetched branches/tags (Gitleaks `git --log-opts=--all`). Review failures
      privately; rotate and revoke **exposed** credentials before publishing.
      Merely deleting a secret from the working tree does not remove history.
- [ ] If sensitive data exists in history, coordinate rotation and Git history
      rewriting with affected collaborators; re-scan after cleanup.
- [ ] Inspect issue/PR history, releases, files, screenshots and past workflow
      artifacts for private data: **Git scanning alone does not cover them.**
- [ ] Complete tests, parser integration, both watchlists (as applicable) and
      negative control tests on pinned test repositories.
- [ ] Validate README, user guide, caveats, license, changelog, release notes,
      version number and `SECURITY.md` for public-facing accuracy.
- [ ] Decide and document which GitHub repository URL and default branch
      will be used after publication. Check for unrelated private commits.

## Release procedure

1. Merge the release-prep branch after green CI and secret-history scan.
2. Ensure the CLI and changelog version are `1.0.0` and current `main` is
   the reviewed source. Manually check `git status` and `git log`.
3. Review tag and main commit; create an annotated tag from a trusted local
   checkout using `git tag -a v1.0.0 -m 'protestware-check v1.0.0'`, then
   `git push origin v1.0.0`. **Do not create the tag if any gate remains open.**
4. GitHub Actions `release.yml` runs release gating, prepares a zip and
   `SHA256SUMS`, then creates a **draft** release using that pre-existing tag.
5. Verify archive checksum, notes, artifacts and source commit. Then manually
   make the repository public (only after the checklist is complete) and
   publish the GitHub Release from the UI. Publishing is a maintainer action.
6. Monitor private vulnerability submissions and user issues after publication.

## History scanning on developer workstations

The CI workflow pins Gitleaks **v8.30.1** and verifies SHA-256 of the Linux
binary. CI suppresses Gitleaks logs and fails closed; investigate detailed findings
privately on an authorized workstation. For a locally installed trusted Gitleaks binary use:

```bash
git fetch --all --tags --prune
gitleaks git --redact --log-opts='--all' --report-format=json \
  --report-path=local-gitleaks-private.json .
```

Treat the private JSON report as sensitive. Review it locally and do not
upload it to public issues or unprotected artifacts. The workflow suppresses
raw findings and only emits a sanitized count; a clean scan is not proof
that no secrets exist.
