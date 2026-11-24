"""Prepare, reproduce or compare the six pinned GEO_ACTION cases without executing them."""
import argparse
import base64
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import analysis_context
import corpus_evaluation
import corpus_review
import json_contracts
import protestware_check as scanner
import safe_io

MANIFEST = ROOT / 'tests/corpus/geo-v1.json'
REVIEW = ROOT / 'tests/corpus/geo-v1-review.json'
AUTHOR_DECISION = ROOT / 'tests/corpus/geo-v1-author-decision.json'
FROZEN_SCANNER = ROOT / 'tests/corpus/geo-v1-scanner-sha256.json'
CURRENT_SCANNER = ROOT / 'tests/corpus/current-scanner-sha256.json'
REFERENCE = ROOT / 'docs/evaluation/geo-v1-author-2026-11-21'
LIMIT = 1_000_000


def verified(raw, case):
    blob = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if blob != case['git_blob_sha'] or sha256(raw).hexdigest() != case['source_sha256']:
        raise ValueError(f"Source checksum mismatch: {case['id']}")
    return raw


def prepare(cases, directory):
    directory.mkdir(exist_ok=True, parents=True)
    for case in cases:
        target = directory / (case['id'] + '.py')
        if target.exists():
            verified(safe_io.read_regular(target, LIMIT), case)
            continue
        url = f"https://api.github.com/repos/{case['repository']}/git/blobs/{case['git_blob_sha']}"
        blob = scanner.api_json(url, os.environ.get('GITHUB_TOKEN'))
        if blob.get('encoding') != 'base64' or blob.get('size', LIMIT + 1) > LIMIT:
            raise ValueError(f"Unexpected upstream blob: {case['id']}")
        raw = verified(base64.b64decode(''.join(blob['content'].split()), validate=True), case)
        if len(raw) > LIMIT:
            raise ValueError('Source exceeds size limit')
        with target.open('xb') as stream:
            stream.write(raw)


def read_author_decision():
    decision = json_contracts.loads(safe_io.read_regular(AUTHOR_DECISION, 20_000))
    if (not isinstance(decision, dict) or type(decision.get('schema')) is not int or decision['schema'] != 1
            or decision.get('evaluation_mode') != 'author-regression'
            or decision.get('reviewer_role') != 'cohort-contributor'
            or decision.get('label_decision') != 'accepted-as-proposed'
            or decision.get('independent_review') is not False
            or decision.get('eligible_for_first_blind_evaluation') is not False
            or not isinstance(decision.get('manifest_sha256'), str)):
        raise ValueError('Invalid author assessment decision')
    return decision


def score_cases(document, sources, checksum, cohort, *, detector_manifest=FROZEN_SCANNER):
    manifest_bytes = detector_manifest.read_bytes()
    detector_digest = sha256(manifest_bytes).hexdigest()
    if detector_manifest == FROZEN_SCANNER and detector_digest != document['detector_manifest_sha256']:
        raise ValueError('Use the scanner revision frozen for this cohort')
    files = json_contracts.loads(manifest_bytes)
    if detector_manifest == CURRENT_SCANNER:
        expected = set(analysis_context.RULE_FILES) | {
            'safe_io.py', 'requirements-ast.txt', 'requirements-resolver.txt', 'scan_coverage.py', 'report_formats.py'}
        if set(files) != expected:
            raise ValueError('Current detector manifest does not cover the scanner files')
    for filename, digest in files.items():
        if sha256((ROOT / filename).read_bytes()).hexdigest() != digest:
            raise ValueError(f'Scanner file differs from {detector_manifest.name}: {filename}')
    cases = []
    by_path = {}
    for entry in document['cases']:
        raw = verified(safe_io.read_regular(sources / (entry['id'] + '.py'), LIMIT), entry)
        lines = raw.decode('utf-8-sig').splitlines(keepends=True)
        start, stop = entry['first'], entry['last']
        if not 1 <= start <= stop <= len(lines):
            raise ValueError('Invalid source interval')
        path = entry['repository'] + '/' + entry['path']
        by_path[path] = entry
        cases.append({**entry, 'path': path, 'code': ''.join(lines[start-1:stop]),
                      'language': 'Python', 'rule': 'GEO_ACTION', 'ast_mode': 'required',
                      'operation_scope': entry['scope'], 'cohort': cohort,
                      'provenance': {'repository': entry['repository'], 'path': entry['path']}})

    locations = {}
    def score(path, *args, **kwargs):
        findings = scanner.scan_text(path, *args, **kwargs)
        case = by_path[path]
        lines = {f['line'] + case['first'] - 1 for f in findings if f['rule'] == 'GEO_ACTION'}
        expected = set(case['evidence_lines'])
        locations[case['id']] = {'reported': sorted(lines), 'outside_reviewed_evidence': sorted(lines - expected)}
        if case['positive']:
            return [f for f in findings if f['line'] + case['first'] - 1 in expected]
        return findings

    report = corpus_evaluation.evaluate(cases, scan=score)
    report.update(manifest_sha256=checksum, detector_manifest_sha256=detector_digest,
                  original_source_lines=locations)
    return report


def evaluate(document, sources, review, checksum):
    if review['status'] != 'claimed-complete':
        raise ValueError('Independent review pending or disputed; no detector run')
    if read_author_decision()['manifest_sha256'] == checksum:
        raise ValueError('Cohort designated for author regression; use fresh cases for a first blind measurement')
    report = score_cases(document, sources, checksum, 'external-geo-v1')
    report['review'] = review
    return report


def evaluate_author(document, sources, checksum, *, detector_manifest=FROZEN_SCANNER):
    decision = read_author_decision()
    if decision['manifest_sha256'] != checksum:
        raise ValueError('Author assessment decision does not cover this manifest')
    report = score_cases(document, sources, checksum, 'author-geo-v1', detector_manifest=detector_manifest)
    report.update(evaluation_mode='author-regression', review=decision)
    return report


def checkout_state(paths):
    """Identify the trusted scanner checkout, including uncommitted evaluation inputs."""
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=ROOT, timeout=10,
                                       stderr=subprocess.DEVNULL, text=True)

    try:
        top, commit = git('rev-parse', '--show-toplevel', 'HEAD').splitlines()
        if Path(top).resolve() == ROOT:
            changed = git('status', '--porcelain', '--untracked-files=all', '--', *paths)
            return {'checkout_commit': commit, 'worktree_status': 'modified' if changed else 'clean'}
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return {'checkout_commit': None, 'worktree_status': 'unavailable'}


def compare(document, sources, checksum):
    original_bytes = (REFERENCE / 'geo-author-first.json').read_bytes()
    original_sha = sha256(original_bytes).hexdigest()
    checks = json_contracts.loads((REFERENCE / 'repeat-check.json').read_bytes())
    baseline = json_contracts.loads(original_bytes)
    provenance = json_contracts.loads((REFERENCE / 'provenance.json').read_bytes())
    if (original_sha != checks['first_sha256'] or baseline['manifest_sha256'] != checksum
            or provenance['manifest_sha256'] != checksum
            or baseline['detector_manifest_sha256'] != document['detector_manifest_sha256']
            or provenance['detector_manifest_sha256'] != baseline['detector_manifest_sha256']):
        raise ValueError('Reference report does not match the pinned author evaluation')

    report = evaluate_author(document, sources, checksum, detector_manifest=CURRENT_SCANNER)
    before = {item['id']: item for item in baseline['results']}
    after = {item['id']: item for item in report['results']}
    cases = []
    for entry in document['cases']:
        case_id = entry['id']
        cases.append({
            'id': case_id, 'source_sha256': entry['source_sha256'], 'expected_lines': entry['evidence_lines'],
            'before': {'outcome': before[case_id]['outcome'], 'ast_status': before[case_id]['ast']['status'],
                       'reported': baseline['original_source_lines'][case_id]['reported']},
            'after': {'outcome': after[case_id]['outcome'], 'ast_status': after[case_id]['ast']['status'],
                      'reported': report['original_source_lines'].get(case_id, {}).get('reported')},
        })
    manifest_bytes = CURRENT_SCANNER.read_bytes()
    if sha256(manifest_bytes).hexdigest() != report['detector_manifest_sha256']:
        raise ValueError('Detector manifest changed during evaluation')
    rules = json_contracts.loads(manifest_bytes)
    scoring_files = ['scripts/evaluate_geo.py', 'corpus_evaluation.py']
    tracked = [*rules, *scoring_files, CURRENT_SCANNER, MANIFEST, AUTHOR_DECISION, REFERENCE]
    report['comparison'] = {
        'reference': {'report_sha256': original_sha, 'scanner_commit': provenance['scanner_commit'],
                      'detector_manifest_sha256': baseline['detector_manifest_sha256'],
                      'overall': baseline['overall'], 'analysis': baseline['analysis']},
        'candidate': {**checkout_state(tracked), 'python': sys.version.split()[0], 'detector_files': rules,
                      'scoring_files': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in scoring_files}},
        'cases': cases,
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'review', 'evaluate', 'evaluate-author', 'compare'))
    parser.add_argument('--sources', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    raw = MANIFEST.read_bytes()
    doc, checksum = json_contracts.loads(raw), sha256(raw).hexdigest()
    try:
        if args.action == 'prepare':
            if not args.sources:
                parser.error('prepare requires --sources DIRECTORY')
            prepare(doc['cases'], args.sources)
            return 0
        if args.action == 'review':
            print(json.dumps(corpus_review.load(REVIEW, doc['cases'], checksum), ensure_ascii=False))
            return 0
        if not args.sources or not args.output:
            parser.error(f'{args.action} requires --sources and a new --output file')
        if args.action == 'compare':
            report = compare(doc, args.sources, checksum)
        elif args.action == 'evaluate-author':
            report = evaluate_author(doc, args.sources, checksum)
        else:
            report = evaluate(doc, args.sources, corpus_review.load(REVIEW, doc['cases'], checksum), checksum)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
        print(json.dumps(report['overall']))
        return corpus_evaluation.status(report, report_only=True)
    except (OSError, ValueError, scanner.ScanError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
