"""Prepare pinned external inputs, validate review, or score the reviewed GEO_ACTION cohort."""
import argparse
import base64
from hashlib import sha1, sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import corpus_evaluation
import corpus_review
import json_contracts
import protestware_check as scanner
import safe_io

MANIFEST = ROOT / 'tests/corpus/geo-v1.json'
REVIEW = ROOT / 'tests/corpus/geo-v1-review.json'
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
        blob = scanner.api_json(url, None)
        if blob.get('encoding') != 'base64' or blob.get('size', LIMIT + 1) > LIMIT:
            raise ValueError(f"Unexpected upstream blob: {case['id']}")
        raw = verified(base64.b64decode(''.join(blob['content'].split()), validate=True), case)
        if len(raw) > LIMIT:
            raise ValueError('Source exceeds size limit')
        with target.open('xb') as stream:
            stream.write(raw)


def evaluate(document, sources, review, checksum):
    if review['status'] != 'claimed-complete':
        raise ValueError('Independent review pending or disputed; no detector run')
    current = (ROOT / 'tests/corpus/current-scanner-sha256.json').read_bytes()
    if sha256(current).hexdigest() != document['detector_manifest_sha256']:
        raise ValueError('Use the scanner revision frozen for this cohort')
    for filename, digest in json.loads(current).items():
        if sha256((ROOT / filename).read_bytes()).hexdigest() != digest:
            raise ValueError('Scanner files differ from the frozen manifest')
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
                      'operation_scope': entry['scope'], 'cohort': 'external-geo-v1',
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
    report.update(manifest_sha256=checksum, detector_manifest_sha256=document['detector_manifest_sha256'],
                  review=review, original_source_lines=locations)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'review', 'evaluate'))
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
        summary = corpus_review.load(REVIEW, doc['cases'], checksum)
        if args.action == 'review':
            print(json.dumps(summary, ensure_ascii=False))
            return 0
        if not args.sources or not args.output:
            parser.error('evaluate requires --sources and a new --output file')
        report = evaluate(doc, args.sources, summary, checksum)
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
