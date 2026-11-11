"""Evaluate labeled source strings without importing or running them."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import corpus_evaluation
import safe_io


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=Path(__file__).resolve().parents[1] / 'tests/corpus/cases.json')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--measure', action='store_true')
    parser.add_argument('--report-only', action='store_true', help='Record FP/FN without failing the gate; analysis errors still fail')
    args = parser.parse_args()
    try:
        if args.output and args.output.resolve() == args.corpus.resolve():
            raise ValueError('Corpus input and output must differ')
        report = corpus_evaluation.evaluate(corpus_evaluation.load(args.corpus), measure=args.measure)
        metadata = json.loads(safe_io.read_regular(args.corpus, 2_000_000))
        report['suite'] = {key: metadata[key] for key in ('suite', 'detector_reference_commit', 'label_scope', 'review', 'policy') if key in metadata}
        report['evaluation_mode'] = 'report-only' if args.report_only else 'regression-gate'
        report['corpus_sha256'] = sha256(safe_io.read_regular(args.corpus, 2_000_000)).hexdigest()
        text = json.dumps(report, indent=2) + '\n'
        if args.output:
            safe_io.atomic_write(args.output, text)
        print(json.dumps({key: report[key] for key in ('cases', 'metrics_valid', 'overall', 'performance')}))
        for result in report['results']:
            if result['outcome'] in {'errors', 'fp', 'fn'}:
                print('CORPUS_CASE=' + json.dumps(result))
        return corpus_evaluation.status(report, report_only=args.report_only)
    except (ValueError, OSError, UnicodeError, RecursionError) as error:
        print(f'Corpus evaluation failed: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
