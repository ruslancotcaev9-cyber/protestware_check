"""Evaluate labeled source strings without importing or running them."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import corpus_evaluation
import corpus_review
import safe_io


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=Path(__file__).resolve().parents[1] / 'tests/corpus/cases.json')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--measure', action='store_true')
    parser.add_argument('--report-only', action='store_true', help='Record FP/FN without failing the gate; analysis errors still fail')
    parser.add_argument('--review-file', type=Path, help='Explicit checksum-bound candidate-label review ledger')
    args = parser.parse_args(argv)
    try:
        if args.output and args.output.resolve() in {p.resolve() for p in (args.corpus, args.review_file) if p is not None}:
            raise ValueError('Corpus input and output must differ')
        metadata, checksum = corpus_evaluation.load_document(args.corpus)
        review = corpus_review.load(args.review_file, metadata['cases'], checksum) if args.review_file else None
        report = corpus_evaluation.evaluate(metadata['cases'], measure=args.measure)
        report['suite'] = {key: metadata[key] for key in ('suite', 'detector_reference_commit', 'label_scope', 'review', 'policy', 'sampling', 'parent_corpus_sha256') if key in metadata}
        report['evaluation_mode'] = 'report-only' if args.report_only else 'regression-gate'
        report['corpus_sha256'] = checksum
        if review is not None:
            report['label_review'] = review
        text = json.dumps(report, indent=2) + '\n'
        if args.output:
            safe_io.atomic_write(args.output, text)
        print(json.dumps({key: report[key] for key in ('cases', 'metrics_valid', 'overall', 'analysis', 'performance')}))
        for result in report['results']:
            if result['outcome'] in {'errors', 'fp', 'fn'}:
                print('CORPUS_CASE=' + json.dumps(result))
        return corpus_evaluation.status(report, report_only=args.report_only)
    except (ValueError, OSError, UnicodeError, RecursionError) as error:
        print(f'Corpus evaluation failed: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
