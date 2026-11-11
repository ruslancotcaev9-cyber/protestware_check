"""Evaluate labeled source strings without importing or running them."""
import argparse
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
    args = parser.parse_args()
    try:
        if args.output and args.output.resolve() == args.corpus.resolve():
            raise ValueError('Corpus input and output must differ')
        report = corpus_evaluation.evaluate(corpus_evaluation.load(args.corpus), measure=args.measure)
        text = json.dumps(report, indent=2) + '\n'
        if args.output:
            safe_io.atomic_write(args.output, text)
        print(json.dumps({key: report[key] for key in ('cases', 'metrics_valid', 'overall', 'performance')}))
        return corpus_evaluation.status(report)
    except (ValueError, OSError, UnicodeError, RecursionError) as error:
        print(f'Corpus evaluation failed: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
