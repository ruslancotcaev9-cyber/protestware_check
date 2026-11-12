"""Prepare or validate proposed-label review files; never approve labels automatically."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import corpus_evaluation
import corpus_review


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('prepare', 'validate'):
        command = commands.add_parser(name)
        command.add_argument('--corpus', type=Path, required=True)
        if name == 'prepare':
            command.add_argument('--output', type=Path, required=True)
            command.add_argument('--worksheet', type=Path)
        else:
            command.add_argument('--review', type=Path, required=True)
            command.add_argument('--require-complete', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'prepare':
            corpus_review.prepare_files(args.corpus, args.output, args.worksheet)
            print('Prepared pending labels; independent review is still required')
            return 0
        document, checksum = corpus_evaluation.load_document(args.corpus)
        summary = corpus_review.load(args.review, document['cases'], checksum)
        print('Corpus label review: ' + summary['status'])
        return int(args.require_complete and summary['status'] != 'claimed-complete')
    except (ValueError, OSError, UnicodeError, RecursionError) as error:
        print(f'Corpus review failed: {type(error).__name__}: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
