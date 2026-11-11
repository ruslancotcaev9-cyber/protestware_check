"""Fresh GitLab artifacts; never import or execute the target project."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_integration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('scanner_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    values = args.scanner_args[1:] if args.scanner_args[:1] == ['--'] else args.scanner_args
    try:
        return ci_integration.scan(args.source, args.output_dir, values)
    except (OSError, ValueError) as error:
        print(f'CI report directory error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
