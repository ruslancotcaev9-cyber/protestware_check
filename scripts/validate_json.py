"""Validate a JSON artifact against bundled contracts without network access."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import json_contracts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=sorted(json_contracts.SCHEMAS))
    parser.add_argument('path', type=Path)
    parser.add_argument('--allow-legacy-report', action='store_true',
                        help='accept schemaless 1.3.0-1.3.2 reports; never rewrites the input')
    args = parser.parse_args(argv)
    if args.allow_legacy_report and args.kind != 'report':
        parser.error('--allow-legacy-report is only valid for report')
    try:
        value = json_contracts.load(args.path, args.kind)
        json_contracts.validate(value, args.kind, allow_legacy_report=args.allow_legacy_report)
    except (ValueError, OSError, RecursionError) as error:
        message = str(error) if isinstance(error, ValueError) else type(error).__name__
        print(f'JSON validation failed: {message}', file=sys.stderr)
        return 2
    print(f'Valid {args.kind} contract')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
