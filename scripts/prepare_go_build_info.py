"""Normalize JSON from a trusted Go CI job; this helper never invokes Go."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import go_build_info
import safe_io


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--modules', type=Path, required=True)
    parser.add_argument('--packages', type=Path, required=True)
    parser.add_argument('--environment', type=Path, required=True)
    parser.add_argument('--tag', action='append', default=[])
    parser.add_argument('--target', action='append')
    parser.add_argument('--mod-mode', choices=('readonly', 'mod'), default='readonly')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-files', type=int, default=10000)
    parser.add_argument('--max-bytes', type=int, default=1_000_000)
    parser.add_argument('--max-total-bytes', type=int, default=100_000_000)
    args = parser.parse_args(argv)
    try:
        if any(value <= 0 for value in (args.max_files, args.max_bytes, args.max_total_bytes)):
            raise ValueError('Input budgets must be positive')
        root = args.source_root.resolve()
        inputs = (args.modules, args.packages, args.environment)
        if any(path.resolve().is_relative_to(root) for path in (*inputs, args.output)):
            raise ValueError('Store raw listings and the output outside --source-root')
        if args.output.resolve() in {path.resolve() for path in inputs}:
            raise ValueError('Go listing inputs and output must differ')
        data = go_build_info.export(args.source_root, args.source_revision, *inputs,
                                    tags=args.tag, targets=args.target or ['./...'], mod_mode=args.mod_mode,
                                    max_files=args.max_files, max_bytes=args.max_bytes,
                                    max_total_bytes=args.max_total_bytes)
        safe_io.atomic_write(args.output, json.dumps(data, indent=2, sort_keys=True) + '\n')
        print(f'Go build-info written: {len(data["inputs"])} inputs, {len(data["packages"])} packages')
        return 0
    except (ValueError, OSError, UnicodeError, TypeError, RecursionError) as error:
        print(f'Go build-info preparation failed: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
