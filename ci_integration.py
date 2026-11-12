"""Prepare GitLab artifacts and carry the scanner's gate outcome to a separate job."""
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile

import protestware_check as scanner
import report_formats
import safe_io
import json_contracts


def _report(path):
    raw = safe_io.read_regular(path, 25_000_000)
    report = json_contracts.report_version(json_contracts.loads(raw), allow_legacy=True)
    if (not isinstance(report, dict) or report.get('tool') != 'protestware-check' or
            not isinstance(report.get('findings'), list) or not isinstance(report.get('scan'), dict) or
            not isinstance(report.get('gate'), dict) or type(report['gate'].get('exit_code')) is not int or
            report['gate']['exit_code'] not in (0, 1, 2)):
        raise ValueError('Invalid scanner JSON report')
    json_contracts.report_semantics(report)
    return raw, report


def scan(source, output_dir, scanner_args=()):
    """Run trusted scanner code only; the source is passed as data to main()."""
    directory = Path(output_dir)
    directory.mkdir(mode=0o700, exist_ok=False)
    status = {'schema': 1, 'scanner_exit_code': 2, 'report_available': False, 'report_sha256': None}
    try:
        with tempfile.TemporaryDirectory(prefix='protestware-ci-') as folder:
            target = Path(folder, 'report.json')
            try:
                code = scanner.main(['--path', str(source), *scanner_args, '--format', 'json', '--output', str(target)])
            except SystemExit as error:
                code = error.code if type(error.code) is int else 2
            if code not in (0, 1, 2) or not target.is_file():
                raise ValueError('Scanner did not produce a fresh JSON report')
            raw, report = _report(target)
            if report['gate']['exit_code'] != code:
                raise ValueError('Scanner exit code differs from the report gate')
            safe_io.atomic_write(directory / 'report.json', raw.decode('utf-8'))
            safe_io.atomic_write(directory / 'findings.sarif', json.dumps(report_formats.sarif(report, gitlab=True), ensure_ascii=False, indent=2) + '\n')
            status.update(scanner_exit_code=code, report_available=True, report_sha256=sha256(raw).hexdigest())
    except (ValueError, OSError, UnicodeError, RecursionError) as error:
        print(f'CI report preparation failed: {error}', file=sys.stderr)
    finally:
        safe_io.atomic_write(directory / 'status.json', json.dumps(status, indent=2) + '\n')
    # A valid report can be ingested even with findings/incomplete analyses. The
    # gate job must be required; scanner failures without a report fail here too.
    return 0 if status['report_available'] else 2


def gate(directory):
    directory = Path(directory)
    try:
        status = json_contracts.load(directory / 'status.json', 'gitlab-status')
        if (not isinstance(status, dict) or type(status.get('schema')) is not int or status['schema'] != 1 or
                type(status.get('scanner_exit_code')) is not int or status['scanner_exit_code'] not in (0, 1, 2) or
                type(status.get('report_available')) is not bool):
            raise ValueError('Invalid CI status artifact')
        if not status['report_available']:
            return 2
        raw, report = _report(directory / 'report.json')
        if sha256(raw).hexdigest() != status.get('report_sha256') or report['gate']['exit_code'] != status['scanner_exit_code']:
            raise ValueError('CI report/status digest or exit code mismatch')
        return status['scanner_exit_code']
    except (ValueError, OSError, UnicodeError, RecursionError, KeyError) as error:
        print(f'CI gate failed: {error}', file=sys.stderr)
        return 2
