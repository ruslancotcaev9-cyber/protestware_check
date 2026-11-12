"""Rule-specific metrics on labeled inert source strings; never execute fixtures."""
from collections import defaultdict
from hashlib import sha256
from pathlib import PurePosixPath
import statistics
import time
import tracemalloc
import textwrap
import re

import protestware_check as scanner
import safe_io
import json_contracts


def load_document(path):
    raw = safe_io.read_regular(path, 2_000_000)
    data = json_contracts.loads(raw)
    if not isinstance(data, dict) or type(data.get('schema')) is not int or data['schema'] != 1 or not isinstance(data.get('cases'), list) or len(data['cases']) > 1000:
        raise ValueError('Invalid corpus schema/size')
    seen = set()
    for case in data['cases']:
        if (not isinstance(case, dict) or any(not isinstance(case.get(key), str) or not case[key] for key in ('id', 'language', 'path', 'rule', 'code')) or
                type(case.get('positive')) is not bool or len(case['code']) > 100000 or case['id'] in seen or
                not isinstance(case.get('allow_domains', []), list) or any(not isinstance(x, str) for x in case.get('allow_domains', []))):
            raise ValueError('Invalid or duplicate corpus case')
        seen.add(case['id'])
        if case.get('ast_mode', 'required') not in ('auto', 'required'):
            raise ValueError('Invalid corpus AST mode')
        for field in ('cohort', 'operation_scope'):
            if field in case and (not isinstance(case[field], str) or not re.fullmatch(r'[a-z0-9-]{1,64}', case[field])):
                raise ValueError('Invalid corpus grouping')
        provenance = case.get('provenance')
        if provenance is not None:
            if (not isinstance(provenance, dict) or not isinstance(provenance.get('fragment'), str) or
                    any(not isinstance(provenance.get(key), str) for key in ('prefix', 'suffix', 'fragment_sha256')) or
                    sha256(provenance['fragment'].encode()).hexdigest() != provenance['fragment_sha256'] or
                    provenance['prefix'] + textwrap.dedent(provenance['fragment'].replace('\r\n', '\n')) + provenance['suffix'] != case['code']):
                raise ValueError('Corpus fragment provenance/content mismatch')
            if (any(not isinstance(provenance.get(key), str) or not provenance[key] for key in ('repository', 'revision', 'path', 'git_blob_sha')) or
                    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}', provenance['repository']) or
                    not re.fullmatch(r'[a-f0-9]{40}', provenance['revision']) or
                    not re.fullmatch(r'[a-f0-9]{40}', provenance['git_blob_sha']) or
                    provenance['path'].startswith('/') or '\\' in provenance['path'] or '..' in PurePosixPath(provenance['path']).parts):
                raise ValueError('Invalid corpus source identity')
            if (type(provenance.get('first_line')) is not int or type(provenance.get('last_line')) is not int or
                    not 1 <= provenance['first_line'] <= provenance['last_line'] <= 10_000_000):
                raise ValueError('Invalid corpus source lines')
    return data, sha256(raw).hexdigest()


def load(path):
    return load_document(path)[0]['cases']


def _metrics(counts):
    tp, fp, tn, fn = (counts.get(key, 0) for key in ('tp', 'fp', 'tn', 'fn'))
    return {**{key: counts.get(key, 0) for key in ('tp', 'fp', 'tn', 'fn', 'errors')},
            'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'false_positive_rate': fp / (fp + tn) if fp + tn else None}


def evaluate(cases, *, measure=False, scan=None):
    scan = scan or scanner.scan_text
    groups = defaultdict(lambda: defaultdict(int))
    repositories, cohorts, scopes, modes, analysis_groups = [defaultdict(lambda: defaultdict(int)) for _ in range(5)]
    analysis_counts = defaultdict(int)
    total = defaultdict(int)
    details, durations = [], []
    if measure:
        tracemalloc.start()
    try:
        for case in cases:
            start = time.perf_counter()
            group = groups[(case['language'], case['rule'])]
            stats, warnings = {}, []
            mode = case.get('ast_mode', 'required')
            repository = (case.get('provenance') or {}).get('repository')
            cohort = case.get('cohort', 'unspecified')
            scope = case.get('operation_scope', 'unspecified')
            try:
                findings = scan(case['path'], case['code'], [], case.get('allow_domains', []),
                                ast_mode=mode, ast_stats=stats, ast_warnings=warnings)
                if stats.get('degraded'):
                    raise scanner.ScanError('AST backend unavailable or source syntax unsupported; evaluation incomplete')
                detected = any(item['rule'] == case['rule'] for item in findings)
                outcome = ('tp' if detected else 'fn') if case['positive'] else ('fp' if detected else 'tn')
                detail = {'id': case['id'], 'outcome': outcome, 'detected': detected,
                          'matching_analyses': sorted({item.get('analysis', 'text-heuristic') for item in findings if item['rule'] == case['rule']})}
            except (scanner.ScanError, ValueError, RecursionError) as error:
                outcome = 'errors'
                detail = {'id': case['id'], 'outcome': outcome, 'diagnostic': str(error)}
            ast_status = next((key for key in ('degraded', 'partial', 'parsed', 'disabled') if stats.get(key)),
                              'error' if outcome == 'errors' else 'not-reported')
            analysis_counts[ast_status] += 1
            detail.update(expected_positive=case['positive'], repository=repository, cohort=cohort,
                          operation_scope=scope, ast={'mode': mode, 'status': ast_status, 'warnings': warnings})
            if repository is not None:
                repositories[repository][outcome] += 1
            cohorts[cohort][outcome] += 1
            scopes[scope][outcome] += 1
            modes[mode][outcome] += 1
            analysis_groups[ast_status][outcome] += 1
            duration = time.perf_counter() - start
            durations.append(duration)
            group[outcome] += 1
            total[outcome] += 1
            details.append(detail)
        peak = tracemalloc.get_traced_memory()[1] if measure else None
    finally:
        if measure:
            tracemalloc.stop()
    groups_of_source = {c['provenance'].get('group', c['provenance']['repository'] + ':' + c['provenance']['path'])
                        for c in cases if c.get('provenance')}
    return {'schema': 1, 'tool_version': scanner.VERSION, 'cases': len(cases),
            'source_groups': len(groups_of_source),
            'whole_file_cases': sum(bool((c.get('provenance') or {}).get('whole_file')) for c in cases),
            'repositories': len(repositories),
            'metrics_valid': not bool(total['errors']), 'overall': _metrics(total),
            'by_language_and_rule': [{'language': key[0], 'rule': key[1], **_metrics(value)} for key, value in sorted(groups.items())],
            'by_repository': [{'repository': key, **_metrics(value)} for key, value in sorted(repositories.items())],
            'by_cohort': [{'cohort': key, **_metrics(value)} for key, value in sorted(cohorts.items())],
            'by_operation_scope': [{'scope': key, **_metrics(value)} for key, value in sorted(scopes.items())],
            'by_ast_mode': [{'mode': key, **_metrics(value)} for key, value in sorted(modes.items())],
            'by_ast_status': [{'status': key, **_metrics(value)} for key, value in sorted(analysis_groups.items())],
            'analysis': {'by_status': dict(sorted(analysis_counts.items())),
                         'complete': not total['errors'] and analysis_counts.get('parsed', 0) == len(cases),
                         'successful_fraction': (len(cases) - total['errors']) / len(cases) if cases else None,
                         'partial_cases': analysis_counts.get('partial', 0)},
            'performance': {'measured': measure, 'elapsed_seconds': sum(durations),
                            'median_case_seconds': statistics.median(durations) if durations else 0,
                            'peak_traced_python_bytes': peak}, 'results': details}


def status(report, *, report_only=False):
    return 2 if report['overall']['errors'] else int(not report_only and bool(report['overall']['fp'] or report['overall']['fn']))
