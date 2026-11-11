"""Rule-specific metrics on labeled inert source strings; never execute fixtures."""
from collections import defaultdict
import json
from pathlib import Path
import statistics
import time
import tracemalloc

import protestware_check as scanner
import safe_io


def load(path):
    data = json.loads(safe_io.read_regular(path, 2_000_000))
    if not isinstance(data, dict) or data.get('schema') != 1 or not isinstance(data.get('cases'), list) or len(data['cases']) > 1000:
        raise ValueError('Invalid corpus schema/size')
    seen = set()
    for case in data['cases']:
        if (not isinstance(case, dict) or any(not isinstance(case.get(key), str) or not case[key] for key in ('id', 'language', 'path', 'rule', 'code')) or
                type(case.get('positive')) is not bool or len(case['code']) > 100000 or case['id'] in seen or
                not isinstance(case.get('allow_domains', []), list) or any(not isinstance(x, str) for x in case.get('allow_domains', []))):
            raise ValueError('Invalid or duplicate corpus case')
        seen.add(case['id'])
    return data['cases']


def _metrics(counts):
    tp, fp, tn, fn = (counts.get(key, 0) for key in ('tp', 'fp', 'tn', 'fn'))
    return {**{key: counts.get(key, 0) for key in ('tp', 'fp', 'tn', 'fn', 'errors')},
            'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'false_positive_rate': fp / (fp + tn) if fp + tn else None}


def evaluate(cases, *, measure=False, scan=None):
    scan = scan or scanner.scan_text
    groups = defaultdict(lambda: defaultdict(int))
    total = defaultdict(int)
    details, durations = [], []
    if measure:
        tracemalloc.start()
    try:
        for case in cases:
            start = time.perf_counter()
            group = groups[(case['language'], case['rule'])]
            try:
                findings = scan(case['path'], case['code'], [], case.get('allow_domains', []), ast_mode='required')
                detected = any(item['rule'] == case['rule'] for item in findings)
                outcome = ('tp' if detected else 'fn') if case['positive'] else ('fp' if detected else 'tn')
                detail = {'id': case['id'], 'outcome': outcome}
            except (scanner.ScanError, ValueError, RecursionError) as error:
                outcome = 'errors'
                detail = {'id': case['id'], 'outcome': outcome, 'diagnostic': str(error)}
            duration = time.perf_counter() - start
            durations.append(duration)
            group[outcome] += 1
            total[outcome] += 1
            details.append(detail)
        peak = tracemalloc.get_traced_memory()[1] if measure else None
    finally:
        if measure:
            tracemalloc.stop()
    return {'schema': 1, 'tool_version': scanner.VERSION, 'cases': len(cases),
            'metrics_valid': not bool(total['errors']), 'overall': _metrics(total),
            'by_language_and_rule': [{'language': key[0], 'rule': key[1], **_metrics(value)} for key, value in sorted(groups.items())],
            'performance': {'measured': measure, 'elapsed_seconds': sum(durations),
                            'median_case_seconds': statistics.median(durations) if durations else 0,
                            'peak_traced_python_bytes': peak}, 'results': details}


def status(report):
    return 2 if report['overall']['errors'] else int(bool(report['overall']['fp'] or report['overall']['fn']))
