"""Versioned, offline JSON contracts. Input is data; no supplied schema is loaded."""
from collections import Counter
from datetime import datetime
from functools import lru_cache
import json
import math
from pathlib import Path
import re

import safe_io

REPORT_SCHEMA = 1
LEVELS = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
LIMITS = {'report': 25_000_000, 'baseline': 5_000_000,
          'go-build-info': 25_000_000, 'gitlab-status': 10_000}
SCHEMAS = {'report': 'report-v1.schema.json', 'baseline': 'baseline-v2.schema.json',
           'go-build-info': 'go-build-info-v1.schema.json',
           'gitlab-status': 'gitlab-status-v1.schema.json'}
LEGACY_REPORT = re.compile(r'1\.3\.[012]')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON member')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('Non-finite JSON number')


def _float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError('Non-finite JSON number')
    return result


def decoder():
    return json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)


def loads(raw):
    """Reject ambiguous JSON, non-finite numbers and excessive nesting/work."""
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant,
                           parse_float=_float)
    except (RecursionError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('Malformed or excessively nested JSON') from error
    pending, visited = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if depth > 64 or visited > 1_000_000:
            raise ValueError('JSON nesting/node budget exceeded')
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        pending.extend((child, depth + 1) for child in children)
    return value


def load(path, kind):
    if kind not in LIMITS:
        raise ValueError('Unknown JSON contract kind')
    return loads(safe_io.read_regular(path, LIMITS[kind]))


def report_version(document, *, allow_legacy=False):
    if not isinstance(document, dict) or document.get('tool') != 'protestware-check':
        raise ValueError('Invalid scanner JSON report')
    if not isinstance(document.get('version'), str) or not re.fullmatch(r'\d+\.\d+\.\d+', document['version']):
        raise ValueError('Invalid scanner version')
    if 'schema' in document:
        if type(document['schema']) is not int or document['schema'] != REPORT_SCHEMA:
            raise ValueError('Unsupported report schema')
        return document
    if allow_legacy and isinstance(document.get('version'), str) and LEGACY_REPORT.fullmatch(document['version']):
        return {**document, 'schema': REPORT_SCHEMA}
    raise ValueError('Report schema is required; legacy 1.3.0-1.3.2 needs explicit compatibility mode')


def report_semantics(document):
    """Check cross-field relations that JSON Schema cannot express."""
    try:
        findings, policy, gate = document['findings'], document['policy'], document['gate']
        if not isinstance(findings, list) or any(
                not isinstance(item, dict) or item.get('severity') not in LEVELS or
                item.get('effective_severity') not in LEVELS or
                item.get('policy_decision') not in {'active', 'baseline', 'suppressed', 'disabled'}
                for item in findings):
            raise ValueError('Invalid report finding decisions')
        if type(gate['exit_code']) is not int or gate['exit_code'] not in (0, 1, 2):
            raise ValueError('Invalid report gate code')
        if type(document['scan']['complete']) is not bool:
            raise ValueError('Invalid report scan completeness')
        counts = Counter(item['severity'] for item in findings)
        if any(type(document['summary'][level]) is not int or document['summary'][level] != counts[level] for level in LEVELS):
            raise ValueError('Report summary differs from findings')
        risk = max((item['severity'] for item in findings if item['severity'] != 'info'), key=LEVELS.__getitem__, default='none')
        active = [item['effective_severity'] for item in findings if item['policy_decision'] == 'active' and item['effective_severity'] != 'info']
        policy_risk = max(active, key=LEVELS.__getitem__, default='none')
        decisions = Counter(item['policy_decision'] for item in findings)
        if (document['risk'] != risk or policy['risk'] != policy_risk or
                any(type(policy['counts'][key]) is not int or policy['counts'][key] != decisions[key]
                    for key in ('active', 'baseline', 'suppressed', 'disabled'))):
            raise ValueError('Report risk/policy differs from findings')
        reasons = gate['reasons']
        if not isinstance(reasons, list) or any(not isinstance(item, str) or not item for item in reasons):
            raise ValueError('Invalid report gate reasons')
        if not document['scan']['complete'] and 'source_incomplete' not in reasons:
            raise ValueError('Incomplete source must block the gate')
        if document['files_scanned'] != document['coverage']['files_analyzed']:
            raise ValueError('Report file counts disagree')
        expected = 2 if reasons else int(LEVELS.get(policy_risk, 0) >= LEVELS[gate['fail_on']])
        if gate['exit_code'] != expected:
            raise ValueError('Report gate differs from risk/completeness')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Malformed scanner report contract') from error


@lru_cache(maxsize=5)
def _validator(filename):
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry
    except ImportError as error:
        raise ValueError('Install requirements-contracts.txt to validate JSON Schema') from error
    schema = loads(safe_io.read_regular(Path(__file__).resolve().parent / 'schemas' / filename, 500_000))
    Draft202012Validator.check_schema(schema)
    checker = FormatChecker(formats=[])

    @checker.checks('date-time', raises=ValueError)
    def date_time(value):
        if not isinstance(value, str):
            return True
        return bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', value)
                    and datetime.fromisoformat(value.upper().replace('Z', '+00:00')).tzinfo is not None)

    # The registry has no retriever. Schemas are bundled and contain local refs;
    # data-provided $schema/$ref members never select a schema or make requests.
    return Draft202012Validator(schema, registry=Registry(), format_checker=checker)


def validate(document, kind, *, allow_legacy_report=False):
    """Validate a bundled structural contract and its available semantic checks."""
    if kind not in SCHEMAS:
        raise ValueError('Unknown JSON contract kind')
    filename = SCHEMAS[kind]
    value = document
    if kind == 'report':
        value = report_version(document, allow_legacy=allow_legacy_report)
    elif kind == 'baseline' and isinstance(document, dict) and type(document.get('schema')) is int and document['schema'] == 1:
        filename = 'baseline-v1.schema.json'
    error = next(_validator(filename).iter_errors(value), None)
    if error is not None:
        # Paths, member names and values can contain private code or credentials.
        # Report only a fixed schema name and the failed keyword.
        raise ValueError(f'Invalid {kind} contract ({error.validator})')
    if kind == 'report':
        report_semantics(value)
    elif kind == 'baseline':
        import scan_policy
        scan_policy.parse_baseline(value)
    elif kind == 'go-build-info':
        import go_build_info
        go_build_info.validate(value)
    elif type(value['schema']) is not int or type(value['scanner_exit_code']) is not int:
        raise ValueError('Invalid GitLab status version/code type')
