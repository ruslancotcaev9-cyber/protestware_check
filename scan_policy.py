"""Explicit, bounded policy/baseline inputs. Findings are retained for review."""
from datetime import date, datetime, timezone
from hashlib import sha256
import json
import re
import tomllib

import safe_io

LEVELS = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
FINGERPRINT = re.compile(r'[a-f0-9]{64}')
RULE = re.compile(r'[A-Z][A-Z0-9_]{0,63}')


def _keys(value, allowed, label):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise ValueError(f'Invalid or unknown {label} fields')


def _strings(value, label):
    if not isinstance(value, list) or len(value) > 200 or any(not isinstance(item, str) or not item or len(item) > 512 for item in value):
        raise ValueError(f'{label} must be a bounded list of nonempty strings')


def _review(value):
    for key, minimum, maximum in (('reason', 8, 1000), ('owner', 2, 200)):
        if not isinstance(value.get(key), str) or not minimum <= len(value[key].strip()) <= maximum:
            raise ValueError(f'Policy exception requires {key}')
    if not isinstance(value.get('expires'), str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value['expires']):
        raise ValueError('Policy exception requires expires = "YYYY-MM-DD"')
    date.fromisoformat(value['expires'])


def load(path=None):
    if path is None:
        return {'schema': 1, 'scan': {}, 'gate': {}, 'rules': {}, 'suppressions': [], 'sha256': None}
    raw = safe_io.read_regular(path, 1_000_000)
    doc = tomllib.loads(raw.decode('utf-8'))
    _keys(doc, ('schema', 'scan', 'gate', 'rules', 'suppressions'), 'policy')
    if type(doc.get('schema')) is not int or doc['schema'] != 1:
        raise ValueError('Policy schema must be 1')
    scan, gate, rules, suppressions = (doc.get(key, default) for key, default in
                                      (('scan', {}), ('gate', {}), ('rules', {}), ('suppressions', [])))
    _keys(scan, ('profile', 'exclude', 'allow_domains'), 'scan')
    if 'profile' in scan and scan['profile'] not in ('source', 'artifact'):
        raise ValueError('Invalid policy scan profile')
    for key in ('exclude', 'allow_domains'):
        if key in scan:
            _strings(scan[key], key)
    _keys(gate, ('fail_on', 'only_new', 'require_complete'), 'gate')
    if 'fail_on' in gate and gate['fail_on'] not in ('low', 'medium', 'high'):
        raise ValueError('Invalid policy fail_on')
    for key in ('only_new', 'require_complete'):
        if key in gate and type(gate[key]) is not bool:
            raise ValueError(f'{key} must be a Boolean')
    if not isinstance(rules, dict) or len(rules) > 200:
        raise ValueError('Invalid policy rules')
    for name, value in rules.items():
        if not RULE.fullmatch(name):
            raise ValueError('Invalid policy rule identifier')
        _keys(value, ('severity', 'enabled', 'reason', 'owner', 'expires'), 'rule')
        if 'severity' in value and value['severity'] not in LEVELS:
            raise ValueError('Invalid rule severity')
        if 'enabled' in value and type(value['enabled']) is not bool:
            raise ValueError('Rule enabled must be a Boolean')
        if 'severity' in value or value.get('enabled') is False:
            _review(value)
    if not isinstance(suppressions, list) or len(suppressions) > 2000:
        raise ValueError('Invalid policy suppressions')
    for value in suppressions:
        _keys(value, ('fingerprint', 'rule', 'reason', 'owner', 'expires'), 'suppression')
        if not isinstance(value.get('fingerprint'), str) or not FINGERPRINT.fullmatch(value['fingerprint']):
            raise ValueError('Suppression requires an exact finding fingerprint')
        if not isinstance(value.get('rule'), str) or not RULE.fullmatch(value['rule']):
            raise ValueError('Suppression requires an exact rule identifier')
        _review(value)
    if len({(item['rule'], item['fingerprint']) for item in suppressions}) != len(suppressions):
        raise ValueError('Duplicate finding suppressions')
    return {'schema': 1, 'scan': scan, 'gate': gate, 'rules': rules,
            'suppressions': suppressions, 'sha256': sha256(raw).hexdigest()}


def fingerprint(finding):
    identity = {key: finding.get(key) for key in ('rule', 'severity', 'evidence', 'package', 'advisory_ids')}
    identity['file'] = str(finding.get('file', '')).replace('\\', '/')
    if isinstance(identity.get('package'), dict):
        identity['package'] = {key: identity['package'].get(key) for key in ('ecosystem', 'name', 'version', 'origin')}
    if isinstance(identity.get('advisory_ids'), list):
        identity['advisory_ids'] = sorted(identity['advisory_ids'])
    return sha256(json.dumps(identity, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()


def load_baseline(path):
    if path is None:
        return None
    doc = json.loads(safe_io.read_regular(path, 5_000_000))
    if (not isinstance(doc, dict) or type(doc.get('schema')) is not int or doc['schema'] != 1 or
            type(doc.get('fingerprint_version')) is not int or doc['fingerprint_version'] != 1):
        raise ValueError('Unsupported baseline schema/fingerprint version')
    values = doc.get('fingerprints')
    if not isinstance(values, list) or len(values) > 50000 or any(not isinstance(item, str) or not FINGERPRINT.fullmatch(item) for item in values):
        raise ValueError('Invalid baseline fingerprints')
    return set(values)


def baseline(report):
    values = sorted({fingerprint(item) for item in report['findings']})
    if len(values) > 50000:
        raise ValueError('Baseline finding limit exceeded')
    return {'schema': 1, 'fingerprint_version': 1, 'tool_version': report['version'],
            'created_at_utc': datetime.now(timezone.utc).isoformat(), 'fingerprints': values}


def apply(report, policy, *, baseline_values=None, only_new=False, fail_on='high',
          dependency_strict=False, malware_strict=False, ast_required=False, today=None):
    today = today or datetime.now(timezone.utc).date()
    if only_new and baseline_values is None:
        raise ValueError('--only-new requires an explicit baseline')
    notices = set()
    exceptions = {(item['rule'], item['fingerprint']): item for item in policy['suppressions']}
    active = []
    counts = {'active': 0, 'baseline': 0, 'suppressed': 0, 'disabled': 0}
    for item in report['findings']:
        item.pop('policy_exception', None)
        item.pop('policy_override', None)
        item.pop('policy_review_required', None)
        value = fingerprint(item)
        item['fingerprint'] = value
        item['baseline_state'] = 'unchanged' if baseline_values is not None and value in baseline_values else 'new'
        item['effective_severity'] = item['severity']
        item.setdefault('confidence', 'medium' if item.get('analysis') or item.get('advisory_ids') else 'low')
        item['policy_decision'] = 'active'
        rule = policy['rules'].get(item['rule'], {})
        if rule.get('expires') and date.fromisoformat(rule['expires']) < today:
            notices.add(f'Expired policy rule exception: {item["rule"]}')
            item['policy_review_required'] = True
            rule = {}
        if 'severity' in rule:
            item['effective_severity'] = rule['severity']
            item['policy_override'] = {key: rule[key] for key in ('reason', 'owner', 'expires')}
        if rule.get('enabled') is False:
            item['policy_decision'] = 'disabled'
            item['policy_exception'] = {key: rule[key] for key in ('reason', 'owner', 'expires')}
        exception = exceptions.get((item['rule'], value))
        if exception is not None:
            if date.fromisoformat(exception['expires']) < today:
                notices.add(f'Expired finding suppression: {value}')
                item['policy_review_required'] = True
            else:
                item['policy_decision'] = 'suppressed'
                item['policy_exception'] = {key: exception[key] for key in ('reason', 'owner', 'expires')}
        if only_new and item['baseline_state'] == 'unchanged' and item['policy_decision'] == 'active' and not item.get('policy_review_required'):
            item['policy_decision'] = 'baseline'
        counts[item['policy_decision']] += 1
        if item['policy_decision'] == 'active' and item['effective_severity'] != 'info':
            active.append(item['effective_severity'])
    risk = max(active, key=LEVELS.get, default='none')
    reasons = []
    require_complete = policy['gate'].get('require_complete', False)
    if not report['scan']['complete']:
        reasons.append('source_incomplete')
    if (ast_required or require_complete) and (report['ast']['partial'] or report['ast']['degraded']):
        reasons.append('ast_incomplete')
    if (dependency_strict or require_complete) and report['dependencies']['mode'] != 'off' and not report['dependencies']['summary']['complete']:
        reasons.append('dependencies_incomplete')
    if (malware_strict or require_complete) and report['malware_intel']['mode'] != 'off' and not (
            report['malware_intel']['complete'] and report['malware_intel']['inventory_complete']):
        reasons.append('advisories_incomplete')
    exit_code = 2 if reasons else int(LEVELS.get(risk, 0) >= LEVELS[fail_on])
    report['policy'] = {'configuration_sha256': policy.get('sha256'), 'only_new': only_new,
                        'baseline_loaded': baseline_values is not None, 'counts': counts,
                        'risk': risk, 'warnings': sorted(notices)}
    report['gate'] = {'exit_code': exit_code, 'fail_on': fail_on, 'reasons': reasons,
                      'require_complete': require_complete}
    report['warnings'].extend(sorted(notices))
    return report
