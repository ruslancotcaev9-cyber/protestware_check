"""Bind proposed corpus labels to an explicit review ledger; never infer approval."""
from collections import Counter
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
from urllib.parse import quote

import corpus_evaluation
import json_contracts
import safe_io


def case_digest(case):
    return sha256(json.dumps(case, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def prepare(cases, corpus_sha256):
    return {'schema': 1, 'corpus_sha256': corpus_sha256,
            'policy': 'Pending candidate labels are not independent review. Reviewer identity/independence must be established outside this file by the trusted review process.',
            'cases': [{'id': case['id'], 'case_sha256': case_digest(case), 'proposed_positive': case['positive'],
                       'decision': 'pending', 'reviewer': None, 'reviewer_type': None,
                       'reviewed_at': None, 'reason': ''} for case in cases]}


def validate(document, cases, corpus_sha256):
    if (not isinstance(document, dict) or type(document.get('schema')) is not int or document['schema'] != 1 or
            set(document) != {'schema', 'corpus_sha256', 'policy', 'cases'} or
            document['corpus_sha256'] != corpus_sha256 or not isinstance(document['policy'], str) or
            not isinstance(document['cases'], list) or len(document['cases']) != len(cases)):
        raise ValueError('Invalid/stale corpus review ledger')
    current = {case['id']: case for case in cases}
    seen, counts = set(), Counter()
    fields = {'id', 'case_sha256', 'proposed_positive', 'decision', 'reviewer', 'reviewer_type', 'reviewed_at', 'reason'}
    for record in document['cases']:
        if not isinstance(record, dict) or set(record) != fields or not isinstance(record['id'], str):
            raise ValueError('Invalid corpus review record')
        identifier = record['id']
        if (identifier in seen or identifier not in current or record['case_sha256'] != case_digest(current[identifier]) or
                type(record['proposed_positive']) is not bool or record['proposed_positive'] != current[identifier]['positive'] or
                not isinstance(record['decision'], str) or record['decision'] not in {'pending', 'confirmed', 'disputed'}):
            raise ValueError('Unknown/duplicate/stale corpus review record')
        seen.add(identifier)
        if record['decision'] == 'pending':
            if any(record[key] is not None for key in ('reviewer', 'reviewer_type', 'reviewed_at')) or record['reason'] != '':
                raise ValueError('Pending label cannot claim a completed review')
        else:
            if (record['reviewer_type'] != 'independent-human' or
                    not isinstance(record['reviewer'], str) or not 2 <= len(record['reviewer'].strip()) <= 200 or
                    not isinstance(record['reason'], str) or not 8 <= len(record['reason'].strip()) <= 2000 or
                    not isinstance(record['reviewed_at'], str) or len(record['reviewed_at']) > 64):
                raise ValueError('Completed review needs reviewer, evidence and timezone-aware time')
            try:
                timestamp = datetime.fromisoformat(record['reviewed_at'].replace('Z', '+00:00'))
            except ValueError as error:
                raise ValueError('Invalid corpus review timestamp') from error
            if timestamp.tzinfo is None:
                raise ValueError('Corpus review timestamp requires timezone')
        counts[record['decision']] += 1
    return {'status': 'disputed' if counts['disputed'] else 'pending' if counts['pending'] else 'claimed-complete',
            'counts': {key: counts[key] for key in ('pending', 'confirmed', 'disputed')},
            'identity_verified': False,
            'basis': 'Claims in a checksum-bound review file; authenticate reviewer and independence in the trusted review process.'}


def load(path, cases, corpus_sha256):
    return validate(json_contracts.loads(safe_io.read_regular(path, 2_000_000)), cases, corpus_sha256)


def worksheet(cases, corpus_sha256):
    lines = ['# Проверка меток внешнего корпуса', '', f'Корпус SHA-256: `{corpus_sha256}`.', '',
             'Все метки ниже — предложения ассистента. Независимое ревью не выполнено. Положительная метка означает операцию, а не вредоносность.', '',
             'Проверяющему: изучить полный исходник и supporting-sources.json для обёрток; подтвердить или оспорить метку в external-review.json, указать имя, время с часовым поясом и обоснование. JSON-файл не удостоверяет личность проверяющего. Спорная метка требует отдельного решения; корпус автоматически не переписывается.', '',
             '| ID / правило | Предложение | Режим / группа | Исходник | Обоснование |',
             '|---|---|---|---|---|']
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    for case in cases:
        p = case['provenance']
        proof = case.get('label_evidence')
        line = proof[0]['line'] if proof else p['first_line']
        url = f"https://github.com/{p['repository']}/blob/{p['revision']}/{quote(p['path'])}#L{line}"
        rows = [case['id'] + ' / ' + case['rule'], 'операция есть' if case['positive'] else 'целевой операции нет',
                case.get('ast_mode', 'required') + ' / ' + case.get('cohort', 'unspecified'),
                f"[{cell(p['repository'] + ':' + p['path'])}]({url})", cell(case.get('rationale', ''))]
        lines.append('| ' + ' | '.join(rows) + ' |')
    return '\n'.join(lines) + '\n'


def prepare_files(corpus, output, worksheet_path=None):
    document, checksum = corpus_evaluation.load_document(corpus)
    targets = [Path(output), *([Path(worksheet_path)] if worksheet_path is not None else [])]
    if len({p.resolve() for p in targets}) != len(targets) or any(p.exists() or p.is_symlink() or p.resolve() == Path(corpus).resolve() for p in targets):
        raise ValueError('Review outputs must be distinct, new files; existing review work is never overwritten')
    safe_io.atomic_write(output, json.dumps(prepare(document['cases'], checksum), ensure_ascii=False, indent=2) + '\n')
    if worksheet_path is not None:
        safe_io.atomic_write(worksheet_path, worksheet(document['cases'], checksum))
