"""Explicit, expiring advisory snapshots. Cache data is never executed."""
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re

import safe_io

MAX_BYTES = 10_000_000
MAX_ENTRIES = 5000


def key_for(source, package):
    return sha256(json.dumps([source, *package], separators=(',', ':')).encode()).hexdigest()


class AdvisoryCache:
    def __init__(self, path, *, mode='readwrite', max_age=86400, now=None):
        if mode not in {'readwrite', 'offline'} or not 1 <= max_age <= 31_536_000:
            raise ValueError('Invalid advisory cache mode/age')
        self.path, self.mode, self.max_age = Path(path), mode, max_age
        self.now = now or datetime.now(timezone.utc)
        self.entries = {}
        self.hits = self.misses = 0
        self.used_times = []
        self.digest = None
        if self.path.exists() or self.path.is_symlink():
            raw = safe_io.read_regular(self.path, MAX_BYTES)
            self.digest = sha256(raw).hexdigest()
            data = json.loads(raw)
            if not isinstance(data, dict) or type(data.get('schema')) is not int or data['schema'] != 1 or not isinstance(data.get('entries'), dict) or len(data['entries']) > MAX_ENTRIES:
                raise ValueError('Invalid advisory snapshot schema or entry limit')
            for key, value in data['entries'].items():
                self.validate(key, value)
            self.entries = data['entries']

    def validate(self, key, entry):
        if not isinstance(entry, dict) or entry.get('source') not in {'osv', 'github'}:
            raise ValueError('Invalid cached advisory source')
        package = entry.get('package')
        if not isinstance(package, list) or len(package) != 3 or any(not isinstance(x, str) or not x or len(x) > 256 for x in package):
            raise ValueError('Invalid cached package identity')
        if key != key_for(entry['source'], package):
            raise ValueError('Cached package key mismatch')
        if not isinstance(entry.get('retrieved_at_utc'), str) or len(entry['retrieved_at_utc']) > 64:
            raise ValueError('Invalid cached advisory timestamp')
        stamp = datetime.fromisoformat(entry['retrieved_at_utc'])
        if stamp.tzinfo is None:
            raise ValueError('Cached advisory timestamp must include timezone')
        records = entry.get('records')
        if not isinstance(records, list) or len(records) > 1000:
            raise ValueError('Invalid cached advisory records')
        pattern = r'MAL-\d{4}-\d+' if entry['source'] == 'osv' else r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}'
        expected_source = 'OpenSSF / OSV.dev' if entry['source'] == 'osv' else 'GitHub Advisory Database'
        for record in records:
            if (not isinstance(record, dict) or not isinstance(record.get('id'), str) or not re.fullmatch(pattern, record['id'], re.I) or
                    record.get('source') != expected_source or not isinstance(record.get('ids'), list) or
                    not record['ids'] or len(record['ids']) > 50 or any(not isinstance(x, str) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,100}', x) for x in record['ids'])):
                raise ValueError('Invalid cached advisory identity')
            expected_url = ('https://osv.dev/vulnerability/' if entry['source'] == 'osv' else 'https://github.com/advisories/') + record['id']
            if record.get('url') != expected_url or record['id'] not in record['ids']:
                raise ValueError('Cached advisory reference mismatch')

    def get(self, source, package):
        entry = self.entries.get(key_for(source, package))
        if entry:
            age = (self.now - datetime.fromisoformat(entry['retrieved_at_utc'])).total_seconds()
            if 0 <= age <= self.max_age:
                self.hits += 1
                self.used_times.append(entry['retrieved_at_utc'])
                return [{**record, 'ids': set(record['ids'])} for record in entry['records']]
        self.misses += 1
        return None

    def put(self, source, package, records):
        if self.mode != 'readwrite':
            return
        key = key_for(source, package)
        entry = {'source': source, 'package': list(package), 'retrieved_at_utc': self.now.isoformat(),
                 'records': [{**record, 'ids': sorted(record['ids'])} for record in records]}
        self.validate(key, entry)
        self.entries[key] = entry

    def save(self):
        if self.mode != 'readwrite':
            return
        items = sorted(self.entries.items(), key=lambda value: value[1]['retrieved_at_utc'], reverse=True)[:MAX_ENTRIES]
        while True:
            text = json.dumps({'schema': 1, 'entries': dict(items)}, ensure_ascii=True, separators=(',', ':')) + '\n'
            if len(text.encode()) <= MAX_BYTES:
                break
            items = items[:len(items) // 2]
        safe_io.atomic_write(self.path, text)

    def metadata(self):
        return {'mode': self.mode, 'loaded_sha256': self.digest, 'max_age_seconds': self.max_age,
                'hits': self.hits, 'misses': self.misses,
                'oldest_used_at_utc': min(map(datetime.fromisoformat, self.used_times)).astimezone(timezone.utc).isoformat() if self.used_times else None}
