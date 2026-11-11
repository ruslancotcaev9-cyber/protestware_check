"""Bounded accounting for selected files and pruned subtrees."""
from collections import Counter


class Coverage:
    def __init__(self, profile='source', *, enumeration='provided', sample_limit=100):
        self.profile = profile
        self.enumeration = enumeration
        self.sample_limit = sample_limit
        self.files = Counter()
        self.directories = Counter()
        self.samples = []
        self.input_bytes = 0
        self.analysis_bytes = 0
        self.analyzed_files = 0
        self.languages = {}
        self.resolved_commit = None
        self.resolved_tree = None

    def record(self, path, status, *, directory=False, size=0):
        (self.directories if directory else self.files)[status] += 1
        self.input_bytes += size
        if status != 'scanned' and len(self.samples) < self.sample_limit:
            self.samples.append({'path': str(path)[:512], 'kind': 'directory' if directory else 'file', 'reason': status})

    def analyzed(self, suffix, size, ast_status):
        self.analyzed_files += 1
        self.analysis_bytes += size
        language = self.languages.setdefault(suffix or '(no extension)', Counter())
        language[ast_status] += 1

    def as_dict(self):
        selected = sum(self.files[k] for k in ('scanned', 'binary', 'oversized', 'read_error', 'invalid_blob'))
        return {'profile': self.profile, 'enumeration': self.enumeration,
                'files_observed': sum(self.files.values()), 'files_selected': selected,
                'files_analyzed': self.analyzed_files, 'file_counts': dict(sorted(self.files.items())),
                'pruned_directories': dict(sorted(self.directories.items())),
                'pruned_subtree_file_counts_unknown': self.enumeration == 'local' and bool(self.directories),
                'input_bytes_read': self.input_bytes, 'analysis_utf8_bytes': self.analysis_bytes,
                'samples': self.samples, 'samples_truncated':
                    sum(v for k, v in self.files.items() if k != 'scanned') + sum(self.directories.values()) > len(self.samples),
                'ast_by_extension': {key: dict(sorted(value.items())) for key, value in sorted(self.languages.items())},
                'resolved_commit': self.resolved_commit, 'resolved_tree': self.resolved_tree}
