"""Bounded package entry lookup over selected text. No filesystem, registry or execution."""
from hashlib import sha256
from pathlib import PurePosixPath
import re

import json_contracts
from js_package_models import MODELS

NAME = re.compile(r'(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\Z')
# Builtins take precedence over node_modules. Their non-deletion semantics are
# opaque here; a same-named selected package must not replace a core module.
CORE = set('assert assert/strict async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns dns/promises domain events fs fs/promises http http2 https inspector inspector/promises module net os path path/posix path/win32 perf_hooks process punycode querystring readline readline/promises repl stream stream/consumers stream/promises stream/web string_decoder sys timers timers/promises tls trace_events tty url util util/types v8 vm wasi worker_threads zlib'.split())


class Packages:
    def __init__(self, sources, manifests, ambiguous=(), max_lookups=2048):
        self.sources, self.manifests = sources, {}
        self.issues, self.used, self.matched = {}, {}, {}
        self.model_cache = {}
        self.model_failures = {}
        self.resolution_cache, self.max_lookups = {}, max_lookups
        self.ambiguous = set(ambiguous)
        for path, content in manifests.items():
            root = str(PurePosixPath(path).parent)
            root = '' if root == '.' else root
            try:
                value = json_contracts.loads(content)
                if not isinstance(value, dict):
                    raise ValueError('not an object')
                self.manifests[root] = value
            except (ValueError, RecursionError):
                self.issues[root] = 'JS package manifest is invalid/ambiguous'
        self.paths = set(sources) | set(manifests)

    @staticmethod
    def join(root, part):
        return root + '/' + part if root else part

    def model(self, root, name, manifest):
        if root not in self.model_cache:
            model = MODELS[name]
            hashes = {}
            for relative, expected in model['files'].items():
                path = self.join(root, relative)
                source = self.sources.get(path)
                if source is None or sha256(source.encode('utf-8')).hexdigest() != expected:
                    self.model_cache[root] = None
                    self.model_failures[root] = path+(': selected file missing' if source is None else ': selected UTF-8 hash mismatch')
                    break
                hashes[path] = expected
            else:
                if manifest.get('version') == model['version'] and manifest.get('main') == model['entry']:
                    self.model_cache[root] = {**{k:model[k] for k in ('id','version','repository','revision')},
                                              'name':name,'root':root,'entry':self.join(root,model['entry']),
                                              'matched_files':hashes,'basis':'exact-selected-source-hashes'}
                    self.matched[root] = self.model_cache[root]
                else:
                    self.model_cache[root] = None
        return self.model_cache[root]

    def resolve(self, importer, specifier, *, require=False):
        if not isinstance(specifier,str):
            return None,None
        key = (str(PurePosixPath(importer).parent),specifier,require)
        if key not in self.resolution_cache:
            if len(self.resolution_cache)>=self.max_lookups:
                return None,'JS package lookup budget exceeded'
            self.resolution_cache[key] = self._resolve(importer,specifier,require=require)
        return self.resolution_cache[key]

    def _resolve(self, importer, specifier, *, require=False):
        if specifier in CORE:
            return None, None
        if not isinstance(specifier, str) or not specifier or any(c in specifier for c in '\\:%?#') or any(ord(c)<32 for c in specifier):
            return None, None
        parts = specifier.split('/')
        count = 2 if specifier.startswith('@') else 1
        name = '/'.join(parts[:count])
        if not NAME.fullmatch(name) or any(p in ('','.','..') for p in parts[count:]):
            return None, None
        parent = PurePosixPath(importer).parent.parts
        root = None
        if len(parent)>64:
            return None, 'JS package lookup depth budget exceeded'
        for depth in range(len(parent),-1,-1):
            prefix = parent[:depth]
            if prefix and prefix[-1] == 'node_modules':
                continue
            candidate = '/'.join((*prefix,'node_modules',name))
            if any(path.startswith(candidate+'/') for path in self.paths):
                root = candidate
                break
        if root is None:
            return None, None
        if any(path.startswith(root+'/') for path in self.ambiguous):
            return None, 'JS selected package inputs are duplicated/ambiguous'
        if root in self.issues:
            return None, self.issues[root]
        manifest = self.manifests.get(root, {})
        if manifest.get('name',name) != name:
            return None, 'JS package manifest name differs from selected package directory'
        if manifest.get('type') not in (None,'commonjs','module'):
            return None, 'JS package module type is unsupported'
        subpath = '/'.join(parts[count:])
        exports = manifest.get('exports')
        if 'exports' in manifest and (not isinstance(exports,str) or not exports.startswith('./') or subpath):
            return None, 'JS conditional/subpath package exports are unsupported'
        target = subpath or exports or manifest.get('main','index.js')
        if (not isinstance(target,str) or not target or len(target)>1024 or target.startswith('/') or
                any(c in target for c in '\\:%?#*') or any(ord(c)<32 for c in target) or
                '..' in PurePosixPath(target).parts):
            return None, 'JS package entry is not a safe selected relative path'
        target = str(PurePosixPath(target))
        suffix = PurePosixPath(target).suffix.lower()
        if suffix and suffix not in {'.js','.cjs','.mjs'}:
            return None, 'JS package entry extension is unsupported'
        full = self.join(root,target)
        candidates = {full} if suffix else {full+'.js',full+'/index.js'}
        found = sorted(candidates.intersection(self.sources))
        if len(found) != 1:
            return None, 'JS package entry is absent from selected files or ambiguous'
        ext = PurePosixPath(found[0]).suffix.lower()
        if require and (ext=='.mjs' or manifest.get('type')=='module' and ext!='.cjs'):
            return None, 'JS require of an ESM package is unsupported'
        record = {'name':name,'version':manifest.get('version') if isinstance(manifest.get('version'),str) else None,
                  'root':root,'entry':found[0], 'model':None,
                  'manifest':self.join(root,'package.json') if root in self.manifests else None}
        if name in MODELS and not subpath:
            model = self.model(root,name,manifest)
            if model is None:
                return None, 'JS package deletion-export model rejected: '+self.model_failures.get(root,'source hashes/metadata do not match')
            record['model'] = model
        self.used[(root,found[0])] = {k:v for k,v in record.items() if k!='model'}
        return record, None

    def module_type(self, path):
        parts = PurePosixPath(path).parts
        boundary = max((i+1 for i,p in enumerate(parts) if p=='node_modules'),default=0)
        roots = [root for root in self.manifests if (path.startswith(root+'/') or not root) and
                 (not boundary or len(PurePosixPath(root).parts)>boundary)]
        root = max(roots,key=len) if roots else None
        return self.manifests.get(root,{}).get('type') if root is not None else None
