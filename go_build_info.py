"""Import/export a trusted Go listing as data. Never invokes Go or target code."""
from collections import deque
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import re

import safe_io
import json_contracts
from analysis_context import digest

HEX = re.compile(r'[a-f0-9]{64}')
REVISION = re.compile(r'(?:[a-f0-9]{40}|[a-f0-9]{64})')
NATIVE = {'.go', '.c', '.h', '.cc', '.cpp', '.cxx', '.s', '.m', '.mm', '.f', '.f90', '.syso', '.swig', '.swigcxx'}
METADATA = {'go.mod', 'go.sum', 'go.work', 'go.work.sum'}
FILE_FIELDS = ('GoFiles', 'CgoFiles', 'CFiles', 'CXXFiles', 'MFiles', 'HFiles', 'FFiles',
               'SFiles', 'SwigFiles', 'SwigCXXFiles', 'SysoFiles', 'EmbedFiles')


def relative(value, *, directory=False):
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(ch) < 32 for ch in value):
        raise ValueError('Invalid Go input path')
    value = value.replace('\\', '/')
    path = PurePosixPath(value)
    if path.is_absolute() or ':' in value or '..' in path.parts or (str(path) == '.' and not directory):
        raise ValueError('Go input path escapes project boundaries')
    return str(path)


def within(path, parent):
    return parent == '.' or path == parent or path.startswith(parent + '/')


def local_path(root, value, *, directory=False):
    string(value, 'local file path')
    path = Path(value).resolve()
    try:
        result = path.relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise ValueError('Go listing references project inputs outside --source-root') from error
    return relative(result, directory=directory)


def read_inputs(root, roots, assets, extras, *, max_files=10000, max_bytes=1_000_000, max_total_bytes=100_000_000):
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError('Go source root must be a real directory')
    paths = set(extras)
    observed = 0
    for directory in sorted(set(roots), key=lambda value: (value.count('/'), value)):
        if any(other != directory and within(directory, other) for other in roots):
            continue
        base = root / directory
        if base.is_symlink() or not base.is_dir() or not base.resolve().is_relative_to(root.resolve()):
            raise ValueError('Go source directory escapes project boundaries')
        def walk_error(error):
            raise OSError('Cannot enumerate Go source inputs') from error
        for folder, dirs, files in os.walk(base, followlinks=False, onerror=walk_error):
            dirs[:] = sorted(name for name in dirs if name not in {'.git', '.hg', '.svn'})
            for name in dirs:
                if Path(folder, name).is_symlink():
                    raise ValueError('Symlinked Go source directories are not supported')
            observed += len(dirs) + len(files)
            if observed > max(100000, max_files * 20):
                raise ValueError('Go source enumeration budget exceeded')
            for name in files:
                path = Path(folder, name).relative_to(root).as_posix()
                if (Path(name).suffix.lower() in NATIVE or name in METADATA or path.endswith('/vendor/modules.txt') or
                        any(within(path, asset) for asset in assets)):
                    paths.add(relative(path))
                    if len(paths) > max_files:
                        raise ValueError('Go input file budget exceeded')
    result, total = {}, 0
    for path in sorted(paths):
        target = root / relative(path)
        if not target.resolve().is_relative_to(root.resolve()):
            raise ValueError('Go input file escapes project boundaries')
        raw = safe_io.read_regular(target, max_bytes)
        total += len(raw)
        if len(result) >= max_files or total > max_total_bytes:
            raise ValueError('Go input byte/file budget exceeded')
        result[path] = sha256(raw).hexdigest()
    return result


def objects(path, *, maximum):
    text = safe_io.read_regular(path, 25_000_000).decode('utf-8-sig')
    decoder, position, result = json_contracts.decoder(), 0, []
    if text.lstrip().startswith('['):
        result = json_contracts.loads(text)
    else:
        while position < len(text):
            if text[position].isspace():
                position += 1
                continue
            value, position = decoder.raw_decode(text, position)
            result.append(value)
            if len(result) > maximum:
                raise ValueError('Go listing object budget exceeded')
    if not isinstance(result, list) or not result or len(result) > maximum or any(not isinstance(item, dict) for item in result):
        raise ValueError('Invalid or empty Go listing')
    return result


def string(value, label):
    if not isinstance(value, str) or not value or len(value) > 1024 or any(ord(ch) < 32 for ch in value):
        raise ValueError('Invalid Go ' + label)
    return value


def module_rows(rows, root):
    from dependency_analysis import is_exact_version
    modules, roots = {}, set()
    for row in rows:
        path = string(row.get('Path'), 'module path')
        if path in modules or row.get('Error'):
            raise ValueError('Duplicate/failed Go module listing')
        main, indirect = row.get('Main', False), row.get('Indirect', False)
        if type(main) is not bool or type(indirect) is not bool:
            raise ValueError('Invalid Go module flags')
        version = row.get('Version', '')
        if not main and not is_exact_version('go', version):
            raise ValueError('Go module lacks an exact selected version')
        module = {'path': path, 'version': version, 'main': main, 'indirect': indirect}
        if main:
            mod = local_path(root, row.get('GoMod', ''))
            if PurePosixPath(mod).name != 'go.mod':
                raise ValueError('Alternate Go modfiles are not supported')
            module['manifest'] = mod
            roots.add(str(PurePosixPath(mod).parent))
        replacement = row.get('Replace')
        if replacement is not None:
            if not isinstance(replacement, dict) or replacement.get('Error'):
                raise ValueError('Invalid Go replacement listing')
            target = {'path': string(replacement.get('Path'), 'replacement path'), 'version': replacement.get('Version', '')}
            if target['version']:
                if not is_exact_version('go', target['version']):
                    raise ValueError('Unpinned Go replacement')
            else:
                target['local_path'] = local_path(root, replacement.get('Dir', ''), directory=True)
                target['manifest'] = local_path(root, replacement.get('GoMod', ''))
                if target['manifest'] != str(PurePosixPath(target['local_path']) / 'go.mod'):
                    raise ValueError('Inconsistent local Go replacement metadata')
                roots.add(target['local_path'])
            module['replace'] = target
        for key in ('Sum', 'GoModSum'):
            value = (replacement or row).get(key)
            if value:
                if not isinstance(value, str) or not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', value):
                    raise ValueError('Invalid Go module checksum metadata')
                module[key] = value
        modules[path] = module
    if not any(item['main'] for item in modules.values()):
        raise ValueError('Go listing has no main project module')
    return modules, roots


def export(root, revision, module_file, package_file, environment_file, *, tags=(), targets=('./...',), mod_mode='readonly', **limits):
    if Path(root).is_symlink():
        raise ValueError('Go source root must not be a symlink')
    root = Path(root).resolve()
    if not REVISION.fullmatch(revision):
        raise ValueError('Expected an exact source revision')
    environment = json_contracts.loads(safe_io.read_regular(environment_file, 100000))
    if not isinstance(environment, dict):
        raise ValueError('Invalid Go environment JSON')
    if not isinstance(environment.get('GOFLAGS', ''), str) or environment.get('GOFLAGS', '').strip():
        raise ValueError('Export requires empty GOFLAGS and explicit listing flags')
    if mod_mode not in {'readonly', 'mod'}:
        raise ValueError('Only explicit readonly/mod production profiles are supported')
    profile = {'goos': string(environment.get('GOOS'), 'GOOS'), 'goarch': string(environment.get('GOARCH'), 'GOARCH'),
               'go_version': string(environment.get('GOVERSION'), 'GOVERSION'), 'mod_mode': mod_mode,
               'tags': sorted(set(tags)), 'targets': sorted(set(targets)), 'cgo_enabled': environment.get('CGO_ENABLED') == '1'}
    if environment.get('CGO_ENABLED') not in {'0', '1'} or not profile['targets'] or any(not re.fullmatch(r'[A-Za-z0-9_.]+', item) for item in profile['tags']):
        raise ValueError('Invalid Go build profile')
    for target in profile['targets']:
        string(target, 'target')
    modules, roots = module_rows(objects(module_file, maximum=2000), root)
    packages, extras, assets = {}, set(), set()
    workspace = environment.get('GOWORK')
    if workspace not in (None, '', 'off'):
        work = local_path(root, workspace)
        if PurePosixPath(work).name != 'go.work':
            raise ValueError('Unsupported Go workspace file')
        extras.add(work)
        if (root / (work + '.sum')).exists():
            extras.add(work + '.sum')
    for row in objects(package_file, maximum=20000):
        name = string(row.get('ImportPath'), 'package path')
        if name in packages or row.get('Error') or row.get('DepsErrors') or row.get('Incomplete') or row.get('ForTest') or name.endswith('.test'):
            raise ValueError('Duplicate, incomplete or test Go package listing')
        standard = row.get('Standard', False)
        dep_only = row.get('DepOnly', False)
        if type(standard) is not bool or type(dep_only) is not bool:
            raise ValueError('Invalid Go package flags')
        module = row.get('Module')
        module_path = module.get('Path') if isinstance(module, dict) else None
        if not standard:
            if not isinstance(module_path, str) or module_path not in modules or module.get('Version', '') != modules[module_path]['version']:
                raise ValueError('Go package/module identity mismatch')
        imports = row.get('Imports', [])
        mapping = row.get('ImportMap', {})
        if not isinstance(imports, list) or not isinstance(mapping, dict):
            raise ValueError('Invalid Go package imports')
        imports = sorted({string(mapping.get(string(item, 'import'), item), 'import') for item in imports if item != 'C'})
        packages[name] = {'path': name, 'module': module_path, 'standard': standard, 'dep_only': dep_only, 'imports': imports}
        local = modules.get(module_path, {})
        owned = local.get('main') or local.get('replace', {}).get('local_path') is not None
        if row.get('CgoFiles') and not profile['cgo_enabled']:
            raise ValueError('Cgo source listing disagrees with the declared build profile')
        if owned:
            directory = local_path(root, row.get('Dir', ''), directory=True)
            if not any(within(directory, source) for source in roots):
                raise ValueError('Go project package lies outside declared module roots')
            for field in FILE_FIELDS:
                files = row.get(field, [])
                if not isinstance(files, list):
                    raise ValueError('Invalid Go source file metadata')
                extras.update(relative(str(PurePosixPath(directory) / relative(item))) for item in files)
            patterns = row.get('EmbedPatterns', [])
            if not isinstance(patterns, list) or any(not isinstance(item, str) for item in patterns):
                raise ValueError('Invalid Go embed pattern metadata')
            for pattern in patterns:
                pattern = relative(pattern.removeprefix('all:'))
                index = next((i for i, ch in enumerate(pattern) if ch in '*?['), len(pattern))
                prefix = pattern[:index]
                asset = prefix.rstrip('/') if index < len(pattern) and prefix.endswith('/') else str(PurePosixPath(prefix).parent)
                assets.add(relative(str(PurePosixPath(directory) / asset), directory=True))
    inputs = read_inputs(root, roots, assets, extras, **limits)
    data = {'schema': 1, 'source_revision': revision, 'profile': profile, 'module_roots': sorted(roots),
            'asset_roots': sorted(assets), 'extra_inputs': sorted(extras), 'inputs': inputs,
            'modules': sorted(modules.values(), key=lambda item: item['path']),
            'packages': sorted(packages.values(), key=lambda item: item['path'])}
    validate(data)
    return data


def validate(data):
    from dependency_analysis import is_exact_version
    if not isinstance(data, dict) or type(data.get('schema')) is not int or data['schema'] != 1 or not isinstance(data.get('source_revision'), str) or not REVISION.fullmatch(data['source_revision']):
        raise ValueError('Invalid Go build-info schema/revision')
    profile = data.get('profile')
    if not isinstance(profile, dict) or set(profile) != {'goos', 'goarch', 'go_version', 'mod_mode', 'tags', 'targets', 'cgo_enabled'}:
        raise ValueError('Invalid Go build profile fields')
    for key in ('goos', 'goarch', 'go_version'):
        string(profile.get(key), key)
    if not isinstance(profile['mod_mode'], str) or profile['mod_mode'] not in {'readonly', 'mod'} or type(profile['cgo_enabled']) is not bool:
        raise ValueError('Unsupported Go build profile')
    for key in ('tags', 'targets'):
        if not isinstance(profile[key], list) or len(profile[key]) > 100 or any(not isinstance(x, str) for x in profile[key]):
            raise ValueError('Invalid Go build profile lists')
    if not profile['targets'] or any(not re.fullmatch(r'[A-Za-z0-9_.]+', tag) for tag in profile['tags']):
        raise ValueError('Invalid Go tags/targets')
    for item in profile['targets']:
        string(item, 'target')
    for key in ('module_roots', 'asset_roots', 'extra_inputs'):
        if not isinstance(data.get(key), list) or len(data[key]) > 20000 or any(not isinstance(item, str) for item in data[key]) or len(set(data[key])) != len(data[key]):
            raise ValueError('Invalid Go source scope')
        for value in data[key]:
            if relative(value, directory=key != 'extra_inputs') != value:
                raise ValueError('Noncanonical Go source scope')
    if not data['module_roots']:
        raise ValueError('Missing Go module roots')
    inputs = data.get('inputs')
    if not isinstance(inputs, dict) or not inputs or len(inputs) > 20000:
        raise ValueError('Invalid Go input inventory')
    for path, value in inputs.items():
        if relative(path) != path:
            raise ValueError('Noncanonical Go input path')
        if not isinstance(value, str) or not HEX.fullmatch(value):
            raise ValueError('Invalid Go input digest')
    modules = data.get('modules')
    packages = data.get('packages')
    if not isinstance(modules, list) or not modules or len(modules) > 2000 or not isinstance(packages, list) or not packages or len(packages) > 20000:
        raise ValueError('Go build-info graph budget/shape invalid')
    by_module, manifests = {}, set()
    for module in modules:
        if not isinstance(module, dict):
            raise ValueError('Invalid Go module')
        name = string(module.get('path'), 'module path')
        if name in by_module or type(module.get('main')) is not bool or type(module.get('indirect')) is not bool:
            raise ValueError('Duplicate/invalid Go module')
        if not module['main'] and not is_exact_version('go', module.get('version', '')):
            raise ValueError('Go module version is not exact')
        if module['main']:
            if module.get('version') != '':
                raise ValueError('Project Go modules must not claim a registry version')
            manifest = relative(module.get('manifest'))
            if PurePosixPath(manifest).name != 'go.mod':
                raise ValueError('Project Go manifest must be go.mod')
            manifests.add(manifest)
        for field in ('Sum', 'GoModSum'):
            if field in module and (not isinstance(module[field], str) or not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', module[field])):
                raise ValueError('Invalid selected Go checksum')
        replacement = module.get('replace')
        if replacement:
            if not isinstance(replacement, dict):
                raise ValueError('Invalid Go replacement')
            string(replacement.get('path'), 'replacement path')
            if replacement.get('version'):
                if not is_exact_version('go', replacement['version']):
                    raise ValueError('Invalid Go replacement version')
            else:
                local = relative(replacement.get('local_path'), directory=True)
                manifest = relative(replacement.get('manifest'))
                if manifest != str(PurePosixPath(local) / 'go.mod'):
                    raise ValueError('Invalid local Go replacement manifest')
                manifests.add(manifest)
        by_module[name] = module
    if not any(item['main'] for item in modules) or not manifests <= set(inputs):
        raise ValueError('Missing Go project manifests/input bindings')
    required_roots = {str(PurePosixPath(path).parent) for path in manifests}
    if set(data['module_roots']) != required_roots:
        raise ValueError('Go module roots disagree with bound manifests')
    if any(not any(within(asset, root) for root in required_roots) for asset in data['asset_roots']):
        raise ValueError('Go asset scope lies outside project modules')
    by_package, roots, edge_count = {}, [], 0
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError('Invalid Go package')
        path = string(package.get('path'), 'package path')
        if path in by_package or type(package.get('standard')) is not bool or type(package.get('dep_only')) is not bool:
            raise ValueError('Duplicate/invalid Go package')
        module = package.get('module')
        if not package['standard'] and (not isinstance(module, str) or module not in by_module):
            raise ValueError('Go package references an unknown module')
        if package['standard'] and module is not None:
            raise ValueError('Standard Go package must not claim a registry module')
        imports = package.get('imports')
        if not isinstance(imports, list) or len(imports) > 20000:
            raise ValueError('Invalid Go import edges')
        edge_count += len(imports)
        if edge_count > 200000:
            raise ValueError('Go import edge budget exceeded')
        for name in imports:
            string(name, 'import edge')
        by_package[path] = package
        if not package['dep_only'] and by_module.get(module, {}).get('main'):
            roots.append(path)
    if not roots:
        raise ValueError('Go package listing has no requested project targets')
    for package in packages:
        if any(name not in by_package for name in package['imports']):
            raise ValueError('Incomplete Go package closure')
    # Genuine production package imports form a DAG. Reject forged cycles without recursion.
    pending = {name: len(set(package['imports'])) for name, package in by_package.items()}
    parents = {name: [] for name in by_package}
    for name, package in by_package.items():
        for child in set(package['imports']):
            parents[child].append(name)
    ready = deque(name for name, count in pending.items() if not count)
    processed = 0
    while ready:
        processed += 1
        for parent in parents[ready.popleft()]:
            pending[parent] -= 1
            if not pending[parent]:
                ready.append(parent)
    if processed != len(by_package):
        raise ValueError('Cyclic Go package imports')
    reached, queue = set(), deque(roots)
    while queue:
        path = queue.popleft()
        if path in reached:
            continue
        reached.add(path)
        queue.extend(by_package[path]['imports'])
    if any(not package['standard'] and package['path'] not in reached for package in packages):
        raise ValueError('Go listing includes unreachable nonstandard packages')
    return by_module, by_package, reached, manifests


def logical_digest(data):
    return digest({key: data[key] for key in ('profile', 'inputs', 'modules', 'packages')})


def load(path, source_root, expected_revision, **limits):
    raw = safe_io.read_regular(path, 25_000_000)
    try:
        data = json_contracts.loads(raw)
        validate(data)
    except (TypeError, KeyError, RecursionError) as error:
        raise ValueError('Malformed or excessively nested Go build-info') from error
    if data['source_revision'] != expected_revision:
        raise ValueError('Go build-info source revision mismatch')
    try:
        observed = read_inputs(source_root, data['module_roots'], data['asset_roots'], data['extra_inputs'], **limits)
    except OSError as error:
        raise ValueError('Go build-info source inputs are stale or unreadable') from error
    if observed != data['inputs']:
        raise ValueError('Go build-info source input set/digests are stale or incomplete')
    return {**data, 'snapshot_sha256': sha256(raw).hexdigest(), 'logical_digest': logical_digest(data), 'inputs_verified': True}
