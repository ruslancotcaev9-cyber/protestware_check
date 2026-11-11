"""CI-only integration: create our own benign Go module and import real Go JSON.

No project supplied by a user or downloaded upstream source is built or executed.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import go_build_info
import protestware_check as scanner
from scripts.prepare_go_build_info import main as prepare


def main():
    with tempfile.TemporaryDirectory() as folder:
        base = Path(folder)
        source = base / 'source'
        library = source / 'lib'
        library.mkdir(parents=True)
        (source / 'go.mod').write_text('module example.test/app\ngo 1.22\nrequire example.test/lib v1.0.0\nreplace example.test/lib => ./lib\n')
        (source / 'main.go').write_text('package app\nimport "example.test/lib"\nfunc Value() string { return lib.Value() }\n')
        (library / 'go.mod').write_text('module example.test/lib\ngo 1.22\n')
        (library / 'lib.go').write_text('package lib\nimport "fmt"\nfunc Value() string { return fmt.Sprint("ok") }\n')
        env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOWORK': 'off',
               'CGO_ENABLED': '0', 'GOFLAGS': '', 'GOENV': 'off'}
        listings = [('modules', ['list', '-mod=readonly', '-m', '-json', 'all']),
                    ('packages', ['list', '-mod=readonly', '-deps', '-json', './...']),
                    ('environment', ['env', '-json', 'GOOS', 'GOARCH', 'GOVERSION', 'CGO_ENABLED', 'GOFLAGS', 'GOWORK'])]
        argv = ['--source-root', str(source), '--source-revision', 'a' * 40, '--output', str(base / 'build-info.json')]
        for name, command in listings:
            result = subprocess.run(['go', *command], cwd=source, env=env, check=True, capture_output=True, text=True, timeout=120)
            path = base / (name + '.json')
            path.write_text(result.stdout)
            argv.extend(['--' + name, str(path)])
        assert prepare(argv) == 0
        build = go_build_info.load(base / 'build-info.json', source, 'a' * 40)
        assert len(build['packages']) > 10, 'Real standard-library closure expected'
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = scanner.main(['--path', str(source), '--go-build-info', str(base / 'build-info.json'),
                                 '--source-revision', 'a' * 40, '--dependency-strict', '--ast-mode', 'off', '--format', 'json'])
        report = json.loads(out.getvalue())
        assert code == 0, report
        packages = report['dependencies']['packages']
        assert [(p['name'], p['origin']['kind']) for p in packages] == [('example.test/lib', 'local')]
        (source / 'added.go').write_text('package app\n')
        try:
            go_build_info.load(base / 'build-info.json', source, 'a' * 40)
        except ValueError:
            pass
        else:
            raise AssertionError('Added Go source must invalidate imported data')
        print(json.dumps({'integration': 'real-go-export-import', 'profile': build['profile'],
                          'packages': len(build['packages']), 'stale_input_rejected': True}))


if __name__ == '__main__':
    main()
