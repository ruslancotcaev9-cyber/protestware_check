"""Verify JSON/SARIF paths on pinned Python data and report whole-file context separately."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import report_formats
from scripts import evaluate_geo as geo


def inspect_case(case, raw, *, whole_file=False):
    lines = raw.decode('utf-8-sig').splitlines(keepends=True)
    first, last = (1, len(lines)) if whole_file else (case['first'], case['last'])
    path = case['path']
    report = geo.scanner.build_report('pinned-source', [(path, ''.join(lines[first-1:last]))], [], [], [],
                                      dependency_mode='off', ast_mode='auto' if whole_file else 'required')
    sarif = report_formats.sarif(report)['runs'][0]['results']
    sarif_paths = {}
    for item in sarif:
        if item['ruleId'] == 'GEO_ACTION':
            site = item['locations'][0]['physicalLocation']['region']['startLine']
            hops = item['codeFlows'][0]['threadFlows'][0]['locations']
            sarif_paths[site] = [hop['location']['physicalLocation']['region']['startLine'] for hop in hops]
    found = []
    network = set()
    for item in report['findings']:
        line = item['line'] + first - 1
        if not case['first'] <= line <= case['last']:
            continue
        if item['rule'].startswith('NET_'):
            network.add(line)
        if item['rule'] == 'GEO_ACTION':
            hops = item['dataflow']
            if [hop['line'] for hop in hops] != sarif_paths[item['line']]:
                raise ValueError(f'{path}:{line}: JSON and SARIF paths differ')
            found.append({'site': line, 'path': [{**hop, 'line': hop['line'] + first - 1} for hop in hops]})
    return {'source_sha256': case['source_sha256'], 'input_lines': [first, last],
            'reported_interval': [case['first'], case['last']], 'ast': report['ast'],
            'warnings': report['warnings'], 'actions': found, 'network_lines': sorted(network)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    cases = {c['id']: c for c in json.loads(geo.MANIFEST.read_bytes())['cases']}
    results = {}
    for name in ('geo-2', 'geo-6'):
        case = cases[name]
        raw = geo.verified(geo.safe_io.read_regular(args.sources / (name + '.py'), geo.LIMIT), case)
        results[name] = inspect_case(case, raw)
        if name == 'geo-2':
            results['geo-2-full-file'] = inspect_case(case, raw, whole_file=True)

    for name in ('geo-2', 'geo-2-full-file'):
        section = results[name]
        sites = {action['site'] for action in section['actions']}
        if sites & {1056, 1133} or not {1056, 1133} <= set(section['network_lines']):
            raise ValueError(f'{name}: IT/MY calls must retain only their ordinary network classification')
    geo6 = {a['site']: a['path'] for a in results['geo-6']['actions']}
    if (130 in geo6 or [(h['kind'], h['line']) for h in geo6.get(125, [])]
            != [('guard', 121), ('call', 125), ('sink', 56)]):
        raise ValueError('geo-6: expected the conditional call path and an unmarked common write')
    geo2 = {a['site']: a['path'] for a in results['geo-2-full-file']['actions']}
    for site, sink_lines in ((934, {63, 68}), (949, {123})):
        path = geo2.get(site, [])
        if (not path or path[0]['line'] != 931 or path[-1]['line'] not in sink_lines
                or path[-1]['message'] != 'requests.get'):
            raise ValueError(f'geo-2 whole file: missing verified network path at {site}')
    manifest = geo.CURRENT_SCANNER.read_bytes()
    report = {'schema': 1, 'scope': 'author-regression-diagnostics',
              **geo.checkout_state([*json.loads(manifest), geo.CURRENT_SCANNER, Path(__file__).resolve()]),
              'detector_manifest_sha256': sha256(manifest).hexdigest(), 'inputs': results}
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write('\n')


if __name__ == '__main__':
    main()
