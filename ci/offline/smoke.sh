#!/usr/bin/env bash
# Both scans and their gates run in fresh read-only containers with only loopback.
set -euo pipefail
image=${1:?verified local image reference required}
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir "$root"/{source,out}
chmod 755 "$root" "$root/source"
chmod 777 "$root/out"
echo 'SELECT 1;' | iconv -f UTF-8 -t UTF-16 > "$root/source/schema.sql"
echo 'package fixture' > "$root/source/main.go"
echo 'namespace Sample; class Program {}' > "$root/source/Program.cs"
echo 'console.log(1)' > "$root/source/main.js"
run=(docker run --rm --pull=never --network none --read-only --cap-drop ALL --security-opt no-new-privileges
     --tmpfs /tmp:rw,nosuid,nodev --user 65532:65532 -v "$root/source:/input:ro" -v "$root/out:/out:rw" "$image")
"${run[@]}" python -I -c 'import socket; assert [name for _, name in socket.if_nameindex()] == ["lo"]'
for iteration in 1 2; do
  "${run[@]}" python -I /opt/protestware/scripts/gitlab_scan.py --source /input --output-dir "/out/r$iteration" -- \
    --ast-mode required --dependencies lock --watchlists off --malware-intel off \
    --project-id offline/fixture --policy /opt/protestware/examples/policy.toml
  "${run[@]}" python -I /opt/protestware/scripts/gitlab_gate.py "/out/r$iteration"
done
"${run[@]}" python -I -c '
import json
from pathlib import Path
a,b = [json.loads(Path("/out", name, "report.json").read_bytes()) for name in ("r1","r2")]
for field in ("findings","scan","coverage","ast","gate","analysis_context"):
    assert a[field] == b[field], field
assert a["coverage"]["files_analyzed"] == 4 and a["ast"]["parsed"] == 4
assert a["gate"]["exit_code"] == 0 and a["gate"]["min_analyzed_files"] == 1
print("OFFLINE_REPEAT=4 files parsed; outcomes identical; gate=0")'
# CI artifacts are private to the non-root job user.
"${run[@]}" python -I -c 'import shutil; shutil.rmtree("/out/r1"); shutil.rmtree("/out/r2")'
