#!/usr/bin/env bash
set -euo pipefail

# Binaries are downloaded only from a versioned upstream release and checked
# against the immutable SHA-256 recorded for that specific release artifact.
VERSION=8.30.1
EXPECTED_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo 'Gitleaks bootstrap supports Linux x86_64 CI runners only' >&2
  exit 2
fi
if [[ $# -ne 1 ]]; then
  echo 'Usage: bash scripts/install_gitleaks.sh DESTINATION_DIRECTORY' >&2
  exit 2
fi
destination="$1"
mkdir -p "$destination"
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT
curl --fail --location --silent --show-error --retry 3 --proto '=https' --tlsv1.2 \
  --output "$archive" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_linux_x64.tar.gz"
printf '%s  %s\n' "$EXPECTED_SHA256" "$archive" | sha256sum --check --status
tar -xzf "$archive" -C "$destination" gitleaks
chmod 0755 "$destination/gitleaks"
echo "Gitleaks v${VERSION}: verified archive SHA-256"
