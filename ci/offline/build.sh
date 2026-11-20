#!/usr/bin/env bash
# Build a transportable Linux/amd64 OCI archive from the trusted scanner checkout.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
out=$(realpath -m "${1:?usage: build.sh NEW_OUTPUT_DIRECTORY}")
mkdir "$out"
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
mkdir -p "$context"/{grammars,scanner/{scripts,schemas,examples}}
cp "$root"/ci/offline/{Dockerfile,requirements.lock} "$context/"
cp "$root"/*.py "$root/LICENSE" "$root/ci/offline/GRAMMAR-NOTICES.txt" "$context/scanner/"
cp "$root"/schemas/*.json "$context/scanner/schemas/"
cp "$root"/scripts/{gitlab_scan,gitlab_gate,validate_json}.py "$context/scanner/scripts/"
cp "$root/examples/policy.toml" "$context/scanner/examples/"
archive=parsers-linux-x86_64.tar.zst
curl -fsSL --retry 3 "https://github.com/xberg-io/tree-sitter-language-pack/releases/download/v1.22.1/$archive" -o "$context/$archive"
(cd "$context" && echo "4ad211e4a265be2106909ef9db4ccdc706e557436a446fbc10afbf23d668a2a5  $archive" | sha256sum -c)
members=()
for lang in c cpp c_sharp go javascript typescript tsx sql html css scss less; do
  members+=("./libtree_sitter_${lang}.so")
done
tar --extract --file="$context/$archive" --directory="$context/grammars" --no-same-owner "${members[@]}"
rm "$context/$archive"
chmod 755 "$context/grammars"
chmod 644 "$context"/grammars/*.so
docker buildx build --platform linux/amd64 --build-arg SOURCE_DATE_EPOCH=0 --provenance=false \
  --sbom=false --output "type=oci,dest=$out/scanner.oci.tar,rewrite-timestamp=true" "$context"
digest=$(skopeo inspect --raw "oci-archive:$out/scanner.oci.tar" | sha256sum | cut -d' ' -f1)
echo "sha256:$digest" > "$out/image-digest.txt"
cat > "$out/protestware-image.yml" <<LOCK
.protestware_image:
  image:
    name: "\${PROTESTWARE_IMAGE_REPOSITORY}@sha256:$digest"
    entrypoint: [""]
LOCK
cp "$root/examples/gitlab-ci-offline.yml" "$out/gitlab-ci-offline.yml"
(cd "$out" && sha256sum scanner.oci.tar image-digest.txt protestware-image.yml gitlab-ci-offline.yml > SHA256SUMS)
echo "OFFLINE_IMAGE_DIGEST=sha256:$digest"
