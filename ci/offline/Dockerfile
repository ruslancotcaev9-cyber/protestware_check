FROM python:3.11-slim-bookworm@sha256:e8c69d86735f6df3efa06b324694fe51f0422785f83a3bd463052636c2421944
ENV TREE_SITTER_LANGUAGE_PACK_CACHE_DIR=/opt/grammar-cache \
    PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/protestware
COPY requirements.lock /opt/protestware/requirements.lock
RUN python -m pip install --no-cache-dir --no-compile --require-hashes --only-binary=:all: -r requirements.lock && python -m pip check
COPY grammars/ /opt/grammar-cache/tree-sitter-language-pack/v1.22.1/libs/
COPY scanner/ /opt/protestware/
USER 65532:65532
RUN --network=none python -c "from tree_sitter_language_pack import get_parser; from polyglot_ast import GRAMMARS; [get_parser(lang) for lang in sorted(set(GRAMMARS.values()))]"
