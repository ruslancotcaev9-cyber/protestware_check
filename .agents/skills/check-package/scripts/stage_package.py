"""Stage exact public releases or a hash-pinned local archive without running package code."""
import argparse
import base64
import binascii
import contextlib
from email.parser import BytesHeaderParser
import gzip
import hashlib
import hmac
import http.client
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

MIB = 1024 * 1024
ARCHIVE_LIMIT, EXPANDED_LIMIT, MEMBER_LIMIT = 32 * MIB, 96 * MIB, 24 * MIB
ENTRY_LIMIT = 5000
HASHES = {"sha256": 32, "sha384": 48, "sha512": 64}


class IntegrityError(ValueError):
    """The bytes disagree with a trusted expected digest."""


class IdentityError(ValueError):
    """The package manifest disagrees with the registry coordinate."""


def pypi_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def limited_read(stream, size):
    data = stream.read(size + 1)
    if len(data) > size:
        raise ValueError("Input exceeds the size limit")
    return data


def verify(data, expected, source):
    if not isinstance(expected, str) or len(expected) > 4096:
        raise ValueError(f"Missing or invalid digest from {source}")
    candidates = []
    for token in expected.split():
        if ":" in token:
            alg, value = token.split(":", 1)
            if alg not in HASHES or not re.fullmatch(r"[a-fA-F0-9]+", value):
                raise ValueError(f"Invalid digest from {source}")
            digest = bytes.fromhex(value)
        else:
            alg, sep, value = token.partition("-")
            if alg == "sha1" and sep:
                continue
            if not sep or alg not in HASHES:
                raise ValueError(f"Unsupported digest from {source}")
            digest = base64.b64decode(value, validate=True)
        if len(digest) != HASHES[alg]:
            raise ValueError(f"Invalid digest length from {source}")
        candidates.append((alg, digest))
    if not candidates:
        raise ValueError(f"A SHA-256 or stronger digest is required from {source}")
    strongest = max((alg for alg, _ in candidates), key=HASHES.get)
    actual = hashlib.new(strongest, data).digest()
    if not any(hmac.compare_digest(actual, d) for a, d in candidates if a == strongest):
        wanted = ", ".join(d.hex() for a, d in candidates if a == strongest)
        raise IntegrityError(f"{source}: {strongest} mismatch. Expected {wanted}. Computed {actual.hex()}")
    return strongest


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def get(url, host, limit):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != host or parsed.query or parsed.fragment
            or not parsed.path.startswith("/") or any(ord(c) <= 32 for c in url)):
        raise ValueError("Unexpected registry URL")
    # Do not forward user credentials, cookies or redirects to artifact-controlled hosts.
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "check-package/1"})
    with opener.open(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError(f"Registry returned status {response.status}")
        return limited_read(response, limit)


def json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Ambiguous JSON with duplicate keys")
        result[key] = value
    return result


def release(args):
    name, version = args.name, args.version
    if len(name) > 214 or len(version) > 128:
        raise ValueError("Package coordinate too long")
    def quote(value):
        return urllib.parse.quote(value, safe="")

    if args.mode == "npm":
        part = r"[a-z0-9][a-z0-9._-]*"
        if not re.fullmatch(fr"(?:@{part}/)?{part}", name):
            raise ValueError("Expected a public npm package name")
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version, re.ASCII):
            raise ValueError("Expected an exact npm release version")
        host = "registry.npmjs.org"
        url = f"https://{host}/{quote(name)}/{quote(version)}"
        meta = json.loads(get(url, host, 2 * MIB), object_pairs_hook=json_object)
        if meta["name"] != name or meta["version"] != version:
            raise ValueError("Registry returned a different package or version")
        artifact_url = meta["dist"]["tarball"]
        digest = meta["dist"].get("integrity")
        flags = {"distribution_type": "npm", "deprecated": bool(meta.get("deprecated"))}
    else:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
            raise ValueError("Expected a public PyPI project name")
        if not re.fullmatch(r"[0-9][0-9A-Za-z._!+-]*", version):
            raise ValueError("Expected an exact PyPI release version")
        url = f"https://pypi.org/pypi/{quote(name)}/{quote(version)}/json"
        meta = json.loads(get(url, "pypi.org", 2 * MIB), object_pairs_hook=json_object)
        if pypi_name(meta["info"]["name"]) != pypi_name(name) or meta["info"]["version"] != version:
            raise ValueError("Registry returned a different package or version")
        files = meta["urls"]
        selected = [f for f in files if f["filename"] == args.filename] if args.filename else files
        if len(selected) != 1:
            names = [f["filename"] for f in files[:40]]
            raise ValueError("Select the intended distribution with --filename. Available: " + ", ".join(names))
        entry = selected[0]
        host, artifact_url = "files.pythonhosted.org", entry["url"]
        if urllib.parse.unquote(urllib.parse.urlsplit(artifact_url).path.rsplit("/", 1)[-1]) != entry["filename"]:
            raise ValueError("Distribution filename differs from its registry URL")
        digest = "sha256:" + entry["digests"]["sha256"]
        flags = {"distribution_type": entry["packagetype"], "yanked": bool(entry.get("yanked"))}
    data = get(artifact_url, host, ARCHIVE_LIMIT)
    alg = verify(data, digest, "registry")
    kind = flags["distribution_type"]
    if kind == "bdist_wheel" and not data.startswith(b"PK\x03\x04"):
        raise ValueError("Published wheel is not a ZIP distribution")
    if (kind == "npm" or (kind == "sdist" and artifact_url.endswith((".tar.gz", ".tgz")))) and not data.startswith(b"\x1f\x8b"):
        raise ValueError("Expected a gzip-compressed tar distribution")
    if kind == "sdist" and artifact_url.endswith(".zip") and not data.startswith(b"PK\x03\x04"):
        raise ValueError("Published ZIP sdist is not a ZIP distribution")
    return data, {"registry_metadata": url, "artifact_url": artifact_url, "registry_digest": digest,
                  "registry_hash_algorithm": alg, "name": name, "version": version, **flags}


def read_local(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Expected a regular local archive")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected a regular local archive")
        return limited_read(stream, ARCHIVE_LIMIT)


def member_parts(name, directory):
    if name.startswith("/") or "\\" in name or len(name) > 1024:
        raise ValueError("Unsafe or overlong archive path")
    parts = [p for p in name.rstrip("/").split("/") if p != "."]
    if not parts and directory:
        return []
    if not parts or len(parts) > 64:
        raise ValueError("Invalid archive path")
    for part in parts:
        if (not part or part in {".", ".."} or part.endswith((".", " ")) or len(part.encode()) > 255
                or re.search(r'[<>:"|?*\x00-\x1f\x7f]', part)
                or re.fullmatch(r"(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9¹²³]|LPT[0-9¹²³])(?:\..*)?", part, re.I)):
            raise ValueError("Unsafe archive path")
    return parts


def zip_directory_limits(data):
    # Bound the central directory before ZipFile allocates a ZipInfo for every record.
    # Fail closed on ZIP64 and multipart archives, which are outside these size budgets.
    start = max(0, len(data) - 65557)
    pos = data.rfind(b"PK\x05\x06", start)
    if pos < 0 or pos + 22 > len(data):
        raise ValueError("Missing ZIP end record")
    disk, first, on_disk, total, size, offset, comment = struct.unpack_from("<4H2IH", data, pos + 4)
    if (disk or first or on_disk != total or total > ENTRY_LIMIT or size > 2 * MIB
            or offset + size != pos or pos + 22 + comment != len(data)):
        raise ValueError("Unsupported ZIP layout or central directory budget exceeded")


def unpack(data, tree):
    count = written = total_size = 0
    names = {}
    explicit = set()

    def write_member(name, directory, size, opener):
        nonlocal count, written, total_size
        count += 1
        if count > ENTRY_LIMIT or not 0 <= size <= MEMBER_LIMIT or total_size + size > EXPANDED_LIMIT:
            raise ValueError("Archive member limit exceeded")
        parts = member_parts(name, directory)
        if not parts:
            return
        path = tree
        for index, part in enumerate(parts):
            path = path / part
            spelling = path.relative_to(tree).as_posix()
            key = unicodedata.normalize("NFC", spelling).casefold()
            is_dir = directory or index + 1 < len(parts)
            prior = names.get(key)
            if prior is not None and prior != (spelling, is_dir):
                raise ValueError("Conflicting archive paths")
            names[key] = (spelling, is_dir)
            if len(names) > 2 * ENTRY_LIMIT:
                raise ValueError("Too many archive paths")
            if is_dir:
                path.mkdir(exist_ok=True)
        if key in explicit:
            raise ValueError("Duplicate archive member")
        explicit.add(key)
        if directory:
            if size:
                raise ValueError("Directory has unexpected content")
            return
        with opener() as source, path.open("xb") as target:
            remaining = size
            while remaining:
                chunk = source.read(min(65536, remaining))
                if not chunk:
                    raise ValueError("Truncated archive member")
                target.write(chunk)
                remaining -= len(chunk)
            if source.read(1):
                raise ValueError("Archive member exceeds declared size")
        total_size += size
        written += 1

    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        zip_directory_limits(data)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                kind = stat.S_IFMT(member.external_attr >> 16)
                if (kind not in {0, stat.S_IFREG, stat.S_IFDIR} or member.flag_bits & 1
                        or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        or member.orig_filename != member.filename
                        or (kind and (kind == stat.S_IFDIR) != member.is_dir())):
                    raise ValueError("Unsupported ZIP entry type, name or compression")
                write_member(member.filename, member.is_dir(), member.file_size, lambda: archive.open(member))
    else:
        raw = data
        if data.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                raw = limited_read(stream, EXPANDED_LIMIT)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE} or member.sparse is not None:
                    raise ValueError("Unsupported TAR entry type")
                write_member(member.name, member.isdir(), member.size, lambda: archive.extractfile(member))
    if not written:
        raise ValueError("Archive has no regular files")
    return {"files": written, "expanded_file_bytes": total_size}


def published_manifest(tree, receipt):
    kind = receipt["distribution_type"]
    if kind == "bdist_wheel":
        manifests = list(tree.glob("*.dist-info/METADATA"))
    elif kind in {"npm", "sdist"}:
        roots = list(tree.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise ValueError("Cannot identify a unique distribution root")
        manifests = [roots[0] / ("package.json" if kind == "npm" else "PKG-INFO")]
    else:
        raise ValueError("Unsupported distribution type")
    if len(manifests) != 1 or not manifests[0].is_file():
        raise ValueError("Expected a unique package manifest")
    with manifests[0].open("rb") as source:
        data = limited_read(source, 2 * MIB)
    if kind == "npm":
        doc = json.loads(data, object_pairs_hook=json_object)
        name, version = doc["name"], doc["version"]
        expected = receipt["name"]
    else:
        headers = BytesHeaderParser().parsebytes(data)
        if any(len(headers.get_all(key, [])) != 1 for key in ("Name", "Version")):
            raise ValueError("Ambiguous or missing name/version in distribution metadata")
        name, version = pypi_name(headers["Name"]), headers["Version"]
        expected = pypi_name(receipt["name"])
    if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
        raise ValueError("Malformed release identity")
    if (name, version) != (expected, receipt["version"]):
        raise IdentityError(f"Manifest claims {name[:214]}@{version[:128]}, registry identifies {expected}@{receipt['version']}")
    return manifests[0].relative_to(tree).as_posix()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("local", "npm", "pypi"):
        cmd = sub.add_parser(mode)
        if mode == "local":
            cmd.add_argument("archive", type=Path)
        else:
            cmd.add_argument("name")
            cmd.add_argument("version")
        if mode == "pypi":
            cmd.add_argument("--filename", help="Exact distribution for the target platform")
        cmd.add_argument("--expect", required=mode == "local", help="Trusted hex sha256:... or SRI sha512-...")
        cmd.add_argument("--workdir", type=Path, help="Existing private parent outside the inspected project")
    args = parser.parse_args()
    if args.mode == "local":
        data, receipt = read_local(args.archive), {"archive_name": args.archive.name}
    else:
        data, receipt = release(args)
    if args.expect is not None:
        receipt["expected_hash_algorithm"] = verify(data, args.expect, "caller")
    with contextlib.ExitStack() as cleanup:
        root = Path(tempfile.mkdtemp(prefix="package-review-", dir=args.workdir)).resolve()
        cleanup.callback(shutil.rmtree, root)
        tree = root / "tree"
        tree.mkdir()
        stats = unpack(data, tree)
        if args.mode != "local":
            receipt["verified_manifest"] = published_manifest(tree, receipt)
        archive_path = root / "artifact.bin"
        archive_path.write_bytes(data)
        receipt.update(status="staged", mode=args.mode, sha256=hashlib.sha256(data).hexdigest(),
                       tree=str(tree), archive=str(archive_path), **stats)
        print(json.dumps(receipt, ensure_ascii=True))
        cleanup.pop_all()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except IntegrityError as exc:
        print(json.dumps({"status": "integrity_mismatch", "detail": str(exc)}))
        sys.exit(1)
    except IdentityError as exc:
        print(json.dumps({"status": "identity_mismatch", "detail": str(exc)}))
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, EOFError,
            tarfile.TarError, zipfile.BadZipFile, zlib.error, http.client.HTTPException, struct.error,
            binascii.Error) as exc:
        print(json.dumps({"status": "incomplete", "detail": str(exc)[:2500]}, ensure_ascii=True))
        sys.exit(2)
