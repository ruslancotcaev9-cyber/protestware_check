"""Offline export adapters: SARIF 2.1.0 and CycloneDX JSON 1.6.

Transforms an existing scan report only. No network access and no execution of
any scanned material is performed. Watchlist matches are NOT SBOM vulnerabilities.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import PurePosixPath
from urllib.parse import quote
from typing import Any
from package_identity import origin_key

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
CYCLONEDX_SCHEMA = "https://cyclonedx.org/schema/bom-1.6.schema.json"


def purl(pkg: dict[str, Any]) -> str | None:
    name = pkg.get("name")
    version = pkg.get("version")
    ecosystem = pkg.get("ecosystem")
    if not isinstance(name, str) or not name or not isinstance(ecosystem, str):
        return None
    kind = {"go": "golang", "pypi": "pypi", "npm": "npm", "cargo": "cargo",
            "composer": "composer", "nuget": "nuget"}.get(ecosystem)
    if kind is None:
        return None
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        scope, local = name[1:].split("/", 1)
        segments = ["%40" + quote(scope, safe=""), quote(local, safe="")]
    else:
        segments = [quote(part, safe="") for part in name.split("/")]
    uri = f"pkg:{kind}/{'/'.join(segments)}"
    if isinstance(version, str) and version:
        uri += "@" + quote(version, safe="")
    return uri


def cyclonedx(report: dict[str, Any]) -> dict[str, Any]:
    """Inventory with deterministic identifiers, best-effort relationships and completeness."""
    dependencies = report.get("dependencies", {})
    summary = dependencies.get("summary", {})
    items = dependencies.get("packages", [])
    root_ref = "project:" + sha256(report["source"].encode()).hexdigest()[:20]
    refs: dict[tuple[str, str, str, str, str], str] = {}
    components = []
    for pkg in items:
        key = (pkg["ecosystem"], pkg["name"], pkg.get("version", ""), pkg.get("manifest", ""), origin_key(pkg.get("origin", {})))
        ref = "package:" + sha256("\x00".join(key).encode()).hexdigest()[:24]
        refs[key] = ref
        properties = [{"name": "protestware-check:origin", "value": str(pkg.get("source", ""))},
                      {"name": "protestware-check:manifest", "value": str(pkg.get("manifest", ""))},
                      {"name": "protestware-check:package-origin", "value": origin_key(pkg.get("origin", {}))},
                      {"name": "protestware-check:direct", "value": str(bool(pkg.get("direct", False))).lower()}]
        if pkg.get("depth") is not None:
            properties.append({"name": "protestware-check:depth", "value": str(pkg["depth"])})
        component: dict[str, Any] = {"type": "library", "name": pkg["name"], "bom-ref": ref, "properties": properties}
        if pkg.get("version"):
            component["version"] = str(pkg["version"])
        if uri := purl(pkg):
            component["purl"] = uri
        if pkg.get("repository"):
            component["externalReferences"] = [{"type": "vcs", "url": "https://github.com/" + pkg["repository"]}]
        components.append(component)

    root_children = set()
    edges: dict[str, set[str]] = {ref: set() for ref in refs.values()}
    index: dict[tuple[str, str], list[tuple[tuple[str, str, str, str, str], str]]] = {}
    for key, ref in refs.items():
        index.setdefault((key[0], key[1].lower()), []).append((key, ref))

    for pkg in items:
        key = (pkg["ecosystem"], pkg["name"], pkg.get("version", ""), pkg.get("manifest", ""), origin_key(pkg.get("origin", {})))
        child_ref = refs[key]
        if pkg.get("direct"):
            root_children.add(child_ref)
        for via in pkg.get("via") or []:
            if not isinstance(via, str):
                continue
            parent_name, _, parent_version = via.rpartition("@")
            # Names beginning with @ (npm scoped names) still rpartition correctly.
            parent_name = parent_name or via
            candidates = index.get((pkg["ecosystem"], parent_name.lower()), [])
            if parent_version:
                candidates = [(k, r) for k, r in candidates if k[2] == parent_version]
            # Do not guess which of several different versions is the parent.
            if len(candidates) == 1 and candidates[0][1] != child_ref:
                edges[candidates[0][1]].add(child_ref)
    root_component = {"type": "application", "name": report["source"], "bom-ref": root_ref}
    completeness = str(bool(summary.get("complete", False))).lower()
    root_component["properties"] = [
        {"name": "protestware-check:dependency-analysis-mode", "value": dependencies.get("mode", "off")},
        {"name": "protestware-check:dependency-analysis-complete", "value": completeness},
    ]
    return {
        "$schema": CYCLONEDX_SCHEMA, "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": report["tool"],
                                              "version": report["version"]}]}, "component": root_component},
        "components": components,
        "dependencies": ([{"ref": root_ref, "dependsOn": sorted(root_children)}] +
                         [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(edges.items())]),
    }


def sarif(report: dict[str, Any], *, gitlab: bool = False) -> dict[str, Any]:
    """Represent observations (not asserted vulnerabilities) in GitHub SARIF 2.1.0."""
    findings = report.get("findings", [])
    def rule_id(item):
        if gitlab and isinstance(item.get('package'), dict) and not item.get('line'):
            from scan_policy import fingerprint
            return str(item['rule']) + '/' + fingerprint(item)[:24]
        return str(item['rule'])
    rules = sorted({rule_id(f) for f in findings})
    first = {rule: next(f for f in findings if rule_id(f) == rule) for rule in rules}
    tags = {"context": "context", "watchlist_context": "context", "watchlist_repository": "supply-chain",
            "watchlist_package": "supply-chain", "malware_advisory": "supply-chain"}
    definitions = [{"id": rule, "shortDescription": {"text": rule.replace("_", " ").capitalize()},
                    "fullDescription": {"text": first[rule].get("message") or rule},
                    "properties": {"tags": [tags.get(first[rule].get("category"), "security")]}}
                   for rule in rules]
    levels = {"info": "note", "low": "note", "medium": "warning", "high": "error"}
    results = []
    for item in findings:
        path, number = str(item.get("file", "")), item.get("line")
        rule = rule_id(item)
        message = str(item.get("message") or rule)
        package = item.get("package")
        if isinstance(package, dict):
            identity = f"{package.get('ecosystem', '')}:{package.get('name', '')}@{package.get('version', '')}"
            message += f" [{identity}]"
        if item.get("advisory_ids"):
            message += " [" + ", ".join(item["advisory_ids"]) + "]"
        result: dict[str, Any] = {"ruleId": rule, "level": levels.get(item.get("effective_severity", item.get("severity")), "note"),
                                  "message": {"text": message},
                                  "properties": {"category": item.get("category", "unknown"),
                                                 "severity": item.get("severity", "info")}}
        for field in ("package", "matched_packages", "advisory_ids", "sources", "references", "version_match",
                      "origin_match", "analysis", "repository", "evidence", "fingerprint", "confidence",
                      "effective_severity", "policy_decision", "policy_override", "policy_exception"):
            if field in item:
                result["properties"][field] = item[field]
        if isinstance(package, dict) and (uri := purl(package)):
            result["properties"]["purl"] = uri
        result['properties']['originalRuleId'] = item['rule']
        if item.get('baseline_state') in {'new', 'unchanged'}:
            result['baselineState'] = item['baseline_state']
        if item.get('policy_decision') in {'suppressed', 'disabled'}:
            exception = item.get('policy_exception', {})
            result['suppressions'] = [{'kind': 'external', 'status': 'accepted', 'justification':
                f"{exception.get('reason', '')} (owner={exception.get('owner', '')}; expires={exception.get('expires', '')})"}]
        if path and not path.startswith("("):
            normalized = path.replace("\\", "/")
            # No escaping repository boundaries; SARIF may carry source-provided paths.
            if (not normalized.startswith("/") and ":" not in normalized and
                    ".." not in PurePosixPath(normalized).parts):
                location = {"artifactLocation": {"uri": quote(normalized, safe="/@+-.~_")}}
                if isinstance(number, int) and number > 0:
                    location["region"] = {"startLine": number}
                result["locations"] = [{"physicalLocation": location}]
        # SARIF 2.1 codeFlows provide the analyst with bounded source-to-sink
        # provenance. Do not allow source-provided paths to escape the project.
        hops = item.get("dataflow")
        if isinstance(hops, list) and hops and len(hops) <= 25:
            thread = []
            for i, hop in enumerate(hops):
                if not isinstance(hop, dict):
                    continue
                hop_path = str(hop.get("file") or path).replace("\\", "/")
                hop_line = hop.get("line")
                if (not hop_path or hop_path.startswith("/") or
                        ":" in hop_path or
                        ".." in PurePosixPath(hop_path).parts or
                        not isinstance(hop_line, int) or hop_line <= 0):
                    continue
                thread.append({"location": {"physicalLocation": {
                    "artifactLocation": {"uri": quote(hop_path, safe="/@+-.~_")},
                    "region": {"startLine": hop_line}},
                    "message": {"text": str(hop.get("kind", "step")) + ": " +
                                     str(hop.get("message", ""))[:180]}},
                    "executionOrder": i})
            if thread:
                result["codeFlows"] = [{"threadFlows": [{"locations": thread}]}]
        fingerprint = "\x00".join([rule, path, str(item.get("evidence", "")).strip()])
        if isinstance(package, dict):
            fingerprint += "\x00" + json.dumps({"package": package, "ids": sorted(item.get("advisory_ids", []))}, sort_keys=True)
        result["partialFingerprints"] = {"primaryLocationLineHash": sha256(fingerprint.encode()).hexdigest()[:32]}
        if item.get('fingerprint'):
            result['partialFingerprints']['protestwareFingerprint/v1'] = item['fingerprint']
        results.append(result)
    ast = report.get("ast", {})
    dependencies = report.get("dependencies", {})
    intelligence = report.get("malware_intel", {})
    ast_attempted = any(ast.get(key, 0) for key in ("parsed", "partial", "degraded"))
    coverage = {"source": report.get("scan", {}).get("complete", True),
                "ast": not (ast.get("partial") or ast.get("degraded")) if ast_attempted else None,
                "dependencies": dependencies.get("summary", {}).get("complete", False) if dependencies.get("mode", "off") != "off" else None,
                "malware_intel": bool(intelligence.get("complete") and intelligence.get("inventory_complete"))
                                 if intelligence.get("mode", "off") != "off" else None}
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": report["tool"], "version": report["version"],
                                        "informationUri": "https://github.com/ruslancotcaev9-cyber/protestware_check",
                                        "rules": definitions}},
                      "automationDetails": {"id": "protestware-check/static-analysis"},
                      "invocations": [{"executionSuccessful": all(value is not False for value in coverage.values()),
                                       "properties": {"analysisCoverage": coverage},
                                       "toolExecutionNotifications": [
                                           {"level": "warning", "message": {"text": str(warning)}}
                                           for warning in report.get("warnings", []) +
                                           report.get("dependencies", {}).get("summary", {}).get("warnings", [])]}],
                      "results": results}]}
