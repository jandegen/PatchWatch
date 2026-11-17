# SPDX-License-Identifier: Apache-2.0
"""Lossless inventory relationships and BSI TR-03183-2 v2.1 checks for CI.

Kept separate from the host agent's deliberately reduced inventory. Scanner output
is evidence, not a licensing decision or proof that the delivery scope is complete.
"""
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
import uuid


SCHEMAS = Path(__file__).with_name("schemas")
FIELDS = ("type", "group", "name", "version", "manufacturer", "authors", "author",
          "supplier", "purl", "cpe", "swid", "omniborId", "swhid", "hashes", "licenses", "externalReferences")
FLAGS = {"executable": ("executable", "non-executable"),
         "archive": ("archive", "no archive"), "structured": ("structured", "unstructured")}


def file_metadata(bom, workspace, scan_root=None):
    """Use actual local file metadata only for directory scans, never image paths.

    File classification and distribution locations need producer evidence; they
    cannot be inferred from the executable permission bit or a package purl.
    """
    def visit(item):
        if item.get("type") == "file":
            name = item.get("name", "")
            properties = item.setdefault("properties", [])
            if not any(p.get("name") == "bsi:component:filename" for p in properties):
                properties.append({"name": "bsi:component:filename", "value": name.rsplit("/", 1)[-1]})
            if scan_root is not None and name and not item.get("version"):
                # Syft directory coordinates are rooted in the scanned tree
                # (e.g. /bin/start.sh), not in the CI runner's host filesystem.
                path = (scan_root / name.lstrip("/")).resolve()
                if path.is_relative_to(workspace) and path.is_relative_to(scan_root) and path.is_file():
                    item["version"] = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        for child in item.get("components", []):
            visit(child)
    for item in bom.get("components", []):
        visit(item)


def component(source):
    """Reduce a scanned component to the fields allowed in the BSI SBOM and map explicit author contacts to creators."""
    result = {k: deepcopy(source[k]) for k in FIELDS if k in source}
    result.setdefault("type", "library")
    # Explicit author contacts can supply creator evidence. A supplier or publisher
    # name alone cannot. Retain the original fields as well as the mapped contact.
    manufacturer = result.get("manufacturer", {})
    if isinstance(manufacturer, dict) and not manufacturer.get("url") and not manufacturer.get("contact"):
        contacts = [deepcopy(author) for author in source.get("authors", [])
                    if isinstance(author, dict) and author.get("email")]
        if contacts:
            result.setdefault("manufacturer", {})["contact"] = contacts
        elif isinstance(source.get("author"), str):
            try:
                author = entity(source["author"])
                if author:
                    result.setdefault("manufacturer", {}).update(author)
            except ValueError:
                pass
    # Retain compliance data and package locations, never arbitrary scanner metadata,
    # embedded file contents, vulnerability data or invalidated source signatures.
    properties = [deepcopy(p) for p in source.get("properties", [])
                  if p.get("name", "").startswith(("bsi:component:", "patchwatch:bsi:"))
                  or (p.get("name", "").startswith("syft:location:") and p["name"].endswith(":path"))]
    if properties:
        result["properties"] = properties
    return result


def assemble(boms, name, version, services=()):
    """Namespace each source's refs; keep instances, source roots and known leaves.

    Containment of scanned components is a directed dependency under TR 3.2.7.
    Unknown dependency lists stay unknown, rather than being turned into leaves.
    """
    root_ref = "urn:patchwatch:ci:" + hashlib.sha256(name.encode()).hexdigest()
    root = {"type": "application", "name": name, "version": version, "bom-ref": root_ref}
    output = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
              "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
              "metadata": {"component": root}, "components": [], "dependencies": [], "compositions": []}
    edges = {root_ref: set()}
    completeness = set()
    for index, bom in enumerate(boms):
        refs, records, nesting = {}, [], []

        def add(source, path, parent=None):
            original = source.get("bom-ref")
            ref = "urn:patchwatch:component:" + hashlib.sha256(f"{index}:{path}:{original or ''}".encode()).hexdigest()
            if original:
                if original in refs:
                    raise ValueError("Scanner SBOM has duplicate component references")
                refs[original] = ref
            item = component(source)
            def namespace(value, location):
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key == "bom-ref":
                            value[key] = "urn:patchwatch:detail:" + hashlib.sha256(f"{ref}:{location}:{child}".encode()).hexdigest()
                        else:
                            namespace(child, location + "/" + key)
                elif isinstance(value, list):
                    for number, child in enumerate(value):
                        namespace(child, location + "/" + str(number))
            namespace(item, "")
            item["bom-ref"] = ref
            output["components"].append(item)
            records.append(ref)
            if parent:
                nesting.append((parent, ref))
            for number, child in enumerate(source.get("components", [])):
                add(child, f"{path}/{number}", ref)
            return ref

        source_root = bom.get("metadata", {}).get("component")
        anchor = add(source_root, "root") if source_root else root_ref
        if source_root:
            edges[root_ref].add(anchor)
        for number, source in enumerate(bom.get("components", [])):
            ref = add(source, str(number))
            nesting.append((anchor, ref))
        for parent, child in nesting:
            edges.setdefault(parent, set()).add(child)
        for dep in bom.get("dependencies", []):
            if dep.get("ref") not in refs or any(child not in refs for child in dep.get("dependsOn", [])):
                raise ValueError("Scanner SBOM contains unresolved dependency references")
            edges.setdefault(refs[dep["ref"]], set()).update(refs[child] for child in dep.get("dependsOn", []))
        for composition in bom.get("compositions", []):
            item = {"aggregate": composition["aggregate"]}
            for key in ("assemblies", "dependencies"):
                if key in composition:
                    if any(ref not in refs for ref in composition[key]):
                        raise ValueError("Scanner SBOM contains unresolved composition references")
                    item[key] = [refs[ref] for ref in composition[key]]
                    completeness.update(item[key])
            if len(item) > 1:
                output["compositions"].append(item)
        # Explicitly communicate what the scanner has not established. Never infer
        # complete recursive delivery coverage from a successful package scan.
        unknown = sorted(set(records) - completeness)
        if unknown:
            output["compositions"].append({"aggregate": "unknown", "dependencies": unknown})
            completeness.update(unknown)
    output["dependencies"] = [{"ref": ref, "dependsOn": sorted(children)} for ref, children in edges.items()]
    output["compositions"].append({"aggregate": "unknown", "dependencies": [root_ref]})
    if services:
        output["services"] = deepcopy(list(services))
    return output


def entity(value):
    """Only an explicitly configured creator, never an inferred package supplier."""
    if not value:
        return None
    if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        return {"contact": [{"email": value}]}
    parts = urlsplit(value)
    if parts.scheme in ("http", "https") and parts.hostname and not parts.username and not parts.password:
        return {"url": [value]}
    raise ValueError("SBOM/component creator must be an email address or HTTP(S) URL")


def local_file(workspace, filename):
    """Existing file below the workspace; paths that leave the project directory are rejected."""
    path = (workspace / filename).resolve()
    if not path.is_relative_to(workspace) or not path.is_file():
        raise ValueError("BSI metadata/artifact paths must be existing files inside CI_PROJECT_DIR")
    return path


def enrich(bom, env, workspace):
    """Apply reviewed per-component metadata, and hash explicitly selected artifacts.

    Selectors are exact output bom-refs, purls or file: paths. No wildcard creator/licence
    defaults are applied to third-party components. Unmatched selectors fail.
    """
    root = bom["metadata"]["component"]
    creator = entity(env.get("PATCHWATCH_SBOM_CREATOR") or env.get("CI_PROJECT_URL"))
    if creator:
        bom["metadata"]["manufacturer"] = creator
    author = entity(env.get("PATCHWATCH_COMPONENT_CREATOR") or env.get("CI_PROJECT_URL"))
    if author:
        root["manufacturer"] = author
    if env.get("PATCHWATCH_DISTRIBUTION_LICENSE"):
        root["licenses"] = [{"expression": env["PATCHWATCH_DISTRIBUTION_LICENSE"], "acknowledgement": "concluded"}]
    filename = env.get("PATCHWATCH_BSI_METADATA")
    if not filename:
        return
    data = json.loads(local_file(workspace, filename).read_text())
    if not isinstance(data, dict) or set(data) - {"root", "components"}:
        raise ValueError("BSI metadata must contain root and/or components")

    def apply(item, extra):
        if not isinstance(extra, dict) or set(extra) - set(FIELDS) - {"properties", "artifact"}:
            raise ValueError("Unsupported component metadata field")
        if "licenses" in extra and item.get("licenses") and item["licenses"] != extra["licenses"]:
            # CDX 1.6 permits exactly one licence expression. Preserve the scanner's
            # original observations when a reviewed distribution expression replaces it.
            item.setdefault("properties", []).append({"name": "patchwatch:bsi:original-licenses",
                                                       "value": json.dumps(item["licenses"], sort_keys=True)})
        for key in FIELDS:
            if key in extra:
                if key == "externalReferences":
                    item[key] = item.get(key, []) + deepcopy(extra[key])
                else:
                    item[key] = deepcopy(extra[key])
        if "properties" in extra:
            replacements = {p["name"] for p in extra["properties"]}
            item["properties"] = [p for p in item.get("properties", []) if p["name"] not in replacements] + deepcopy(extra["properties"])
        if extra.get("artifact"):
            path = local_file(workspace, extra["artifact"])
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha512").hexdigest()
            item.setdefault("hashes", [])[:] = [h for h in item.get("hashes", []) if h["alg"] != "SHA-512"] + [{"alg": "SHA-512", "content": digest}]
            properties = [p for p in item.get("properties", []) if p["name"] != "bsi:component:filename"]
            item["properties"] = properties + [{"name": "bsi:component:filename", "value": path.name}]
            if not item.get("version"):
                item["version"] = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
            # Distribution URL must be supplied by the producer, not an invented URL
            # to a runner's local filesystem.
            for ref in item.get("externalReferences", []):
                if ref.get("type") == "distribution":
                    ref["hashes"] = [h for h in ref.get("hashes", []) if h["alg"] != "SHA-512"] + [{"alg": "SHA-512", "content": digest}]
        # Scanner SHA-512 hashes refer to the file itself. Attach them to an
        # explicitly supplied distribution reference for the TR 8.2 mapping.
        hashes = [h for h in item.get("hashes", []) if h.get("alg") == "SHA-512"]
        for ref in item.get("externalReferences", []):
            if ref.get("type") == "distribution" and hashes and not ref.get("hashes"):
                ref["hashes"] = deepcopy(hashes)

    apply(root, data.get("root", {}))
    overrides = data.get("components", {})
    if not isinstance(overrides, dict):
        raise ValueError("BSI components metadata must be an object indexed by bom-ref or purl")
    for selector, extra in overrides.items():
        matches = [c for c in bom.get("components", []) if selector in
                   (c.get("bom-ref"), c.get("purl"), "file:" + c.get("name", "") if c.get("type") == "file" else None)]
        if not matches:
            raise ValueError("BSI metadata selector does not match any scanned component: " + selector)
        if len(matches) > 1 and any(k in extra for k in ("artifact", "hashes", "version", "name", "type")):
            raise ValueError("Instance-specific BSI metadata requires a unique bom-ref selector")
        for item in matches:
            apply(item, extra)


@lru_cache(maxsize=1)
def schema_validator():
    # Offline registry: validation never fetches untrusted schema references.
    """JSON-schema validator for CycloneDX 1.6 with an offline schema registry (no network access)."""
    from jsonschema import Draft7Validator, FormatChecker
    from referencing import Registry, Resource
    schemas = [json.loads((SCHEMAS / name).read_text()) for name in
               ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")]
    registry = Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in schemas)
    return Draft7Validator(schemas[0], registry=registry, format_checker=FormatChecker())


@lru_cache(maxsize=1)
def license_identifiers():
    """``(valid SPDX license ids, valid license exception ids)`` from the packaged schemas."""
    return (set(json.loads((SCHEMAS / "spdx.schema.json").read_text())["enum"]),
            set(json.loads((SCHEMAS / "license-exceptions.json").read_text())))


def valid_expression(expression):
    """Parse SPDX AND/OR/WITH and parentheses; reject names and unknown identifiers."""
    if not isinstance(expression, str) or len(expression) > 4096:
        return False
    tokens = re.findall(r"\(|\)|[^\s()]+", expression)
    identifiers, exceptions = license_identifiers()
    position = 0

    def identifier(token):
        return (token in identifiers or (token.endswith("+") and token[:-1] in identifiers)
                or bool(re.fullmatch(r"LicenseRef-[A-Za-z0-9.-]+", token)))

    def atom():
        nonlocal position
        if position >= len(tokens):
            raise ValueError
        token = tokens[position]
        position += 1
        if token == "(":
            expression_rule()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError
            position += 1
        else:
            if not identifier(token):
                raise ValueError
            if position < len(tokens) and tokens[position] == "WITH":
                position += 1
                if position >= len(tokens) or tokens[position] not in exceptions:
                    raise ValueError
                position += 1

    def expression_rule():
        nonlocal position
        atom()
        while position < len(tokens) and tokens[position] in ("AND", "OR"):
            position += 1
            atom()

    try:
        expression_rule()
        return position == len(tokens)
    except (ValueError, RecursionError):
        return False


def findings(bom):
    """Machine-checkable requirements; completeness of physical delivery is an audit duty."""
    issues = []

    def fail(rule, ref, message):
        issues.append({"rule": rule, "ref": ref, "message": message})

    for error in schema_validator().iter_errors(bom):
        fail("4", "/" + "/".join(map(str, error.absolute_path)), "Invalid CycloneDX 1.6: " + error.validator)
    if issues:
        return issues  # Semantic checks assume the types guaranteed by the schema.
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        fail("4", "document", "CycloneDX 1.6 is required by this validator")
    if bom.get("vulnerabilities"):
        fail("3.1", "document", "Vulnerability information must be distributed separately")

    def creator(value):
        if not isinstance(value, dict):
            return False
        candidates = value.get("url", []) + [c.get("email", "") for c in value.get("contact", [])]
        for candidate in candidates:
            try:
                if entity(candidate):
                    return True
            except ValueError:
                pass
        return False

    metadata = bom.get("metadata", {})
    if not creator(metadata.get("manufacturer")):
        fail("5.2.1", "document", "SBOM creator email/URL missing")
    timestamp = metadata.get("timestamp", "")
    try:
        if not re.fullmatch(r"\d{4}-\d\d-\d\d[Tt]\d\d:\d\d:\d\d(?:\.\d+)?(?:[Zz]|[+-]\d\d:\d\d)", timestamp):
            raise ValueError
        datetime.fromisoformat(timestamp.upper().replace("Z", "+00:00"))
    except ValueError:
        fail("5.2.1", "document", "Compilation timestamp missing or invalid (RFC 3339 required)")
    root = metadata.get("component", {})
    items = [root] + bom.get("components", [])
    refs = {c.get("bom-ref") for c in items}
    if None in refs or len(refs) != len(items):
        fail("4", "document", "Component bom-refs must be present and unique")
    all_refs = []
    def collect_refs(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "bom-ref":
                    all_refs.append(child)
                else:
                    collect_refs(child)
        elif isinstance(value, list):
            for child in value:
                collect_refs(child)
    collect_refs(bom)
    if len(all_refs) != len(set(all_refs)):
        fail("4", "document", "All CycloneDX bom-refs, including licence/organization refs, must be unique")
    known = set()
    aggregates = {}
    for composition in bom.get("compositions", []):
        known.update(composition.get("dependencies", []))
        known.update(composition.get("assemblies", []))
        for ref in composition.get("dependencies", []) + composition.get("assemblies", []):
            aggregates.setdefault(ref, set()).add(composition["aggregate"])
    for ref, values in aggregates.items():
        if "complete" in values and len(values) > 1:
            fail("3.1", ref, "Contradictory dependency completeness assertions")
    graph = {dep["ref"]: dep.get("dependsOn", []) for dep in bom.get("dependencies", [])}
    reached, pending = set(), [root.get("bom-ref")]
    while pending:
        current = pending.pop()
        if current not in reached:
            reached.add(current)
            pending.extend(graph.get(current, []))
    for ref in refs - reached:
        fail("5.1", ref, "Component is disconnected from the primary component")
    for dep in bom.get("dependencies", []):
        if dep["ref"] not in refs or any(ref not in refs for ref in dep.get("dependsOn", [])):
            fail("5.1", dep["ref"], "Unresolved dependency reference")
    if known - refs:
        fail("5.2.2", "document", "Unresolved composition reference")
    for item in items:
        ref = item.get("bom-ref", "primary")
        if not creator(item.get("manufacturer")):
            fail("5.2.2", ref, "Component creator email/URL missing")
        if not item.get("name", "").strip():
            fail("5.2.2", ref, "Component name missing")
        if not str(item.get("version", "")).strip() or str(item.get("version")).upper() in ("UNKNOWN", "NOASSERTION"):
            fail("5.2.2", ref, "Exact version or file modification timestamp missing")
        properties = {}
        for prop in item.get("properties", []):
            properties.setdefault(prop["name"], []).append(prop["value"])
        for original in properties.get("patchwatch:bsi:original-licenses", []):
            try:
                choices = json.loads(original)
                if not isinstance(choices, list) or not choices:
                    raise ValueError
                for choice in choices:
                    if not isinstance(choice, dict):
                        raise ValueError
                    license = choice.get("license", {})
                    if not isinstance(license, dict) or not valid_expression(choice.get("expression") or license.get("id") or license.get("name")):
                        raise ValueError
            except (ValueError, TypeError):
                fail("6.1", ref, "Original licence observations need reviewed SPDX identifiers/expressions")
        scope = properties.get("patchwatch:bsi:scope", ["delivery"])
        if len(scope) != 1 or scope[0] not in ("delivery", "identified"):
            fail("5.1", ref, "Scope must be delivery or identified (first external dependency)")
        if scope == ["identified"] and item is not root:
            continue  # TR 3.2.4: creator, name, version and available unique IDs.
        if ref not in known:
            fail("5.2.2", ref, "Dependency completeness missing")
        licenses = item.get("licenses", [])
        concluded = False
        for choice in licenses:
            license = choice.get("license", {})
            expression = choice.get("expression") or license.get("id") or license.get("name")
            if not valid_expression(expression):
                fail("6.1", ref, "A valid SPDX licence expression/identifier is required")
            if choice.get("acknowledgement", license.get("acknowledgement")) == "concluded":
                concluded = True
        if not concluded:
            fail("5.2.2", ref, "Reviewed distribution licences (concluded) missing")
        for reference in item.get("externalReferences", []):
            if reference["type"] in ("source-distribution", "distribution", "vcs") and not urlsplit(reference["url"]).scheme:
                fail("5.2.4", ref, "Source/distribution location must be an absolute URI")
        physical = item.get("type") == "file" or any("bsi:component:" + key in properties for key in ("filename", *FLAGS))
        if physical:
            filename = properties.get("bsi:component:filename", [])
            if len(filename) != 1 or not filename[0] or filename[0] in (".", "..") or "/" in filename[0] or "\\" in filename[0]:
                fail("5.2.2", ref, "Actual filename (without filesystem path) missing or invalid")
            for key, allowed in FLAGS.items():
                values = properties.get("bsi:component:" + key, [])
                if len(values) != 1 or values[0] not in allowed:
                    fail("5.2.2", ref, "Missing/invalid BSI property: " + key)
            hashes = [h for r in item.get("externalReferences", []) if r.get("type") == "distribution" for h in r.get("hashes", [])]
            if not any(h.get("alg") == "SHA-512" and re.fullmatch(r"[0-9a-fA-F]{128}", h.get("content", "")) for h in hashes):
                fail("5.2.2", ref, "SHA-512 of deployable artifact in distribution reference missing")
            sha512s = {h["content"].lower() for h in hashes + item.get("hashes", []) if h.get("alg") == "SHA-512"}
            if len(sha512s) > 1:
                fail("3.1", ref, "Conflicting SHA-512 hashes for the deployable component")
    by_ref = {item.get("bom-ref"): item for item in items}
    for issue in issues:
        if issue["ref"] in by_ref:
            item = by_ref[issue["ref"]]
            issue["component"] = {key: item[key] for key in ("name", "version", "purl") if key in item}
    return issues


def check_and_write(bom, env, workspace):
    """Always save the delivered document and pre-upload diagnostics, including on failure."""
    mode = env.get("PATCHWATCH_BSI_MODE", "enforce")
    if mode not in ("enforce", "report"):
        raise ValueError("PATCHWATCH_BSI_MODE must be enforce or report")
    errors = findings(bom)
    sbom = workspace / env.get("PATCHWATCH_SBOM_OUTPUT", "patchwatch-sbom.json")
    report = workspace / env.get("PATCHWATCH_BSI_REPORT", "patchwatch-bsi-report.json")
    sbom.write_text(json.dumps(bom, indent=2) + "\n")
    report.write_text(json.dumps({"standard": "BSI TR-03183-2 v2.1.0", "mode": mode,
                                 "checksPassed": not errors, "findings": errors,
                                 "deliveryCoverageVerified": False,
                                 "limitations": ["Delivery coverage and build-equivalent information require producer review."]}, indent=2) + "\n")
    if errors:
        print(f"BSI SBOM check: {len(errors)} findings; see {report.name}")
        if mode == "enforce" or any(issue["rule"] == "4" for issue in errors):
            raise ValueError("BSI SBOM requirements not met; upload refused (see " + report.name + ")")
    return errors
