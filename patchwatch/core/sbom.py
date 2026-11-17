# SPDX-License-Identifier: Apache-2.0
"""SBOM reduction and upload shared by the host agent and the GitLab CI integration."""
import hashlib
import json
import re
import time
import urllib.error
import uuid

from .http import request as http_request


def license_choices(raw):
    """Keep identifiers and short license names, without license texts, URLs or provenance."""
    choices = []
    expressions = []
    if not isinstance(raw, list):
        return []
    for choice in raw:
        if not isinstance(choice, dict):
            continue
        expression = choice.get("expression")
        if isinstance(expression, str) and 0<len(expression)<=1024 and re.fullmatch(r"[A-Za-z0-9.+(): _-]+", expression):
            entry = {"expression": expression.strip()}
            if choice.get("acknowledgement") in ("declared", "concluded"):
                entry["acknowledgement"] = choice["acknowledgement"]
            expressions.append(entry)
            continue
        license = choice.get("license")
        if not isinstance(license, dict):
            continue
        identifier, name = license.get("id"), license.get("name")
        if isinstance(identifier, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,127}", identifier):
            item = {"id": identifier}
        elif isinstance(name, str) and 0<len(name.strip())<=160 and not any(c in name for c in "\r\n"):
            item = {"name": name.strip()}
        else:
            continue
        if license.get("acknowledgement") in ("declared", "concluded"):
            item["acknowledgement"] = license["acknowledgement"]
        choices.append({"license": item})
    # CycloneDX permits either license objects or exactly one expression, never a mixture.
    # An expression is kept verbatim; AND/OR semantics are not guessed.
    result = expressions[:1] if expressions else choices
    return [json.loads(s) for s in sorted({json.dumps(c,sort_keys=True) for c in result})]


def merge_licenses(previous, incoming):
    """Union of two license lists; returns ``(licenses, conflict)`` where ``conflict`` is true when different expressions cannot be combined without a licensing decision."""
    if not previous: return incoming, False
    if not incoming or previous==incoming: return previous, False
    if all("license" in choice for choice in previous+incoming):
        return [json.loads(s) for s in sorted({json.dumps(c,sort_keys=True) for c in previous+incoming})], False
    # Different expressions cannot safely be combined without a licensing decision.
    return previous, True


def sanitize(boms, host_name, asset_id=None, version="current", root_type="device", services=()):
    """Reduce Syft SBOMs to the privacy-minimized CycloneDX document that is uploaded.

    Keeps package identity, license identifiers, package paths and the scanner's dependency edges; drops
    everything else (file entries, metadata, descriptions). Components are deduplicated across ``boms`` and
    anchored below one root component identified by ``asset_id`` (or ``host_name``)."""
    components = {}
    source_maps = []
    for bom in boms:
        refs = {}
        for source in bom.get("components", []):
            if source.get("type") == "file" or not source.get("name"):
                continue
            item = {k: source[k] for k in ("type", "group", "name", "version", "purl", "cpe") if source.get(k)}
            item.setdefault("type", "library")
            # Only package paths; Syft metadata, file contents, users and environment are discarded.
            paths = []
            for prop in source.get("properties", []):
                if prop.get("name", "").startswith("syft:location:") and prop["name"].endswith(":path"):
                    paths.append({"name": prop["name"], "value": str(prop.get("value", ""))})
            identity = json.dumps(item, sort_keys=True)
            ref = hashlib.sha256(identity.encode()).hexdigest()
            if source.get("bom-ref"):
                refs[source["bom-ref"]] = ref
            item["bom-ref"] = ref
            previous = components.get(ref, {})
            licenses, conflict = merge_licenses(previous.get("licenses", []), license_choices(source.get("licenses", [])))
            if licenses:
                item["licenses"] = licenses
            if conflict:
                paths.append({"name": "patchwatch:license-conflict", "value": "true"})
            old = previous.get("properties", [])
            unique = {(p["name"], p["value"]): p for p in old + paths}
            if unique:
                item["properties"] = list(unique.values())
            components[ref] = item
        source_maps.append(refs)
    # References are local to each source SBOM. Deduplication must never join unrelated
    # packages merely because two scans assigned the same original bom-ref.
    edges = {ref: set() for ref in components}
    for bom, refs in zip(boms, source_maps):
        for dependency in bom.get("dependencies", []):
            parent = refs.get(dependency.get("ref"))
            if parent:
                edges[parent].update(refs[child] for child in dependency.get("dependsOn", [])
                                     if child in refs and refs[child] != parent)
    root_ref = "urn:patchwatch:host:" + hashlib.sha256((asset_id or host_name).encode()).hexdigest()
    # Anchor only the scanner's known dependency subgraphs. Linking the host directly
    # to every unrelated inventory entry both invents dependency information and makes
    # DTrack 4.14 materialize a very large project dependency field for every SQL row.
    children = set().union(*edges.values()) if edges else set()
    nodes = {ref for ref, targets in edges.items() if targets} | children
    roots = sorted(nodes - children)
    reached = set()
    def visit(seed):
        pending = [seed]
        while pending:
            node = pending.pop()
            if node not in reached:
                reached.add(node)
                pending.extend(edges[node] - reached)
    for root in roots:
        visit(root)
    # A disconnected cycle has no indegree-zero root, but must remain reachable.
    for node in sorted(nodes):
        if node not in reached:
            roots.append(node)
            visit(node)
    dependencies = [{"ref": root_ref, "dependsOn": roots}]
    # Absence of a record means the scanner did not establish this package's dependencies;
    # an empty list would incorrectly claim that it has none.
    dependencies.extend({"ref": ref, "dependsOn": sorted(children)}
                        for ref, children in sorted(edges.items()) if children)
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
            "metadata": {"component": {"type": root_type, "name": host_name, "version": version, "bom-ref": root_ref,
                                       **({"properties": [{"name": "patchwatch:asset-id", "value": asset_id}]} if asset_id else {})}},
            "components": list(components.values()), "dependencies": dependencies}
    if services:
        bom["services"] = list(services)
    return bom


def multipart(fields, bom):
    """Encode ``fields`` and the BOM as ``multipart/form-data``; returns ``(body, content type)``."""
    boundary = uuid.uuid4().hex
    body = bytearray()
    for key, value in fields.items():
        body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
    body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="bom"; filename="sbom.json"\r\nContent-Type: application/json\r\n\r\n'.encode())
    body.extend(json.dumps(bom).encode())
    body.extend(f'\r\n--{boundary}--\r\n'.encode())
    return bytes(body), "multipart/form-data; boundary=" + boundary


def rejection(error):
    """Reason of an HTTP 400: Dependency-Track reports validation problems there. Other bodies stay out of logs."""
    if error.code != 400 or not error.fp:
        return ""
    try:
        text = error.read(2048).decode("utf-8", errors="replace")
    except Exception:
        return ""
    text = "".join(c if c.isprintable() else " " for c in text).strip()
    return ": " + text[:300] if text else ""


def upload_and_wait(url, key, fields, bom, poll_attempts=120, request=http_request, sleep=time.sleep):
    """POST the SBOM (retrying transient failures) and wait until DTrack finished processing it."""
    body, content_type = multipart(fields, bom)
    if len(body) > 128 * 1024 * 1024:
        raise RuntimeError("SBOM exceeds the 128 MiB gateway upload limit")
    headers = {"X-Api-Key": key, "Content-Type": content_type}
    for attempt in range(4):
        try:
            result, _ = request(url + "/api/v1/bom", body, headers, "POST")
            break
        except urllib.error.HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504) or attempt == 3:
                raise RuntimeError(f"Upload failed (HTTP {error.code}){rejection(error)}") from None
        except (urllib.error.URLError, TimeoutError):
            if attempt == 3:
                raise RuntimeError("Upload failed: network/TLS error") from None
        sleep(2 ** attempt)
    token = (result or {}).get("token")
    if not token:
        raise RuntimeError("Upload response did not include a processing token")
    # Acceptance is asynchronous. Wait for processing; findings can arrive later.
    failures = 0
    for _ in range(poll_attempts):
        try:
            status, _ = request(url + "/api/v1/bom/token/" + str(uuid.UUID(token)), headers={"X-Api-Key": key})
        except urllib.error.HTTPError as error:
            # A busy API server (several large uploads at once) may answer a status check with 5xx.
            failures += 1
            if error.code not in (429, 500, 502, 503, 504) or failures > 10:
                raise RuntimeError(f"Status check failed (HTTP {error.code})") from None
            sleep(5)
            continue
        except (urllib.error.URLError, TimeoutError):
            failures += 1
            if failures > 10:
                raise RuntimeError("Status check failed: network/TLS error") from None
            sleep(5)
            continue
        failures = 0
        if not status.get("processing", True):
            return
        sleep(5)
    raise RuntimeError("SBOM processing did not finish within the polling budget")
