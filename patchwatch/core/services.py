# SPDX-License-Identifier: Apache-2.0
"""CycloneDX services found next to the packages: the services of Compose files below the scan paths.

Shared by the agent and the CI module. Only service names and image references are taken over (no
environment, secrets, volumes or commands). Stdlib only, so Compose files are read with a small
line parser instead of a YAML library."""
import os
from pathlib import Path
import re

COMPOSE_FILES = {n + e for n in ("compose", "docker-compose") for e in (".yaml", ".yml")}
SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "__pycache__", "site-packages", "proc", "sys"}
KEY = re.compile(r"""^(\s*)(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9][A-Za-z0-9._-]*))\s*:\s*(.*?)\s*(?:#.*)?$""")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
MAX_DEPTH = 5
MAX_SERVICES = 200


def compose_services(text):
    """[(name, image or None)] of the top-level `services:` mapping of a Compose file."""
    result, inside, child_indent, prop_indent, current = [], False, None, None, None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = KEY.match(line)
        if not match:
            continue
        indent = len(match.group(1).expandtabs())
        key = match.group(2) or match.group(3) or match.group(4)
        value = match.group(5).strip("'\"")
        if indent == 0:
            inside, child_indent, prop_indent, current = key == "services", None, None, None
        elif inside:
            if child_indent is None:
                child_indent = indent
            if indent == child_indent:
                current, prop_indent = [key, None], None
                result.append(current)
            elif current and indent > child_indent:
                if prop_indent is None:
                    prop_indent = indent
                if indent == prop_indent and key == "image" and value:
                    current[1] = value
    return [(n, i) for n, i in result if NAME.fullmatch(n)]


def find_services(paths):
    """CycloneDX service entries of all Compose files below the given directories."""
    found = {}
    for base in paths:
        base = Path(base)
        for folder, dirs, files in os.walk(base):
            depth = len(Path(folder).relative_to(base).parts)
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS] if depth < MAX_DEPTH else []
            for file in sorted(COMPOSE_FILES.intersection(files)):
                try:
                    text = (Path(folder) / file).read_text(errors="replace")
                except OSError:
                    continue
                for name, image in compose_services(text):
                    found.setdefault(name, image)
    return [service(name, image) for name, image in sorted(found.items())[:MAX_SERVICES]]


def service(name, image=None):
    """CycloneDX service entry for a Compose service; the version is the image tag and the image reference is kept as a property (never with variables)."""
    item = {"bom-ref": "service:" + name, "name": name}
    if image:
        reference = image.split("@", 1)[0]
        tag = reference.rsplit(":", 1)[1] if ":" in reference.rsplit("/", 1)[-1] else None
        if tag and "$" not in tag:
            item["version"] = tag
        if "$" not in image:
            item["properties"] = [{"name": "patchwatch:image", "value": image}]
    return item


def merge(*lists):
    """Union by name; the first list wins."""
    merged = {}
    for items in lists:
        for item in items:
            merged.setdefault(item["name"], item)
    return [merged[name] for name in sorted(merged)]
