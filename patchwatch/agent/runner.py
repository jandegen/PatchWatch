# SPDX-License-Identifier: Apache-2.0
"""One inventory run: scan, reduce to the privacy-minimized SBOM and upload it.

The run is split into small steps (:func:`single_instance`, :func:`collect_boms`,
:func:`upload`) so that each can be tested without Syft or a Dependency-Track server.
"""
from contextlib import contextmanager
import fcntl
from pathlib import Path
import tempfile
from typing import Mapping, Union

from ..core.http import request
from ..core.sbom import sanitize, upload_and_wait
from ..core.services import find_services
from .config import AgentConfig
from .extensions import collect as collect_extensions, reconcile as reconcile_extensions
from .scanner import scan, source_spec


@contextmanager
def single_instance(lock_path: Path):
    """Exclusive, non-blocking lock so that at most one agent runs per machine; yields whether it was acquired."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        yield True


def collect_boms(config: AgentConfig, extensions: dict, workdir: Path) -> list:
    """Scan every root and image; extension manifests found at a root are merged into Syft's records."""
    sources = [source_spec(root, True) for root in config.roots] + [source_spec(i, False) for i in config.images]
    boms = []
    for index, source in enumerate(sources):
        scanned = scan(config.syft, source, workdir / f"{index}.json", config.excludes, config.scan_timeout)
        if index < len(config.roots):
            reconcile_extensions(scanned, extensions, config.roots[index])
        boms.append(scanned)
    boms.append(extensions)
    return boms


def upload_fields(config: AgentConfig) -> dict:
    """Form fields of the BOM upload. With a registered ``project_uuid`` nothing is auto-created."""
    fields = {"autoCreate": "false" if config.project_uuid else "true", "projectName": config.host_name,
              "projectVersion": "current", "isLatest": "true", "projectTags": ",".join(config.tags)}
    if config.project_uuid:
        fields["project"] = config.project_uuid
    return fields


def run(config: Union[AgentConfig, Mapping]) -> None:
    """Create and upload the inventory of this host.

    Raises ``ValueError``/``RuntimeError``/``OSError``/``subprocess.SubprocessError`` for configuration,
    scan and upload problems; returns silently when another run holds the lock.
    """
    if not isinstance(config, AgentConfig):
        config = AgentConfig.from_dict(config)
    key = config.read_api_key()
    with single_instance(config.lock_file) as acquired:
        if not acquired:
            return
        extensions = collect_extensions(config.extension_options)
        if not config.roots and not config.images and not extensions["components"]:
            raise ValueError("At least one scan root, image or installed extension is required")
        # Raw Syft SBOMs live only in this directory and never outlive the process.
        with tempfile.TemporaryDirectory(prefix="patchwatch-") as directory:
            boms = collect_boms(config, extensions, Path(directory))
        services = find_services(config.roots) if config.detect_services else []
        bom = sanitize(boms, config.host_name, config.host_id, services=services)
        if not bom["components"] and not config.allow_empty:
            raise RuntimeError("Empty inventory rejected; verify scan roots and permissions")
        upload_and_wait(config.url, key, upload_fields(config), bom, config.poll_attempts, request=request)
        print(f"Inventory processed: {config.host_name} ({len(bom['components'])} components)")
