# SPDX-License-Identifier: Apache-2.0
"""First-install profile: create ``agent.json`` with a fresh asset identity, never overwrite one."""
import json
import os
from pathlib import Path
import uuid

from ..core.tags import hostname

# Documented in docs/usage/agent.md; ``agent/agent.example.json`` is kept equal by a test.
PROFILE_TEMPLATE = {
    "url": "https://patchwatch.example.org",
    "host_id": "replace-with-stable-asset-id",
    "api_key_file": "/etc/patchwatch/api-key",
    "roots": ["/usr", "/opt"],
    "images": [],
    "scan_extensions": True,
    "tags": [],
    "excludes": [],
    "detect_services": True,
    "scan_timeout": 7200,
    "lock_file": "/var/lib/patchwatch/agent.lock",
    "agent_scope": "system",
}


def initialize_profile(path, *, syft=None, host_id=None, host_name=None) -> bool:
    """Write a profile for this machine unless ``path`` exists; returns whether it was created.

    The identity (``host_id``) is generated here, once: cloned OS images and packages therefore
    never share one. The file is created exclusively with mode 0600.
    """
    path = Path(path)
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    profile = dict(PROFILE_TEMPLATE, host_id=host_id or str(uuid.uuid4()), hostname=hostname(host_name))
    if syft:
        profile["syft"] = str(syft)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(descriptor, "w") as stream:
        json.dump(profile, stream, indent=2)
        stream.write("\n")
    return True
