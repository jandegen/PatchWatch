# SPDX-License-Identifier: Apache-2.0
"""Validated agent configuration.

The agent reads one JSON file (default ``/etc/patchwatch/agent.json``). :meth:`AgentConfig.from_dict`
checks everything that can be checked without touching the network or the scanner, so that a
broken profile fails fast and with a message that contains neither URLs nor secrets.
"""
from dataclasses import dataclass, field
import json
from pathlib import Path
import stat
from typing import Any, Mapping, Optional
import uuid

from ..core.http import check_url
from ..core.tags import hostname, inventory_tags

DEFAULT_CONFIG_PATH = "/etc/patchwatch/agent.json"
DEFAULT_LOCK_FILE = "/var/lib/patchwatch/agent.lock"
DEFAULT_ROOTS = ("/usr", "/opt")
DEFAULT_SCAN_TIMEOUT = 7200
DEFAULT_POLL_ATTEMPTS = 120


def _string_list(raw: Mapping[str, Any], key: str, default=()) -> tuple:
    value = raw.get(key, list(default))
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a list of strings")
    return tuple(value)


def _positive_int(raw: Mapping[str, Any], key: str, default: int) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{key} must be a positive integer")
    return value


@dataclass(frozen=True)
class AgentConfig:
    """Everything one agent run needs. Instances are immutable and contain no secret values."""

    url: str                      # Dependency-Track base URL, validated by ``check_url``
    host_id: str                  # stable asset identifier, never derived from the hostname
    host_name: str                # normalized DNS hostname
    tags: tuple                   # canonical project tags (key:value)
    api_key_file: Path            # the upload key lives in a 0600/0400 file, never in the profile
    project_uuid: Optional[str] = None
    roots: tuple = DEFAULT_ROOTS
    images: tuple = ()
    excludes: tuple = ()
    syft: str = "syft"
    scan_timeout: int = DEFAULT_SCAN_TIMEOUT
    poll_attempts: int = DEFAULT_POLL_ATTEMPTS
    lock_file: Path = Path(DEFAULT_LOCK_FILE)
    allow_empty: bool = False
    detect_services: bool = True
    # Options that only the extension scanner reads (``scan_extensions``, ``extension_homes``).
    extension_options: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "AgentConfig":
        """Validate a decoded profile; raises ``ValueError`` with a secret-free message."""
        url = check_url(raw["url"], raw.get("allow_http", False)) if "url" in raw else None
        if url is None:
            raise ValueError("url is required")
        if "?" in url:
            raise ValueError("API base URL must not contain a query")
        if not raw.get("host_id"):
            raise ValueError("host_id is required")
        host_name = hostname(raw.get("hostname"))
        tags = inventory_tags(raw, host_name)
        project_uuid = str(uuid.UUID(raw["project_uuid"])) if raw.get("project_uuid") else None
        if not raw.get("api_key_file"):
            raise ValueError("api_key_file is required")
        return cls(
            url=url, host_id=str(raw["host_id"]), host_name=host_name, tags=tuple(tags),
            api_key_file=Path(raw["api_key_file"]), project_uuid=project_uuid,
            roots=_string_list(raw, "roots", DEFAULT_ROOTS), images=_string_list(raw, "images"),
            excludes=_string_list(raw, "excludes"), syft=str(raw.get("syft", "syft")),
            scan_timeout=_positive_int(raw, "scan_timeout", DEFAULT_SCAN_TIMEOUT),
            poll_attempts=_positive_int(raw, "poll_attempts", DEFAULT_POLL_ATTEMPTS),
            lock_file=Path(raw.get("lock_file", DEFAULT_LOCK_FILE)),
            allow_empty=bool(raw.get("allow_empty", False)),
            detect_services=bool(raw.get("detect_services", True)),
            extension_options={k: raw[k] for k in ("scan_extensions", "extension_homes") if k in raw})

    @classmethod
    def load(cls, path) -> "AgentConfig":
        return cls.from_dict(json.loads(Path(path).read_text()))

    def read_api_key(self) -> str:
        """The upload key; refuses group/world-accessible files and keys with line breaks."""
        if stat.S_IMODE(self.api_key_file.stat().st_mode) & 0o077:
            raise ValueError("API key file must have mode 0600 or 0400")
        key = self.api_key_file.read_text().strip()
        if not key or any(c in key for c in "\r\n"):
            raise ValueError("Empty or invalid API key")
        return key
