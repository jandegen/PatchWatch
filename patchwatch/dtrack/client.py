# SPDX-License-Identifier: Apache-2.0
"""Thin Dependency-Track 5.x REST client (API v1 and v2) and the administrative login.

The client only transports requests. Which settings, teams or policies a deployment needs is
decided by :mod:`patchwatch.dtrack.setup`, so that read-only consumers (CI, monitoring,
reports) can share this module without pulling in the provisioning code.
"""
import json
import os
import urllib.error
from urllib.parse import urlencode

from ..core.http import check_url, request, secret

PAGE_SIZE = 100


class DependencyTrack:
    """Authenticated access to one Dependency-Track instance.

    ``headers`` carry the credential (``X-Api-Key`` or ``Authorization``); the client never
    logs or otherwise exposes them.
    """

    def __init__(self, url, headers):
        self.url, self.headers = url, headers

    def _send(self, prefix, path, data, method):
        headers = dict(self.headers)
        if data is not None:
            data = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        try:
            return request(self.url + prefix + path, data, headers, method)[0]
        except urllib.error.HTTPError as error:
            if error.code != 304:  # an update that would not change anything is not an error
                raise
            error.close()
            return None

    def call(self, path, data=None, method=None):
        """Request ``/api/v1/<path>``; ``data`` is sent as JSON. Returns the decoded body (``None`` for HTTP 304)."""
        return self._send("/api/v1/", path, data, method)

    def v2(self, path, data=None, method=None):
        """Request ``/api/v2/<path>``; the HTTP 304 of an update without changes yields ``None``."""
        return self._send("/api/v2/", path, data, method)

    def all(self, path):
        """All items of a paginated v1 list endpoint."""
        items, page = [], 1
        while True:
            batch = self.call(path + ("&" if "?" in path else "?") + urlencode({"pageNumber": page, "pageSize": PAGE_SIZE}))
            items.extend(batch)
            if len(batch) < PAGE_SIZE:
                return items
            page += 1

    def secret(self, name, value):
        """Create or rotate a managed secret; extensions reference credentials by secret name only."""
        try:
            self.v2("secrets", {"name": name, "value": value}, "POST")
        except urllib.error.HTTPError as error:
            if error.code != 409:
                raise
            error.close()
            self.v2("secrets/" + name, {"value": value}, "PATCH")
        return name

    def extension(self, point, name, **config):
        """Merge settings into an extension's runtime config, preserving unrelated administrator choices."""
        path = f"extension-points/{point}/extensions/{name}/config"
        try:
            current = (self.v2(path) or {}).get("config", {})
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            error.close()
            current = {}
        current.update(config)
        self.v2(path, {"config": current}, "PUT")

    def mirror(self, source):
        """Start a vulnerability data source mirror run now; a run that is already active is fine."""
        try:
            self.v2(f"vuln-data-sources/{source}/mirror-runs", {}, "POST")
        except urllib.error.HTTPError as error:
            if error.code not in (409, 304):
                raise
            error.close()

    def property(self, group, name, value, kind="BOOLEAN"):
        """Set a global configuration property."""
        self.call("configProperty", {"groupName": group, "propertyName": name, "propertyValue": value,
                                     "propertyType": kind}, "POST")


def read_only_client(url=None, key=None):
    """Client for the read-only key of a CI job or monitor, taken from ``DT_URL`` / ``DT_API_KEY(_FILE)``."""
    url = check_url(url or os.environ["DT_URL"], os.getenv("ALLOW_HTTP") == "true")
    key = key or secret("DT_API_KEY")
    if not key:
        raise ValueError("DT_API_KEY(_FILE) is required")
    return DependencyTrack(url, {"X-Api-Key": key})


def admin_client(url, initial_admin=False):
    """Client with administrative rights: ``DT_ADMIN_API_KEY`` or a login as ``admin``.

    With ``initial_admin`` the factory default password of a fresh installation is rotated once.
    """
    url = check_url(url, os.getenv("ALLOW_HTTP") == "true")
    api_key = secret("DT_ADMIN_API_KEY")
    if api_key:
        return DependencyTrack(url, {"X-Api-Key": api_key})
    password = secret("DT_ADMIN_PASSWORD")
    if not password:
        raise ValueError("DT_ADMIN_PASSWORD(_FILE) or DT_ADMIN_API_KEY(_FILE) is required")

    def form(path, fields):
        return request(url + "/api/v1/user/" + path, urlencode(fields).encode(),
                       {"Content-Type": "application/x-www-form-urlencoded"}, "POST")[0]

    try:
        token = form("login", {"username": "admin", "password": password})
    except urllib.error.HTTPError as error:
        if not initial_admin or error.code not in (401, 403):
            raise
        form("forceChangePassword", {"username": "admin", "password": "admin", "newPassword": password,
                                     "confirmPassword": password})
        token = form("login", {"username": "admin", "password": password})
    return DependencyTrack(url, {"Authorization": "Bearer " + token})
