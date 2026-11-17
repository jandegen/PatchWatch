# SPDX-License-Identifier: Apache-2.0
"""CI, MR and branch container projects aggregate their component metrics.

The CI upload key cannot change projects, so this runs with the admin credentials of the setup
(every deployment) or on its own: python -m patchwatch.dtrack.groups
"""
import base64
import json
import time
import uuid
import urllib.error
from urllib.parse import urlencode
from .scopes import SCOPED_TAGS

LOGIC = "AGGREGATE_DIRECT_CHILDREN"
CI_TAG = "source:gitlab-ci"


class AggregationError(RuntimeError):
    """Safe, actionable diagnostic for the setup log."""


def _tag(project, key):
    return next((t["name"] for t in project.get("tags") or [] if t["name"].startswith(key + ":")), None)


def _content(value):
    """Exports use database UUIDs as BOM references; compare inventory independently of those."""
    if isinstance(value, dict):
        return {k: _content(v) for k, v in value.items() if k != "bom-ref"}
    if isinstance(value, list):
        return sorted((_content(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value


def _identity(service):
    return tuple(service.get(k) or "" for k in ("group", "name", "version"))


def _export(client, project):
    return client.call("bom/cyclonedx/project/" + project["uuid"] + "?format=json&version=1.6")


def _import(client, project, bom):
    result = client.call("bom", {"project": project["uuid"],
                         "bom": base64.b64encode(json.dumps(bom).encode()).decode()}, "PUT")
    token = str(uuid.UUID(result["token"]))
    for _ in range(120):
        if not client.call("bom/token/" + token).get("processing", True):
            return
        time.sleep(5)
    raise RuntimeError("Service migration import timed out; parent inventory was preserved; rerun patchwatch.dtrack.groups")


def migrate_services(client, parent):
    """Copy, verify, then delete. Never clear a parent by uploading an empty BOM."""
    source_entries = client.all("service/project/" + parent["uuid"])
    source = _export(client, parent)
    if source.get("components"):
        raise RuntimeError("Parent contains package components; move them to an inventory subproject before retrying")
    services = source.get("services", [])
    if not services:
        raise RuntimeError("Aggregation conflict without exported services; inspect parent components/services and retry")
    name = parent["name"] + "/services"
    try:
        child = client.call("project/lookup?" + urlencode({"name": name, "version": parent.get("version")}))
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        error.close()
        child = client.call("project", {"name": name, "version": parent.get("version"),
                            "parent": {"uuid": parent["uuid"]},
                            "tags": [t for t in parent.get("tags", []) if t["name"] != "patchwatch-role:parent"]
                                    + [{"name": "patchwatch-role:services"}],
                            "active": parent.get("active", True), "isLatest": bool(parent.get("isLatest"))}, "PUT")
    if (_tag(child, "gitlab-project-id") != _tag(parent, "gitlab-project-id")
            or CI_TAG not in {t["name"] for t in child.get("tags", [])}
            or child.get("collectionLogic")
            or (child.get("parent") or {}).get("uuid") not in (None, parent["uuid"])):
        raise RuntimeError("Service subproject name is already used by another project; resolve the collision and retry")
    target = _export(client, child)
    if target.get("components"):
        raise RuntimeError("Service subproject contains packages; reserve /services for service inventory and retry")
    merged = {_identity(s): s for s in target.get("services", [])}
    for service in services:
        key = _identity(service)
        if key in merged and _content(merged[key]) != _content(service):
            raise RuntimeError("Service metadata conflicts with the subproject; reconcile both inventories and retry")
        merged.setdefault(key, service)
    target["services"] = list(merged.values())
    _import(client, child, target)
    verified = {_identity(s): _content(s) for s in _export(client, child).get("services", [])}
    if any(verified.get(_identity(s)) != _content(s) for s in merged.values()):
        raise RuntimeError("Service copy verification failed; parent inventory was preserved; inspect exports and retry")
    client.call("project/" + child["uuid"], {"parent": {"uuid": parent["uuid"]},
                "active": child.get("active", True), "isLatest": bool(child.get("isLatest"))}, "PATCH")
    if _content(_export(client, parent).get("services", [])) != _content(services):
        raise RuntimeError("Parent services changed during migration; pause CI and retry; parent inventory was preserved")
    # Delete only the captured source entries; newly added services must remain untouched.
    for service in source_entries:
        try:
            client.call("service/" + service["uuid"], method="DELETE")
        except urllib.error.HTTPError as error:
            if error.code != 404:  # deleting a parent service can also remove its nested services
                raise
            error.close()
    if client.all("service/project/" + parent["uuid"]):
        raise RuntimeError("Parent still has services; pause CI uploads and rerun patchwatch.dtrack.groups")


def sync(client, *, migrate=True):
    """Idempotent. Returns what was changed.

    1. Re-parent: DTrack applies the parent of an upload only when it creates the project, so
       components that existed before their container project stay roots. A CI project named
       <container>/<component> of the same GitLab project and version is moved below <container>.
    2. Containers with children aggregate their children's metrics, at every nesting level.
       Scoped projects are only adopted under containers of the same scope.
    """
    changed = []
    ci = [p for p in client.all("project")
          if (CI_TAG in {t["name"] for t in p.get("tags") or []}
              or SCOPED_TAGS & {t["name"] for t in p.get("tags") or []})
          and _tag(p, "patchwatch-role") != "patchwatch-role:folder"]
    containers = {(p["name"], p.get("version")): p for p in ci}
    for project in ci:
        container = containers.get((project["name"].rpartition("/")[0], project.get("version")))
        if (container and _tag(container, "gitlab-project-id") == _tag(project, "gitlab-project-id")
                and SCOPED_TAGS.intersection(t["name"] for t in container.get("tags") or [])
                == SCOPED_TAGS.intersection(t["name"] for t in project.get("tags") or [])
                and container is not project and not project.get("parent")):
            update = {"parent": {"uuid": container["uuid"]},
                      "active": project.get("active", True), "isLatest": bool(project.get("isLatest"))}
            if project.get("collectionLogic"):  # v5 has no NONE value: plain projects omit the field
                update["collectionLogic"] = project["collectionLogic"]
            client.call("project/" + project["uuid"], update, "PATCH")
            changed.append(f"{project['name']} -> {container['name']}")
    for project in ci:
        if project.get("collectionLogic") == LOGIC:
            continue
        if (_tag(project, "patchwatch-role") != "patchwatch-role:parent"
                and not client.call(f"project/{project['uuid']}/children")
                and not any(c.endswith(" -> " + project["name"]) for c in changed)):
            continue  # an ordinary project without components below it
        update = {"collectionLogic": LOGIC, "active": project.get("active", True),
                  "isLatest": bool(project.get("isLatest"))}
        try:
            try:
                client.call("project/" + project["uuid"], update, "PATCH")
            except urllib.error.HTTPError as error:
                if error.code != 409:
                    raise
                error.close()
                if not migrate:
                    raise RuntimeError("Parent still has inventory; run python -m patchwatch.dtrack.groups with admin credentials")
                migrate_services(client, project)
                client.call("project/" + project["uuid"], update, "PATCH")
        except (RuntimeError, ValueError, KeyError, urllib.error.URLError) as error:
            if isinstance(error, urllib.error.HTTPError):
                cause = f"HTTP {error.code}"
                error.close()
            elif isinstance(error, urllib.error.URLError):
                cause = "network/TLS error; check API connectivity"
            else:
                cause = str(error)
            raise AggregationError(f"Aggregation failed for {project['name']} @ {project.get('version')}: {cause}. "
                               "Resolve the cause and rerun python -m patchwatch.dtrack.groups with admin credentials; "
                               "pause CI during migration") from None
        changed.append(project["name"] + " aggregates children")
    return changed


def main():
    """CLI: reconcile project groups and aggregation with admin credentials (``DT_URL``, ``DT_ADMIN_*``)."""
    import os
    from .client import admin_client
    os.umask(0o077)
    changed = sync(admin_client(os.environ["DT_URL"]))
    print("Project groups: " + ("; ".join(changed) or "no change"))


if __name__ == "__main__":
    main()
