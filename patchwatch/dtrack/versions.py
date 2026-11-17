# SPDX-License-Identifier: Apache-2.0
"""Reconcile project hierarchy, aggregation and Latest with a server-side management key."""
from collections import defaultdict
import re

from .scopes import SCOPED_TAGS

RELEASE = re.compile(r"v?(0|[1-9]\d*)(?:\.(0|[1-9]\d*))*\Z")
BRANCH_COMMENT = "PatchWatch default branch: "
OTHER_BRANCH_COMMENT = "PatchWatch branch: "
RELEASE_COMMENT = "PatchWatch release: "
FOLDER_TAG = "patchwatch-role:folder"
FOLDER_VERSION = "all versions"
CI_TAGS = frozenset({"managed-by:patchwatch", "source:gitlab-ci"})


def release_key(version):
    """Stable numeric tags only; prereleases and arbitrary labels are not releases."""
    if not RELEASE.fullmatch(version or ""):
        return None
    parts = [int(n) for n in version.removeprefix("v").split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def is_branch(project):
    """Whether a version is the default-branch version of its project (comment marker, or named main/master) and not a release."""
    comments = [(r.get("comment") or "") for r in project.get("externalReferences") or []]
    if any(c.startswith(RELEASE_COMMENT) for c in comments):
        return False
    return any(c.startswith(BRANCH_COMMENT) for c in comments) or project.get("version") in ("main", "master")


def is_other_branch(project):
    """Feature or integration branch: never a release candidate, never the default branch."""
    return any((r.get("comment") or "").startswith(OTHER_BRANCH_COMMENT) for r in project.get("externalReferences") or [])


def sync(client):
    """Highest active stable release per GitLab project; otherwise its default branch.

    Components follow the same release as their container. Missing component releases get no
    Latest flag, rather than advertising a different version. Import time never orders releases.
    """
    families = defaultdict(list)
    for project in client.all("project"):
        tags = {t["name"] for t in project.get("tags") or []}
        pid = next((t for t in tags if t.startswith("gitlab-project-id:")), None)
        if pid and {"managed-by:patchwatch", "source:gitlab-ci"} <= tags:
            families[pid].append(project)
    changed = []
    for projects in families.values():
        active = [p for p in projects if p.get("active", True)]
        releases = [p for p in active if not is_branch(p) and not is_other_branch(p)
                    and release_key(p.get("version")) is not None]
        # A deterministic tie-break handles equal aliases such as v1 and v1.0.0.
        newest = max(releases, key=lambda p: (release_key(p["version"]), len(p["version"]), p["version"]), default=None)
        branches = sorted({p["version"] for p in active if is_branch(p)})
        version = newest["version"] if newest else (branches[0] if len(branches) == 1 else None)
        for project in projects:
            desired = project.get("active", True) and version is not None and project.get("version") == version
            update = {}
            if bool(project.get("isLatest")) != desired:
                update["isLatest"] = desired
            # Collection projects reject BOM uploads. Their provenance follows the most recently
            # imported direct child of the same version; unrelated project links are preserved.
            if project.get("collectionLogic") == "AGGREGATE_DIRECT_CHILDREN":
                children = [p for p in active if p["name"].rpartition("/")[0] == project["name"]
                            and p.get("version") == project.get("version") and p.get("lastBomImport")]
                child = max(children, key=lambda p: (p["lastBomImport"], p["uuid"]), default=None)
                refs = [r for r in (child or {}).get("externalReferences") or []
                        if (r.get("comment") or "").startswith("PatchWatch ")]
                if refs:
                    existing = project.get("externalReferences") or []
                    merged = [r for r in existing if not (r.get("comment") or "").startswith("PatchWatch ")] + refs
                    if merged != existing:
                        update["externalReferences"] = merged
            if update:
                # DTrack PATCH has primitive defaults: always preserve active and Latest explicitly.
                update.update({"active": project.get("active", True), "isLatest": desired})
                if project.get("collectionLogic"):  # v5 has no NONE value: plain projects omit the field
                    update["collectionLogic"] = project["collectionLogic"]
                client.call("project/" + project["uuid"], update, "PATCH")
                changed.append(f"{project['name']} @ {project['version']}: latest={str(desired).lower()}")
    return changed


def adopt(client):
    """Hang scoped (MR / branch) component versions below a parent with the same version.

    The worker does this for new uploads; this migrates versions created earlier. A parent name is only
    trusted when an unscoped project of the same GitLab project carries exactly that name, so a plain
    project whose path merely contains a slash is never mistaken for a component."""
    projects = client.all("project")
    names = defaultdict(set)
    parents = {}
    for p in projects:
        tags = {t["name"] for t in p.get("tags") or []}
        parents[(p["name"], p.get("version"))] = p
        pid = next((t for t in tags if t.startswith("gitlab-project-id:")), None)
        if pid and not tags & SCOPED_TAGS:
            names[pid].add(p["name"])
    changed = []
    for p in projects:
        tags = {t["name"] for t in p.get("tags") or []}
        scope, pid = tags & SCOPED_TAGS, next((t for t in tags if t.startswith("gitlab-project-id:")), None)
        parent_name = p["name"].rpartition("/")[0]
        if p.get("parent") or len(scope) != 1 or not pid or parent_name not in names[pid]:
            continue
        key = (parent_name, p.get("version"))
        parent = parents.get(key)
        if parent is None:
            parent = client.call("project", {"name": parent_name, "version": p.get("version"), "classifier": "APPLICATION",
                                             "active": True, "tags": [{"name": t} for t in (*scope, pid)]}, "PUT")
            parents[key] = parent
        elif not {*scope, pid} <= {t["name"] for t in parent.get("tags") or []}:
            continue  # a parent we do not own, such as a release of that name
        client.call("project/" + p["uuid"], {"parent": {"uuid": parent["uuid"]}, "active": p.get("active", True),
                                             "isLatest": bool(p.get("isLatest"))}, "PATCH")
        changed.append(f"{p['name']} @ {p.get('version')}: parent {parent_name}")
    return changed


def folders(client):
    """One plain navigation project per GitLab repository, above its version parents.

    No CI/managed/scope tags: the folder is neither an inventory nor a collection,
    a release candidate or a notification target. Existing foreign parents are preserved.
    """
    projects = client.all("project")
    families = defaultdict(list)
    for p in projects:
        tags = {t["name"] for t in p.get("tags") or []}
        pid = next((t for t in tags if t.startswith("gitlab-project-id:")), None)
        if pid and CI_TAGS <= tags and FOLDER_TAG not in tags:
            families[pid].append(p)
    changed = []
    for pid, regular in families.items():
        # A repository path is established by its regular inventory, never guessed
        # from a scoped project or from an arbitrary slash in its name.
        name = min((p["name"] for p in regular), key=lambda n: (n.count("/"), n))
        folder = next((p for p in projects if p["name"] == name and p.get("version") == FOLDER_VERSION), None)
        if folder and (not {pid, FOLDER_TAG} <= {t["name"] for t in folder.get("tags") or []}
                       or folder.get("collectionLogic") or folder.get("parent")):
            raise RuntimeError(f"Folder name collision: {name} @ {FOLDER_VERSION}; resolve before retrying")
        candidates = [p for p in projects if p["name"] == name and p.get("version") != FOLDER_VERSION
                      and pid in {t["name"] for t in p.get("tags") or []}
                      and (CI_TAGS <= {t["name"] for t in p.get("tags") or []}
                           or SCOPED_TAGS & {t["name"] for t in p.get("tags") or []})
                      and (not p.get("parent") or (folder and p["parent"]["uuid"] == folder["uuid"]))]
        if not candidates:
            continue
        if folder is None:
            folder = client.call("project", {"name": name, "version": FOLDER_VERSION,
                                 "description": "PatchWatch navigation folder for all versions; no metric aggregation.",
                                 "active": True, "isLatest": False,
                                 "tags": [{"name": FOLDER_TAG}, {"name": pid}]}, "PUT")
            changed.append(f"{name}: versions folder created")
        for p in candidates:
            if (p.get("parent") or {}).get("uuid") == folder["uuid"]:
                continue
            update = {"parent": {"uuid": folder["uuid"]}, "active": p.get("active", True),
                      "isLatest": bool(p.get("isLatest"))}
            if p.get("collectionLogic"):
                update["collectionLogic"] = p["collectionLogic"]
            client.call("project/" + p["uuid"], update, "PATCH")
            changed.append(f"{name} @ {p.get('version')}: versions folder")
    return changed


def reconcile(client):
    """One maintenance pass with the project-versions key: adoption, aggregation (without service migration), Latest flags and folders."""
    from .groups import sync as sync_groups
    # The periodic key may manage projects but must never migrate service inventory.
    return adopt(client) + sync_groups(client, migrate=False) + sync(client) + folders(client)


def main():
    """CLI: reconcile once, or every ``--interval`` seconds (Compose)."""
    import argparse
    import os
    import time
    from .client import DependencyTrack
    from ..core.http import check_url, secret
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=int, default=0, help="Repeat every N seconds (Compose); default: run once")
    args = parser.parse_args()
    key = secret("DT_API_KEY")
    if not key or args.interval < 0:
        parser.error("DT_API_KEY(_FILE) and a nonnegative interval are required")
    client = DependencyTrack(check_url(os.environ["DT_URL"], os.getenv("ALLOW_HTTP") == "true"), {"X-Api-Key": key})
    while True:
        changed = reconcile(client)
        print("Project versions: " + ("; ".join(changed) or "no change"), flush=True)
        if not args.interval:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
