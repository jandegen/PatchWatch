# SPDX-License-Identifier: Apache-2.0
"""Remove projects of the retired scheme <project>/mr-feedback/<component> (dry run unless --apply)."""
from .scopes import MR_TAG


def legacy_projects(client):
    """Only projects that sit below a `mr-feedback` path segment AND carry the worker's scope tag."""
    found = []
    for p in client.all("project"):
        tags = {t["name"] for t in p.get("tags") or []}
        parts = p["name"].split("/")
        if MR_TAG in tags and "mr-feedback" in parts[1:]:
            found.append(p)
    return found


def main():
    """CLI: list (or with ``--apply`` delete) projects of the retired mr-feedback layout."""
    import argparse
    import os
    from .client import DependencyTrack
    from ..core.http import check_url, secret
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="delete; without it only list")
    args = parser.parse_args()
    key = secret("DT_API_KEY")
    if not key:
        parser.error("DT_API_KEY(_FILE) is required")
    client = DependencyTrack(check_url(os.environ["DT_URL"], os.getenv("ALLOW_HTTP") == "true"), {"X-Api-Key": key})
    projects = legacy_projects(client)
    for p in projects:
        print(("delete " if args.apply else "would delete ") + f"{p['name']} @ {p.get('version')}")
        if args.apply:
            client.call("project/" + p["uuid"], None, "DELETE")
    print(f"{len(projects)} legacy project version(s)" + ("" if args.apply else "; rerun with --apply to delete"))


if __name__ == "__main__":
    main()
