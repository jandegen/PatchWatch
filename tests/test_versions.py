# SPDX-License-Identifier: Apache-2.0
import copy
import unittest

from patchwatch.dtrack import versions


def project(uid, version, name="g/p", **extra):
    return {"uuid": uid, "name": name, "version": version, "active": True, "isLatest": False,
            "tags": [{"name": t} for t in ("managed-by:patchwatch", "source:gitlab-ci", "gitlab-project-id:1")], **extra}


class Client:
    def __init__(self, projects):
        self.projects = copy.deepcopy(projects)
        self.patched = []

    def all(self, path):
        assert path == "project"  # includes nested projects
        return copy.deepcopy(self.projects)

    def call(self, path, data=None, method=None):
        if path.endswith("/children"):
            return [copy.deepcopy(p) for p in self.projects if (p.get("parent") or {}).get("uuid") == path.split("/")[1]]
        if method == "PUT":
            created = {"uuid": "new-" + data["version"].replace("/", "-"), **data}
            self.projects.append(created)
            self.created = getattr(self, "created", []) + [data]
            return created
        assert method == "PATCH"
        self.patched.append((path, data))
        for p in self.projects:
            if path == "project/" + p["uuid"]:
                p.update(data)


def comment_ref(text):
    return [{"type": "vcs", "url": "https://gitlab.example/g/p/-/commit/" + "a" * 40, "comment": text}]


class Versions(unittest.TestCase):
    def latest(self, client):
        return {p["uuid"] for p in client.projects if p.get("isLatest")}

    def test_numeric_order_survives_old_release_and_branch_reuploads(self):
        client = Client([project("branch", "main", isLatest=True, lastBomImport=999),
                         project("old", "v1.9.0", lastBomImport=9999),
                         project("new", "v1.10.0", lastBomImport=1)])
        versions.sync(client)
        self.assertEqual(self.latest(client), {"new"})
        client.patched.clear()
        self.assertEqual(versions.sync(client), [])
        self.assertEqual(client.patched, [])

    def test_feature_branches_never_compete_with_the_default_branch_or_releases(self):
        other = "PatchWatch branch: "
        client = Client([project("main", "main", externalReferences=comment_ref("PatchWatch default branch: main")),
                         project("dev", "dev", externalReferences=comment_ref(other + "dev")),
                         project("num", "2.0", externalReferences=comment_ref(other + "2.0"))])
        versions.sync(client)
        self.assertEqual(self.latest(client), {"main"})
        client.projects.append(project("rel", "v1.0.0"))
        versions.sync(client)
        self.assertEqual(self.latest(client), {"rel"})

    def test_branch_is_fallback_and_prereleases_are_not_stable_releases(self):
        client = Client([project("b", "main"), project("rc", "v2.0.0-rc.1"), project("alias", "latest"),
                         project("inactive", "v3.0.0", active=False, isLatest=True)])
        versions.sync(client)
        self.assertEqual(self.latest(client), {"b"})
        self.assertFalse(client.projects[-1]["active"])

    def test_custom_numeric_default_branch_is_not_mistaken_for_release(self):
        refs = [{"type": "vcs", "url": "https://gitlab/commit/abc", "comment": versions.BRANCH_COMMENT + "2026 (abc)"}]
        client = Client([project("b", "2026", externalReferences=refs), project("r", "v1.0.0")])
        versions.sync(client)
        self.assertEqual(self.latest(client), {"r"})
        client = Client([project("b", "2026", externalReferences=refs)])
        versions.sync(client)
        self.assertEqual(self.latest(client), {"b"})

    def test_components_follow_family_release_even_when_their_release_is_missing(self):
        client = Client([project("p", "v2.0.0"), project("p0", "main"),
                         project("c", "v2.0.0", name="g/p/api", parent={"uuid": "p"}),
                         project("c0", "main", name="g/p/api"),
                         project("w0", "main", name="g/p/web", isLatest=True)])
        versions.sync(client)
        self.assertEqual(self.latest(client), {"p", "c"})

    def test_hosts_mr_projects_and_unmanaged_projects_are_preserved(self):
        host = project("h", "current", tags=[{"name": "asset-type:workstation"}], isLatest=True)
        unmanaged = project("u", "v9.0.0", tags=[{"name": "source:gitlab-ci"}], isLatest=True)
        mr = project("mr", "mr-42-abc", tags=[{"name": "source:gitlab-mr"}])
        other = project("o", "main", tags=[{"name": t} for t in
                        ("managed-by:patchwatch", "source:gitlab-ci", "gitlab-project-id:2")])
        client = Client([host, unmanaged, mr, other, project("r", "v1.0.0")])
        versions.sync(client)
        self.assertEqual(self.latest(client), {"h", "u", "o", "r"})
        self.assertFalse(any(path in ("project/h", "project/u", "project/mr") for path, _ in client.patched))

    def test_collection_provenance_follows_latest_import_and_preserves_other_links(self):
        website = {"type": "website", "url": "https://example.org", "comment": None}
        refs = [{"type": "vcs", "url": "https://gitlab/commit/new", "comment": versions.BRANCH_COMMENT + "main (new)"}]
        client = Client([project("p", "main", collectionLogic="AGGREGATE_DIRECT_CHILDREN", parent=None,
                                 externalReferences=[website]),
                         project("c", "main", name="g/p/api", parent={"uuid": "p"}, lastBomImport=42,
                                 externalReferences=refs)])
        versions.sync(client)
        self.assertEqual(client.projects[0]["externalReferences"], [website] + refs)
        self.assertEqual(client.projects[0]["collectionLogic"], "AGGREGATE_DIRECT_CHILDREN")
        self.assertEqual(self.latest(client), {"p", "c"})
        self.assertEqual(versions.sync(client), [])

    def test_equal_numeric_aliases_are_deterministic_and_missing_branches_are_not_guessed(self):
        client = Client([project("alias", "v1"), project("full", "v1.0.0"), project("zero", "v1.0")])
        versions.sync(client)
        self.assertEqual(self.latest(client), {"full"})
        client = Client([project("a", "develop"), project("b", "production")])
        self.assertEqual(versions.sync(client), [])


if __name__ == "__main__":
    unittest.main()


class NoCollectionLogic(unittest.TestCase):
    def test_plain_projects_never_send_the_removed_none_value(self):
        client = Client([project("a", "v1.0.0")])
        versions.sync(client)
        self.assertTrue(client.patched)
        self.assertTrue(all("collectionLogic" not in data for _, data in client.patched))

    def test_existing_collection_logic_is_preserved(self):
        client = Client([project("a", "v1.0.0", collectionLogic="AGGREGATE_DIRECT_CHILDREN")])
        versions.sync(client)
        self.assertEqual(client.patched[0][1]["collectionLogic"], "AGGREGATE_DIRECT_CHILDREN")


def scoped(uid, version, name, scope="scan-purpose:mr-feedback", **extra):
    return {"uuid": uid, "name": name, "version": version, "active": True, "isLatest": False,
            "tags": [{"name": t} for t in (scope, "gitlab-project-id:1")], **extra}


class Adopt(unittest.TestCase):
    def test_loose_scoped_versions_get_a_created_parent_and_share_it(self):
        client = Client([project("main", "main", name="g/p"),
                         scoped("a", "mr-5", "g/p/api"), scoped("b", "mr-5", "g/p/web"),
                         scoped("c", "feat/x", "g/p/api", scope="scan-purpose:branch")])
        changed = versions.adopt(client)
        self.assertEqual(len(changed), 3)
        self.assertEqual(sorted((d["name"], d["version"]) for d in client.created), [("g/p", "feat/x"), ("g/p", "mr-5")])
        self.assertEqual(sorted(t["name"] for t in client.created[0]["tags"]),
                         sorted(["gitlab-project-id:1", client.created[0]["tags"][0]["name"]]))
        self.assertEqual({d["parent"]["uuid"] for path, d in client.patched if path in ("project/a", "project/b")},
                         {"new-mr-5"})
        self.assertEqual(versions.adopt(client), [])

    def test_unrelated_projects_are_left_alone(self):
        client = Client([project("main", "main", name="g/p"),
                         scoped("plain", "mr-5", "g/p"),                    # default worker: name is the path itself
                         scoped("odd", "mr-5", "other/thing"),               # no unscoped project of that name
                         scoped("done", "mr-5", "g/p/api", parent={"uuid": "x"}),
                         project("v1", "mr-5", name="g/p")])                 # foreign parent of that version
        client.projects.append(scoped("c", "mr-5", "g/p/web"))
        self.assertEqual(versions.adopt(client), [])
        self.assertFalse(getattr(client, "created", []))
        self.assertEqual(client.patched, [])


class Hierarchy(unittest.TestCase):
    def test_periodic_reconciliation_aggregates_and_groups_all_versions_idempotently(self):
        client = Client([project("main", "main"),
                         project("api", "main", name="g/p/api", parent={"uuid": "main"}),
                         scoped("mr", "mr-19", "g/p/api"),
                         scoped("branch", "feat/x", "g/p/api", scope="scan-purpose:branch")])
        versions.reconcile(client)
        by_id = {p["uuid"]: p for p in client.projects}
        folder = next(p for p in client.projects if p.get("version") == versions.FOLDER_VERSION)
        self.assertNotIn("collectionLogic", folder)
        self.assertFalse(folder["isLatest"])
        self.assertEqual({t["name"] for t in folder["tags"]}, {versions.FOLDER_TAG, "gitlab-project-id:1"})
        for uid in ("main", "new-mr-19", "new-feat-x"):
            self.assertEqual(by_id[uid]["collectionLogic"], "AGGREGATE_DIRECT_CHILDREN")
            self.assertEqual(by_id[uid]["parent"], {"uuid": folder["uuid"]})
        self.assertEqual(by_id["mr"]["parent"], {"uuid": "new-mr-19"})
        self.assertEqual(versions.reconcile(client), [])

    def test_foreign_folder_collision_is_not_modified(self):
        client = Client([project("main", "main"),
                         project("foreign", versions.FOLDER_VERSION, tags=[])])
        with self.assertRaisesRegex(RuntimeError, "Folder name collision"):
            versions.folders(client)
        self.assertEqual(client.patched, [])
        self.assertFalse(getattr(client, "created", []))

    def test_existing_foreign_parent_is_preserved(self):
        client = Client([project("main", "main", parent={"uuid": "foreign"})])
        self.assertEqual(versions.folders(client), [])
        self.assertFalse(getattr(client, "created", []))
