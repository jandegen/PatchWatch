# SPDX-License-Identifier: Apache-2.0
import io
import unittest
import urllib.error

from unittest.mock import patch

from patchwatch.dtrack import groups


class Client:
    def __init__(self, projects, children):
        self.projects, self.children, self.patched = projects, children, []

    def all(self, path):
        assert path == "project"
        return self.projects

    def call(self, path, data=None, method=None):
        if path.endswith("/children"):
            return self.children.get(path.split("/")[1], [])
        self.patched.append((path, data, method))


def project(uuid, name, pid="1", version="main", tags=("source:gitlab-ci",), logic=None):
    return {"uuid": uuid, "name": name, "version": version, **({"collectionLogic": logic} if logic else {}),
            "tags": [{"name": t} for t in (*tags, "gitlab-project-id:" + pid)]}


class Refusing(Client):
    """v5 answers 409 when a project that has components or services becomes a collection project."""

    def call(self, path, data=None, method=None):
        if method == "PATCH" and data and data.get("collectionLogic"):
            raise urllib.error.HTTPError("http://dt/api/v1/" + path, 409, "Conflict", {}, io.BytesIO(b""))
        return super().call(path, data, method)


class Groups(unittest.TestCase):
    def test_failed_conversion_aborts_with_cause_and_action(self):
        client = Refusing([project("p", "g/app")], {"p": [{"name": "g/app/api"}]})
        with patch("patchwatch.dtrack.groups.migrate_services", side_effect=RuntimeError("Parent contains package components")):
            with self.assertRaisesRegex(RuntimeError, "g/app @ main.*package components.*rerun"):
                groups.sync(client)

    def test_existing_components_are_moved_below_their_container_and_it_aggregates(self):
        client = Client([project("p", "g/app"), project("c1", "g/app/api"), project("c2", "g/app/web")], {})
        result = groups.sync(client)
        self.assertEqual(sorted(client.patched), sorted([
            ("project/c1", {"parent": {"uuid": "p"}, "active": True, "isLatest": False}, "PATCH"),
            ("project/c2", {"parent": {"uuid": "p"}, "active": True, "isLatest": False}, "PATCH"),
            ("project/p", {"collectionLogic": groups.LOGIC, "active": True, "isLatest": False}, "PATCH")]))
        self.assertIn("g/app aggregates children", result)

    def test_unrelated_projects_are_left_alone(self):
        client = Client([project("p", "g/app", pid="1"), project("x", "g/app/api", pid="2"),  # other GitLab project
                         project("v", "g/app/api", version="v1"),                              # other version
                         project("w", "dev-station", tags=("asset-type:workstation",)),
                         project("s", "g/single")], {})
        self.assertEqual(groups.sync(client), [])
        self.assertEqual(client.patched, [])

    def test_container_with_children_from_earlier_uploads_aggregates(self):
        client = Client([project("p", "g/app")], {"p": [{"name": "g/app/api"}]})
        self.assertEqual(groups.sync(client), ["g/app aggregates children"])

    def test_explicit_empty_parent_aggregates_without_children(self):
        client = Client([project("p", "g/app", tags=("source:gitlab-ci", "patchwatch-role:parent"))], {})
        self.assertEqual(groups.sync(client), ["g/app aggregates children"])

    def test_second_run_changes_nothing(self):
        client = Client([project("p", "g/app", logic=groups.LOGIC)], {"p": [{"name": "c"}]})
        self.assertEqual(groups.sync(client), [])
        self.assertEqual(client.patched, [])

    def test_patch_preserves_latest_and_inactive_state(self):
        parent = dict(project("p", "g/app"), isLatest=True, active=False)
        child = dict(project("c", "g/app/api"), isLatest=True, active=False)
        client = Client([parent, child], {})
        groups.sync(client)
        for _, data, _ in client.patched:
            self.assertEqual((data["isLatest"], data["active"]), (True, False))

    def test_nested_scoped_parents_aggregate_but_navigation_folder_does_not(self):
        folder = project("f", "g/app", version="all versions", tags=("patchwatch-role:folder",))
        parents = [dict(project(str(i), "g/app", version=v, tags=(scope,)), parent={"uuid": "f"})
                   for i, (v, scope) in enumerate((("mr-19", "scan-purpose:mr-feedback"),
                                                  ("base-main", "scan-purpose:mr-feedback"),
                                                  ("test/version-check", "scan-purpose:branch")))]
        client = Client([folder, *parents], {p["uuid"]: [{"uuid": "service"}] for p in parents})
        groups.sync(client, migrate=False)
        self.assertEqual({path for path, _, _ in client.patched}, {"project/0", "project/1", "project/2"})
        self.assertTrue(all(data["collectionLogic"] == groups.LOGIC for _, data, _ in client.patched))

    def test_periodic_management_key_does_not_attempt_inventory_migration(self):
        client = Refusing([project("p", "g/app")], {"p": [{"uuid": "c"}]})
        with patch("patchwatch.dtrack.groups.migrate_services") as migrate:
            with self.assertRaisesRegex(groups.AggregationError, "admin credentials"):
                groups.sync(client, migrate=False)
            migrate.assert_not_called()

    def test_components_do_not_cross_scopes_or_replace_existing_parents(self):
        parent = project("p", "g/app")
        scoped = project("s", "g/app/api", tags=("scan-purpose:branch",))
        nested = dict(project("n", "g/app/web"), parent={"uuid": "foreign"})
        client = Client([parent, scoped, nested], {})
        self.assertEqual(groups.sync(client), [])


class MigrationClient(Client):
    """Stateful v5 model: imports replace inventory; collection projects reject own inventory."""
    def __init__(self, services, child_services=(), fail=None):
        import copy
        self.copy = copy.deepcopy
        self.parent = dict(project("p", "g/app"), active=False, isLatest=True)
        self.child = dict(project("s", "g/app/services"), parent={"uuid": "p"}) if child_services else None
        self.inventory = {"p": self.copy(services), "s": self.copy(list(child_services))}
        self.fail, self.events, self.created = fail, [], 0
        super().__init__([self.parent], {"p": [{"uuid": "api", "name": "g/app/api"}]})

    def all(self, path):
        if path.startswith("service/project/"):
            return [dict(s, uuid="service-" + s["name"]) for s in self.inventory[path.rsplit("/", 1)[1]]]
        return super().all(path)

    def call(self, path, data=None, method=None):
        import base64
        import json
        self.events.append((path, method))
        if path.startswith("bom/cyclonedx/project/"):
            identifier = path.split("/")[3].split("?")[0]
            return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                    "metadata": {"component": {"type": "application", "name": "g/app/services", "version": "main"}},
                    "components": [{"name": "package"}] if self.fail == "packages" and identifier == "p" else [],
                    "services": self.copy(self.inventory[identifier])}
        if path.startswith("project/lookup?"):
            if self.child:
                return self.copy(self.child)
            raise urllib.error.HTTPError("u", 404, "missing", {}, io.BytesIO())
        if path == "project" and method == "PUT":
            self.created += 1
            self.child = dict(self.copy(data), uuid="s")
            return self.copy(self.child)
        if path == "bom":
            if self.fail == "import":
                raise urllib.error.HTTPError("u", 403, "denied", {}, io.BytesIO())
            bom = json.loads(base64.b64decode(data["bom"]))
            self.inventory[data["project"]] = [] if self.fail == "verify" else bom["services"]
            return {"token": "11111111-1111-4111-8111-111111111111"}
        if path.startswith("bom/token/"):
            return {"processing": self.fail == "timeout"}
        if method == "DELETE":
            if self.fail == "delete":
                raise urllib.error.HTTPError("u", 403, "denied", {}, io.BytesIO())
            self.inventory["p"] = [s for s in self.inventory["p"] if "service-" + s["name"] != path.split("/")[1]]
            return
        if path == "project/p" and method == "PATCH":
            if self.inventory["p"] or self.fail == "packages":
                raise urllib.error.HTTPError("u", 409, "conflict", {}, io.BytesIO())
            self.parent.update(data)
        return super().call(path, data, method)


class ServiceMigration(unittest.TestCase):
    def setUp(self):
        self.services = [{"bom-ref": "original", "name": "db", "version": "17", "endpoints": ["https://db"],
                          "properties": [{"name": "patchwatch:image", "value": "postgres:17"}],
                          "services": [{"name": "nested", "bom-ref": "nested-ref"}]}]

    def test_services_are_copied_verified_removed_and_aggregation_is_idempotent(self):
        client = MigrationClient(self.services)
        self.assertEqual(groups.sync(client), ["g/app aggregates children"])
        self.assertEqual(client.inventory["p"], [])
        self.assertEqual(client.inventory["s"], self.services)
        self.assertEqual(client.child["version"], "main")
        self.assertEqual(client.child["parent"], {"uuid": "p"})
        self.assertEqual(client.child["active"], False)
        self.assertEqual(client.child["isLatest"], True)
        self.assertEqual(groups.sync(client), [])
        self.assertEqual(client.created, 1)
        paths = [p for p, _ in client.events]
        self.assertLess(paths.index("bom"), paths.index("service/service-db"))

    def test_existing_service_inventory_is_preserved_and_not_duplicated(self):
        extra = {"name": "web"}
        client = MigrationClient(self.services, self.services + [extra])
        groups.sync(client)
        self.assertEqual(client.inventory["s"], self.services + [extra])
        self.assertEqual(client.created, 0)

    def test_import_verification_and_timeout_failures_preserve_parent(self):
        for failure in ("import", "verify", "timeout", "packages"):
            with self.subTest(failure=failure), patch("patchwatch.dtrack.groups.time.sleep"):
                client = MigrationClient(self.services, fail=failure)
                with self.assertRaisesRegex(groups.AggregationError, "g/app @ main.*rerun"):
                    groups.sync(client)
                self.assertEqual(client.inventory["p"], self.services)
                self.assertFalse(any(method == "DELETE" for _, method in client.events))
                self.assertNotIn("collectionLogic", client.parent)

    def test_retry_after_delete_failure_preserves_copy_and_creates_no_duplicate(self):
        client = MigrationClient(self.services, fail="delete")
        with self.assertRaises(groups.AggregationError):
            groups.sync(client)
        self.assertEqual(client.inventory["p"], self.services)
        self.assertEqual(client.inventory["s"], self.services)
        client.fail = None
        groups.sync(client)
        self.assertEqual(client.created, 1)
        self.assertEqual(client.inventory["s"], self.services)

    def test_conflicting_child_is_not_overwritten(self):
        for child in ([dict(self.services[0], endpoints=["https://different"])], [{"name": "web"}]):
            client = MigrationClient(self.services, child)
            if child[0]["name"] == "web":
                client.child["tags"] = []
            with self.assertRaises(groups.AggregationError):
                groups.sync(client)
            self.assertEqual(client.inventory["p"], self.services)
            self.assertEqual(client.inventory["s"], child)
            self.assertFalse(any(method == "DELETE" for _, method in client.events))


if __name__ == "__main__":
    unittest.main()
