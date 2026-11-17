# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from patchwatch.ci import delta


def comp(name, version, license_id=None, ref=None):
    c = {"name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}?arch=x", "bom-ref": ref or f"{name}-{version}"}
    if license_id:
        c["licenses"] = [{"license": {"id": license_id}}]
    return c


def vuln(vid, ref, level="HIGH", state=None):
    v = {"id": vid, "source": {"name": "NVD"}, "ratings": [{"severity": level.lower()}], "affects": [{"ref": ref}]}
    if state:
        v["analysis"] = {"state": state}
    return v


def violation(policy, name, version, state="WARN", kind="LICENSE"):
    return {"type": kind, "policyCondition": {"policy": {"name": policy, "violationState": state}},
            "component": {"name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}"}}


class FakeClient:
    def __init__(self, projects, boms, violations=None):
        self.projects, self.boms, self.violations = projects, boms, violations or {}

    def call(self, path):
        return self.boms[path.split("/")[3].split("?")[0]]

    def all(self, path):
        if path.startswith("project"):
            return self.projects
        return self.violations.get(path.rsplit("/", 1)[1], [])


OLD = {"components": [comp("a", "1", "MIT"), comp("b", "1", "MIT"), comp("gone", "1", "MIT")],
       "vulnerabilities": [vuln("CVE-1", "a-1"), vuln("CVE-2", "b-1", "LOW")]}
NEW = {"components": [comp("a", "2", "MIT"), comp("b", "1", "GPL-3.0-only"), comp("new", "1"), comp("lic", "1", "AGPL-3.0-only")],
       "vulnerabilities": [vuln("CVE-1", "a-2"), vuln("CVE-3", "new-1", "CRITICAL"),
                           vuln("CVE-4", "b-1", state="false_positive")]}
PROJECTS = [{"name": "g/p", "version": "v1.0.0", "uuid": "u1", "isLatest": False},
            {"name": "g/p", "version": "v1.1.0", "uuid": "u2", "isLatest": False},
            {"name": "g/p", "version": "main", "uuid": "u3", "isLatest": True},
            {"name": "g/other", "version": "v0.1.0", "uuid": "u9"}]


def client():
    return FakeClient(PROJECTS, {"u1": OLD, "u2": NEW, "u3": NEW},
                      {"u1": [violation("Unresolved", "x", "1")],
                       "u2": [violation("Unresolved", "x", "2"), violation("Unresolved", "new", "1")]})


class Baseline(unittest.TestCase):
    def test_latest_release_remains_a_branch_baseline(self):
        projects = [dict(p, isLatest=p["version"] == "v1.1.0") for p in PROJECTS if p["name"] == "g/p"]
        self.assertEqual(delta.pick_baseline(projects, "main")["version"], "v1.1.0")

    def test_previous_release_for_tags_and_latest_release_for_branches(self):
        projects = [p for p in PROJECTS if p["name"] == "g/p"]
        self.assertEqual(delta.pick_baseline(projects, "v1.1.0")["version"], "v1.0.0")
        self.assertEqual(delta.pick_baseline(projects, "main")["version"], "v1.1.0")
        self.assertIsNone(delta.pick_baseline(projects, "v1.0.0"))

    def test_mr_and_branch_versions_are_never_a_baseline_unless_named_explicitly(self):
        projects = [p for p in PROJECTS if p["name"] == "g/p"] + [
            {"name": "g/p", "version": "mr-3", "uuid": "m", "lastBomImport": 99, "tags": [{"name": "scan-purpose:mr-feedback"}]},
            {"name": "g/p", "version": "feat", "uuid": "f", "lastBomImport": 98, "tags": [{"name": "scan-purpose:branch"}]}]
        self.assertEqual(delta.pick_baseline(projects, "main")["version"], "v1.1.0")
        self.assertEqual(delta.pick_baseline(projects, "dev")["version"], "v1.1.0")
        self.assertEqual(delta.pick_baseline(projects, "main", "mr-3")["version"], "mr-3")

    def test_rerun_of_old_release_is_not_compared_with_newer_one(self):
        projects = [dict(p, lastBomImport=i) for i, p in enumerate(PROJECTS[:3])]
        self.assertIsNone(delta.pick_baseline(projects, "v1.0.0"))

    def test_numeric_not_lexical_order_and_explicit_baseline(self):
        projects = [{"version": v, "uuid": v} for v in ("v1.9.0", "v1.10.0", "v1.11.0")]
        self.assertEqual(delta.pick_baseline(projects, "v1.11.0")["version"], "v1.10.0")
        self.assertEqual(delta.pick_baseline(projects, "v1.11.0", "v1.9.0")["version"], "v1.9.0")
        with self.assertRaises(ValueError):
            delta.pick_baseline(projects, "v1.11.0", "nope")


class Diff(unittest.TestCase):
    def setUp(self):
        self.result = delta.build(client(), "g/p", "v1.1.0", "https://pw", {})

    def test_vulnerabilities_new_fixed_unchanged_and_suppressed_ignored(self):
        v = self.result["vulnerabilities"]
        self.assertEqual([x["id"] for x in v["new"]], ["CVE-3"])
        self.assertEqual([x["id"] for x in v["fixed"]], ["CVE-2"])
        self.assertEqual(v["unchanged"], 1)  # CVE-1 survives the version bump of "a"

    def test_licenses(self):
        lic = self.result["licenses"]
        self.assertEqual(lic["newLicenses"], ["AGPL-3.0-only", "GPL-3.0-only"])
        self.assertEqual(lic["changed"], [{"component": "b", "from": ["MIT"], "to": ["GPL-3.0-only"]}])
        self.assertEqual(lic["unresolved"], ["new"])

    def test_components_and_violations(self):
        c = self.result["components"]
        self.assertEqual([x["component"] for x in c["added"]], ["lic", "new"])
        self.assertEqual([x["component"] for x in c["removed"]], ["gone"])
        self.assertEqual(c["versionChanged"], [{"component": "a", "from": ["1"], "to": ["2"]}])
        self.assertEqual([x["component"] for x in self.result["violations"]["new"]], ["new"])
        self.assertEqual(self.result["violations"]["unchanged"], 1)
        self.assertTrue(self.result["relevant"])

    def test_identical_versions_are_not_relevant(self):
        same = FakeClient(PROJECTS, {"u1": OLD, "u2": OLD})
        self.assertFalse(delta.build(same, "g/p", "v1.1.0", "https://pw", {})["relevant"])

    def test_first_version_has_no_baseline(self):
        result = delta.build(client(), "g/p", "v1.0.0", "https://pw", {})
        self.assertIsNone(result["baseline"])
        self.assertIn("nothing to compare", delta.render(result))

    def test_markdown_contains_the_findings_and_truncates(self):
        text = delta.render(self.result)
        for expected in ("v1.0.0", "**CRITICAL** CVE-3 in new", "GPL-3.0-only", "No license information: new"):
            self.assertIn(expected, text)
        many = dict(self.result, vulnerabilities={"new": [{"id": f"CVE-{i}", "severity": "LOW", "component": "c"}
                                                          for i in range(60)], "fixed": [], "unchanged": 0})
        self.assertIn("and 20 more", delta.render(many))


class Settle(unittest.TestCase):
    def test_waits_until_two_reads_agree(self):
        reads = [{"vulnerabilities": {}, "violations": {}}, {"vulnerabilities": {"k": 1}, "violations": {}},
                 {"vulnerabilities": {"k": 1}, "violations": {}}]
        sleeps = []
        with patch("patchwatch.ci.delta.snapshot", side_effect=reads):
            result, settled = delta.settled_snapshot(None, {}, 300, 20, sleeps.append)
        self.assertTrue(settled)
        self.assertEqual(result["vulnerabilities"], {"k": 1})
        self.assertEqual(sleeps, [20, 20])

    def test_gives_up_after_the_limit(self):
        counter = iter(range(100))
        with patch("patchwatch.ci.delta.snapshot", side_effect=lambda *a: {"vulnerabilities": {next(counter): 1}, "violations": {}}):
            _, settled = delta.settled_snapshot(None, {}, 40, 20, lambda s: None)
        self.assertFalse(settled)


class Notify(unittest.TestCase):
    def setUp(self):
        patcher = patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in [n for n in os.environ if n.startswith("PATCHWATCH_")]:
            del os.environ[name]
        self.result = delta.build(client(), "g/p", "v1.1.0", "https://pw", {})

    def test_webhook_and_mail_are_sent_for_relevant_changes(self):
        env = {"PATCHWATCH_DELTA_SMTP_HOST": "smtp.example.org", "PATCHWATCH_DELTA_MAIL_TO": "a@example.org, b@example.org",
               "PATCHWATCH_DELTA_SMTP_USER": "u"}
        with patch.dict(os.environ, {"PATCHWATCH_DELTA_WEBHOOK": "https://chat.example.org/hook",
                                     "PATCHWATCH_DELTA_SMTP_PASSWORD": "pw"}), \
                patch("patchwatch.ci.delta.post_json") as post, patch("patchwatch.ci.delta.smtplib.SMTP") as smtp:
            smtp.return_value.__enter__.return_value = smtp.return_value
            sent = delta.notify(env, self.result, "text")
        self.assertEqual(sent, ["webhook", "mail"])
        self.assertEqual(post.call_args.args, ("https://chat.example.org/hook", {"text": "text"}))
        server = smtp.return_value
        server.starttls.assert_called_once()
        server.login.assert_called_once_with("u", "pw")
        message = server.send_message.call_args.args[0]
        self.assertEqual(message["To"], "a@example.org, b@example.org")
        self.assertIn("1 new vulnerabilities", message["Subject"])

    def test_modes(self):
        quiet = dict(self.result, relevant=False)
        with patch.dict(os.environ, {"PATCHWATCH_DELTA_WEBHOOK": "https://x.example/h"}), \
                patch("patchwatch.ci.delta.post_json") as post:
            self.assertEqual(delta.notify({}, quiet, "t"), [])
            self.assertEqual(delta.notify({"PATCHWATCH_DELTA_NOTIFY": "never"}, self.result, "t"), [])
            self.assertEqual(delta.notify({"PATCHWATCH_DELTA_NOTIFY": "always"}, quiet, "t"), ["webhook"])
            with self.assertRaises(ValueError):
                delta.notify({"PATCHWATCH_DELTA_NOTIFY": "x"}, quiet, "t")
        self.assertEqual(post.call_count, 1)

    def test_plain_http_webhook_is_refused_without_leaking_the_url(self):
        with patch.dict(os.environ, {"PATCHWATCH_DELTA_WEBHOOK": "http://secret.example/token"}), \
                patch("patchwatch.ci.delta.post_json") as post, patch("sys.stderr") as err:
            self.assertEqual(delta.notify({}, self.result, "t"), [])
        post.assert_not_called()
        self.assertNotIn("secret.example", "".join(str(c) for c in err.write.call_args_list))

    def test_run_writes_files(self):
        with tempfile.TemporaryDirectory() as folder, patch("builtins.print"):
            delta.run(client(), "g/p", "v1.1.0", "https://pw", {"PATCHWATCH_DELTA_NOTIFY": "never"}, folder)
            data = json.loads((Path(folder) / "patchwatch-delta.json").read_text())
            self.assertEqual(data["baseline"]["version"], "v1.0.0")
            self.assertIn("New vulnerabilities", (Path(folder) / "patchwatch-delta.md").read_text())


if __name__ == "__main__":
    unittest.main()
