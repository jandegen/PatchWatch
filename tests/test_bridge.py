# SPDX-License-Identifier: Apache-2.0
import copy
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from patchwatch.bridge import Bridge, events, make_handler


def finding():
    return {"notification": {"group": "NEW_VULNERABILITY", "subject": {
        "component": {"name": "example", "version": "1.0", "purl": "pkg:pypi/example@1.0"},
        "vulnerability": {"vulnId": "CVE-2026-12345", "severity": "HIGH"},
        "affectedProjects": [{"uuid": "host-uuid-1", "name": "devhost-asset-1", "tags": [{"name": "team:platform"}]}]}}}


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "bridge.sqlite"
        self.routes = [{"name": "platform", "kind": "slack", "url": "https://example.org/hook", "tags": ["team:platform"]}]
        self.bridge = Bridge(self.path, self.routes)

    def test_threshold_and_multiple_hosts(self):
        payload = finding()
        payload["notification"]["subject"]["affectedProjects"].append({"uuid": "second", "name": "devhost-asset-2"})
        self.assertEqual(len(events(payload)), 2)
        payload["notification"]["subject"]["vulnerability"]["severity"] = "MEDIUM"
        self.assertEqual(events(payload), [])

    def test_new_dependency_and_new_vulnerability_dedupe(self):
        original = finding()
        event = events(original)[0]
        subject = original["notification"]["subject"]
        payload = {"notification": {"group": "NEW_VULNERABLE_DEPENDENCY", "subject": {
            "project": subject["affectedProjects"][0], "component": subject["component"],
            "vulnerabilities": [subject["vulnerability"], {"vulnId": "CVE-second", "severity": "CRITICAL"}]}}}
        self.assertEqual(len(events(payload)), 2)
        self.assertEqual(events(payload)[0]["key"], event["key"])

    def test_policy_does_not_need_severity(self):
        payload = finding(); subject = payload["notification"]["subject"]
        payload["notification"]["group"] = "POLICY_VIOLATION"
        subject["project"] = subject.pop("affectedProjects")[0]
        del subject["vulnerability"]
        subject["policyViolation"] = {"uuid": "violation-1", "policyCondition": {"uuid": "condition-1"}}
        self.assertEqual(events(payload)[0]["severity"], "POLICY")

    def test_v5_payload_with_prefixed_group_and_renamed_condition(self):
        """Shape of a real Dependency-Track 5.2 webhook: GROUP_ prefix, subject.project and policyViolation.condition."""
        project = {"uuid": "p-1", "name": "g/app", "version": "main", "tags": ["team:platform"], "isActive": True}
        policy = {"notification": {"group": "GROUP_POLICY_VIOLATION", "level": "LEVEL_INFORMATIONAL", "subject": {
            "component": {"uuid": "c-1", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
            "project": project, "policyViolation": {"uuid": "v-1", "type": "LICENSE", "condition": {
                "uuid": "cond-1", "policy": {"uuid": "pol-1", "name": "Review", "violationState": "WARN"}}}}}}
        event = events(policy)[0]
        self.assertEqual((event["group"], event["issue"], event["severity"]), ("POLICY_VIOLATION", "policy:cond-1", "POLICY"))
        self.assertEqual(event["tags"], ["team:platform"])
        vulnerability = {"notification": {"group": "GROUP_NEW_VULNERABILITY", "subject": {
            "component": policy["notification"]["subject"]["component"], "project": project,
            "vulnerability": {"uuid": "x", "vulnId": "CVE-2026-1", "source": "NVD", "severity": "CRITICAL"},
            "affectedProjects": []}}}
        self.assertEqual(events(vulnerability)[0]["issue"], "CVE-2026-1")
        self.assertEqual(events(vulnerability)[0]["project_uuid"], "p-1")
        self.assertEqual(events({"notification": {"group": "GROUP_BOM_PROCESSED", "subject": {}}}), [])

    def test_v5_and_v4_findings_share_one_dedupe_key(self):
        v4 = finding()
        v4["notification"]["subject"]["affectedProjects"] = [{"uuid": "p-1", "name": "g/app"}]
        v5 = copy.deepcopy(v4)
        v5["notification"]["group"] = "GROUP_NEW_VULNERABILITY"
        self.assertEqual(events(v4)[0]["key"], events(v5)[0]["key"])

    def test_durable_dedupe_and_retry(self):
        self.assertEqual(self.bridge.enqueue(finding()), 1)
        self.assertEqual(Bridge(self.path, self.routes).enqueue(finding()), 0)
        with patch.object(self.bridge, "deliver", side_effect=OSError("offline")):
            self.bridge.drain()
        with self.bridge.db() as db:
            row = db.execute("SELECT * FROM deliveries").fetchone()
            self.assertEqual(row["attempts"], 1)
            self.assertIsNone(row["delivered"])
            db.execute("UPDATE deliveries SET next_try=0")
        with patch.object(self.bridge, "deliver") as deliver:
            self.bridge.drain(); self.bridge.drain()
            self.assertEqual(deliver.call_count, 1)
        self.assertIn("patchwatch_deliveries_pending 0", self.bridge.metrics())

    def test_partial_failure_retries_only_failed_target(self):
        self.bridge.routes.append({"name": "other", "kind": "slack", "url": "https://example.org/other"})
        self.bridge.enqueue(finding())
        def deliver(route, event):
            if route["name"] == "other":
                raise OSError("offline")
        with patch.object(self.bridge, "deliver", side_effect=deliver): self.bridge.drain()
        with self.bridge.db() as db: db.execute("UPDATE deliveries SET next_try=0")
        with patch.object(self.bridge, "deliver") as deliver:
            self.bridge.drain()
            self.assertEqual(deliver.call_count, 1)
            self.assertEqual(deliver.call_args.args[0]["name"], "other")

    def test_routing_does_not_broadcast_unmatched_hosts(self):
        payload = finding(); payload["notification"]["subject"]["affectedProjects"][0]["tags"] = []
        self.assertEqual(self.bridge.enqueue(payload), 0)
        self.assertEqual(self.bridge.enqueue(finding()), 1)

    def test_jira_timeout_recovery_uses_label(self):
        route = {"kind": "jira", "url": "https://jira.example.org", "project": "SEC", "token_env": "TEST_TOKEN"}
        with patch("patchwatch.bridge.secret", return_value="token"), patch("patchwatch.bridge.request", return_value=({"issues": [{"key": "SEC-1"}]}, {})), patch("patchwatch.bridge.post_json") as post:
            self.bridge.deliver(route, events(finding())[0])
            post.assert_not_called()

    def test_kev_bypasses_threshold_and_sets_priority(self):
        payload = finding()
        payload["notification"]["subject"]["vulnerability"]["severity"] = "MEDIUM"
        kev = {"CVE-2026-12345": {"due": "2026-12-01", "ransomware": True}}
        self.assertEqual(events(payload), [])
        event = events(payload, kev=kev)[0]
        self.assertEqual((event["kev"], event["priority"], event["kev_due"], event["ransomware"]), (True, "kev", "2026-12-01", True))
        self.assertEqual(events(finding())[0]["priority"], "medium")
        payload["notification"]["subject"]["vulnerability"]["severity"] = "CRITICAL"
        self.assertEqual(events(payload)[0]["priority"], "high")

    def test_kev_refresh_keeps_last_good_copy_on_failure(self):
        bridge = Bridge(self.path, self.routes, kev_url="https://example.org/kev.json")
        catalog = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Known"}]}
        with patch("patchwatch.bridge.request", return_value=(catalog, {})):
            self.assertTrue(bridge.refresh_kev(now=1000))
        self.assertEqual(bridge.kev_entries()["CVE-2026-12345"], {"due": "2026-12-01", "ransomware": True})
        with patch("patchwatch.bridge.request", side_effect=OSError("offline")):
            self.assertFalse(bridge.refresh_kev(now=1000 + 86400))
        with patch("patchwatch.bridge.request", return_value=({"vulnerabilities": []}, {})):
            self.assertFalse(bridge.refresh_kev(now=1000 + 86400 + 3600))
        self.assertIn("CVE-2026-12345", bridge.kev_entries())
        payload = finding()
        payload["notification"]["subject"]["vulnerability"]["severity"] = "LOW"
        self.assertEqual(bridge.enqueue(payload), 1)

    def test_jira_priority_only_when_mapped(self):
        kev = {"CVE-2026-12345": {"due": "2026-12-01", "ransomware": False}}
        event = events(finding(), kev=kev)[0]
        route = {"kind": "jira", "url": "https://jira.example.org", "project": "SEC", "token_env": "T"}
        def sent(route):
            with patch("patchwatch.bridge.secret", return_value="t"), patch("patchwatch.bridge.request", return_value=({"issues": []}, {})), patch("patchwatch.bridge.post_json") as post:
                self.bridge.deliver(route, event)
                return post.call_args[0][1]["fields"]
        fields = sent(route)
        self.assertNotIn("priority", fields)
        self.assertIn("kev", fields["labels"])
        self.assertIn("2026-12-01", fields["description"])
        self.assertEqual(sent({**route, "priority_map": {"kev": "Highest"}})["priority"], {"name": "Highest"})

    def test_epss_raises_priority_and_degrades_gracefully(self):
        from patchwatch.bridge import priority
        self.assertEqual(priority("MEDIUM", None, 0.6), "high")
        self.assertEqual(priority("LOW", None, 0.2), "medium")
        self.assertEqual(priority("LOW", None, 0.01), "low")
        self.assertEqual(priority("LOW", {"due": ""}, 0.0), "kev")
        bridge = Bridge(self.path, self.routes, epss_url="https://example.org/epss")
        with patch("patchwatch.bridge.request", return_value=({"data": [{"cve": "CVE-2026-12345", "epss": "0.87"}]}, {})) as call:
            self.assertEqual(bridge.epss_score("CVE-2026-12345", now=1000), 0.87)
            self.assertEqual(bridge.epss_score("CVE-2026-12345", now=2000), 0.87)
            self.assertEqual(call.call_count, 1)
        self.assertIsNone(bridge.epss_score("GHSA-xxxx-yyyy-zzzz"))
        with patch("patchwatch.bridge.request", side_effect=OSError("offline")):
            self.assertEqual(bridge.epss_score("CVE-2026-12345", now=1000 + 86400), 0.87)
            self.assertIsNone(bridge.epss_score("CVE-2026-99999", now=1000))

    def test_late_kev_listing_escalates_existing_jira_ticket(self):
        route = {"name": "jira", "kind": "jira", "url": "https://jira.example.org", "project": "SEC", "token_env": "T",
                 "priority_map": {"kev": "Highest"}}
        bridge = Bridge(self.path, [route], kev_url="https://example.org/kev.json")
        self.assertEqual(bridge.enqueue(finding()), 1)
        calls = []
        def fake(url, data=None, headers=None, method=None):
            calls.append((url, method, data))
            return ({"issues": [{"key": "SEC-7"}]}, {}) if "search" in url else (None, {})
        with patch("patchwatch.bridge.secret", return_value="t"), patch("patchwatch.bridge.request", side_effect=fake), patch("patchwatch.bridge.post_json"):
            bridge.drain()
            self.assertEqual(bridge.escalate(now=1), 0)  # not in KEV yet: nothing to raise
            catalog = {"vulnerabilities": [{"cveID": "CVE-2026-12345", "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Unknown"}]}
            with patch("patchwatch.bridge.request", return_value=(catalog, {})):
                bridge.refresh_kev(now=10)
            calls.clear()
            self.assertEqual(bridge.escalate(now=11), 1)
            self.assertEqual(bridge.escalate(now=12), 0)  # only once
        put = [c for c in calls if c[1] == "PUT"][0]
        self.assertTrue(put[0].endswith("/rest/api/2/issue/SEC-7"))
        body = json.loads(put[2])
        self.assertEqual(body["fields"]["priority"], {"name": "Highest"})
        self.assertEqual(body["update"]["labels"], [{"add": "kev"}])

    def test_http_auth_validation_and_persist_before_ack(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.bridge, "x" * 32))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:" + str(server.server_port)
        def post(path, data, content_type="application/json"):
            return urllib.request.urlopen(urllib.request.Request(base + path, data=data, headers={"Content-Type": content_type}))
        with self.assertRaises(urllib.error.HTTPError) as error: post("/webhook/wrong", b"{}")
        self.assertEqual(error.exception.code, 401)
        error.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as error: post("/webhook/" + "x" * 32, b"{}")
        self.assertEqual(error.exception.code, 400)
        error.exception.close()
        with post("/webhook/" + "x" * 32, json.dumps(finding()).encode()) as response:
            self.assertEqual(response.status, 202)
            self.assertEqual(json.load(response), {"queued": 1})
        with self.bridge.db() as db: self.assertEqual(db.execute("SELECT count(*) FROM deliveries").fetchone()[0], 1)
        with post("/webhook/" + "x" * 32, json.dumps(finding()).encode()) as response:
            self.assertEqual(json.load(response), {"queued": 0})

    def test_tag_lookup_for_standard_dtrack_payload(self):
        payload = finding()
        del payload["notification"]["subject"]["affectedProjects"][0]["tags"]
        lookup = lambda identity: {"tags": [{"name": "team:platform"}]}
        bridge = Bridge(self.path, self.routes, project_lookup=lookup)
        self.assertEqual(bridge.enqueue(payload), 1)

    def test_kev_review_deadline_survives_duplicate_events_and_restarts(self):
        from datetime import datetime, timezone
        with self.bridge.db() as db:
            db.execute("INSERT INTO kev VALUES ('CVE-2026-12345','2026-12-01',0)")
        self.bridge.routes.append({'name':'second','kind':'slack','url':'https://example.org/second'})
        with patch('patchwatch.bridge.time.time', return_value=1000):
            self.assertEqual(self.bridge.enqueue(finding()), 2)
        with patch('patchwatch.bridge.time.time', return_value=2000):
            self.assertEqual(Bridge(self.path, self.bridge.routes).enqueue(finding()), 0)
        with self.bridge.db() as db:
            queued = [json.loads(r['event']) for r in db.execute('SELECT event FROM deliveries')]
        expected = datetime.fromtimestamp(1000+86400,timezone.utc).isoformat()
        self.assertEqual({e['kev_review_due'] for e in queued}, {expected})
        self.assertEqual(self.bridge.review_due(queued[0]['key'],now=3000), expected)

    def test_jira_kev_review_due_date_is_set_without_replacing_cisa_date(self):
        event=events(finding(), kev={'CVE-2026-12345':{'due':'2026-12-01'}})[0]
        event['kev_review_due']='2026-11-15T12:00:00+00:00'
        route={'kind':'jira','url':'https://jira.example.org','project':'SEC','token_env':'TEST_TOKEN'}
        with patch('patchwatch.bridge.secret',return_value='token'), patch('patchwatch.bridge.request',return_value=({'issues':[]},{})), patch('patchwatch.bridge.post_json') as send:
            self.bridge.deliver(route,event)
        fields=send.call_args.args[1]['fields']
        self.assertEqual(fields['duedate'],'2026-11-15')
        self.assertIn('2026-12-01',fields['description'])
        self.assertIn('2026-11-15T12:00:00+00:00',fields['description'])
