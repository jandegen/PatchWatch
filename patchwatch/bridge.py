# SPDX-License-Identifier: Apache-2.0
"""Authenticated, durable Dependency-Track webhook outbox."""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
import re
from pathlib import Path
import signal
import sqlite3
import threading
import time

from .core.http import check_url, post_json, request, secret

LOG = logging.getLogger("patchwatch")
SEVERITIES = {"UNASSIGNED": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GROUPS = {"NEW_VULNERABILITY", "NEW_VULNERABLE_DEPENDENCY", "POLICY_VIOLATION"}


def priority(severity, kev, epss=None, high=0.5, medium=0.1):
    """Ticket urgency: actively exploited (CISA KEV) always wins, then exploit probability (EPSS), then severity."""
    if kev:
        return "kev"
    epss = epss or 0.0
    if epss >= high or severity == "CRITICAL":
        return "high"
    if epss >= medium or severity in ("HIGH", "POLICY"):
        return "medium"
    return "low"


def events(payload, minimum="HIGH", kev=None):
    """Normalize a Dependency-Track notification into alert events (one per affected project) with a stable dedupe key; accepts v4 and v5 payloads."""
    kev = kev or {}
    notification = payload["notification"]
    # v5 renders protobuf enums with their prefix (GROUP_POLICY_VIOLATION); v4 used the bare name.
    group = str(notification["group"]).removeprefix("GROUP_")
    if group not in GROUPS:
        return []
    subject = notification["subject"]
    component = subject.get("component", {})
    if not component.get("name"):
        raise ValueError("Missing component")
    projects = subject.get("affectedProjects") or subject.get("projects") or [subject.get("project")]
    if not projects or any(not isinstance(p, dict) or not p.get("uuid") for p in projects):
        raise ValueError("Missing project identity")
    if group == "POLICY_VIOLATION":
        violation = subject["policyViolation"]
        condition = violation.get("condition") or violation.get("policyCondition") or {}
        policy = condition.get("policy", {})
        issue = "policy:" + str(condition.get("uuid") or policy.get("uuid") or violation.get("uuid") or "")
        if issue == "policy:":
            raise ValueError("Missing policy identity")
        vulnerabilities = [{"vulnId": issue, "severity": "POLICY"}]
    else:
        vulnerabilities = subject.get("vulnerabilities") or [subject.get("vulnerability")]
    results = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict) or not vulnerability.get("vulnId"):
            raise ValueError("Missing vulnerability identity")
        severity = vulnerability.get("severity", "UNASSIGNED").upper()
        known = kev.get(vulnerability["vulnId"].upper()) if group != "POLICY_VIOLATION" else None
        # Actively exploited findings bypass the severity threshold.
        if group != "POLICY_VIOLATION" and not known and SEVERITIES.get(severity, 0) < SEVERITIES[minimum]:
            continue
        for project in projects:
            identity = [project["uuid"], component.get("purl") or [component.get("group", ""), component["name"], component.get("version", "")], vulnerability["vulnId"]]
            key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
            raw_tags = project.get("tags", [])
            if isinstance(raw_tags, str):
                raw_tags = raw_tags.split(",")
            tags = [t.get("name", "") if isinstance(t, dict) else str(t) for t in raw_tags]
            results.append({"key": key, "project": project.get("name", project["uuid"]),
                            "project_uuid": project["uuid"], "tags": tags, "severity": severity,
                            "component": component["name"], "version": component.get("version", ""),
                            "issue": vulnerability["vulnId"], "group": group,
                            "kev": bool(known), "kev_due": (known or {}).get("due", ""),
                            "ransomware": bool(known and known.get("ransomware")),
                            "priority": priority(severity, known)})
    return results


class Bridge:
    """Alert bridge: filters and enriches findings (KEV, EPSS, project metadata), deduplicates them in SQLite and forwards them to the configured routes."""
    def __init__(self, path, routes, minimum="HIGH", project_lookup=None, kev_url=None, epss_url=None, epss_high=0.5, epss_medium=0.1):
        if minimum not in SEVERITIES:
            raise ValueError("Invalid minimum severity")
        self.path, self.routes, self.minimum = str(path), routes, minimum
        self.project_lookup = project_lookup
        self.kev_url = check_url(kev_url) if kev_url else None
        self.kev_next = 0.0
        self.escalate_next = 0.0
        self.epss_high, self.epss_medium = epss_high, epss_medium
        self.epss_url = check_url(epss_url) if epss_url else None
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        for route in routes:
            if route["kind"] not in ("slack", "teams", "jira"):
                raise ValueError("Unknown target kind")
            check_url(route["url"], route.get("allow_http", False))
            if route["kind"] == "jira":
                if not route.get("project") or not route.get("token_env"):
                    raise ValueError("Jira requires project and token_env")
                if not isinstance(route.get("priority_map", {}), dict):
                    raise ValueError("priority_map must be an object")
        names = [r["name"] for r in routes]
        if len(names) != len(set(names)):
            raise ValueError("Target names must be unique")
        with self.db() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY, target TEXT NOT NULL, event TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_try REAL NOT NULL DEFAULT 0, delivered REAL, created REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS escalated (id TEXT PRIMARY KEY)")
            db.execute("CREATE TABLE IF NOT EXISTS kev_reviews (id TEXT PRIMARY KEY, due TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS epss (cve TEXT PRIMARY KEY, score REAL NOT NULL, fetched REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, due TEXT NOT NULL, ransomware INTEGER NOT NULL)")

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def review_due(self, event_key, now=None):
        """One durable deadline per finding, shared by all routes and delivery retries."""
        now = time.time() if now is None else now
        due = datetime.fromtimestamp(now + 86400, timezone.utc).isoformat()
        with self.db() as db:
            db.execute("INSERT OR IGNORE INTO kev_reviews (id,due) VALUES (?,?)", (event_key, due))
            return db.execute("SELECT due FROM kev_reviews WHERE id=?", (event_key,)).fetchone()['due']

    def refresh_kev(self, now=None):
        """Replace the local CISA KEV copy. On failure keep the last good copy and retry in an hour."""
        now = time.time() if now is None else now
        if not self.kev_url or now < self.kev_next:
            return False
        try:
            catalog = request(self.kev_url)[0]
            rows = [(str(v["cveID"]).upper(), str(v.get("dueDate", "")), int(v.get("knownRansomwareCampaignUse") == "Known"))
                    for v in catalog["vulnerabilities"]]
            if not rows:
                raise ValueError("Empty KEV catalog")
        except Exception as error:
            self.kev_next = now + 3600
            LOG.warning("KEV refresh failed (%s); using last known catalog", type(error).__name__)
            return False
        with self.db() as db:
            db.execute("DELETE FROM kev")
            db.executemany("INSERT OR REPLACE INTO kev (cve,due,ransomware) VALUES (?,?,?)", rows)
        self.kev_next = now + 86400
        self.escalate_next = now
        return True

    def epss_score(self, cve, now=None):
        """Exploit probability for a CVE (cached one day). Never raises; unknown or unreachable gives None."""
        now = time.time() if now is None else now
        cve = cve.upper()
        if not self.epss_url or not CVE.match(cve):
            return None
        with self.db() as db:
            row = db.execute("SELECT score,fetched FROM epss WHERE cve=?", (cve,)).fetchone()
        if row and now - row["fetched"] < 86400:
            return row["score"]
        try:
            from urllib.parse import urlencode
            data = request(self.epss_url + "?" + urlencode({"cve": cve}))[0]["data"]
            score = float(data[0]["epss"]) if data else None
        except Exception as error:
            LOG.warning("EPSS lookup failed (%s)", type(error).__name__)
            return row["score"] if row else None
        if score is not None:
            with self.db() as db:
                db.execute("INSERT OR REPLACE INTO epss (cve,score,fetched) VALUES (?,?,?)", (cve, score, now))
        return score

    def escalate(self, now=None):
        """Raise already delivered tickets/messages whose CVE was added to KEV after delivery."""
        now = time.time() if now is None else now
        if now < self.escalate_next:
            return 0
        kev = self.kev_entries()
        with self.db() as db:
            rows = db.execute("SELECT id,target,event FROM deliveries WHERE delivered IS NOT NULL AND id NOT IN (SELECT id FROM escalated)").fetchall()
        done, failed = 0, False
        for row in rows:
            event = json.loads(row["event"])
            known = kev.get(event["issue"].upper())
            if event.get("kev") or not known:
                continue
            event.update(kev=True, kev_due=known["due"], ransomware=known["ransomware"], priority="kev",
                         kev_review_due=self.review_due(event["key"], now))
            route = next((r for r in self.routes if r["name"] == row["target"]), None)
            try:
                if route:
                    self.deliver(route, event, update=True)
            except Exception as error:
                failed = True
                LOG.warning("KEV escalation pending (%s)", type(error).__name__)
                continue
            with self.db() as db:
                db.execute("INSERT OR IGNORE INTO escalated (id) VALUES (?)", (row["id"],))
            done += 1
        self.escalate_next = now + 3600 if failed else float("inf")
        return done

    def kev_entries(self):
        with self.db() as db:
            return {r["cve"]: {"due": r["due"], "ransomware": bool(r["ransomware"])} for r in db.execute("SELECT * FROM kev")}

    def enqueue(self, payload):
        count = 0
        kev = self.kev_entries()
        pending = events(payload, self.minimum, kev)
        for event in pending:
            if event.get("kev"):
                event["kev_review_due"] = self.review_due(event["key"])
        with self.db() as db:
            for event in pending:
                if not event["tags"] and self.project_lookup and any(r.get("tags") for r in self.routes):
                    project = self.project_lookup(event["project_uuid"])
                    event["tags"] = [t["name"] for t in project.get("tags", [])]
                for route in self.routes:
                    tags = route.get("tags", [])
                    projects = route.get("projects", [])
                    if tags and not set(tags).intersection(event["tags"]):
                        continue
                    if projects and event["project"] not in projects:
                        continue
                    identity = event["key"] + ":" + route["name"]
                    cursor = db.execute("INSERT OR IGNORE INTO deliveries (id,target,event,created) VALUES (?,?,?,?)",
                                        (identity, route["name"], json.dumps(event), time.time()))
                    count += cursor.rowcount
        return count

    def jira_headers(self, route):
        token = secret(route["token_env"])
        if not token:
            raise ValueError("Missing Jira credential")
        auth = "Bearer " + token
        if route.get("username"):
            auth = "Basic " + base64.b64encode((route["username"] + ":" + token).encode()).decode()
        return {"Authorization": auth}

    def deliver(self, route, event, update=False):
        """Send an event. With update=True the finding became urgent after delivery: raise it instead of creating it."""
        if event.get("kev") and not event.get("kev_review_due"):
            event = {**event, "kev_review_due": self.review_due(event["key"])}
        epss = None if event.get("kev") else self.epss_score(event["issue"])
        urgency = priority(event["severity"], event.get("kev"), epss, self.epss_high, self.epss_medium)
        flag = "[KEV] " if event.get("kev") else ""
        message = f"{flag}[{event['severity']}] {event['issue']}: {event['component']} {event['version']} on {event['project']}"
        if epss is not None:
            message += f" (EPSS {epss:.0%})"
        if event.get("kev_review_due"):
            message += " | KEV review due: " + event["kev_review_due"]
        if update:
            message = "Now actively exploited: " + message
        if route["kind"] == "slack":
            post_json(route["url"], {"text": message})
        elif route["kind"] == "teams":
            post_json(route["url"], {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": [{"type": "TextBlock", "text": message, "wrap": True}]}}]})
        else:
            headers = self.jira_headers(route)
            base = route["url"].rstrip("/")
            label = "patchwatch-" + event["key"]
            # Search by deterministic label before POST: handles retries after an ambiguous timeout.
            # Jira v2 supports Server/Data Center and Jira Cloud's text description format.
            from urllib.parse import urlencode
            result, _ = request(base + "/rest/api/2/search?" + urlencode({"jql": 'labels = "' + label + '"', "maxResults": 1}), headers=headers)
            found = (result or {}).get("issues")
            details = ""
            labels = ["patchwatch", label]
            if event.get("kev"):
                labels.append("kev")
                details += "\nActively exploited (CISA KEV)"
                if event.get("kev_due"):
                    details += ", remediation due " + event["kev_due"]
                if event.get("kev_review_due"):
                    details += "\nInternal review deadline (24h): " + event["kev_review_due"]
                if event.get("ransomware"):
                    details += ", used in ransomware campaigns"
            if epss is not None:
                details += f"\nEPSS: {epss:.1%} probability of exploitation within 30 days"
            # Jira priority names differ per instance, so only set them when the route maps them.
            name = route.get("priority_map", {}).get(urgency)
            if update:
                if not found:
                    return
                fields = {"priority": {"name": name}} if name else {}
                if event.get("kev_review_due"):
                    fields["duedate"] = event["kev_review_due"][:10]
                put = {"update": {"labels": [{"add": "kev"}], "comment": [{"add": {"body": message + details}}]}}
                if fields:
                    put["fields"] = fields
                request(base + "/rest/api/2/issue/" + found[0]["key"], json.dumps(put).encode(),
                        {"Content-Type": "application/json", **headers}, "PUT")
                return
            if found:
                return
            fields = {"project": {"key": route["project"]}, "issuetype": {"name": route.get("issue_type", "Task")},
                      "summary": message[:255], "description": message + "\nFinding: " + event["key"] + details, "labels": labels}
            if name:
                fields["priority"] = {"name": name}
            if event.get("kev_review_due"):
                fields["duedate"] = event["kev_review_due"][:10]
            post_json(base + "/rest/api/2/issue", {"fields": fields}, headers)

    def drain(self):
        with self.db() as db:
            rows = db.execute("SELECT * FROM deliveries WHERE delivered IS NULL AND next_try <= ? ORDER BY created LIMIT 100", (time.time(),)).fetchall()
        for row in rows:
            try:
                route = next(r for r in self.routes if r["name"] == row["target"])
                self.deliver(route, json.loads(row["event"]))
            except Exception as error:
                # Payloads and destination URLs contain sensitive information; never log them.
                LOG.warning("Delivery pending (%s)", type(error).__name__)
                with self.db() as db:
                    db.execute("UPDATE deliveries SET attempts=attempts+1,next_try=? WHERE id=?",
                               (time.time() + min(3600, 2 ** min(row["attempts"] + 1, 12)), row["id"]))
            else:
                with self.db() as db:
                    db.execute("UPDATE deliveries SET delivered=? WHERE id=?", (time.time(), row["id"]))

    def metrics(self):
        with self.db() as db:
            row = db.execute("SELECT count(*) AS total, coalesce(sum(delivered IS NULL),0) AS pending, coalesce(max(CASE WHEN delivered IS NULL THEN ?-created ELSE 0 END),0) AS age FROM deliveries", (time.time(),)).fetchone()
        return f"patchwatch_deliveries_total {row['total']}\npatchwatch_deliveries_pending {row['pending']}\npatchwatch_oldest_pending_seconds {row['age']}\n"


def make_handler(bridge, token):
    """HTTP request handler class for the webhook, health and metrics endpoints."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, body=b"", content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                try:
                    with bridge.db() as db:
                        db.execute("SELECT 1 FROM deliveries LIMIT 1")
                    self.respond(200, b'{"status":"ok"}')
                except sqlite3.Error:
                    self.respond(503)
            elif self.path == "/metrics":
                self.respond(200, bridge.metrics().encode(), "text/plain; version=0.0.4")
            else:
                self.respond(404)

        def do_POST(self):
            self.connection.settimeout(15)
            if not hmac.compare_digest(self.path, "/webhook/" + token):
                self.respond(401)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 2 * 1024 * 1024:
                    self.respond(413)
                    return
                if self.headers.get_content_type() != "application/json":
                    self.respond(415)
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError("Truncated request")
                payload = json.loads(body)
                count = bridge.enqueue(payload)
            except (ValueError, KeyError, TypeError, AttributeError):
                self.respond(400)
                return
            except (sqlite3.Error, OSError, RuntimeError):
                self.respond(503)
                return
            self.respond(202, json.dumps({"queued": count}).encode())
    return Handler


def main():
    """Run the bridge service (configuration from the environment)."""
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO)
    token = secret("WEBHOOK_TOKEN")
    if len(token) < 32 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in token):
        raise SystemExit("WEBHOOK_TOKEN must have at least 32 URL-safe characters")
    routes_file = os.getenv("ROUTES_FILE", "/run/secrets/routes.json")
    routes = json.loads(Path(routes_file).read_text())
    lookup = None
    key = secret("DT_API_KEY")
    if key:
        base = check_url(os.environ["DT_URL"], os.getenv("ALLOW_HTTP") == "true")
        from urllib.parse import quote
        def lookup(identity):
            return request(base + "/api/v1/project/" + quote(identity, safe=""), headers={"X-Api-Key": key})[0]
    elif any(r.get("tags") for r in routes):
        raise SystemExit("Tag routing requires DT_API_KEY(_FILE) and DT_URL for project lookup")
    kev_url = None
    if os.getenv("KEV_ENABLED", "true") == "true":
        kev_url = os.getenv("KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    epss_url = None
    if os.getenv("EPSS_ENABLED", "true") == "true":
        epss_url = os.getenv("EPSS_URL", "https://api.first.org/data/v1/epss")
    bridge = Bridge(os.getenv("DATABASE_PATH", "/data/bridge.sqlite"), routes, os.getenv("MIN_SEVERITY", "HIGH"), lookup, kev_url,
                    epss_url, float(os.getenv("EPSS_HIGH", "0.5")), float(os.getenv("EPSS_MEDIUM", "0.1")))
    stop = threading.Event()
    def worker():
        while not stop.is_set():
            try:
                bridge.refresh_kev()
                bridge.escalate()
                bridge.drain()
            except Exception as error:
                LOG.error("Outbox worker error (%s)", type(error).__name__)
            stop.wait(2)
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    server = ThreadingHTTPServer(("0.0.0.0", int(os.getenv("PORT", "8080"))), make_handler(bridge, token))
    server.daemon_threads = True
    def shutdown(*_):
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever()
    finally:
        stop.set()
        server.server_close()
        thread.join(timeout=35)


if __name__ == "__main__":
    main()
