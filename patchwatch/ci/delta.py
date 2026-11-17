# SPDX-License-Identifier: Apache-2.0
"""Delta report: licenses, vulnerabilities and policy violations of a project version against its predecessor."""
import argparse
from datetime import datetime, timezone
from email.message import EmailMessage
import json
import os
from pathlib import Path
import re
import smtplib
import ssl
import sys
import time
import urllib.error
from urllib.parse import urlencode

from ..dtrack.client import DependencyTrack
from ..core.http import check_url, post_json, secret
from ..dtrack.scopes import is_scoped

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSIGNED")
# Analysis states that remove a finding from the report (suppressed or assessed as not exploitable/resolved).
IGNORED_STATES = {"not_affected", "false_positive", "resolved", "resolved_with_pedigree"}
VERSION = re.compile(r"v?(\d+(?:\.\d+)*)(?:[-+].*)?\Z")
MAX_ROWS = 40
NOTIFY_MODES = ("relevant", "always", "never")


def component_key(component):
    """Identity of a component across versions: the package URL without version and qualifiers."""
    purl = (component.get("purl") or "").split("#")[0].split("?")[0]
    head, at, tail = purl.rpartition("@")
    if at and "/" in head and "/" not in tail:
        purl = head
    if purl:
        return purl
    group = component.get("group")
    return (group + "/" if group else "") + (component.get("name") or "?")


def label(component):
    """Display name ``group/name`` of a component."""
    group = component.get("group")
    return (group + "/" if group else "") + (component.get("name") or "?")


def licenses(component):
    """Set of license ids, names and expressions of a component."""
    result = set()
    for entry in component.get("licenses") or []:
        if entry.get("expression"):
            result.add(entry["expression"])
            continue
        lic = entry.get("license") or {}
        value = lic.get("id") or lic.get("name")
        if value:
            result.add(value)
    return result


def severity(vulnerability):
    """Highest severity among a vulnerability's ratings, ``UNASSIGNED`` if none."""
    ranks = [(r.get("severity") or "").upper() for r in vulnerability.get("ratings") or []]
    for level in SEVERITIES:
        if level in ranks:
            return level
    return "UNASSIGNED"


def snapshot(client, project):
    """Components, active vulnerabilities and unsuppressed policy violations of one project version."""
    identifier = project["uuid"]
    bom = client.call("bom/cyclonedx/project/" + identifier + "?" + urlencode({"variant": "withVulnerabilities"}))
    components, by_ref = {}, {}
    for component in bom.get("components") or []:
        key = component_key(component)
        entry = components.setdefault(key, {"name": label(component), "versions": set(), "licenses": set()})
        entry["versions"].add(component.get("version") or "")
        entry["licenses"] |= licenses(component)
        if component.get("bom-ref"):
            by_ref[component["bom-ref"]] = key
    vulnerabilities = {}
    for vulnerability in bom.get("vulnerabilities") or []:
        if (vulnerability.get("analysis") or {}).get("state") in IGNORED_STATES:
            continue
        for affect in vulnerability.get("affects") or []:
            key = by_ref.get(affect.get("ref"))
            if key is not None:
                vulnerabilities[(vulnerability.get("id"), key)] = {
                    "id": vulnerability.get("id"), "source": (vulnerability.get("source") or {}).get("name"),
                    "severity": severity(vulnerability), "component": components[key]["name"]}
    violations = {}
    for violation in client.all("violation/project/" + identifier):
        policy = violation["policyCondition"]["policy"]
        key = component_key(violation.get("component") or {})
        violations[(violation["type"], policy["name"], policy["violationState"], key)] = {
            "type": violation["type"], "policy": policy["name"], "state": policy["violationState"],
            "component": label(violation.get("component") or {})}
    return {"components": components, "vulnerabilities": vulnerabilities, "violations": violations}


def ranked(items):
    """Items ordered from the most to the least severe."""
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(items, key=lambda v: (order.get(v.get("severity"), 9), v["component"], v["id"]))


def diff(old, new):
    """Difference between two summaries: added/removed/changed components, license changes, new and resolved vulnerabilities and violations."""
    old_c, new_c = old["components"], new["components"]
    added = [{"component": new_c[k]["name"], "versions": sorted(new_c[k]["versions"]),
              "licenses": sorted(new_c[k]["licenses"])} for k in sorted(new_c.keys() - old_c.keys())]
    removed = [{"component": old_c[k]["name"], "versions": sorted(old_c[k]["versions"]),
                "licenses": sorted(old_c[k]["licenses"])} for k in sorted(old_c.keys() - new_c.keys())]
    changed = [{"component": new_c[k]["name"], "from": sorted(old_c[k]["versions"]), "to": sorted(new_c[k]["versions"])}
               for k in sorted(old_c.keys() & new_c.keys()) if old_c[k]["versions"] != new_c[k]["versions"]]
    license_changes = [{"component": new_c[k]["name"], "from": sorted(old_c[k]["licenses"]),
                        "to": sorted(new_c[k]["licenses"])}
                       for k in sorted(old_c.keys() & new_c.keys()) if old_c[k]["licenses"] != new_c[k]["licenses"]]
    old_set = set().union(*(c["licenses"] for c in old_c.values()))
    new_set = set().union(*(c["licenses"] for c in new_c.values()))
    unresolved = sorted({new_c[k]["name"] for k in new_c if not new_c[k]["licenses"]
                         and (k not in old_c or old_c[k]["licenses"])})
    new_v = ranked([new["vulnerabilities"][k] for k in new["vulnerabilities"].keys() - old["vulnerabilities"].keys()])
    fixed_v = ranked([old["vulnerabilities"][k] for k in old["vulnerabilities"].keys() - new["vulnerabilities"].keys()])
    new_p = [new["violations"][k] for k in sorted(new["violations"].keys() - old["violations"].keys())]
    done_p = [old["violations"][k] for k in sorted(old["violations"].keys() - new["violations"].keys())]
    result = {
        "components": {"added": added, "removed": removed, "versionChanged": changed,
                       "total": {"baseline": len(old_c), "current": len(new_c)}},
        "licenses": {"newLicenses": sorted(new_set - old_set), "droppedLicenses": sorted(old_set - new_set),
                     "changed": license_changes, "unresolved": unresolved,
                     "added": [{"component": new_c[k]["name"], "licenses": sorted(new_c[k]["licenses"] - old_c.get(k, {}).get("licenses", set()))}
                               for k in sorted(new_c) if new_c[k]["licenses"] - old_c.get(k, {}).get("licenses", set())],
                     "removed": [{"component": old_c[k]["name"], "licenses": sorted(old_c[k]["licenses"] - new_c.get(k, {}).get("licenses", set()))}
                                 for k in sorted(old_c) if old_c[k]["licenses"] - new_c.get(k, {}).get("licenses", set())]},
        "vulnerabilities": {"new": new_v, "fixed": fixed_v,
                            "unchanged": len(new["vulnerabilities"].keys() & old["vulnerabilities"].keys())},
        "violations": {"new": new_p, "resolved": done_p,
                       "unchanged": len(new["violations"].keys() & old["violations"].keys())}}
    result["relevant"] = bool(new_v or new_p or license_changes or unresolved or result["licenses"]["newLicenses"])
    return result


def version_tuple(version):
    """Numeric version tuple, or ``None`` for versions that are not plain numbers."""
    match = VERSION.fullmatch(version or "")
    return tuple(int(n) for n in match.group(1).split(".")) if match else None


def pick_baseline(projects, version, explicit=None):
    """Previous release: the next lower version number; for unversioned branches the highest release."""
    if explicit:
        found = next((p for p in projects if p.get("version") == explicit), None)
        if found is None:
            raise ValueError("Baseline version not found in Dependency-Track")
        return found
    others = [p for p in projects if p.get("version") != version and p.get("active", True) and not is_scoped(p)]
    current = version_tuple(version)
    parsed = [(version_tuple(p.get("version")), p) for p in others]
    parsed = [(v, p) for v, p in parsed if v is not None and (current is None or v < current)]
    if parsed:
        return max(parsed, key=lambda item: (item[0], item[1].get("lastBomImport") or 0))[1]
    if current is None and others:
        return max(others, key=lambda p: p.get("lastBomImport") or 0)
    return None


def render(delta):
    """Markdown report of a delta."""
    project, base = delta["project"], delta["baseline"]
    lines = [f"# PatchWatch delta: {project['name']} {project['version']}"]
    if base is None:
        lines += ["", "No earlier version found: nothing to compare with yet."]
        return "\n".join(lines) + "\n"
    c, lic, vul, pol = delta["components"], delta["licenses"], delta["vulnerabilities"], delta["violations"]
    lines += [f"Compared with **{base['version']}**. Components: {c['total']['baseline']} → {c['total']['current']}.", ""]
    if not delta.get("settled", True):
        lines += ["_Vulnerability analysis was still running; findings may be incomplete._", ""]
    lines += ["| | New | Fixed / resolved | Unchanged |", "|---|---|---|---|",
              f"| Vulnerabilities | {len(vul['new'])} | {len(vul['fixed'])} | {vul['unchanged']} |",
              f"| Policy violations | {len(pol['new'])} | {len(pol['resolved'])} | {pol['unchanged']} |",
              f"| Components | +{len(c['added'])} | -{len(c['removed'])} | {len(c['versionChanged'])} version changes |", ""]

    def section(title, rows, empty):
        lines.append(f"## {title}")
        if not rows:
            lines.append(empty)
        for row in rows[:MAX_ROWS]:
            lines.append("- " + row)
        if len(rows) > MAX_ROWS:
            lines.append(f"- … and {len(rows) - MAX_ROWS} more (see patchwatch-delta.json)")
        lines.append("")

    section("New vulnerabilities", [f"**{v['severity']}** {v['id']} in {v['component']}" for v in vul["new"]], "None.")
    section("Fixed vulnerabilities", [f"{v['severity']} {v['id']} in {v['component']}" for v in vul["fixed"]], "None.")
    section("New policy violations", [f"{v['state']} {v['type']}: {v['policy']} ({v['component']})" for v in pol["new"]], "None.")
    section("Licenses", ([f"New license: {n}" for n in lic["newLicenses"]]
                         + [f"{x['component']}: {', '.join(x['from']) or 'none'} → {', '.join(x['to']) or 'none'}" for x in lic["changed"]]
                         + [f"No license information: {n}" for n in lic["unresolved"]]), "No license changes.")
    section("Added components", [f"{x['component']} {', '.join(x['versions'])} ({', '.join(x['licenses']) or 'no license'})"
                                 for x in c["added"]], "None.")
    section("Removed components", [f"{x['component']} {', '.join(x['versions'])}" for x in c["removed"]], "None.")
    return "\n".join(lines)


def subject(delta):
    """One-line notification title with the number of new vulnerabilities and violations."""
    project, vul = delta["project"], delta["vulnerabilities"]
    return (f"[PatchWatch] {project['name']} {project['version']}: {len(vul['new'])} new vulnerabilities, "
            f"{len(delta['violations']['new'])} new policy violations")


def send_webhook(url, text):
    """Post the report text to a chat webhook (HTTPS only)."""
    post_json(check_url(url, False), {"text": text})


def send_mail(env, title, text):
    """Send the report by SMTP (STARTTLS); recipients and server come from ``PATCHWATCH_DELTA_*``."""
    host, recipients = env["PATCHWATCH_DELTA_SMTP_HOST"], [a.strip() for a in env["PATCHWATCH_DELTA_MAIL_TO"].split(",") if a.strip()]
    sender = env.get("PATCHWATCH_DELTA_MAIL_FROM") or "patchwatch@" + host
    message = EmailMessage()
    message["Subject"], message["From"], message["To"] = title, sender, ", ".join(recipients)
    message.set_content(text)
    port = int(env.get("PATCHWATCH_DELTA_SMTP_PORT") or 587)
    context = ssl.create_default_context()
    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=30, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=30)
    with server:
        if port != 465:
            server.starttls(context=context)
        user, password = env.get("PATCHWATCH_DELTA_SMTP_USER"), secret("PATCHWATCH_DELTA_SMTP_PASSWORD")
        if user:
            server.login(user, password)
        server.send_message(message)


def notify(env, delta, text):
    """Webhook (Slack/Mattermost-compatible `text`) and/or e-mail; failures are returned, never raised."""
    mode = env.get("PATCHWATCH_DELTA_NOTIFY") or "relevant"
    if mode not in NOTIFY_MODES:
        raise ValueError("PATCHWATCH_DELTA_NOTIFY must be relevant, always or never")
    if mode == "never" or delta["baseline"] is None or (mode == "relevant" and not delta["relevant"]):
        return []
    sent, failed = [], []
    hook = secret("PATCHWATCH_DELTA_WEBHOOK")
    if hook:
        try:
            send_webhook(hook, text)
            sent.append("webhook")
        except (OSError, ValueError, urllib.error.URLError):
            failed.append("webhook")
    if env.get("PATCHWATCH_DELTA_SMTP_HOST") and env.get("PATCHWATCH_DELTA_MAIL_TO"):
        try:
            send_mail(env, subject(delta), text)
            sent.append("mail")
        except (OSError, ValueError, smtplib.SMTPException):
            failed.append("mail")
    for channel in failed:
        print(f"Delta report: delivery via {channel} failed (check URL, host and credentials)", file=sys.stderr)
    return sent


def settled_snapshot(client, project, wait, interval=20, sleep=time.sleep):
    """Vulnerability analysis runs after the BOM import; wait until two reads agree or time runs out."""
    previous, waited = snapshot(client, project), 0
    while wait > 0:
        if waited >= wait:
            return previous, False
        sleep(interval)
        waited += interval
        current = snapshot(client, project)
        if current["vulnerabilities"] == previous["vulnerabilities"] and current["violations"] == previous["violations"]:
            return current, True
        previous = current
    return previous, True


def build(client, name, version, base_url, env, wait=0, sleep=time.sleep):
    """Compare ``version`` of project ``name`` with its baseline; waits up to ``wait`` seconds for analysis results."""
    projects = [p for p in client.all("project?" + urlencode({"name": name})) if p.get("name") == name]
    current = next((p for p in projects if p.get("version") == version), None)
    if current is None:
        raise ValueError("Project version not found in Dependency-Track")
    baseline = pick_baseline(projects, version, env.get("PATCHWATCH_DELTA_BASELINE") or None)
    delta = {"generatedAt": datetime.now(timezone.utc).isoformat(),
             "project": {"name": name, "version": version, "url": base_url + "/projects/" + current["uuid"]},
             "baseline": None}
    if baseline is None:
        delta["relevant"] = False
        return delta
    now, settled = settled_snapshot(client, current, wait, sleep=sleep)
    delta.update(diff(snapshot(client, baseline), now))
    delta["baseline"] = {"version": baseline["version"], "url": base_url + "/projects/" + baseline["uuid"]}
    delta["settled"] = settled
    return delta


def run(client, name, version, base_url, env, directory, wait=0, sleep=time.sleep):
    """Build the delta, write ``patchwatch-delta.json``/``.md`` and notify according to ``PATCHWATCH_DELTA_NOTIFY``."""
    delta = build(client, name, version, base_url, env, wait, sleep)
    text = render(delta)
    directory = Path(directory)
    (directory / "patchwatch-delta.json").write_text(json.dumps(delta, indent=2) + "\n")
    (directory / "patchwatch-delta.md").write_text(text)
    print(text)
    delta["notified"] = notify(env, delta, text)
    return delta


def main():
    """CLI: delta report of one project version."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, help="Dependency-Track project name")
    parser.add_argument("--version", required=True, help="Version to report on")
    parser.add_argument("--baseline", help="Version to compare with (default: previous release)")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--wait", type=int, default=0, metavar="SECONDS",
                        help="Wait up to this long for the vulnerability analysis to settle")
    args = parser.parse_args()
    os.umask(0o077)
    env = dict(os.environ)
    if args.baseline:
        env["PATCHWATCH_DELTA_BASELINE"] = args.baseline
    try:
        url = check_url(os.environ["DT_URL"], os.getenv("ALLOW_HTTP") == "true")
        key = secret("DT_API_KEY")
        if not key:
            raise ValueError("DT_API_KEY(_FILE) is required (VIEW_PORTFOLIO and VIEW_POLICY_VIOLATION)")
        run(DependencyTrack(url, {"X-Api-Key": key}), args.project, args.version, url, env, args.output_dir, args.wait)
    except urllib.error.HTTPError as error:
        parser.exit(1, f"Delta report failed: HTTP {error.code} from the PatchWatch API\n")
    except (OSError, KeyError, ValueError, urllib.error.URLError) as error:
        detail = str(error) if isinstance(error, ValueError) else "check API access and arguments"
        parser.exit(1, f"Delta report failed ({type(error).__name__}): {detail}\n")


if __name__ == "__main__":
    main()
