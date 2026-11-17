# SPDX-License-Identifier: Apache-2.0
"""Exit nonzero when a devhost has not supplied a recent SBOM."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from urllib.parse import urlencode
from ..core.http import check_url, request, secret
from ..core.tags import is_host_project


def stale_projects(projects, max_age_hours, now=None, expected=()):
    """Names of host projects whose last BOM import is older than ``max_age_hours``, plus ``expected`` hosts that never reported."""
    now = time.time() if now is None else now
    stale, seen = [], set()
    for project in projects:
        name = project.get("name", "")
        if not is_host_project(project) or project.get("version") != "current" or project.get("active") is False:
            continue
        seen.add(name)
        value = project.get("lastBomImport")
        try:
            if isinstance(value, (int, float)):
                timestamp = float(value)/1000
            else:
                date = datetime.fromisoformat(value.replace("Z", "+00:00"))
                timestamp = (date if date.tzinfo else date.replace(tzinfo=timezone.utc)).timestamp()
        except (TypeError, ValueError, AttributeError):
            timestamp = 0
        if now - timestamp > max_age_hours * 3600:
            stale.append(name)
    return sorted(set(stale).union(set(expected) - seen))


def portfolio_consistency(projects, metrics, now=None, grace_minutes=75):
    """Error text when Dependency-Track's portfolio metrics lag behind the settled host inventory, otherwise ``None``."""
    now = time.time() if now is None else now
    managed = [p for p in projects if is_host_project(p) and p.get('active') is not False and p.get('version')=='current']
    # Native portfolio aggregation is hourly; allow one cadence plus a margin after a BOM import.
    settled = [p for p in managed if now-float(p.get('lastBomImport') or 0)/1000 > grace_minutes*60]
    if not settled:
        return None
    expected_components = sum(p.get('metrics',{}).get('components',0) for p in settled)
    expected_findings = sum(p.get('metrics',{}).get('findingsTotal',0) for p in settled)
    if (metrics.get('projects',0)<len(settled) or metrics.get('components',0)<expected_components
            or metrics.get('findingsTotal',0)<expected_findings):
        return 'Portfolio metrics lag behind the host inventory; refresh the dashboard metrics'
    return None


def main():
    """CLI: print the monitoring result as JSON; exit 1 for stale hosts or lagging metrics, 2 on API errors."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-age-hours", type=float, default=float(os.getenv("MAX_AGE_HOURS", "48")))
    parser.add_argument("--expected-file", default=os.getenv("EXPECTED_HOSTS_FILE"))
    parser.add_argument("--skip-portfolio-check", action="store_true", help="Only check host upload age")
    args = parser.parse_args()
    url = check_url(os.environ["DT_URL"], os.getenv("ALLOW_HTTP") == "true")
    key = secret("DT_API_KEY")
    if not key or args.max_age_hours <= 0:
        parser.error("A read-only API key and positive age limit are required")
    projects, page = [], 1
    try:
        while True:
            items, _ = request(url + "/api/v1/project?" + urlencode({"pageNumber": page, "pageSize": 100}), headers={"X-Api-Key": key})
            projects.extend(items)
            if len(items) < 100:
                break
            page += 1
        expected = json.loads(Path(args.expected_file).read_text()) if args.expected_file else []
        stale = stale_projects(projects, args.max_age_hours, expected=expected)
        consistency = None
        if not args.skip_portfolio_check:
            metrics, _ = request(url+"/api/v1/metrics/portfolio/current",headers={"X-Api-Key":key})
            consistency = portfolio_consistency(projects, metrics)
    except Exception:
        parser.exit(2, "Inventory monitoring failed: check API, credential and expected-hosts file\n")
    print(json.dumps({"stale_hosts": stale, "max_age_hours": args.max_age_hours, "portfolio_error": consistency}))
    if stale or consistency:
        parser.exit(1)


if __name__ == "__main__":
    main()
