# SPDX-License-Identifier: Apache-2.0
"""Idempotent Dependency-Track 5.x setup using an admin login or API key.

Run on every deployment (``python -m patchwatch.dtrack.setup``). Every step only adds or
reconciles what PatchWatch owns and leaves unrelated administrator choices untouched.
"""
import argparse
import json
import os
from pathlib import Path

from ..core.http import check_url, secret
from ..core.tags import MANAGED_TAG
from .client import DependencyTrack, admin_client
from .groups import AggregationError, sync as sync_groups
from .policies import load as load_policies, load_license_groups, sync as sync_policies
from .scopes import definitions as scoped_policies
from .versions import adopt, folders, sync as sync_versions

DEFAULT_ECOSYSTEMS = "npm;PyPI;Go;Maven;crates.io;Alpine;Debian;Ubuntu"
# Key files that the (non-root) monitor and version containers read.
WORLD_READABLE_KEYS = ("monitor_key", "versions_key")


class Provisioner:
    """Provisioning steps against one :class:`DependencyTrack` instance."""

    def __init__(self, client: DependencyTrack):
        self.client = client

    # -- teams and access -------------------------------------------------------------------

    def team(self, name, permissions, key_path=None):
        """Create the team, enforce least privilege and (once) write its API key to ``key_path``."""
        client = self.client
        team = next((t for t in client.all("team") if t["name"] == name), None)
        if team is None:
            team = client.call("team", {"name": name}, "PUT")
        existing = {p["name"] for p in team.get("permissions", [])}
        for permission in existing - set(permissions):
            client.call(f"permission/{permission}/team/{team['uuid']}", method="DELETE")
        for permission in set(permissions) - existing:
            client.call(f"permission/{permission}/team/{team['uuid']}", method="POST")
        if key_path is None:
            return team  # Browser-only teams do not need an API key.
        key_path = Path(key_path)
        if not key_path.exists():
            key = client.call(f"team/{team['uuid']}/key", method="PUT")
            key_path.write_text(key["key"])
            key_path.chmod(0o444 if key_path.name in WORLD_READABLE_KEYS else 0o600)
        return team

    def oidc(self):
        """Reconcile explicitly requested browser teams (``OIDC_TEAM_MAPPINGS_FILE``) without issuing API keys."""
        filename = os.getenv("OIDC_TEAM_MAPPINGS_FILE")
        if not filename:
            return
        mappings = json.loads(Path(filename).read_text())
        # Validate everything before changing access permissions.
        if not isinstance(mappings, list) or any(
            not isinstance(m, dict) or not isinstance(m.get("team"), str) or not m["team"]
            or not isinstance(m.get("group"), str) or not m["group"]
            or not isinstance(m.get("permissions"), list) or not m["permissions"]
            or any(not isinstance(p, str) or not p for p in m["permissions"])
            for m in mappings
        ):
            raise ValueError("Invalid OIDC team mappings")
        groups = {g["name"]: g for g in self.client.all("oidc/group")}
        for mapping in mappings:
            team = self.team(mapping["team"], mapping["permissions"])
            name = mapping["group"]
            if name not in groups:
                groups[name] = self.client.call("oidc/group", {"name": name}, "PUT")
            # The API returns the existing mapping when called again.
            self.client.call("oidc/mapping", {"team": team["uuid"], "group": groups[name]["uuid"]}, "PUT")

    def teams(self, output):
        """The API-key teams of this deployment; separate keys can be rotated or revoked independently."""
        self.team("sbom-upload", ["BOM_UPLOAD", "PROJECT_CREATION_UPLOAD"], output / "upload_key")
        self.team("ci-upload", ["BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO"], output / "ci_upload_key")
        # Project administration remains server-side; CI can upload and look up parents.
        self.team("project-versions", ["VIEW_PORTFOLIO", "PORTFOLIO_MANAGEMENT"], output / "versions_key")
        # v5 requires VIEW_VULNERABILITY for the BOM export with vulnerabilities (delta reports, MR feedback).
        self.team("inventory-monitor", ["VIEW_PORTFOLIO", "VIEW_POLICY_VIOLATION", "VIEW_VULNERABILITY"],
                  output / "monitor_key")

    # -- vulnerability sources ----------------------------------------------------------------

    def trivy(self):
        """Enable the Trivy analyzer when ``TRIVY_URL`` is set; otherwise keep the current configuration."""
        url = os.getenv("TRIVY_URL")
        if not url:
            return
        url = check_url(url, os.getenv("ALLOW_HTTP") == "true")
        token = secret("TRIVY_TOKEN")
        if not token or any(c in token for c in "\r\n"):
            raise ValueError("TRIVY_TOKEN(_FILE) is required with TRIVY_URL")
        ignore_unfixed = os.getenv("TRIVY_IGNORE_UNFIXED", "false").lower()
        if ignore_unfixed not in ("true", "false"):
            raise ValueError("TRIVY_IGNORE_UNFIXED must be true or false")
        secret_name = self.client.secret("PATCHWATCH_TRIVY_TOKEN", token)
        self.client.extension("vuln-analyzer", "trivy", enabled=True, apiUrl=url, apiToken=secret_name,
                              ignoreUnfixed=ignore_unfixed == "true", scanLibrary=True, scanOs=True)

    def vulnerability_sources(self):
        """OSV and EPSS always; credential-dependent feeds only when their credentials are supplied."""
        client = self.client
        ecosystems = os.getenv("OSV_ECOSYSTEMS", DEFAULT_ECOSYSTEMS)
        ecosystems = [e.strip() for e in ecosystems.replace(",", ";").split(";") if e.strip()]
        client.property("vuln-source", "epss.enabled", "true")
        client.extension("vuln-data-source", "osv", enabled=True, aliasSyncEnabled=True, ecosystems=ecosystems)
        if secret("GITHUB_TOKEN"):
            client.extension("vuln-data-source", "github", enabled=True,
                             apiToken=client.secret("PATCHWATCH_GITHUB_TOKEN", secret("GITHUB_TOKEN")))
        if secret("OSS_INDEX_TOKEN"):
            client.extension("vuln-analyzer", "oss-index", enabled=True, username=os.environ["OSS_INDEX_USERNAME"],
                             apiToken=client.secret("PATCHWATCH_OSSINDEX_TOKEN", secret("OSS_INDEX_TOKEN")))
        else:
            client.extension("vuln-analyzer", "oss-index", enabled=False)

    # -- notifications, policies, hierarchy -----------------------------------------------------

    def webhook_rule(self, webhook_url):
        """Notification rule that forwards findings of managed projects to the bridge."""
        client = self.client
        client.call("tag", [MANAGED_TAG], "PUT")
        publisher = next(p for p in client.all("notification/publisher") if p.get("extensionName") == "webhook")
        name = "Patchwatch bridge"
        rule = next((r for r in client.all("notification/rule") if r["name"] == name), None)
        if rule is None:
            rule = client.call("notification/rule", {"name": name, "scope": "PORTFOLIO", "level": "INFORMATIONAL",
                                                     "publisher": {"uuid": publisher["uuid"]}}, "PUT")
        rule.update({"level": "INFORMATIONAL", "enabled": True, "notifyChildren": True, "logSuccessfulPublish": False,
                     "tags": [{"name": MANAGED_TAG}],
                     "notifyOn": ["NEW_VULNERABILITY", "NEW_VULNERABLE_DEPENDENCY", "POLICY_VIOLATION"],
                     "publisherConfig": json.dumps({"destinationUrl": webhook_url})})
        client.call("notification/rule", rule, "POST")

    def policies(self, definitions, license_groups):
        """Security/license policies plus their copy for merge-request and branch scans."""
        sync_policies(self.client, definitions, license_groups)
        sync_policies(self.client, scoped_policies(definitions), license_groups)

    def hierarchy(self):
        """Adopt existing projects into groups, aggregate scoped versions and maintain the navigation folders."""
        changes = adopt(self.client) + sync_groups(self.client)
        print("Project groups: " + ("; ".join(changes) or "no change"))
        sync_versions(self.client)
        folders(self.client)

    # -- orchestration ------------------------------------------------------------------------

    def run(self, output, webhook_url, public_url):
        """Provision everything. Inputs are validated first so a bad file leaves the instance untouched."""
        definitions, license_groups = load_policies(), load_license_groups()
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.trivy()
        self.oidc()
        self.teams(output)
        self.client.property("telemetry", "submission.enabled", "false")
        self.client.property("general", "base.url", public_url, "URL")
        self.vulnerability_sources()
        self.webhook_rule(webhook_url)
        self.policies(definitions, license_groups)
        self.hierarchy()
        self.client.call("metrics/portfolio/refresh")
        print("Dependency-Track configured: upload/CI-upload/monitor teams, OSV, security/license policies and webhook rule "
              "(Trivy configured when TRIVY_URL is set)")


def configure(url, output, webhook_url, public_url, initial_admin=False):
    """Authenticate as administrator and provision the instance."""
    Provisioner(admin_client(url, initial_admin)).run(output, webhook_url, public_url)


def main():
    """CLI: provision Dependency-Track from the environment (``DT_URL``, ``BRIDGE_URL``, ``PUBLIC_URL``, secrets)."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initial-admin", action="store_true", help="Allow first-install rotation of admin/admin")
    parser.add_argument("--output", default=".secrets")
    args = parser.parse_args()
    os.umask(0o077)
    webhook_url = os.environ["BRIDGE_URL"].rstrip("/") + "/webhook/" + secret("WEBHOOK_TOKEN")
    try:
        configure(os.environ["DT_URL"], args.output, webhook_url, os.environ["PUBLIC_URL"], args.initial_admin)
    except AggregationError as error:
        parser.exit(1, f"Setup failed: {error}\n")
    except Exception as error:
        parser.exit(1, f"Setup failed ({type(error).__name__}); check API connectivity, credentials and configuration\n")


if __name__ == "__main__":
    main()
