# SPDX-License-Identifier: Apache-2.0
"""GitLab CI integration: SBOM of a repository and/or its images, upload to Dependency-Track, optional gate."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import uuid
import urllib.error
from urllib.parse import quote, urlencode

from ..dtrack.compliance import breaches
from . import delta
from . import bsi
from ..dtrack.client import DependencyTrack
from ..core.http import check_url, secret
from ..core.tags import ci_tags
from ..core.quality import violations as quality_violations
from ..core.sbom import upload_and_wait
from ..core.services import find_services, merge, service
from ..dtrack.versions import BRANCH_COMMENT, OTHER_BRANCH_COMMENT, RELEASE_COMMENT

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSIGNED")
NAME_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class Skip(Exception):
    """The pipeline context is not one that should be uploaded (e.g. a feature branch)."""


def words(value):
    """Whitespace-separated words of an environment value."""
    return (value or "").split()


def target(env):
    """Upload target; Latest is reconciled server-side across existing versions."""
    tag = env.get("CI_COMMIT_TAG")
    branch = env.get("CI_COMMIT_BRANCH")
    if tag:
        version, latest = tag, False
    elif branch and branch == env.get("CI_DEFAULT_BRANCH"):
        version, latest = branch, False
    elif branch and branch in words(env.get("PATCHWATCH_BRANCHES")):
        version, latest = branch, False
    else:
        if branch:
            raise Skip(f"Branch {branch!r} is not the default branch and is not allowed by PATCHWATCH_BRANCHES; "
                       "run_if only controls job scheduling. Set branches (PATCHWATCH_BRANCHES) to allow uploads; "
                       "no upload or report was produced")
        raise Skip("No branch or tag in this pipeline; no upload or report was produced")
    if not usable_version(version):
        raise ValueError("Version (branch or tag name) is not usable as a Dependency-Track version")
    return version, latest


def usable_version(version):
    """Whether a string may be used as a Dependency-Track version (non-empty, <= 128 chars, no control characters or commas)."""
    return bool(version) and len(version) <= 128 and not any(ord(c) < 32 or c == "," for c in version)


def provenance(bom, env):
    """Attach explicit GitLab provenance to both inventory and container SBOMs."""
    metadata = bom["metadata"]
    metadata["timestamp"] = datetime.now(timezone.utc).isoformat()
    root = metadata["component"]
    values = {"commit": env.get("CI_COMMIT_SHA"), "ref": env.get("CI_COMMIT_TAG") or env.get("CI_COMMIT_BRANCH"),
              "default-branch": env.get("CI_DEFAULT_BRANCH"), "pipeline": env.get("CI_PIPELINE_URL")}
    root.setdefault("properties", []).extend({"name": "patchwatch:" + k, "value": v} for k, v in values.items() if v)
    refs = root.setdefault("externalReferences", [])
    project_url = env.get("CI_PROJECT_URL")
    commit = env.get("CI_COMMIT_SHA")
    if project_url and commit:
        branch = env.get("CI_COMMIT_BRANCH", "")
        # Only the default branch is a candidate for Latest; other branches are recorded as such.
        comment = (RELEASE_COMMENT + env["CI_COMMIT_TAG"] if env.get("CI_COMMIT_TAG")
                   else (BRANCH_COMMENT if not env.get("CI_DEFAULT_BRANCH") or branch == env["CI_DEFAULT_BRANCH"]
                         else OTHER_BRANCH_COMMENT) + branch)
        refs.append({"type": "vcs", "url": project_url.rstrip("/") + "/-/commit/" + quote(commit, safe=""),
                     "comment": comment + " (" + commit[:8] + ")"})
    if env.get("CI_PIPELINE_URL"):
        refs.append({"type": "build-system", "url": env["CI_PIPELINE_URL"], "comment": "PatchWatch pipeline"})


def project_name(env):
    """Dependency-Track project name: the GitLab project path, plus ``/component`` for multi-component repositories."""
    name = env["CI_PROJECT_PATH"]
    component = env.get("PATCHWATCH_COMPONENT", "").strip()
    if component:
        if not NAME_PART.fullmatch(component):
            raise ValueError("PATCHWATCH_COMPONENT must be a short name of letters, digits, '.', '_' or '-'")
        name += "/" + component
    return name


def service_names(env):
    """Validated, de-duplicated names of ``PATCHWATCH_SERVICES``."""
    names = words(env.get("PATCHWATCH_SERVICES"))
    for service in names:
        if not NAME_PART.fullmatch(service):
            raise ValueError("PATCHWATCH_SERVICES must be names of letters, digits, '.', '_' or '-'")
    return list(dict.fromkeys(names))


def detected_services(env, workspace):
    """Services of Compose files in the scan paths plus the explicitly named ones."""
    explicit = [service(n) for n in service_names(env)]
    if env.get("PATCHWATCH_DETECT_SERVICES", "true") != "true":
        return explicit
    paths = [workspace / p for p in words(env.get("PATCHWATCH_SCAN_PATHS", "."))]
    return merge(explicit, find_services([p for p in paths if p.resolve().is_relative_to(workspace) and p.is_dir()]))


def parent_bom(name, version):
    """Empty SBOM used only to create an aggregation container."""
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
            "metadata": {"component": {"type": "application", "name": name, "version": version}},
            "components": []}
    return bom


def lookup_parent(client, name, version):
    """Never replace an existing parent BOM: it may still contain legacy inventory."""
    try:
        return client.call("project/lookup?" + urlencode({"name": name, "version": version}))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            error.close()
            return None
        if error.code == 403:
            error.close()
            raise RuntimeError("Parent lookup requires VIEW_PORTFOLIO: rerun PatchWatch setup to update the CI key "
                               "or supply PATCHWATCH_READ_KEY") from None
        raise


def sources(env, workspace):
    """Syft sources (directories, images, archives) selected by the job variables; paths must exist inside the project."""
    result = []
    for path in words(env.get("PATCHWATCH_SCAN_PATHS", ".")):
        resolved = (workspace / path).resolve()
        if not resolved.is_relative_to(workspace) or not resolved.exists():
            raise ValueError(f"Scan path {path!r} must exist inside the project directory")
        result.append("dir:" + str(resolved))
    for image in words(env.get("PATCHWATCH_IMAGES")):
        if image.startswith("-") or "://" in image:
            raise ValueError("Images must be plain registry references")
        result.append("registry:" + image)
    if not result:
        raise ValueError("At least one scan path or image is required")
    return result


def scan(env, workspace, directory, extra_sources=()):
    """Run Syft for every source and return the decoded SBOMs."""
    syft_env = dict(os.environ)
    # Capture unowned executables/archives as well as package-managed files. The
    # CycloneDX encoder includes file hashes; no raw file contents are uploaded.
    syft_env["SYFT_FILE_METADATA_SELECTION"] = "all"
    syft_env["SYFT_FILE_METADATA_DIGESTS"] = "sha512"
    registry, token = env.get("CI_REGISTRY"), env.get("CI_JOB_TOKEN")
    if registry and token and any(i.startswith(registry + "/") for i in words(env.get("PATCHWATCH_IMAGES"))):
        # Images of the GitLab registry: authenticate with the job token, never on a command line.
        syft_env.setdefault("SYFT_REGISTRY_AUTH_AUTHORITY", registry)
        syft_env.setdefault("SYFT_REGISTRY_AUTH_USERNAME", "gitlab-ci-token")
        syft_env.setdefault("SYFT_REGISTRY_AUTH_PASSWORD", token)
    boms = []
    selected = sources(env, workspace) if words(env.get("PATCHWATCH_SCAN_PATHS", ".")) or words(env.get("PATCHWATCH_IMAGES")) else []
    selected.extend(extra_sources)
    if not selected:
        raise ValueError("At least one scan path or image is required")
    for index, source in enumerate(selected):
        output = Path(directory) / f"{index}.json"
        args = [env.get("PATCHWATCH_SYFT", "syft"), "scan", source, "-o", "cyclonedx-json=" + str(output)]
        if source.startswith("dir:"):
            args.extend(["--exclude", "./.git/**"])
            scan_root = Path(source[4:])
            # A repeated local dry run must not inventory its own previous
            # documents and recursively change the software snapshot.
            generated = [env.get("PATCHWATCH_SBOM_OUTPUT", "patchwatch-sbom.json"),
                         env.get("PATCHWATCH_BSI_REPORT", "patchwatch-bsi-report.json"),
                         env.get("PATCHWATCH_REPORT", "patchwatch-report.json"),
                         "patchwatch-delta.json", "patchwatch-delta.md"]
            for filename in generated:
                path = (workspace / filename).resolve()
                if path.is_relative_to(scan_root):
                    args.extend(["--exclude", "./" + path.relative_to(scan_root).as_posix()])
        for excluded in words(env.get("PATCHWATCH_EXCLUDE")):
            args.extend(["--exclude", excluded])
        subprocess.run(args, check=True, timeout=3600, stdout=subprocess.DEVNULL, env=syft_env)
        scanned = json.loads(output.read_text())
        if source.startswith("dir:"):
            source_root = scanned.get("metadata", {}).get("component")
            if source_root:
                # Syft encodes a directory as type=file. It is a logical scan
                # scope, not a deployable file with its own filename/hash.
                source_root["type"] = "application"
                source_root["name"] = env.get("CI_PROJECT_PATH", "repository") + ":" + str(Path(source[4:]).relative_to(workspace))
                source_root["version"] = env.get("CI_COMMIT_SHA", "")
                author = bsi.entity(env.get("PATCHWATCH_COMPONENT_CREATOR") or env.get("CI_PROJECT_URL"))
                if author:
                    source_root["manufacturer"] = author
                if env.get("PATCHWATCH_DISTRIBUTION_LICENSE"):
                    source_root["licenses"] = [{"expression": env["PATCHWATCH_DISTRIBUTION_LICENSE"], "acknowledgement": "concluded"}]
        bsi.file_metadata(scanned, workspace, Path(source[4:]) if source.startswith("dir:") else None)
        boms.append(scanned)
    return boms


def trust_ca(value):
    """Use an internal CA for the Dependency-Track upload only (a file path or PEM content)."""
    if not value:
        return
    if "BEGIN CERTIFICATE" in value:
        handle = tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False)
        handle.write(value)
        handle.close()
        value = handle.name
    if not Path(value).is_file():
        raise ValueError("PATCHWATCH_CA_CERT must be a certificate file or PEM content")
    os.environ["SSL_CERT_FILE"] = value


def summary(client, name, version, base_url):
    """Findings and policy violations of the uploaded version; needs a read-only key."""
    project = client.call("project/lookup?" + urlencode({"name": name, "version": version}))
    identifier = project["uuid"]
    # Project metrics need only VIEW_PORTFOLIO; the finding list would need VIEW_VULNERABILITY as well.
    # Metrics exclude suppressed findings and may trail the analysis by a short time.
    try:
        metrics = client.call("metrics/project/" + identifier + "/current")
        findings = {s: int(metrics.get(s.lower(), 0) or 0) for s in SEVERITIES}
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        findings = None  # not calculated yet; never reported as zero
    counts = Counter()
    for violation in client.all("violation/project/" + identifier):
        policy = violation["policyCondition"]["policy"]
        counts[(violation["type"], policy["violationState"], policy["name"])] += 1
    violations = [{"type": t, "state": s, "policy": p, "count": n} for (t, s, p), n in sorted(counts.items())]
    return {"uuid": identifier, "url": base_url + "/projects/" + identifier,
            "findings": findings,
            "unsuppressedViolations": violations}


def delta_report(client, name, version, base_url, env, workspace):
    """Delta against the previous release. Informational: a failure here never fails the pipeline."""
    try:
        wait = int(env.get("PATCHWATCH_DELTA_WAIT") or 300)
        result = delta.run(client, name, version, base_url, env, env.get("PATCHWATCH_DELTA_DIR") or workspace, wait)
    except (OSError, KeyError, ValueError, urllib.error.URLError) as error:
        code = f" (HTTP {error.code})" if isinstance(error, urllib.error.HTTPError) else ""
        print(f"Delta report skipped: {type(error).__name__}{code}; check read key permissions and PATCHWATCH_DELTA_* settings")
        return None
    return {"baseline": (result["baseline"] or {}).get("version"), "relevant": result["relevant"],
            "notified": result.get("notified", [])}


def gate(result, fail_on):
    # Same semantics as patchwatch.dtrack.compliance: unsuppressed native policy violations.
    """Whether the project report breaches the ``fail_on`` threshold."""
    return breaches({"projects": [{"licenseConflicts": [], "unsuppressedViolations": result["unsuppressedViolations"],
                                                   "qualityViolations": result.get("qualityViolations", [])}]},
                    fail_on)


def run(env, dry_run=False):
    """One CI job: scan, assemble and check the SBOM, upload it (unless ``dry_run``), then report, gate and compare."""
    workspace = Path(env.get("CI_PROJECT_DIR", ".")).resolve()
    version, latest = target(env)
    name = project_name(env)
    parent_mode = env.get("PATCHWATCH_MODE", "inventory") == "parent"
    if env.get("PATCHWATCH_MODE", "inventory") not in ("inventory", "parent"):
        raise ValueError("PATCHWATCH_MODE must be inventory or parent")
    if not parent_mode and env.get("PATCHWATCH_COMPONENT", "").strip() == "services":
        raise ValueError("The component name services is reserved for the parent job service inventory")
    if parent_mode and env.get("PATCHWATCH_COMPONENT", "").strip():
        raise ValueError("The parent project cannot be a component")
    fail_on = env.get("PATCHWATCH_FAIL_ON", "none") or "none"
    if fail_on not in ("none", "warn", "fail"):
        raise ValueError("PATCHWATCH_FAIL_ON must be none, warn or fail")
    team = (env.get("PATCHWATCH_TEAM") or env.get("CI_PROJECT_ROOT_NAMESPACE", "")).strip()
    try:
        tags = ci_tags(env["CI_PROJECT_ID"], team, env.get("PATCHWATCH_ENVIRONMENT"))
        if env.get("CI_COMMIT_TAG"):
            tags.append("policy-profile:distribution")
            tags.sort()
    except ValueError:
        raise ValueError("Team/environment are not valid tag values (lowercase letters, digits, '.', '_', '-'); "
                         "set the 'team' input explicitly") from None
    url = key = read_key = None
    if not dry_run:
        if not env.get("PATCHWATCH_URL"):
            raise ValueError("PATCHWATCH_URL is not set")
        url = check_url(env["PATCHWATCH_URL"], env.get("PATCHWATCH_ALLOW_HTTP") == "true")
        key = secret("PATCHWATCH_UPLOAD_KEY")
        if not key or any(c in key for c in "\r\n"):
            raise ValueError("PATCHWATCH_UPLOAD_KEY is not set; protected variables exist only on protected branches and tags")
        read_key = secret("PATCHWATCH_READ_KEY")
        if fail_on != "none" and not read_key:
            raise ValueError("fail_on needs PATCHWATCH_READ_KEY; missing data is never treated as passed")
    if parent_mode:
        bom = parent_bom(name, version)
        tags.append("patchwatch-role:parent")
        services_bom = parent_bom(name + "/services", version)
        services_bom["services"] = detected_services(env, workspace)
        provenance(services_bom, env)
        print(f"Parent project: {name} @ {version}; {len(services_bom['services'])} services in {name}/services")
    else:
        with tempfile.TemporaryDirectory(prefix="patchwatch-ci-") as directory:
            scanned = scan(env, workspace, directory)
            # DTrack branch names are routing slots. The document describes a
            # particular software snapshot, including changes in mutable image tags.
            fingerprint = hashlib.sha256(json.dumps([
                {"component": b.get("metadata", {}).get("component"),
                 "components": b.get("components", []), "dependencies": b.get("dependencies", [])}
                for b in scanned], sort_keys=True).encode()).hexdigest()[:16]
            software_version = env.get("CI_COMMIT_TAG") or (
                env["CI_COMMIT_SHA"] + "." + fingerprint if env.get("CI_COMMIT_SHA") else
                version if env.get("PATCHWATCH_BSI_MODE") == "report" else "")
            bom = bsi.assemble(scanned, name, software_version, services=detected_services(env, workspace))
        if not bom["components"] and env.get("PATCHWATCH_ALLOW_EMPTY") != "true":
            raise RuntimeError("Empty inventory rejected; check scan paths and whether the repository contains lock files")
        print(f"Inventory: {name} @ {version}: {len(bom['components'])} components")
    provenance(bom, env)
    bsi_findings = []
    if not parent_mode:
        bsi.enrich(bom, env, workspace)
        bsi_findings = bsi.check_and_write(bom, env, workspace)
    else:
        # These empty documents administer DTrack collections/services; they are
        # not delivery-item SBOMs and must never receive a conformance claim.
        (workspace / "patchwatch-bsi-report.json").write_text(json.dumps({
            "standard": "BSI TR-03183-2 v2.1.0", "applicable": False,
            "reason": "Administrative aggregation/services container; validate its component SBOMs."}, indent=2) + "\n")
    if dry_run:
        output = workspace / env.get("PATCHWATCH_SBOM_OUTPUT", "patchwatch-sbom.json")
        output.write_text(json.dumps(bom))
        if parent_mode:
            output.with_name(output.stem + "-services" + output.suffix).write_text(json.dumps(services_bom))
        return 0
    trust_ca(env.get("PATCHWATCH_CA_CERT"))
    fields = {"autoCreate": "true", "projectName": name, "projectVersion": version,
              "isLatest": "true" if latest else "false", "projectTags": ",".join(tags)}
    if env.get("PATCHWATCH_COMPONENT", "").strip():
        # Components hang below the project itself; DTrack does not create a missing parent.
        fields.update({"parentName": env["CI_PROJECT_PATH"], "parentVersion": version})
    if parent_mode:
        client = DependencyTrack(url, {"X-Api-Key": read_key or key})
        existing = lookup_parent(client, name, version)
        if existing and existing.get("collectionLogic") != "AGGREGATE_DIRECT_CHILDREN":
            if client.all("service/project/" + existing["uuid"]):
                raise RuntimeError("Parent still owns services: run python -m patchwatch.dtrack.groups with admin credentials "
                                   "to migrate them before repeating CI; existing inventory was preserved")
        if not existing:
            upload_and_wait(url, key, fields, bom)
        service_target = lookup_parent(client, name + "/services", version)
        if service_target:
            target_tags = {t["name"] for t in service_target.get("tags", [])}
            parent_uuid = (service_target.get("parent") or {}).get("uuid")
            if ("gitlab-project-id:" + str(env["CI_PROJECT_ID"]) not in target_tags
                    or "source:gitlab-ci" not in target_tags or service_target.get("collectionLogic")
                    or parent_uuid not in (None, (existing or {}).get("uuid"))
                    or client.all("component/project/" + service_target["uuid"])):
                raise RuntimeError("Service subproject name collision: reserve /services for service inventory; "
                                   "existing inventory was preserved")
        service_fields = dict(fields, projectName=name + "/services", parentName=name, parentVersion=version)
        service_fields["projectTags"] = ",".join(t for t in tags if t != "patchwatch-role:parent") + ",patchwatch-role:services"
        # Upload an empty inventory too: removed Compose services must disappear on later runs.
        upload_and_wait(url, key, service_fields, services_bom)
        print("Service inventory processed; aggregation is reconciled by python -m patchwatch.dtrack.groups")
        return 0
    try:
        upload_and_wait(url, key, fields, bom)
    except RuntimeError as error:
        if "parentName" in fields and "HTTP 404" in str(error):
            raise RuntimeError("Parent project not found: add a job with mode: parent in an earlier stage "
                               "(see docs/usage/ci-integration.md)") from None
        raise
    print("Upload processed by Dependency-Track")
    report = {"generatedAt": datetime.now(timezone.utc).isoformat(), "project": name, "version": version,
              "commit": env.get("CI_COMMIT_SHA"), "pipeline": env.get("CI_PIPELINE_URL"),
              "components": len(bom["components"]), "tags": tags, "failOn": fail_on,
              "bsiFindings": bsi_findings,
              "qualityViolations": quality_violations(bom)}
    for issue in report["qualityViolations"]:
        print(f"SBOM {issue['state']}: {issue['policy']} ({issue['count']})")
    if read_key:
        report.update(summary(DependencyTrack(url, {"X-Api-Key": read_key}), name, version, url))
        found = report["findings"]
        print("Findings: " + ("metrics not calculated yet" if found is None
                              else ", ".join(f"{s} {n}" for s, n in found.items() if n) or "none"))
        for item in report["unsuppressedViolations"]:
            print(f"Policy {item['state']}: {item['policy']} ({item['count']})")
        print("Project: " + report["url"])
        if env.get("PATCHWATCH_DELTA", "true") != "false":
            report["delta"] = delta_report(DependencyTrack(url, {"X-Api-Key": read_key}), name, version, url, env, workspace)
    else:
        print("No PATCHWATCH_READ_KEY: findings are visible in PatchWatch, not in this job")
    Path(env.get("PATCHWATCH_REPORT", workspace / "patchwatch-report.json")).write_text(json.dumps(report, indent=2) + "\n")
    return 2 if read_key and gate(report, fail_on) else 0


def main():
    """CLI of the CI job (``python -m patchwatch.ci``)."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Scan and write the SBOM locally; no upload, no credentials needed")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        code = run(dict(os.environ), args.dry_run)
    except Skip as notice:
        parser.exit(0, "WARNING: PatchWatch CI skipped: " + str(notice) + "\n")
    except (OSError, KeyError, ValueError, RuntimeError, subprocess.SubprocessError, ssl.SSLError,
            urllib.error.URLError) as error:
        # No URLs, response bodies or credentials in the job log.
        if isinstance(error, (ValueError, RuntimeError)):
            detail = str(error)
        elif isinstance(error, urllib.error.HTTPError):
            detail = f"HTTP {error.code} from the PatchWatch API (no response body is logged)"
        else:
            detail = "check scan inputs, Syft and API access"
        parser.exit(1, f"PatchWatch CI failed ({type(error).__name__}): {detail}\n")
    if code:
        parser.exit(code, "Compliance threshold exceeded; see patchwatch-report.json\n")


if __name__ == "__main__":
    main()
