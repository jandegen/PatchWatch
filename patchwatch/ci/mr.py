# SPDX-License-Identifier: Apache-2.0
"""Credential-free SBOM producer and trusted GitLab merge-request feedback worker."""
import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import uuid
import zipfile
from urllib.parse import quote, urlencode

from . import pipeline
from . import bsi
from . import delta
from ..dtrack.client import DependencyTrack
from ..core.http import check_url, request, secret
from ..dtrack.scopes import BRANCH_TAG, MR_TAG
from ..core.sbom import upload_and_wait
from ..core.services import compose_services
from ..dtrack.versions import OTHER_BRANCH_COMMENT

SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
ARTIFACT = "patchwatch-mr.json"
BRANCH_ARTIFACT = "patchwatch-branch.json"
REPORT_VERSION = 2
BRANCH_VERSION = 1
# Branch names that would collide with versions owned by the merge request flow.
RESERVED_VERSION = re.compile(r"(?:mr-[0-9]+|base-.*)\Z")
COMMIT_URL = re.compile(r"/-/commit/([0-9a-f]{40}|[0-9a-f]{64})\Z")
COMMENT_VERSION = 3
ACTIVE = {"created", "waiting_for_resource", "preparing", "pending", "running", "scheduled"}


class Pending(Exception):
    """A required scan is not available yet; retry on the next worker run."""


class GitLab:
    """Minimal GitLab REST client (``/api/v4``) with a project/job token; redirects are never followed."""
    def __init__(self, url, token):
        self.url = check_url(url)
        self.headers = {"PRIVATE-TOKEN": token}

    def call(self, path, data=None, method=None):
        headers = dict(self.headers)
        if data is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(data).encode()
        return request(self.url + "/api/v4/" + path, data, headers, method)[0]

    def all(self, path):
        page = 1
        while True:
            batch = self.call(path + ("&" if "?" in path else "?") + urlencode({"per_page": 100, "page": page}))
            if not isinstance(batch, list):
                raise ValueError("Expected a GitLab list response")
            yield from batch
            if len(batch) < 100:
                return
            page += 1

    def upload(self, project, path):
        """Attach a generated report to its target project, independently of job retention."""
        path = Path(path)
        if not re.fullmatch(r"[A-Za-z0-9._-]+", path.name):
            raise ValueError("Unsafe report filename")
        boundary = "patchwatch-" + uuid.uuid4().hex
        data = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
                'Content-Type: application/zip\r\n\r\n').encode() + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
        return request(self.url + f"/api/v4/projects/{int(project)}/uploads", data,
                       {**self.headers, "Content-Type": "multipart/form-data; boundary=" + boundary}, "POST")[0]


def git(workspace, *args, check=True, **kwargs):
    """Run git in ``workspace`` without hooks."""
    return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(workspace), *args],
                          check=check, capture_output=True, timeout=300, **kwargs)


def checkout_tree(workspace, tree, destination):
    """Materialize tracked files, including export-ignored files, without modifying the checkout."""
    destination.mkdir()
    # A separate index avoids worktree changes, checkout hooks, and archive export-ignore rules.
    index = destination.parent / (destination.name + ".index")
    env = {**os.environ, "GIT_INDEX_FILE": str(index)}
    git(workspace, "read-tree", tree, env=env)
    git(workspace, "checkout-index", "--all", "--prefix=" + str(destination) + "/", env=env)


def inside(workspace, path):
    """Resolve ``path`` below ``workspace``; paths that leave the repository are rejected."""
    resolved = (workspace / path).resolve()
    if not resolved.is_relative_to(workspace):
        raise ValueError("Scan inputs must stay inside the repository")
    return resolved


def scan_tree(env, workspace, directory, version):
    """Resolve images from this tree and optionally build its Dockerfiles without upload keys."""
    directory.mkdir()
    options = dict(env, CI_COMMIT_SHA=version)
    paths = [p for p in pipeline.words(env.get("PATCHWATCH_SCAN_PATHS", ".")) if inside(workspace, p).exists()]
    images = pipeline.words(env.get("PATCHWATCH_IMAGES"))
    for selector in pipeline.words(env.get("PATCHWATCH_COMPOSE_IMAGES")):
        filename, colon, service = selector.rpartition(":")
        if not colon or not filename or not pipeline.NAME_PART.fullmatch(service):
            raise ValueError("Compose image selectors must be file:service")
        path = inside(workspace, filename)
        if path.exists():
            entries = dict(compose_services(path.read_text()))
            if service in entries:
                image = entries[service]
                if not image or "$" in image:
                    raise ValueError("Compose image references must be literal; use dockerfiles for builds")
                images.append(image)
    options.update({"PATCHWATCH_SCAN_PATHS": " ".join(paths), "PATCHWATCH_IMAGES": " ".join(dict.fromkeys(images))})
    archives = []
    for number, filename in enumerate(pipeline.words(env.get("PATCHWATCH_DOCKERFILES"))):
        dockerfile = inside(workspace, filename)
        if not dockerfile.exists():
            continue  # A removed Dockerfile means the image inventory disappears on this side.
        tag = "patchwatch-mr-" + hashlib.sha256(str(directory).encode()).hexdigest()[:20] + f":{number}"
        archive = directory / f"image-{number}.tar"
        try:
            subprocess.run(["docker", "build", "--pull", "--file", str(dockerfile), "--tag", tag, str(workspace)],
                           check=True, timeout=1800)
            subprocess.run(["docker", "save", "--output", str(archive), tag], check=True, timeout=300)
        finally:
            subprocess.run(["docker", "image", "rm", tag], check=False, capture_output=True, timeout=60)
        archives.append("docker-archive:" + str(archive))
    selected = paths or images or archives
    boms = pipeline.scan(options, workspace, directory, extra_sources=archives) if selected else []
    bom = bsi.assemble(boms, env.get("CI_PROJECT_PATH", "mr-scan"), version)
    # A merge-tree SHA is a tree object, not necessarily a reachable commit.
    # Do not manufacture a /-/commit/<tree> source URL for the paired scan.
    pipeline.provenance(bom, dict(env, CI_COMMIT_SHA=""))
    bom["metadata"]["component"].setdefault("properties", []).append({"name": "patchwatch:source-tree", "value": version})
    if env.get("CI_PROJECT_URL"):
        bom["metadata"]["component"].setdefault("externalReferences", []).append({"type": "vcs", "url": env["CI_PROJECT_URL"]})
    bsi.enrich(bom, env, workspace)
    return bom


def produce(env):
    """Scan the target and its actual merge with this MR in one credential-free job."""
    sha = env.get("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA") or env.get("CI_COMMIT_SHA", "")
    if not SHA.fullmatch(sha):
        raise ValueError("MR source must be a full commit SHA")
    branch = env.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "")
    if not branch:
        raise ValueError("MR target branch is required")
    workspace = Path(env["CI_PROJECT_DIR"]).resolve()
    # Full history is supplied by GIT_DEPTH=0. Fetch the target at scan time, not an old diff base.
    git(workspace, "check-ref-format", "refs/heads/" + branch)
    git(workspace, "fetch", "--no-tags", "origin", "refs/heads/" + branch)
    target = git(workspace, "rev-parse", "FETCH_HEAD^{commit}", text=True).stdout.strip()
    merged = git(workspace, "merge-tree", "--write-tree", target, sha, check=False, text=True)
    result = {"formatVersion": REPORT_VERSION, "headSha": sha, "targetSha": target,
              "pipelineSha": env["CI_COMMIT_SHA"], "status": "conflict" if merged.returncode == 1 else "complete"}
    if merged.returncode not in (0, 1):
        raise RuntimeError("Cannot compute merge tree; ensure Git >= 2.38 and full repository history")
    if merged.returncode == 0:
        tree = merged.stdout.splitlines()[0]
        if not SHA.fullmatch(tree):
            raise ValueError("Invalid merge tree")
        result["mergedTree"] = tree
        with tempfile.TemporaryDirectory(prefix="patchwatch-mr-") as folder:
            root = Path(folder)
            for name, commit in (("baseline", target), ("merged", tree)):
                checkout_tree(workspace, commit, root / name)
                result[name] = scan_tree(env, root / name, root / (name + "-scan"), commit)
        result["bsiFindings"] = {name: bsi.findings(result[name]) for name in ("baseline", "merged")}
        if not result["baseline"]["components"] and not result["merged"]["components"]:
            raise ValueError("Both inventories are empty; check scan inputs")
    (workspace / ARTIFACT).write_text(json.dumps(result) + "\n")


def produce_branch(env):
    """Scan one pushed branch commit without credentials; a protected worker uploads it later."""
    sha, branch = env.get("CI_COMMIT_SHA", ""), env.get("CI_COMMIT_BRANCH", "")
    if not SHA.fullmatch(sha) or not branch:
        raise ValueError("A branch pipeline with a full commit SHA is required")
    workspace = Path(env["CI_PROJECT_DIR"]).resolve()
    with tempfile.TemporaryDirectory(prefix="patchwatch-branch-") as folder:
        root = Path(folder)
        checkout_tree(workspace, sha, root / "tree")
        bom = scan_tree(env, root / "tree", root / "tree-scan", sha)
    if not bom["components"]:
        raise ValueError("Empty inventory rejected; check scan inputs")
    result = {"formatVersion": BRANCH_VERSION, "kind": "branch", "branch": branch, "headSha": sha,
              "pipelineSha": sha, "bom": bom, "bsiFindings": bsi.findings(bom)}
    (workspace / BRANCH_ARTIFACT).write_text(json.dumps(result) + "\n")


def job_for(gl, project, pipelines, sha, job_name, source):
    """The successful scan job of the newest pipeline of ``source`` for commit ``sha`` or its merge-result commit.

    Raises ``Pending`` while the job is missing or not yet successful."""
    candidates = sorted(pipelines, key=lambda p: p["id"], reverse=True)
    for candidate in candidates:
        pipeline = gl.call(f"projects/{project}/pipelines/{int(candidate['id'])}")
        if pipeline.get("project_id") != project or pipeline.get("source") != source:
            continue
        pipeline_sha = pipeline.get("sha", "")
        if not SHA.fullmatch(pipeline_sha):
            raise ValueError("Invalid pipeline SHA")
        if pipeline_sha != sha:
            # Merged-results / train commits must include this MR head as a direct parent.
            commit = gl.call(f"projects/{project}/repository/commits/{pipeline_sha}")
            parents = commit.get("parent_ids", [])
            if len(parents) != 2 or sha not in parents:
                continue
        jobs = gl.all(f"projects/{project}/pipelines/{int(pipeline['id'])}/jobs")
        matches = [j for j in jobs if j.get("name") == job_name]
        if matches:
            job = max(matches, key=lambda j: j["id"])
            if job.get("status") != "success" or job.get("commit", {}).get("id") != pipeline_sha:
                raise Pending("Scan job is not successful yet")
            return job
    raise Pending("No matching SBOM job for this commit; run the scan pipeline")


def artifact(gl, project, job):
    """Download and validate the merge-request SBOM artifact of a scan job."""
    try:
        pair = gl.call(f"projects/{project}/jobs/{int(job['id'])}/artifacts/{ARTIFACT}")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise Pending("SBOM artifact is missing or expired; retry the scan job") from None
        raise
    if not isinstance(pair, dict) or pair.get("formatVersion") != REPORT_VERSION:
        raise ValueError("Expected a paired MR scan artifact (formatVersion 2)")
    if any(not isinstance(pair.get(k), str) or not SHA.fullmatch(pair[k]) for k in ("headSha", "targetSha", "pipelineSha")):
        raise ValueError("Invalid scan provenance")
    if pair["pipelineSha"] != job["commit"]["id"]:
        raise ValueError("Scan does not belong to this pipeline commit")
    if pair.get("status") == "conflict":
        return pair
    if pair.get("status") != "complete" or not isinstance(pair.get("mergedTree"), str) or not SHA.fullmatch(pair["mergedTree"]):
        raise ValueError("Invalid merge result")
    for key in ("baseline", "merged"):
        validate_bom(pair.get(key))
    if not pair["baseline"]["components"] and not pair["merged"]["components"]:
        raise ValueError("Both MR inventories are empty")
    return pair


def branch_artifact(gl, project, job, branch, sha):
    """Download and validate the branch SBOM artifact; it must belong to ``branch`` and ``sha``."""
    try:
        data = gl.call(f"projects/{project}/jobs/{int(job['id'])}/artifacts/{BRANCH_ARTIFACT}")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise Pending("Branch SBOM artifact is missing or expired; retry the scan job") from None
        raise
    if (not isinstance(data, dict) or data.get("formatVersion") != BRANCH_VERSION or data.get("kind") != "branch"
            or data.get("branch") != branch or data.get("headSha") != sha or data.get("pipelineSha") != job["commit"]["id"]):
        raise ValueError("Branch scan artifact does not belong to this branch commit")
    validate_bom(data.get("bom"))
    if not data["bom"]["components"]:
        raise ValueError("Branch inventory is empty")
    return data["bom"]


def tag_names(project):
    """Tag names of a Dependency-Track project."""
    return {t.get("name") if isinstance(t, dict) else t for t in project.get("tags") or []}


def recorded_commit(project):
    """Commit a version was scanned at, from the provenance reference Patchwatch itself attached."""
    for ref in project.get("externalReferences") or []:
        match = COMMIT_URL.search(ref.get("url") or "")
        if ref.get("type") == "vcs" and (ref.get("comment") or "").startswith("PatchWatch ") and match:
            return match[1]
    return None


def stamp(bom, web_url, commit, comment, pipeline_url=None):
    """Record the scanned commit so later runs can tell whether a version is still current."""
    metadata = bom["metadata"]
    metadata["timestamp"] = datetime.now(timezone.utc).isoformat()
    root = metadata["component"]
    root.setdefault("properties", []).append({"name": "patchwatch:commit", "value": commit})
    refs = root.setdefault("externalReferences", [])
    refs.append({"type": "vcs", "url": web_url.rstrip("/") + "/-/commit/" + quote(commit, safe=""), "comment": comment})
    if pipeline_url:
        refs.append({"type": "build-system", "url": pipeline_url, "comment": "PatchWatch pipeline"})


def validate_bom(bom):
    """Check that an untrusted artifact is a plain CycloneDX document; its claimed identity and destinations are ignored."""
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or not isinstance(bom.get("components"), list):
        raise ValueError("Expected a CycloneDX JSON artifact")
    # Treat the artifact as data. Ignore its metadata, destinations and claimed identity.
    for component in bom["components"]:
        if not isinstance(component, dict):
            raise ValueError("Invalid component in SBOM artifact")
        for field in ("name", "group", "version", "purl", "cpe", "type", "bom-ref"):
            if field in component and not isinstance(component[field], str):
                raise ValueError("Invalid component field in SBOM artifact")
        if not isinstance(component.get("licenses", []), list) or not isinstance(component.get("properties", []), list):
            raise ValueError("Invalid component metadata in SBOM artifact")
    if not isinstance(bom.get("dependencies", []), list):
        raise ValueError("Invalid dependencies in SBOM artifact")


def inline(value, max_length=300):
    """Escape text for a single line of GitLab markdown (no mentions, HTML or formatting)."""
    value = html.escape(str(value)).replace("@", "@\u200b")
    value = " ".join(value.split())
    if max_length and len(value) > max_length:
        value = value[:max_length] + "…"
    return re.sub(r"([\\`*_{}\[\]()#+.!|~])", r"\\\1", value)


def render(result, limit=20):
    """Bounded comment; untrusted package names cannot inject quick actions or mentions."""
    v, p, lic = result["vulnerabilities"], result["violations"], result["licenses"]
    lines = ["| Findings | New | Fixed / dropped | Unchanged |", "|---|---:|---:|---:|",
             f"| Vulnerabilities | {len(v['new'])} | {len(v['fixed'])} | {v['unchanged']} |",
             f"| Policy violations | {len(p['new'])} | {len(p['resolved'])} | {p['unchanged']} |", "",
             "Compares the target branch **without this MR** with its computed **merge result**.",
             "The following changes would occur on merge.", ""]

    def section(title, rows):
        lines.extend(["**" + title + "**", *["- " + inline(x, max_length=300 if limit else None) for x in rows[:limit]]])
        if not rows:
            lines.append("None.")
        elif limit and len(rows) > limit:
            lines.append(f"- … {len(rows) - limit} more entries in the full report.")
        lines.append("")

    def vulnerability(x):
        return f"{x['severity']}: {x['id']} ({x['component']})"

    section("New vulnerabilities", [vulnerability(x) for x in v['new']])
    section("Fixed / dropped vulnerabilities", [vulnerability(x) for x in v['fixed']])
    section("New licenses per package", [f"{x['component']}: {', '.join(x['licenses'])}" for x in lic['added']])
    section("Dropped licenses per package", [f"{x['component']}: {', '.join(x['licenses'])}" for x in lic['removed']])
    section("Changed licenses", [f"{x['component']}: {', '.join(x['from']) or '?'} → {', '.join(x['to']) or '?'}"
                                   for x in lic['changed']])
    section("Licenses appearing in the inventory for the first time", lic['newLicenses'])
    section("Licenses dropping out of the inventory entirely", lic['droppedLicenses'])
    section("New missing license information", lic['unresolved'])
    section("New policy violations", [f"{x['state']}: {x['policy']} ({x['component']})" for x in p['new']])
    section("Dropped policy violations", [f"{x['state']}: {x['policy']} ({x['component']})" for x in p['resolved']])
    if limit:
        lines.append(f"Preview: at most {limit} entries per section; long texts are truncated. Full details in the linked report.")
    lines.append("Snapshot: two identical queries do not guarantee that all analyzers have finished scanning.")
    return "\n".join(lines)


class Worker:
    """The protected feedback worker: uploads the untrusted scan artifacts of merge requests and branches to scoped Dependency-Track versions and posts the result."""
    def __init__(self, gl, dt, url, upload_key, project, job_name, component="", wait=300, output=Path("."),
                 branch_job="", baseline="scan"):
        self.gl, self.dt, self.url, self.upload_key = gl, dt, url, upload_key
        self.project, self.job_name, self.component = project, job_name, component
        self.wait, self.output = wait, Path(output)
        self.branch_job = branch_job
        if baseline not in ("branch", "scan"):
            raise ValueError("Baseline must be branch or scan")
        self.baseline = baseline
        if component and not pipeline.NAME_PART.fullmatch(component):
            raise ValueError("Invalid component name")
        self.bot = gl.call("user")["id"]
        self.info = gl.call(f"projects/{project}")
        # Same project name as the CI inventory; the version (branch, mr-<iid>) and the scope tag
        # keep merge requests and feature branches apart from releases, Latest and notifications.
        self.name = self.info['path_with_namespace'] + ("/" + component if component else "")
        self.marker = "<!-- patchwatch-mr:" + ("component:" + component if component else "default") + " -->"
        self.annotations = {}

    def lookup(self, version, name=None):
        try:
            return self.dt.call("project/lookup?" + urlencode({"name": name or self.name, "version": version}))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def web_url(self):
        return self.info.get("web_url") or self.gl.url + "/" + quote(self.info["path_with_namespace"], safe="/")

    def upload_version(self, bom, version, tag, commit, comment, pipeline_url=None):
        """Create or refresh a version this worker owns; never overwrite a release or CI inventory."""
        if not pipeline.usable_version(version):
            raise ValueError("Version is not usable as a Dependency-Track version")
        existing = self.lookup(version)
        if existing is not None and tag not in tag_names(existing):
            raise ValueError(f"Version {version!r} exists and is not owned by {tag}; refusing to overwrite it")
        cleaned = bsi.assemble([bom], self.name, version=commit)
        stamp(cleaned, self.web_url(), commit, comment, pipeline_url)
        # Treat producer artifacts as untrusted observations. Re-check at the
        # protected upload boundary; never run producer-supplied enrichment paths.
        options = dict(os.environ, CI_PROJECT_URL=self.web_url())
        suffix = hashlib.sha256(version.encode()).hexdigest()[:16]
        options["PATCHWATCH_SBOM_OUTPUT"] = "patchwatch-sbom-" + suffix + ".json"
        options["PATCHWATCH_BSI_REPORT"] = "patchwatch-bsi-report-" + suffix + ".json"
        self.output.mkdir(parents=True, exist_ok=True)
        bsi.enrich(cleaned, options, self.output.resolve())
        bsi.check_and_write(cleaned, options, self.output.resolve())
        tags = ",".join([tag, f"gitlab-project-id:{self.project}"])
        fields = {"autoCreate": "true", "projectName": self.name, "projectVersion": version,
                  "isLatest": "false", "projectTags": tags}
        if self.component and self.ensure_parent(version, tag, tags):
            fields.update({"parentName": self.info["path_with_namespace"], "parentVersion": version})
        upload_and_wait(self.url, self.upload_key, fields, cleaned)
        return self.lookup(version)

    def ensure_parent(self, version, tag, tags):
        """Group the component versions of one branch or merge request under <project>@<version>.

        Dependency-Track does not create a missing parent, so it is created from an empty SBOM. Components
        are uploaded by separate jobs, hence a lost creation race is fine as long as the parent now exists.
        A parent this worker does not own is left alone and the component is uploaded without one."""
        name = self.info["path_with_namespace"]
        existing = self.lookup(version, name)
        if existing is None:
            try:
                upload_and_wait(self.url, self.upload_key, {"autoCreate": "true", "projectName": name,
                                "projectVersion": version, "isLatest": "false", "projectTags": tags},
                                pipeline.parent_bom(name, version))
            except RuntimeError:
                pass
            existing = self.lookup(version, name)
            if existing is None:
                raise RuntimeError(f"Parent project {name}@{version} could not be created")
        return tag in tag_names(existing)

    def target_version(self, branch, sha):
        """The target branch's own inventory, if it was scanned at exactly the merge target commit."""
        project = self.lookup(branch) if pipeline.usable_version(branch) else None
        if project and project.get("active", True) and MR_TAG not in tag_names(project) and recorded_commit(project) == sha:
            return project
        return None

    def write_annotations(self):
        self.output.mkdir(parents=True, exist_ok=True)
        (self.output / "patchwatch-annotations.json").write_text(json.dumps({"patchwatch": list(self.annotations.values())}, indent=2) + "\n")

    def previous_report_url(self, body):
        prefix = self.gl.url + "/" + quote(self.info['path_with_namespace'], safe="/") + "/uploads/"
        match = re.search(re.escape(prefix) + r"[0-9a-f]{32,64}/patchwatch-mr-[0-9]+-[A-Za-z0-9._-]+-[0-9a-f]{12}\.zip", body)
        return match[0] if match else None

    def annotate_report(self, iid, url):
        self.annotations[iid] = {"external_link": {"label": f"MR !{int(iid)} · {self.component or 'default'} · full report (ZIP)", "url": url}}
        self.write_annotations()

    def attach_report(self, iid, result):
        """Store full JSON/Markdown and publish an immutable ZIP in the MR's project."""
        directory = self.output / str(iid)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "patchwatch-delta.json").write_text(json.dumps(result, indent=2) + "\n")
        (directory / "patchwatch-delta.md").write_text(
            f"# PatchWatch · {self.name}\n\nMR: {result['headSha']}\n\nTarget branch: {result['targetSha']}\n\n"
            f"Merge tree: {result['mergedTree']}\n\n" + render(result, limit=None))
        filename = f"patchwatch-mr-{int(iid)}-{self.component or 'default'}-{result['headSha'][:12]}.zip"
        archive = directory / filename
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name in ("patchwatch-delta.md", "patchwatch-delta.json"):
                bundle.write(directory / name, arcname=name)
        uploaded = self.gl.upload(self.project, archive)
        # Only accept the expected attachment path; never follow an API-supplied external URL.
        relative = uploaded.get("url") if isinstance(uploaded, dict) else None
        if not isinstance(relative, str) or not re.fullmatch(r"/uploads/[0-9a-f]{32,64}/" + re.escape(filename), relative):
            raise ValueError("Unexpected GitLab upload URL")
        url = self.gl.url + "/" + quote(self.info['path_with_namespace'], safe="/") + relative
        self.annotate_report(iid, url)
        return url

    def current(self, mr, target_sha):
        fresh = self.gl.call(f"projects/{self.project}/merge_requests/{int(mr['iid'])}")
        if any(fresh.get(k) != mr.get(k) for k in ("sha", "source_project_id", "target_project_id", "target_branch")):
            return False
        return fresh.get("state") == "opened" and self.branch(mr)["commit"]["id"] == target_sha

    def branch(self, mr):
        return self.gl.call(f"projects/{self.project}/repository/branches/" + quote(mr["target_branch"], safe=""))

    def note(self, iid):
        notes = self.gl.all(f"projects/{self.project}/merge_requests/{iid}/notes")
        return next((n for n in notes if not n.get("system") and n.get("author", {}).get("id") == self.bot
                     and n.get("body", "").startswith(self.marker + "\n")), None)

    def publish(self, mr, target_sha, content):
        # A serialized worker plus this check prevents older analyses replacing newer commits.
        if not self.current(mr, target_sha):
            return False
        path = f"projects/{self.project}/merge_requests/{int(mr['iid'])}/notes"
        note = self.note(mr["iid"])
        previous_url = self.previous_report_url(note['body']) if note else None
        if previous_url and previous_url not in content:
            content += (f"\n\n[Download the latest full report](<{previous_url}>)"
                        " · previous evaluation, see the SHAs and timestamp in the archive.")
        title = "PatchWatch" + (" · " + self.component if self.component else "")
        body = self.marker + f"\n### {title}\nMR head · `{mr['sha']}`\nTarget branch without MR · `{target_sha}`\n\n" + content
        if note:
            if note["body"] != body:
                self.gl.call(path + f"/{int(note['id'])}", {"body": body}, "PUT")
        else:
            self.gl.call(path, {"body": body}, "POST")
        return True

    def refresh_scan(self, mr, target_sha, pipelines):
        """Request at most one automatic rescan per head/target pair, shared by all components."""
        fingerprint = hashlib.sha256(f"{mr['sha']}:{target_sha}".encode()).hexdigest()
        marker = f"<!-- patchwatch-scan-request:{fingerprint} -->"
        notes = list(self.gl.all(f"projects/{self.project}/merge_requests/{mr['iid']}/notes"))
        requested = any(n.get("author", {}).get("id") == self.bot and marker in n.get("body", "") for n in notes)
        active = any(p.get("status") in ACTIVE for p in pipelines)
        content = "**Pending:** the target branch has changed. The merge result has to be scanned again."
        if requested or active:
            self.publish(mr, target_sha, content + ("\n" + marker if requested else ""))
            return
        if self.publish(mr, target_sha, content + "\nNeuer MR-Scan wird angefordert.\n" + marker):
            # Recheck immediately before starting an MR pipeline with the bot's identity.
            if self.current(mr, target_sha):
                self.gl.call(f"projects/{self.project}/merge_requests/{int(mr['iid'])}/pipelines", {}, "POST")

    def process(self, mr):
        if mr.get("state") != "opened" or mr.get("source_project_id") != self.project or mr.get("target_project_id") != self.project:
            return  # Forks require an explicit trust policy; do not fetch arbitrary projects.
        sha, target_sha = mr["sha"], self.branch(mr)["commit"]["id"]
        if not SHA.fullmatch(sha) or not SHA.fullmatch(target_sha):
            raise ValueError("Invalid GitLab commit SHA")
        try:
            pipelines = list(self.gl.all(f"projects/{self.project}/merge_requests/{int(mr['iid'])}/pipelines"))
            current_job = job_for(self.gl, self.project, pipelines, sha, self.job_name, "merge_request_event")
            pair = artifact(self.gl, self.project, current_job)
            if pair["headSha"] != sha:
                raise ValueError("Artifact source does not match the MR head")
            if pair["targetSha"] != target_sha:
                self.refresh_scan(mr, target_sha, pipelines)
                return
            if pair["status"] == "conflict":
                self.publish(mr, target_sha, "**Merge conflict:** no unambiguous merge result. Resolve the conflicts and restart the MR pipeline; no change report is claimed.")
                return
            fingerprint = hashlib.sha256(f"v{REPORT_VERSION}/comment-{COMMENT_VERSION}:{sha}:{target_sha}:{pair['mergedTree']}:{current_job['id']}".encode()).hexdigest()
            done = f"<!-- patchwatch-result:{fingerprint} -->"
            previous = self.note(mr["iid"])
            if previous and done in previous["body"]:
                previous_url = self.previous_report_url(previous['body'])
                if previous_url:
                    self.annotate_report(mr['iid'], previous_url)
                    return
            boms = [pair["baseline"], pair["merged"]]
            if not self.publish(mr, target_sha, "**Analyse ausstehend:** SBOMs werden ausgewertet."):
                return
            pipeline_url = (current_job.get("pipeline") or {}).get("web_url")
            target_branch = mr["target_branch"]
            # Compare with the target branch's version when it is current; otherwise with the paired scan.
            base = self.target_version(target_branch, target_sha) if self.baseline == "branch" else None
            source = "branch" if base else "scan"
            if base is None:
                base = self.upload_version(boms[0], "base-" + target_branch, MR_TAG, target_sha,
                                           f"PatchWatch merge request baseline: {target_branch}", pipeline_url)
            merged = self.upload_version(boms[1], f"mr-{int(mr['iid'])}", MR_TAG, sha,
                                         f"PatchWatch merge request: !{int(mr['iid'])}", pipeline_url)
            projects = [base, merged]
            old, old_settled = delta.settled_snapshot(self.dt, projects[0], self.wait)
            new, new_settled = delta.settled_snapshot(self.dt, projects[1], self.wait)
            result = delta.diff(old, new)
            result.update({"generatedAt": datetime.now(timezone.utc).isoformat(),
                           "project": {"name": self.name, "version": projects[1]["version"]},
                           "baseline": {"version": projects[0]["version"], "source": source},
                           "targetBranch": target_branch, "settled": old_settled and new_settled,
                           "headSha": sha, "targetSha": target_sha,
                           "mergedTree": pair['mergedTree'], "comparison": "target-vs-merge-result",
                           "jobs": {"current": current_job['id'], "baseline": current_job['id']}})
            # Avoid uploading an obsolete report if either branch advanced during analysis.
            if not self.current(mr, target_sha):
                return
            report_url = self.attach_report(mr['iid'], result)
            # Use the trusted configured URL; encode the API-provided identifier as one path segment.
            link = self.url + "/projects/" + quote(projects[1]["uuid"], safe="")
            content = (f"**[Download the full report (ZIP: Markdown + JSON)](<{report_url}>)**\n"
                       "GitLab attachment for this evaluation; independent of the retention of CI artifacts.\n\n"
                       f"Merge-Ergebnis (Git-Baum) · `{pair['mergedTree']}`\n\n"
                       f"Vergleich: `{inline(projects[1]['version'])}` gegen dTrack-Version `{inline(projects[0]['version'])}` "
                       f"({'Target branch inventory' if source == 'branch' else 'MR scan of the target branch'})\n\n" + render(result) + f"\n\n[Open dTrack](<{link}>)")
            if result["settled"]:
                content += "\n" + done
            else:
                content = "**Analysis incomplete; will be checked again in the next worker run.**\n\n" + content
            self.publish(mr, target_sha, content)
        except Pending as notice:
            self.publish(mr, target_sha, "**Pending:** " + str(notice))
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, urllib.error.URLError):
            self.publish(mr, target_sha, "**Evaluation failed.** No approval; see the worker log for details. The next run will try again.")
            raise

    def sync_branch(self, branch, sha):
        """Upload a feature branch's credential-free scan as the dTrack version named like the branch."""
        if not SHA.fullmatch(sha):
            raise ValueError("Invalid GitLab commit SHA")
        if not pipeline.usable_version(branch) or RESERVED_VERSION.fullmatch(branch):
            print(f"Branch {branch!r}: name cannot be used as a version; skipped")
            return
        existing = self.lookup(branch)
        if existing is not None:
            if BRANCH_TAG not in tag_names(existing):
                print(f"Branch {branch!r}: a version of that name exists and is not a branch scan; skipped")
                return
            if recorded_commit(existing) == sha:
                return
        query = urlencode({"ref": branch, "sha": sha})
        pipelines = list(self.gl.all(f"projects/{self.project}/pipelines?{query}"))
        job = job_for(self.gl, self.project, pipelines, sha, self.branch_job, "push")
        bom = branch_artifact(self.gl, self.project, job, branch, sha)
        # Skip a branch that moved while its scan was read; the next run uploads the newer commit.
        head = self.gl.call(f"projects/{self.project}/repository/branches/" + quote(branch, safe=""))
        if head["commit"]["id"] != sha:
            return
        self.upload_version(bom, branch, BRANCH_TAG, sha, OTHER_BRANCH_COMMENT + branch,
                            (job.get("pipeline") or {}).get("web_url"))
        print(f"Branch {branch!r}: version uploaded at {sha[:8]}")

    def run_branches(self):
        """Every unprotected non-default branch; protected branches upload through the regular CI job."""
        failed = False
        default = self.info.get("default_branch")
        for branch in self.gl.all(f"projects/{self.project}/repository/branches"):
            name = branch.get("name", "")
            if name == default or branch.get("protected"):
                continue
            try:
                self.sync_branch(name, branch["commit"]["id"])
            except Pending as notice:
                print(f"Branch {name!r}: {notice}")
            except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, urllib.error.URLError) as error:
                print(f"Branch {name!r}: upload failed ({type(error).__name__}); check scan artifacts and credentials")
                failed = True
        return failed

    def run(self):
        failed = False
        self.write_annotations()
        for mr in self.gl.all(f"projects/{self.project}/merge_requests?state=opened"):
            try:
                self.process(mr)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, urllib.error.URLError) as error:
                print(f"MR !{int(mr['iid'])}: feedback failed ({type(error).__name__}); check credentials and scan artifacts")
                failed = True
        if self.branch_job:
            failed = self.run_branches() or failed
        return int(failed)


def main():
    """CLI with the subcommands ``scan``, ``branch-scan`` (unprivileged producers) and ``worker`` (protected consumer)."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scan")
    sub.add_parser("branch-scan")
    worker = sub.add_parser("worker")
    worker.add_argument("--project", required=True, type=int)
    worker.add_argument("--job", default="patchwatch-mr-sbom")
    worker.add_argument("--component", default="")
    worker.add_argument("--branch-job", default="", help="Scan job of feature-branch pipelines; empty disables branch versions")
    worker.add_argument("--baseline", choices=("branch", "scan"), default="scan",
                        help="Paired scan of the target branch (scan, default) or its dTrack version when current (branch)")
    worker.add_argument("--wait", type=int, default=300)
    worker.add_argument("--output-dir", default="patchwatch-mr-reports")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "scan":
            produce(dict(os.environ))
            return
        if args.command == "branch-scan":
            produce_branch(dict(os.environ))
            return
        if args.project <= 0 or not 1 <= args.wait <= 1800:
            raise ValueError("Project must be positive; wait must be between 1 and 1800 seconds")
        token, upload_key, read_key = (secret(n) for n in ("PATCHWATCH_GITLAB_TOKEN", "PATCHWATCH_UPLOAD_KEY", "PATCHWATCH_READ_KEY"))
        if any(not key or any(c in key for c in "\r\n") for key in (token, upload_key, read_key)):
            raise ValueError("GitLab token, upload key and read key are required")
        # Applies to both GitLab and dTrack; never disable certificate verification.
        pipeline.trust_ca(secret("PATCHWATCH_CA_CERT"))
        url = check_url(os.environ["PATCHWATCH_URL"])
        gl = GitLab(os.environ["PATCHWATCH_GITLAB_URL"], token)
        code = Worker(gl, DependencyTrack(url, {"X-Api-Key": read_key}), url, upload_key,
                      args.project, args.job, args.component, args.wait, Path(args.output_dir),
                      args.branch_job, args.baseline).run()
    except (OSError, KeyError, ValueError, TypeError, AttributeError, RuntimeError, subprocess.SubprocessError, urllib.error.URLError) as error:
        parser.exit(1, f"MR feedback failed ({type(error).__name__}); check configuration and API access\n")
    if code:
        parser.exit(code)


if __name__ == "__main__":
    main()
