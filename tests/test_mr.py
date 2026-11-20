# SPDX-License-Identifier: Apache-2.0
import copy
import json
import os
import tempfile
import subprocess
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import urllib.error

from patchwatch.ci import mr
from patchwatch.dtrack.scopes import BRANCH_TAG, MR_TAG, definitions
from patchwatch.dtrack.policies import load

HEAD, BASE, TREE = "a" * 40, "b" * 40, "c" * 40
BOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
    {"type": "library", "name": "demo", "version": "1", "purl": "pkg:npm/demo@1"}]}
EMPTY = {"components": {}, "vulnerabilities": {}, "violations": {}}


class FakeGitLab:
    def __init__(self):
        self.url = 'https://gitlab.example'
        self.uploads = []
        self.mr = {"iid": 42, "state": "opened", "sha": HEAD, "source_project_id": 123,
                   "target_project_id": 123, "target_branch": "release/1"}
        self.target = BASE
        self.notes, self.writes = [], []
        self.pair = {"formatVersion": 2, "headSha": HEAD, "targetSha": BASE,
                     "pipelineSha": HEAD, "mergedTree": TREE, "status": "complete",
                     "baseline": copy.deepcopy(BOM), "merged": copy.deepcopy(BOM)}
        self.bom = self.pair["merged"]
        self.pipeline_sha = HEAD
        self.parents = [BASE, HEAD]
        self.pipeline_status = "success"
        self.pipeline_source = {10: "merge_request_event", 20: "push"}
        self.status = "success"
        self.missing = False

    def upload(self, project, path):
        self.uploads.append((project, path.name, path.read_bytes()))
        return {'url': '/uploads/' + 'd' * 32 + '/' + path.name}

    def call(self, path, data=None, method=None):
        if method in ("POST", "PUT"):
            self.writes.append((path, data, method))
            if path.endswith("/pipelines"):
                return {"id": 30, "status": "pending", "sha": HEAD}
            note = {"id": 99, "body": data['body'], "author": {"id": 7}}
            if method == "PUT":
                self.notes = [note if n['id'] == 99 else n for n in self.notes]
            else:
                self.notes.append(note)
            return note
        if path == "user":
            return {"id": 7}
        if path == "projects/123":
            return {"path_with_namespace": "team/app"}
        if path.endswith("repository/branches/release%2F1"):
            return {"commit": {"id": self.target}}
        if path == "projects/123/merge_requests/42":
            return dict(self.mr)
        if "/jobs/" in path and "/artifacts/" in path:
            if self.missing:
                raise urllib.error.HTTPError("x", 404, "missing", {}, None)
            return self.pair
        if "/repository/commits/" in path:
            return {"parent_ids": self.parents}
        if "/pipelines/" in path:
            pid = int(path.rsplit("/", 1)[1])
            return {"id": pid, "project_id": 123, "sha": self.pipeline_sha if pid == 10 else BASE,
                    "source": self.pipeline_source[pid]}
        raise AssertionError(path)

    def all(self, path):
        if path.endswith("/notes"):
            return iter(copy.deepcopy(self.notes))
        if path.endswith("/jobs"):
            pid = int(path.split("/")[-2])
            return iter([{"id": pid + 1, "name": "patchwatch-mr-sbom", "status": self.status,
                          "commit": {"id": self.pipeline_sha if pid == 10 else BASE}}])
        if path.endswith("merge_requests/42/pipelines"):
            return iter([{"id": 10, "sha": self.pipeline_sha, "status": self.pipeline_status}])
        if "/pipelines?" in path:
            return iter([{"id": 20, "sha": BASE}])
        if path.endswith("merge_requests?state=opened"):
            return iter([dict(self.mr)])
        raise AssertionError(path)


class FakeDTrack:
    """Versions that were uploaded (or added by a test) are found; everything else is HTTP 404."""
    def __init__(self):
        self.projects = {}

    @staticmethod
    def key(name, version):
        """Plain versions of team/app are keyed by version alone; other names (components) by pair."""
        return version if name == "team/app" else (name, version)

    def add(self, version, tags=(), commit=None, active=True, comment="PatchWatch default branch: main"):
        refs = [{"type": "vcs", "url": f"https://gitlab.example/team/app/-/commit/{commit}", "comment": comment}] if commit else []
        self.projects[version] = {"uuid": "uuid-" + version, "version": version, "active": active,
                                  "tags": [{"name": t} for t in tags], "externalReferences": refs}

    def register(self, url, key, fields, bom):
        root = bom["metadata"]["component"]
        self.projects[self.key(fields["projectName"], fields["projectVersion"])] = {
            "uuid": "uuid-" + fields["projectVersion"], "version": fields["projectVersion"], "active": True,
            "tags": [{"name": t} for t in fields["projectTags"].split(",")],
            "externalReferences": root.get("externalReferences", [])}

    def call(self, path):
        from urllib.parse import parse_qs
        query = parse_qs(path.split("?", 1)[1])
        key = self.key(query['name'][0], query['version'][0])
        if key not in self.projects:
            raise urllib.error.HTTPError("x", 404, "missing", {}, None)
        return self.projects[key]


class Feedback(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {"PATCHWATCH_BSI_MODE": "report"}))
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.gl = FakeGitLab()
        self.dt = FakeDTrack()
        self.worker = mr.Worker(self.gl, self.dt, "https://dtrack.example", "upload-secret", 123,
                                "patchwatch-mr-sbom", output=Path(self.folder.name))
        self.upload = self.enterContext(patch("patchwatch.ci.mr.upload_and_wait", side_effect=self.dt.register))
        self.snapshot = self.enterContext(patch("patchwatch.ci.mr.delta.settled_snapshot", return_value=(EMPTY, True)))

    def test_end_to_end_upload_compare_comment_and_idempotent_rerun(self):
        self.assertEqual(self.worker.run(), 0)
        self.assertEqual(self.upload.call_count, 2)
        fields = [c.args[2] for c in self.upload.call_args_list]
        self.assertEqual(fields[0]['projectName'], "team/app")
        self.assertEqual(fields[0]['projectVersion'], "base-release/1")
        self.assertEqual(fields[1]['projectVersion'], "mr-42")
        self.assertEqual(fields[1]['projectTags'], MR_TAG + ",gitlab-project-id:123")
        self.assertEqual(fields[1]['isLatest'], "false")
        self.assertEqual([w[2] for w in self.gl.writes], ["POST", "PUT"])
        body = self.gl.notes[0]['body']
        self.assertIn(HEAD, body)
        self.assertIn(BASE, body)
        self.assertIn("Snapshot", body)
        self.assertIn("patchwatch-result:", body)
        self.assertIn("Download the full report", body)
        self.assertIn("https://gitlab.example/team/app/uploads/", body)
        self.assertEqual(len(self.gl.uploads), 1)
        with zipfile.ZipFile(Path(self.folder.name) / '42' / self.gl.uploads[0][1]) as report:
            self.assertEqual(set(report.namelist()), {'patchwatch-delta.json', 'patchwatch-delta.md'})
            self.assertEqual(json.loads(report.read('patchwatch-delta.json'))['mergedTree'], TREE)
        result = json.loads((Path(self.folder.name) / "42/patchwatch-delta.json").read_text())
        self.assertEqual(result['jobs'], {"current": 11, "baseline": 11})
        self.worker.run()
        self.assertEqual(self.upload.call_count, 2)
        self.assertEqual(len(self.gl.writes), 2)
        self.assertEqual(len(self.gl.uploads), 1)
        annotations = json.loads((Path(self.folder.name) / 'patchwatch-annotations.json').read_text())
        self.assertEqual(annotations['patchwatch'][0]['external_link']['url'],
                         'https://gitlab.example/team/app/uploads/' + 'd' * 32 + '/' + self.gl.uploads[0][1])

    def test_pending_status_keeps_the_last_report_link_with_a_stale_label(self):
        self.worker.process(self.gl.mr)
        url = self.worker.previous_report_url(self.gl.notes[0]['body'])
        self.gl.status = 'running'
        self.worker.process(self.gl.mr)
        self.assertIn('Pending', self.gl.notes[0]['body'])
        self.assertIn(url, self.gl.notes[0]['body'])
        self.assertIn('previous evaluation', self.gl.notes[0]['body'])

    def test_cached_report_still_appears_in_a_new_jobs_annotations(self):
        self.worker.process(self.gl.mr)
        worker = mr.Worker(self.gl, self.dt, 'https://dtrack.example', 'key', 123,
                           'patchwatch-mr-sbom', output=Path(self.folder.name))
        worker.run()
        self.assertEqual(len(self.gl.uploads), 1)
        annotations = json.loads((Path(self.folder.name) / 'patchwatch-annotations.json').read_text())
        self.assertEqual(len(annotations['patchwatch']), 1)

    def test_upload_url_cannot_redirect_reviewers_to_an_external_site(self):
        with patch.object(self.gl, 'upload', return_value={'url': 'https://attacker.example/report.zip'}):
            self.assertEqual(self.worker.run(), 1)
        self.assertNotIn('attacker.example', self.gl.notes[0]['body'])

    def test_failed_scan_is_pending_without_upload(self):
        self.gl.status = "failed"
        self.worker.process(self.gl.mr)
        self.upload.assert_not_called()
        self.assertIn("Pending", self.gl.notes[0]['body'])

    def test_fork_closed_and_merged_mrs_are_skipped(self):
        for change in ({"source_project_id": 456}, {"state": "closed"}, {"state": "merged"}):
            self.worker.process({**self.gl.mr, **change})
        self.upload.assert_not_called()
        self.assertFalse(self.gl.writes)

    def test_expired_artifact_is_pending(self):
        self.gl.missing = True
        self.worker.process(self.gl.mr)
        self.upload.assert_not_called()
        self.assertIn("expired", self.gl.notes[0]['body'])

    def test_synthetic_merge_pipeline_cannot_stand_in_for_head_scan(self):
        self.gl.pipeline_source[10] = "push"
        self.worker.process(self.gl.mr)
        self.upload.assert_not_called()
        self.assertIn("Pending", self.gl.notes[0]['body'])

    def test_head_changed_during_analysis_does_not_publish_stale_result(self):
        def change(*args):
            self.gl.mr['sha'] = "c" * 40
            return EMPTY, True
        self.snapshot.side_effect = change
        self.worker.process(dict(self.gl.mr))
        self.assertEqual(len(self.gl.writes), 1)  # initial pending only
        self.assertNotIn("patchwatch-result:", self.gl.notes[0]['body'])

    def test_target_changed_during_analysis_does_not_publish_stale_result(self):
        def change(*args):
            self.gl.target = "c" * 40
            return EMPTY, True
        self.snapshot.side_effect = change
        self.worker.process(self.gl.mr)
        self.assertEqual(len(self.gl.writes), 1)

    def test_user_cannot_spoof_bot_note(self):
        self.gl.notes = [{"id": 88, "body": self.worker.marker + "\nfake", "author": {"id": 8}}]
        self.worker.process(self.gl.mr)
        self.assertEqual(len(self.gl.notes), 2)
        self.assertEqual(self.gl.notes[0]['body'], self.worker.marker + "\nfake")

    def test_incomplete_analysis_retries_without_completed_marker(self):
        self.snapshot.return_value = EMPTY, False
        self.worker.process(self.gl.mr)
        self.assertIn("Analysis incomplete", self.gl.notes[0]['body'])
        self.assertNotIn("patchwatch-result:", self.gl.notes[0]['body'])
        self.worker.process(self.gl.mr)
        self.assertEqual(self.upload.call_count, 4)
        self.assertEqual(len(self.gl.notes), 1)

    def test_api_error_replaces_old_success_and_fails_worker(self):
        self.upload.side_effect = RuntimeError("do not expose secret-body")
        with patch("builtins.print") as log:
            self.assertEqual(self.worker.run(), 1)
        self.assertIn("Evaluation failed", self.gl.notes[0]['body'])
        self.assertNotIn("secret-body", self.gl.notes[0]['body'])
        self.assertNotIn("secret-body", str(log.call_args))

    def test_untrusted_metadata_is_replaced_and_no_url_is_followed(self):
        self.gl.bom['metadata'] = {"component": {"name": "malicious", "version": "main"}}
        self.gl.bom['externalReferences'] = [{"url": "https://attacker.example"}]
        self.worker.process(self.gl.mr)
        uploaded = self.upload.call_args.args[3]
        self.assertEqual(uploaded['metadata']['component']['name'], "team/app")
        self.assertNotIn("externalReferences", uploaded)

    def test_malformed_component_reports_failure(self):
        self.gl.bom['components'] = [{"name": {"bad": "shape"}}]
        self.assertEqual(self.worker.run(), 1)
        self.upload.assert_not_called()
        self.assertIn("Evaluation failed", self.gl.notes[0]['body'])

    def test_default_component_marker_is_distinct(self):
        component = mr.Worker(self.gl, self.dt, "https://dt", "key", 123, "scan", component="default")
        self.assertNotEqual(component.marker, self.worker.marker)

    def test_report_lists_fixed_cves_and_per_package_license_additions_and_removals(self):
        def component(name, license):
            return {"name": name, "versions": {"1"}, "licenses": {license}}
        old = {"components": {"kept": component("kept", "MIT"), "gone": component("gone", "MIT")},
               "vulnerabilities": {("CVE-OLD", "gone"): {"id": "CVE-OLD", "severity": "HIGH", "component": "gone"}},
               "violations": {}}
        new = {"components": {"kept": component("kept", "MIT"), "added": component("added", "MIT")},
               "vulnerabilities": {("CVE-NEW", "added"): {"id": "CVE-NEW", "severity": "CRITICAL", "component": "added"}},
               "violations": {}}
        self.snapshot.side_effect = [(old, True), (new, True)]
        self.worker.process(self.gl.mr)
        body = self.gl.notes[0]['body']
        self.assertIn("CVE-OLD", body)
        self.assertIn("CVE-NEW", body)
        self.assertIn("gone: MIT", body)
        self.assertIn("added: MIT", body)
        self.assertIn("Fixed / dropped vulnerabilities", body)
        data = json.loads((Path(self.folder.name) / "42/patchwatch-delta.json").read_text())
        self.assertEqual(data['licenses']['newLicenses'], [])  # MIT was already present elsewhere.
        self.assertEqual(data['licenses']['droppedLicenses'], [])
        self.assertEqual(data['comparison'], 'target-vs-merge-result')
        self.assertEqual(data['mergedTree'], TREE)

    def test_stale_target_requests_one_pipeline_and_never_compares_wrong_trees(self):
        self.gl.target = "d" * 40
        self.worker.process(self.gl.mr)
        self.worker.process(self.gl.mr)
        self.upload.assert_not_called()
        starts = [w for w in self.gl.writes if w[0].endswith('/pipelines')]
        self.assertEqual(len(starts), 1)
        self.assertIn("Pending", self.gl.notes[0]['body'])
        self.assertNotIn("patchwatch-result:", self.gl.notes[0]['body'])

    def test_running_pipeline_prevents_duplicate_rescan(self):
        self.gl.target = "d" * 40
        self.gl.pipeline_status = 'running'
        self.worker.process(self.gl.mr)
        self.assertFalse(any(w[0].endswith('/pipelines') for w in self.gl.writes))
        self.upload.assert_not_called()

    def test_merge_conflict_is_reported_without_upload_or_success_marker(self):
        self.gl.pair['status'] = 'conflict'
        self.worker.process(self.gl.mr)
        self.upload.assert_not_called()
        self.assertIn("Merge conflict", self.gl.notes[0]['body'])
        self.assertNotIn("patchwatch-result:", self.gl.notes[0]['body'])

    def test_artifact_cannot_claim_a_different_source_or_pipeline(self):
        for field in ('headSha', 'pipelineSha'):
            with self.subTest(field=field):
                self.gl.pair[field] = "e" * 40
                self.assertEqual(self.worker.run(), 1)
                self.upload.assert_not_called()
                self.gl.pair[field] = HEAD

    def test_merged_results_pipeline_is_bound_to_its_source_parent(self):
        self.gl.pipeline_sha = "f" * 40
        self.gl.pair['pipelineSha'] = self.gl.pipeline_sha
        self.worker.process(self.gl.mr)
        self.assertEqual(self.upload.call_count, 2)

    def test_synthetic_pipeline_with_unrelated_parents_is_not_accepted(self):
        self.gl.pipeline_sha = "f" * 40
        self.gl.parents = [BASE, "e" * 40]
        self.worker.process(self.gl.mr)
        self.upload.assert_not_called()
        self.assertIn("Pending", self.gl.notes[0]['body'])

    def test_removing_all_packages_is_a_valid_one_sided_empty_inventory(self):
        self.gl.pair['merged'] = {"bomFormat": "CycloneDX", "components": []}
        self.worker.process(self.gl.mr)
        self.assertEqual(self.upload.call_count, 2)
        self.assertEqual(self.upload.call_args.args[3]['components'], [])


class BaselineChoice(Feedback):
    def setUp(self):
        super().setUp()
        self.worker = mr.Worker(self.gl, self.dt, "https://dtrack.example", "upload-secret", 123,
                                "patchwatch-mr-sbom", output=Path(self.folder.name), baseline="branch")

    def test_paired_scan_is_the_default_baseline(self):
        self.dt.add("release/1", ["source:gitlab-ci"], commit=BASE)
        default = mr.Worker(self.gl, self.dt, "https://dtrack.example", "key", 123, "patchwatch-mr-sbom",
                            output=Path(self.folder.name))
        default.process(self.gl.mr)
        self.assertEqual([c.args[2]['projectVersion'] for c in self.upload.call_args_list], ["base-release/1", "mr-42"])

    def test_current_target_branch_version_is_the_baseline(self):
        self.dt.add("release/1", ["source:gitlab-ci"], commit=BASE)
        self.worker.process(self.gl.mr)
        fields = [c.args[2] for c in self.upload.call_args_list]
        self.assertEqual([f['projectVersion'] for f in fields], ["mr-42"])
        result = json.loads((Path(self.folder.name) / "42/patchwatch-delta.json").read_text())
        self.assertEqual(result['baseline'], {"version": "release/1", "source": "branch"})
        self.assertEqual(result['targetBranch'], "release/1")
        self.assertEqual(self.snapshot.call_args_list[0].args[1]['version'], "release/1")
        self.assertIn("dTrack-Version `release/1`", self.gl.notes[0]['body'])

    def test_outdated_or_foreign_target_version_falls_back_to_the_paired_scan(self):
        for kwargs in ({"commit": "e" * 40}, {"commit": BASE, "active": False}, {"commit": BASE, "tags": [MR_TAG]}):
            self.upload.reset_mock()
            self.dt.projects.clear()
            self.dt.add("release/1", kwargs.get("tags", ["source:gitlab-ci"]), commit=kwargs["commit"], active=kwargs.get("active", True))
            self.worker.process(self.gl.mr)
            self.assertEqual([c.args[2]['projectVersion'] for c in self.upload.call_args_list], ["base-release/1", "mr-42"])
            self.gl.notes.clear()

    def test_invalid_baseline_is_rejected(self):
        with self.assertRaises(ValueError):
            mr.Worker(self.gl, self.dt, "https://dtrack.example", "key", 123, "x", baseline="main")

    def test_existing_versions_of_other_owners_are_never_overwritten(self):
        self.dt.add("mr-42", ["source:gitlab-ci"], commit=HEAD)
        self.assertEqual(self.worker.run(), 1)
        self.assertNotIn("mr-42", [c.args[2]['projectVersion'] for c in self.upload.call_args_list])
        self.assertEqual(self.dt.projects["mr-42"]["tags"], [{"name": "source:gitlab-ci"}])

    def test_uploaded_versions_record_their_commit_for_later_comparison(self):
        self.worker.process(self.gl.mr)
        self.assertEqual(mr.recorded_commit(self.dt.projects["mr-42"]), HEAD)
        self.assertEqual(mr.recorded_commit(self.dt.projects["base-release/1"]), BASE)


class FakeBranchGitLab:
    """Branch list, push pipelines and branch scan artifacts of a project with two feature branches."""
    def __init__(self):
        self.url = 'https://gitlab.example'
        self.head = HEAD
        self.names = ["main", "dev", "feat/x"]
        self.protected = {"main", "dev"}
        self.artifact = {"formatVersion": 1, "kind": "branch", "branch": "feat/x", "headSha": HEAD,
                         "pipelineSha": HEAD, "bom": copy.deepcopy(BOM)}
        self.pipelines, self.job_status, self.moved = [{"id": 40, "sha": HEAD}], "success", None

    def call(self, path, data=None, method=None):
        if path == "user":
            return {"id": 7}
        if path == "projects/123":
            return {"path_with_namespace": "team/app", "default_branch": "main", "web_url": "https://gitlab.example/team/app"}
        if path.startswith("projects/123/repository/branches/"):
            return {"commit": {"id": self.moved or self.head}}
        if path == "projects/123/pipelines/40":
            return {"id": 40, "project_id": 123, "sha": HEAD, "source": "push"}
        if path.endswith("/artifacts/patchwatch-branch.json"):
            return self.artifact
        raise AssertionError(path)

    def all(self, path):
        if path.endswith("/repository/branches"):
            return iter([{"name": n, "protected": n in self.protected, "commit": {"id": self.head}} for n in self.names])
        if path.endswith("merge_requests?state=opened"):
            return iter([])
        if "/pipelines?" in path:
            return iter(self.pipelines)
        if path.endswith("/pipelines/40/jobs"):
            return iter([{"id": 41, "name": "patchwatch-branch-sbom", "status": self.job_status,
                          "commit": {"id": HEAD}, "pipeline": {"web_url": "https://gitlab.example/team/app/-/pipelines/40"}}])
        raise AssertionError(path)


class ParentProjects(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {"PATCHWATCH_BSI_MODE": "report"}))
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.gl, self.dt = FakeBranchGitLab(), FakeDTrack()
        self.upload = self.enterContext(patch("patchwatch.ci.mr.upload_and_wait", side_effect=self.dt.register))
        self.worker = mr.Worker(self.gl, self.dt, "https://dtrack.example", "key", 123, "patchwatch-mr-sbom",
                                component="api", output=Path(self.folder.name), branch_job="patchwatch-branch-sbom")

    def test_component_version_hangs_below_a_parent_with_the_same_version(self):
        self.assertEqual(self.worker.run(), 0)
        parent, child = (c.args[2] for c in self.upload.call_args_list)
        self.assertEqual((parent['projectName'], parent['projectVersion']), ("team/app", "feat/x"))
        self.assertEqual(parent['projectTags'], BRANCH_TAG + ",gitlab-project-id:123")
        self.assertEqual((child['projectName'], child['parentName'], child['parentVersion']),
                         ("team/app/api", "team/app", "feat/x"))
        self.assertEqual(self.upload.call_args_list[0].args[3]['components'], [])

    def test_existing_parent_is_reused_and_foreign_parent_is_left_alone(self):
        self.dt.add("feat/x", tags=[BRANCH_TAG])
        self.worker.upload_version({"components": []}, "feat/x", BRANCH_TAG, HEAD, "c")
        self.assertEqual(self.upload.call_count, 1)
        self.assertEqual(self.upload.call_args.args[2]['parentName'], "team/app")
        self.dt.add("v1", tags=["source:gitlab-ci"])
        self.worker.upload_version({"components": []}, "v1", BRANCH_TAG, HEAD, "c")
        self.assertNotIn("parentName", self.upload.call_args.args[2])

    def test_lost_creation_race_is_fine_but_a_missing_parent_is_an_error(self):
        def racing(url, key, fields, bom):
            self.dt.register(url, key, fields, bom)
            if "parentName" not in fields and fields['projectName'] == "team/app":
                raise RuntimeError("Upload failed (HTTP 409)")
        self.upload.side_effect = racing
        self.assertEqual(self.worker.run(), 0)
        self.upload.side_effect = RuntimeError("boom")
        with self.assertRaisesRegex(RuntimeError, "could not be created"):
            self.worker.upload_version({"components": []}, "other", BRANCH_TAG, HEAD, "c")


class BranchVersions(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {"PATCHWATCH_BSI_MODE": "report"}))
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.gl, self.dt = FakeBranchGitLab(), FakeDTrack()
        self.upload = self.enterContext(patch("patchwatch.ci.mr.upload_and_wait", side_effect=self.dt.register))
        self.worker = mr.Worker(self.gl, self.dt, "https://dtrack.example", "key", 123, "patchwatch-mr-sbom",
                                output=Path(self.folder.name), branch_job="patchwatch-branch-sbom")

    def test_unprotected_branch_becomes_a_version_named_like_the_branch_and_is_not_repeated(self):
        self.assertEqual(self.worker.run(), 0)
        fields = self.upload.call_args.args[2]
        self.assertEqual(self.upload.call_count, 1)
        self.assertEqual((fields['projectName'], fields['projectVersion']), ("team/app", "feat/x"))
        self.assertEqual(fields['projectTags'], BRANCH_TAG + ",gitlab-project-id:123")
        self.assertEqual(fields['isLatest'], "false")
        project = self.dt.projects["feat/x"]
        self.assertEqual(mr.recorded_commit(project), HEAD)
        self.assertEqual(project['externalReferences'][0]['comment'], "PatchWatch branch: feat/x")
        self.assertEqual(self.worker.run(), 0)
        self.assertEqual(self.upload.call_count, 1)

    def test_disabled_without_a_branch_job(self):
        worker = mr.Worker(self.gl, self.dt, "https://dtrack.example", "key", 123, "x", output=Path(self.folder.name))
        self.assertEqual(worker.run(), 0)
        self.upload.assert_not_called()

    def test_missing_scan_is_pending_not_a_failure(self):
        self.gl.pipelines = []
        self.assertEqual(self.worker.run(), 0)
        self.gl.pipelines, self.gl.job_status = [{"id": 40, "sha": HEAD}], "running"
        self.assertEqual(self.worker.run(), 0)
        self.upload.assert_not_called()

    def test_names_of_releases_and_merge_requests_are_never_overwritten(self):
        self.gl.names = ["feat/x", "v1.0.0", "mr-7", "base-main"]
        self.dt.add("v1.0.0", ["source:gitlab-ci"], commit=HEAD)
        self.dt.add("feat/x", ["source:gitlab-ci"])
        self.assertEqual(self.worker.run(), 0)
        self.upload.assert_not_called()

    def test_artifact_of_another_commit_is_a_failure_and_a_moved_branch_is_skipped(self):
        self.gl.artifact["headSha"] = BASE
        self.assertEqual(self.worker.run(), 1)
        self.gl.artifact["headSha"], self.gl.moved = HEAD, BASE
        self.assertEqual(self.worker.run(), 0)
        self.upload.assert_not_called()

    def test_scan_producer_writes_a_branch_artifact_from_the_pushed_commit(self):
        folder = Path(self.folder.name)
        with patch("patchwatch.ci.mr.checkout_tree") as checkout, patch("patchwatch.ci.mr.scan_tree", return_value=copy.deepcopy(BOM)):
            mr.produce_branch({"CI_PROJECT_DIR": str(folder), "CI_COMMIT_SHA": HEAD, "CI_COMMIT_BRANCH": "feat/x"})
        self.assertEqual(checkout.call_args.args[1], HEAD)
        data = json.loads((folder / "patchwatch-branch.json").read_text())
        self.assertEqual((data["branch"], data["headSha"], data["pipelineSha"]), ("feat/x", HEAD, HEAD))
        with self.assertRaises(ValueError):
            mr.produce_branch({"CI_PROJECT_DIR": str(folder), "CI_COMMIT_SHA": "short", "CI_COMMIT_BRANCH": "x"})


class ProducerAndTransport(unittest.TestCase):
    def test_multipart_upload_uses_private_header_and_preserves_zip_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / 'report.zip'
            archive.write_bytes(b'PK\x00\xffbinary')
            with patch('patchwatch.ci.mr.request', return_value=({'url': '/uploads/x/report.zip'}, {})) as http:
                result = mr.GitLab('https://gitlab.example', 'private-token').upload(123, archive)
            url, payload, headers, method = http.call_args.args
            self.assertEqual(url, 'https://gitlab.example/api/v4/projects/123/uploads')
            self.assertEqual(headers['PRIVATE-TOKEN'], 'private-token')
            self.assertIn(b'PK\x00\xffbinary', payload)
            self.assertIn(b'filename="report.zip"', payload)
            self.assertTrue(headers['Content-Type'].startswith('multipart/form-data; boundary='))
            self.assertEqual(method, 'POST')
            self.assertEqual(result['url'], '/uploads/x/report.zip')

    def test_full_report_has_no_row_or_text_truncation(self):
        license = 'LicenseRef-' + 'X' * 600
        current = {'components': {'demo': {'name': 'demo', 'versions': {'1'}, 'licenses': {license}}},
                   'vulnerabilities': {(str(i), 'demo'): {'id': f'CVE-{i}', 'severity': 'LOW', 'component': 'demo'} for i in range(30)},
                   'violations': {}}
        result = mr.delta.diff(EMPTY, current)
        preview, full = mr.render(result), mr.render(result, limit=None)
        self.assertNotIn(license, preview)
        self.assertIn(license, full)
        self.assertNotIn('CVE-29', preview)
        self.assertIn('CVE-29', full)
        self.assertNotIn('more entries', full)

    def test_mr_policies_mirror_ci_rules_without_production_or_distribution_scope(self):
        original = load()
        before = copy.deepcopy(original)
        derived = definitions(original)
        expected = [p for p in original if {"managed-by:patchwatch", "source:gitlab-ci"}.intersection(p['scopeTags'])]
        self.assertEqual(len(derived), len(expected))
        self.assertTrue(derived)
        for source, target in zip(expected, derived):
            self.assertEqual(target['scopeTags'], [MR_TAG, BRANCH_TAG])
            self.assertTrue(target['name'].startswith('Patchwatch MR '))
            self.assertEqual(target['conditions'], source['conditions'])
            self.assertEqual(target['violationState'], source['violationState'])
        self.assertEqual(original, before)

    def test_pagination_and_mutation_use_private_header(self):
        with patch("patchwatch.ci.mr.request", side_effect=[([{}] * 100, {}), ([{"id": 101}], {}), ({}, {})]) as http:
            gl = mr.GitLab("https://gitlab.example", "secret-token")
            self.assertEqual(len(list(gl.all("projects/123/jobs?scope=success"))), 101)
            self.assertIn("page=2", http.call_args.args[0])
            gl.call("projects/123/merge_requests/42/notes/9", {"body": "report\nnext"}, "PUT")
            args = http.call_args.args
            self.assertEqual(args[2]['PRIVATE-TOKEN'], "secret-token")
            self.assertNotIn("secret-token", args[0])
            self.assertEqual(json.loads(args[1]), {"body": "report\nnext"})

    def test_plain_http_rejected(self):
        with self.assertRaises(ValueError):
            mr.GitLab("http://gitlab.example", "token")

    def test_comment_escapes_untrusted_mentions_markdown_and_quick_actions(self):
        value = mr.inline("<script>\n/merge\n@all [click](https://evil) `code` | demo")
        self.assertNotIn("<script>", value)
        self.assertNotIn("\n", value)
        self.assertNotIn("@all", value)
        self.assertIn("\\[click\\]", value)


class PairedProducer(unittest.TestCase):
    """Real Git branches reproduce the attribution bug that a head-vs-target diff had."""
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.run_git('init', '-b', 'main')
        self.run_git('config', 'user.name', 'Test')
        self.run_git('config', 'user.email', 'test@example.org')
        (self.repo / 'deps.txt').write_text('old')
        self.commit('base')
        self.run_git('branch', 'feature')
        (self.repo / 'target-only.txt').write_text('target dependency')
        self.commit('target advances independently')
        self.target = self.run_git('rev-parse', 'HEAD')
        self.run_git('checkout', 'feature')
        (self.repo / 'deps.txt').write_text('new')
        self.commit('MR change')
        self.head = self.run_git('rev-parse', 'HEAD')
        self.run_git('remote', 'add', 'origin', str(self.repo))
        self.env = {'CI_PROJECT_DIR': str(self.repo), 'CI_COMMIT_SHA': self.head,
                    'CI_MERGE_REQUEST_TARGET_BRANCH_NAME': 'main'}

    def run_git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL, text=True).strip()

    def commit(self, message):
        self.run_git('add', '.')
        self.run_git('commit', '-m', message)

    def test_diverged_target_changes_survive_in_both_scanned_trees(self):
        seen = []
        def scan(env, workspace, directory, **kwargs):
            seen.append({p.name: p.read_text() for p in workspace.iterdir()})
            return [BOM]
        with patch('patchwatch.ci.mr.pipeline.scan', side_effect=scan), patch('patchwatch.ci.mr.upload_and_wait') as upload:
            mr.produce(self.env)
        self.assertEqual(seen[0]['deps.txt'], 'old')
        self.assertEqual(seen[1]['deps.txt'], 'new')
        self.assertEqual(seen[0]['target-only.txt'], seen[1]['target-only.txt'])
        pair = json.loads((self.repo / mr.ARTIFACT).read_text())
        self.assertEqual(pair['targetSha'], self.target)
        self.assertEqual(pair['headSha'], self.head)
        self.assertEqual(pair['status'], 'complete')
        self.assertEqual(self.run_git('rev-parse', 'HEAD'), self.head)
        self.assertFalse((self.repo / 'target-only.txt').exists())
        upload.assert_not_called()

    def test_conflict_produces_explicit_status_instead_of_false_findings(self):
        self.run_git('checkout', 'main')
        (self.repo / 'deps.txt').write_text('conflicting target change')
        self.commit('conflict')
        self.run_git('checkout', 'feature')
        with patch('patchwatch.ci.mr.pipeline.scan') as scan:
            mr.produce(self.env)
        scan.assert_not_called()
        self.assertEqual(json.loads((self.repo / mr.ARTIFACT).read_text())['status'], 'conflict')

    def test_compose_image_versions_are_read_independently_from_each_tree(self):
        self.run_git('checkout', 'main')
        (self.repo / 'compose.yaml').write_text('services:\n  database:\n    image: postgres:16\n')
        self.commit('old image')
        self.run_git('checkout', 'feature')
        self.run_git('merge', 'main', '--no-edit')
        (self.repo / 'compose.yaml').write_text('services:\n  database:\n    image: postgres:17\n')
        self.commit('upgrade image')
        self.env.update({'CI_COMMIT_SHA': self.run_git('rev-parse', 'HEAD'), 'PATCHWATCH_SCAN_PATHS': '',
                         'PATCHWATCH_COMPOSE_IMAGES': 'compose.yaml:database'})
        images = []
        def scan(env, *args, **kwargs):
            images.append(env['PATCHWATCH_IMAGES'])
            return [BOM]
        with patch('patchwatch.ci.mr.pipeline.scan', side_effect=scan):
            mr.produce(self.env)
        self.assertEqual(images, ['postgres:16', 'postgres:17'])

    def test_export_ignore_does_not_remove_dependencies_from_scan(self):
        (self.repo / '.gitattributes').write_text('deps.txt export-ignore\n')
        self.commit('export ignore')
        self.env['CI_COMMIT_SHA'] = self.run_git('rev-parse', 'HEAD')
        def scan(env, workspace, directory, **kwargs):
            self.assertTrue((workspace / 'deps.txt').is_file())
            return [BOM]
        with patch('patchwatch.ci.mr.pipeline.scan', side_effect=scan):
            mr.produce(self.env)

    def test_empty_inventory_on_both_sides_is_rejected(self):
        with patch('patchwatch.ci.mr.pipeline.scan', return_value=[{'components': []}]):
            with self.assertRaisesRegex(ValueError, 'Both inventories'):
                mr.produce(self.env)

    def test_scan_paths_cannot_escape_the_materialized_tree(self):
        self.env['PATCHWATCH_SCAN_PATHS'] = '../'
        with self.assertRaisesRegex(ValueError, 'inside the repository'):
            mr.produce(self.env)


if __name__ == "__main__":
    unittest.main()
