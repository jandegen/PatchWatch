# SPDX-License-Identifier: Apache-2.0
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from patchwatch.ci import pipeline as ci
from patchwatch.core.tags import ci_tags


def environment(folder, **extra):
    env = {"CI_PROJECT_DIR": folder, "CI_PROJECT_PATH": "Platform/Web-App", "CI_PROJECT_ID": "42",
           "CI_PROJECT_ROOT_NAMESPACE": "Platform", "CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": "main",
           "PATCHWATCH_BSI_MODE": "report",  # legacy inventory cases; enforce is tested in test_ci_sbom.py
           "PATCHWATCH_URL": "https://patchwatch.example.org"}
    env.update(extra)
    return env


def fake_syft(args, **kwargs):
    output = next(a.split("=", 1)[1] for a in args if a.startswith("cyclonedx-json="))
    Path(output).write_text(json.dumps({"components": [{"type": "library", "name": "pkg", "version": "1"}]}))


class Isolated(unittest.TestCase):
    """CI jobs of this very repository have PATCHWATCH_* variables set; tests must not depend on them."""
    def setUp(self):
        lookup = patch("patchwatch.ci.pipeline.lookup_parent", return_value=None)
        self.lookup = lookup.start()
        self.addCleanup(lookup.stop)
        patcher = patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in [n for n in os.environ if n.startswith(("PATCHWATCH_", "SYFT_", "SSL_CERT_FILE"))]:
            del os.environ[name]


class Target(Isolated):
    def test_latest_is_selected_server_side_for_branches_and_tags(self):
        self.assertEqual(ci.target({"CI_COMMIT_BRANCH": "main", "CI_DEFAULT_BRANCH": "main"}), ("main", False))
        self.assertEqual(ci.target({"CI_COMMIT_TAG": "v1.2.3", "CI_DEFAULT_BRANCH": "main"}), ("v1.2.3", False))

    def test_other_branches_are_skipped(self):
        with self.assertRaises(ci.Skip):
            ci.target({"CI_COMMIT_BRANCH": "feature", "CI_DEFAULT_BRANCH": "main"})

    def test_allowed_branches_are_exact_names_and_never_latest(self):
        env = {"CI_DEFAULT_BRANCH": "main", "PATCHWATCH_BRANCHES": " main\tdev release/next\n"}
        for branch, latest in (("main", False), ("dev", False), ("release/next", False)):
            with self.subTest(branch=branch):
                self.assertEqual(ci.target(dict(env, CI_COMMIT_BRANCH=branch)), (branch, latest))
        for branch in ("de", "dev-extra", "feature", ""):
            with self.subTest(branch=branch), self.assertRaises(ci.Skip):
                ci.target(dict(env, CI_COMMIT_BRANCH=branch))
        self.assertEqual(ci.target(dict(env, CI_COMMIT_BRANCH="main", CI_COMMIT_TAG="v1.1.0")),
                         ("v1.1.0", False))

    def test_allowed_branch_versions_are_validated(self):
        for branch in ("bad,name", "x" * 129):
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                ci.target({"CI_COMMIT_BRANCH": branch, "PATCHWATCH_BRANCHES": branch})

    def test_skipped_pipeline_logs_a_warning_without_scanning_or_uploading(self):
        for extra, reason in (({}, "No branch or tag"),
                              ({"CI_COMMIT_BRANCH": "feature", "PATCHWATCH_BRANCHES": "dev"},
                               "Branch 'feature'")):
            with self.subTest(extra=extra), patch.dict(os.environ, extra, clear=True), \
                    patch("sys.argv", ["patchwatch-ci"]), patch("sys.stderr", new_callable=io.StringIO) as stderr, \
                    patch("patchwatch.ci.pipeline.subprocess.run") as scan, patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                with self.assertRaises(SystemExit) as exit:
                    ci.main()
                self.assertEqual(exit.exception.code, 0)
                self.assertIn("WARNING: PatchWatch CI skipped:", stderr.getvalue())
                self.assertIn(reason, stderr.getvalue())
                self.assertIn("no upload or report was produced", stderr.getvalue())
                if extra:
                    self.assertIn("PATCHWATCH_BRANCHES", stderr.getvalue())
                    self.assertIn("run_if only controls job scheduling", stderr.getvalue())
                scan.assert_not_called()
                upload.assert_not_called()

    def test_component_extends_name_and_is_validated(self):
        self.assertEqual(ci.project_name({"CI_PROJECT_PATH": "g/p", "PATCHWATCH_COMPONENT": "api"}), "g/p/api")
        with self.assertRaises(ValueError):
            ci.project_name({"CI_PROJECT_PATH": "g/p", "PATCHWATCH_COMPONENT": "../x"})


class Tags(Isolated):
    def test_canonical_application_tags(self):
        self.assertEqual(ci_tags(42, "Platform", "Production"),
                         ["asset-type:application", "environment:production", "gitlab-project-id:42",
                          "managed-by:patchwatch", "source:gitlab-ci", "team:platform"])

    def test_invalid_values_are_rejected(self):
        with self.assertRaises(ValueError):
            ci_tags("abc", "team")
        with self.assertRaises(ValueError):
            ci_tags(1, "my team")


class Sources(Isolated):
    def test_paths_stay_inside_the_workspace(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder).resolve()
            (workspace / "svc").mkdir()
            result = ci.sources({"PATCHWATCH_SCAN_PATHS": "svc", "PATCHWATCH_IMAGES": "registry.example/app:1"}, workspace)
            self.assertEqual(result, ["dir:" + str(workspace / "svc"), "registry:registry.example/app:1"])
            for bad in ("..", "/etc", "missing"):
                with self.assertRaises(ValueError):
                    ci.sources({"PATCHWATCH_SCAN_PATHS": bad}, workspace)

    def test_images_must_be_plain_references(self):
        with tempfile.TemporaryDirectory() as folder:
            for bad in ("--config=x", "docker://x"):
                with self.assertRaises(ValueError):
                    ci.sources({"PATCHWATCH_SCAN_PATHS": "", "PATCHWATCH_IMAGES": bad}, Path(folder))
            with self.assertRaises(ValueError):
                ci.sources({"PATCHWATCH_SCAN_PATHS": ""}, Path(folder))


class Run(Isolated):
    def test_allowed_branch_upload_leaves_latest_to_server_and_writes_report(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), \
                    patch("patchwatch.ci.pipeline.subprocess.run", side_effect=fake_syft), \
                    patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                for branch in ("main", "dev"):
                    self.assertEqual(ci.run(environment(folder, CI_COMMIT_BRANCH=branch,
                                                        PATCHWATCH_BRANCHES="dev")), 0)
                    fields, bom = upload.call_args.args[2:]
                    self.assertEqual(fields["projectVersion"], branch)
                    self.assertEqual(fields["isLatest"], "false")
                    self.assertEqual(bom["metadata"]["component"]["version"], branch)
                    report = json.loads((Path(folder) / "patchwatch-report.json").read_text())
                    self.assertEqual(report["version"], branch)
                    self.assertEqual(report["components"], 1)
                self.assertEqual(upload.call_count, 2)

    def test_upload_fields_and_report(self):
        with tempfile.TemporaryDirectory() as folder:
            env = environment(folder, PATCHWATCH_TEAM="platform", PATCHWATCH_ENVIRONMENT="production")
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "upload-secret"}), \
                    patch("patchwatch.ci.pipeline.subprocess.run", side_effect=fake_syft) as syft, \
                    patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                self.assertEqual(ci.run(env), 0)
            args = syft.call_args.args[0]
            self.assertEqual(args[2], "dir:" + str(Path(folder).resolve()))
            url, key, fields, bom = upload.call_args.args
            self.assertEqual(url, "https://patchwatch.example.org")
            self.assertEqual(key, "upload-secret")
            self.assertEqual((fields["projectName"], fields["projectVersion"], fields["isLatest"], fields["autoCreate"]),
                             ("Platform/Web-App", "main", "false", "true"))
            self.assertIn("team:platform", fields["projectTags"])
            self.assertIn("managed-by:patchwatch", fields["projectTags"])
            self.assertNotIn("policy-profile:distribution", fields["projectTags"])
            self.assertEqual(bom["metadata"]["component"]["type"], "application")
            report = json.loads((Path(folder) / "patchwatch-report.json").read_text())
            self.assertEqual(report["components"], 1)
            self.assertNotIn("upload-secret", json.dumps(report))

    def test_provenance_is_uploaded_for_inventory_and_parent_and_written_to_report(self):
        for mode in ("inventory", "parent"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                env = environment(folder, PATCHWATCH_MODE=mode, CI_COMMIT_SHA="abcdef0123456789",
                                  CI_PROJECT_URL="https://gitlab.example/Platform/Web-App",
                                  CI_PIPELINE_URL="https://gitlab.example/Platform/Web-App/-/pipelines/42")
                with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), \
                        patch("patchwatch.ci.pipeline.subprocess.run", side_effect=fake_syft), \
                        patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                    ci.run(env)
                bom = upload.call_args.args[3]
                refs = bom["metadata"]["component"]["externalReferences"]
                self.assertEqual(refs[0]["url"], env["CI_PROJECT_URL"] + "/-/commit/" + env["CI_COMMIT_SHA"])
                self.assertIn("main (abcdef01)", refs[0]["comment"])
                self.assertEqual(refs[1]["url"], env["CI_PIPELINE_URL"])
                self.assertIn("timestamp", bom["metadata"])
                if mode == "inventory":
                    report = json.loads((Path(folder) / "patchwatch-report.json").read_text())
                    self.assertEqual(report["commit"], env["CI_COMMIT_SHA"])
                    self.assertEqual(report["pipeline"], env["CI_PIPELINE_URL"])

    def test_release_provenance_and_numeric_default_branch(self):
        for extra, prefix in (({"CI_COMMIT_TAG": "v1.2.0"}, "PatchWatch release: "),
                              ({"CI_COMMIT_BRANCH": "2026", "CI_DEFAULT_BRANCH": "2026"}, "PatchWatch default branch: "),
                              ({"CI_COMMIT_BRANCH": "dev", "CI_DEFAULT_BRANCH": "main"}, "PatchWatch branch: dev")):
            bom = ci.parent_bom("g/p", "version")
            env = dict(CI_PROJECT_URL="https://gitlab.example/g/p", CI_COMMIT_SHA="abcdef012345", **extra)
            ci.provenance(bom, env)
            self.assertTrue(bom["metadata"]["component"]["externalReferences"][0]["comment"].startswith(prefix))

    def test_team_falls_back_to_root_namespace_and_tag_pipelines_are_not_latest(self):
        with tempfile.TemporaryDirectory() as folder:
            env = environment(folder, CI_COMMIT_TAG="v1.0.0", CI_COMMIT_BRANCH="")
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), \
                    patch("patchwatch.ci.pipeline.subprocess.run", side_effect=fake_syft), \
                    patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                ci.run(env)
            fields = upload.call_args.args[2]
            self.assertEqual((fields["projectVersion"], fields["isLatest"]), ("v1.0.0", "false"))
            self.assertIn("policy-profile:distribution", fields["projectTags"])
            self.assertIn("team:platform", fields["projectTags"])

    def test_gate_requires_read_key_and_evaluates_policy_state(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}):
                with self.assertRaises(ValueError):
                    ci.run(environment(folder, PATCHWATCH_FAIL_ON="fail"))
            result = {"unsuppressedViolations": [{"type": "SECURITY", "state": "FAIL", "policy": "p", "count": 1}]}
            self.assertTrue(ci.gate(result, "fail"))
            self.assertFalse(ci.gate(result, "none"))
            self.assertFalse(ci.gate({"unsuppressedViolations": [{"type": "LICENSE", "state": "WARN", "policy": "p", "count": 1}]}, "fail"))
            self.assertTrue(ci.gate({"unsuppressedViolations": [{"type": "LICENSE", "state": "WARN", "policy": "p", "count": 1}]}, "warn"))

    def test_gate_exit_code_after_summary(self):
        with tempfile.TemporaryDirectory() as folder:
            summary = {"uuid": "u", "url": "https://x/projects/u", "findings": {"CRITICAL": 1},
                       "unsuppressedViolations": [{"type": "SECURITY", "state": "FAIL", "policy": "p", "count": 1}]}
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k", "PATCHWATCH_READ_KEY": "r"}), \
                    patch("patchwatch.ci.pipeline.subprocess.run", side_effect=fake_syft), \
                    patch("patchwatch.ci.pipeline.upload_and_wait"), patch("patchwatch.ci.pipeline.summary", return_value=summary):
                self.assertEqual(ci.run(environment(folder, PATCHWATCH_FAIL_ON="fail")), 2)
                self.assertEqual(ci.run(environment(folder)), 0)

    def test_missing_credentials_and_http_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("PATCHWATCH_UPLOAD_KEY", None)
                os.environ.pop("PATCHWATCH_UPLOAD_KEY_FILE", None)
                with self.assertRaises(ValueError):
                    ci.run(environment(folder))
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}):
                with self.assertRaises(ValueError):
                    ci.run(environment(folder, PATCHWATCH_URL="http://patchwatch.example.org"))

    def test_empty_inventory_is_rejected(self):
        def empty(args, **kwargs):
            output = next(a.split("=", 1)[1] for a in args if a.startswith("cyclonedx-json="))
            Path(output).write_text(json.dumps({"components": []}))
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), \
                    patch("patchwatch.ci.pipeline.subprocess.run", side_effect=empty), patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                with self.assertRaises(RuntimeError):
                    ci.run(environment(folder))
                upload.assert_not_called()

    def test_dry_run_needs_no_credentials_and_never_uploads(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "out.json"
            env = environment(folder, PATCHWATCH_URL="", PATCHWATCH_SBOM_OUTPUT=str(output))
            with patch("patchwatch.ci.pipeline.subprocess.run", side_effect=fake_syft), patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                self.assertEqual(ci.run(env, dry_run=True), 0)
            upload.assert_not_called()
            self.assertEqual(json.loads(output.read_text())["bomFormat"], "CycloneDX")

    def test_registry_images_use_the_job_token_via_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            env = environment(folder, PATCHWATCH_SCAN_PATHS="", PATCHWATCH_IMAGES="reg.example/g/p/app:1",
                              CI_REGISTRY="reg.example", CI_JOB_TOKEN="job-token")
            with patch("patchwatch.ci.pipeline.subprocess.run", side_effect=fake_syft) as syft:
                ci.scan(env, Path(folder).resolve(), folder)
            self.assertNotIn("job-token", " ".join(syft.call_args.args[0]))
            self.assertEqual(syft.call_args.kwargs["env"]["SYFT_REGISTRY_AUTH_PASSWORD"], "job-token")
            self.assertEqual(syft.call_args.args[0][2], "registry:reg.example/g/p/app:1")


class Parent(Isolated):
    def test_parent_mode_uploads_an_empty_sbom_for_the_project_itself(self):
        with tempfile.TemporaryDirectory() as folder:
            env = environment(folder, PATCHWATCH_MODE="parent")
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), \
                    patch("patchwatch.ci.pipeline.subprocess.run") as syft, patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                self.assertEqual(ci.run(env), 0)
            syft.assert_not_called()
            fields, bom = upload.call_args_list[0].args[2:]
            self.assertEqual(fields["projectName"], "Platform/Web-App")
            self.assertNotIn("parentName", fields)
            self.assertEqual(bom["components"], [])
            self.assertFalse((Path(folder) / "patchwatch-report.json").exists())

    def test_existing_collection_is_preserved_and_services_are_still_uploaded(self):
        self.lookup.side_effect = lambda client, name, version: (
            None if name.endswith("/services") else {"uuid": "p", "collectionLogic": "AGGREGATE_DIRECT_CHILDREN"})
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                env = environment(folder, PATCHWATCH_MODE="parent", PATCHWATCH_SERVICES="api")
                ci.run(env)
                ci.run(env)
            self.assertEqual(upload.call_count, 2)
            for call in upload.call_args_list:
                fields, bom = call.args[2:]
                self.assertEqual(fields["projectName"], "Platform/Web-App/services")
                self.assertEqual(bom["services"][0]["name"], "api")

    def test_legacy_parent_services_are_never_overwritten_by_ci(self):
        self.lookup.return_value = {"uuid": "p"}
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), \
                patch("patchwatch.ci.pipeline.DependencyTrack.all", return_value=[{"name": "legacy"}]), \
                patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
            with self.assertRaisesRegex(RuntimeError, "migrate"):
                ci.run(environment(folder, PATCHWATCH_MODE="parent"))
            upload.assert_not_called()

    def test_service_target_with_packages_is_preserved(self):
        self.lookup.side_effect = [{"uuid": "p", "collectionLogic": "AGGREGATE_DIRECT_CHILDREN"},
                                   {"uuid": "s", "tags": [{"name": "source:gitlab-ci"},
                                                           {"name": "gitlab-project-id:42"}]}]
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), \
                patch("patchwatch.ci.pipeline.DependencyTrack.all", return_value=[{"name": "package"}]), \
                patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
            with self.assertRaisesRegex(RuntimeError, "collision"):
                ci.run(environment(folder, PATCHWATCH_MODE="parent"))
            upload.assert_not_called()

    def test_services_component_name_is_reserved(self):
        with tempfile.TemporaryDirectory() as folder, self.assertRaisesRegex(ValueError, "reserved"):
            ci.run(environment(folder, PATCHWATCH_COMPONENT="services"), dry_run=True)

    def test_parent_dry_run_writes_both_boms(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "bom.json"
            ci.run(environment(folder, PATCHWATCH_MODE="parent", PATCHWATCH_SERVICES="api",
                               PATCHWATCH_SBOM_OUTPUT=str(output)), dry_run=True)
            self.assertNotIn("services", json.loads(output.read_text()))
            self.assertEqual(json.loads(output.with_name("bom-services.json").read_text())["services"][0]["name"], "api")

    def test_parent_lists_services_as_cyclonedx_services(self):
        with tempfile.TemporaryDirectory() as folder:
            env = environment(folder, PATCHWATCH_MODE="parent", PATCHWATCH_SERVICES="api web api")
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                self.assertEqual(ci.run(env), 0)
            self.assertEqual(upload.call_count, 2)
            parent_fields, parent_bom = upload.call_args_list[0].args[2:]
            self.assertNotIn("services", parent_bom)
            self.assertEqual(parent_bom["components"], [])
            fields, bom = upload.call_args.args[2:]
            self.assertEqual((fields["projectName"], fields["parentName"], fields["parentVersion"]),
                             ("Platform/Web-App/services", "Platform/Web-App", "main"))
            self.assertNotIn("patchwatch-role:parent", fields["projectTags"])
            self.assertEqual([s["name"] for s in bom["services"]], ["api", "web"])
            self.assertEqual(bom["components"], [])
            with self.assertRaises(ValueError):
                ci.service_names({"PATCHWATCH_SERVICES": "a,b"})

    def test_parent_detects_compose_services_in_the_workspace(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "compose.yaml").write_text(
                "name: x\nservices:\n  db:\n    image: postgres:17-alpine\n    environment:\n      image: no\n  web:\n    build: .\n")
            env = environment(folder, PATCHWATCH_MODE="parent", PATCHWATCH_SCAN_PATHS=".")
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                self.assertEqual(ci.run(env), 0)
            services = {s["name"]: s for s in upload.call_args.args[3]["services"]}
            self.assertEqual(set(services), {"db", "web"})
            self.assertEqual(services["db"]["version"], "17-alpine")
            self.assertNotIn("version", services["web"])

    def test_components_are_uploaded_below_the_project(self):
        with tempfile.TemporaryDirectory() as folder:
            env = environment(folder, PATCHWATCH_COMPONENT="api")
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), \
                    patch("patchwatch.ci.pipeline.subprocess.run", side_effect=fake_syft), patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                ci.run(env)
            fields = upload.call_args.args[2]
            self.assertEqual((fields["projectName"], fields["parentName"], fields["parentVersion"]),
                             ("Platform/Web-App/api", "Platform/Web-App", "main"))

    def test_missing_parent_gives_an_actionable_message(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "k"}), patch("patchwatch.ci.pipeline.subprocess.run", side_effect=fake_syft), \
                    patch("patchwatch.ci.pipeline.upload_and_wait", side_effect=RuntimeError("Upload failed (HTTP 404)")):
                with self.assertRaisesRegex(RuntimeError, "mode: parent"):
                    ci.run(environment(folder, PATCHWATCH_COMPONENT="api"))

    def test_parent_cannot_be_a_component_and_mode_is_validated(self):
        with tempfile.TemporaryDirectory() as folder:
            for extra in ({"PATCHWATCH_MODE": "parent", "PATCHWATCH_COMPONENT": "x"}, {"PATCHWATCH_MODE": "other"}):
                with self.assertRaises(ValueError):
                    ci.run(environment(folder, **extra), dry_run=True)


class Summary(Isolated):
    class Client:
        def __init__(self, metrics): self.metrics = metrics
        def call(self, path):
            if path.startswith("project/lookup"):
                return {"uuid": "u-1"}
            if isinstance(self.metrics, Exception):
                raise self.metrics
            return self.metrics
        def all(self, path):
            return [{"type": "SECURITY", "policyCondition": {"policy": {"name": "p", "violationState": "FAIL"}}}]

    def test_severity_counts_come_from_project_metrics(self):
        result = ci.summary(self.Client({"critical": 1, "high": 2, "medium": 0, "low": 3, "unassigned": None}), "n", "main", "https://x")
        self.assertEqual(result["findings"], {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 3, "UNASSIGNED": 0})
        self.assertEqual(result["url"], "https://x/projects/u-1")
        self.assertEqual(result["unsuppressedViolations"], [{"type": "SECURITY", "state": "FAIL", "policy": "p", "count": 1}])

    def test_missing_metrics_are_unknown_not_zero(self):
        import urllib.error
        missing = urllib.error.HTTPError("u", 404, "nf", {}, None)
        self.assertIsNone(ci.summary(self.Client(missing), "n", "main", "https://x")["findings"])
        with self.assertRaises(urllib.error.HTTPError):
            ci.summary(self.Client(urllib.error.HTTPError("u", 403, "no", {}, None)), "n", "main", "https://x")


class Upload(Isolated):
    def test_transient_errors_are_retried_and_processing_awaited(self):
        import urllib.error
        from patchwatch.core.sbom import upload_and_wait
        token = str(uuid.uuid4())
        calls = []
        def request(url, data=None, headers=None, method=None):
            calls.append(url)
            if len(calls) == 1:
                raise urllib.error.HTTPError(url, 503, "unavailable", {}, None)
            if method == "POST":
                return {"token": token}, {}
            return {"processing": len(calls) < 4}, {}
        upload_and_wait("https://x", "k", {"projectName": "n"}, {"bomFormat": "CycloneDX"}, request=request, sleep=lambda s: None)
        self.assertEqual(len(calls), 4)

    def test_transient_status_errors_are_retried_and_others_reported_with_code(self):
        import urllib.error
        from patchwatch.core.sbom import upload_and_wait
        token = str(uuid.uuid4())
        calls = []
        def flaky(url, data=None, headers=None, method=None):
            calls.append(url)
            if method == "POST":
                return {"token": token}, {}
            if len(calls) == 2:
                raise urllib.error.HTTPError(url, 502, "bad gateway", {}, None)
            return {"processing": False}, {}
        upload_and_wait("https://x", "k", {}, {}, request=flaky, sleep=lambda s: None)
        self.assertEqual(len(calls), 3)
        def denied(url, data=None, headers=None, method=None):
            if method == "POST":
                return {"token": token}, {}
            raise urllib.error.HTTPError(url, 404, "nf", {}, None)
        with self.assertRaises(RuntimeError) as caught:
            upload_and_wait("https://x", "k", {}, {}, request=denied, sleep=lambda s: None)
        self.assertEqual(str(caught.exception), "Status check failed (HTTP 404)")

    def test_http_error_message_has_no_url_or_body(self):
        import urllib.error
        from patchwatch.core.sbom import upload_and_wait
        def request(url, *a, **k):
            raise urllib.error.HTTPError(url, 403, "secret-body", {}, None)
        with self.assertRaises(RuntimeError) as caught:
            upload_and_wait("https://x", "k", {}, {}, request=request, sleep=lambda s: None)
        self.assertEqual(str(caught.exception), "Upload failed (HTTP 403)")

    def test_http_400_includes_the_servers_reason(self):
        import io, urllib.error
        from patchwatch.core.sbom import upload_and_wait
        def request(url, *a, **k):
            raise urllib.error.HTTPError(url, 400, "bad", {}, io.BytesIO(b'{"detail":"collection project\n"}'))
        with self.assertRaises(RuntimeError) as caught:
            upload_and_wait("https://x", "k", {}, {}, request=request, sleep=lambda s: None)
        self.assertEqual(str(caught.exception), 'Upload failed (HTTP 400): {"detail":"collection project "}')


class DeltaIntegration(Isolated):
    def test_delta_failure_never_fails_the_pipeline(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch("patchwatch.ci.delta.run", side_effect=ValueError("x")), patch("builtins.print") as out:
                result = ci.delta_report(object(), "g/p", "main", "https://pw", {}, Path(folder))
            self.assertIsNone(result)
            self.assertIn("Delta report skipped", out.call_args.args[0])

    def test_delta_result_is_summarised_in_the_report(self):
        fake = {"baseline": {"version": "v1"}, "relevant": True, "notified": ["mail"]}
        with patch("patchwatch.ci.delta.run", return_value=fake) as run:
            result = ci.delta_report(object(), "g/p", "main", "https://pw", {"PATCHWATCH_DELTA_WAIT": "5"}, Path("."))
        self.assertEqual(result, {"baseline": "v1", "relevant": True, "notified": ["mail"]})
        self.assertEqual(run.call_args.args[-1], 5)


class ParentLookup(unittest.TestCase):
    def test_missing_parent_and_lookup_permission_errors(self):
        import urllib.error
        from unittest.mock import Mock
        for code in (404, 403, 401):
            with self.subTest(code=code):
                client = Mock()
                client.call.side_effect = urllib.error.HTTPError("u", code, "error", {}, io.BytesIO())
                if code == 404:
                    self.assertIsNone(ci.lookup_parent(client, "g/app", "main"))
                elif code == 403:
                    with self.assertRaisesRegex(RuntimeError, "VIEW_PORTFOLIO.*setup"):
                        ci.lookup_parent(client, "g/app", "main")
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        ci.lookup_parent(client, "g/app", "main")


if __name__ == "__main__":
    unittest.main()
