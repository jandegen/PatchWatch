# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from patchwatch.ci import pipeline as ci, bsi as ci_sbom, mr


CREATOR = {"url": ["https://producer.example.org"]}
LICENSES = [{"expression": "MIT", "acknowledgement": "concluded"}]
SHA = "a" * 40


def package(ref="pkg", **extra):
    return {"type": "library", "name": "demo", "version": "1.0", "bom-ref": ref,
            "purl": "pkg:npm/demo@1.0", "manufacturer": deepcopy(CREATOR),
            "licenses": deepcopy(LICENSES), **extra}


def source():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"component": package("source", name="source", type="application")},
            "components": [package()],
            "dependencies": [{"ref": "source", "dependsOn": ["pkg"]}, {"ref": "pkg", "dependsOn": []}],
            "compositions": [{"aggregate": "complete", "dependencies": ["source", "pkg"]}]}


def environment(workspace, **extra):
    return {"CI_PROJECT_DIR": str(workspace), "CI_PROJECT_PATH": "team/app", "CI_PROJECT_ID": "42",
            "CI_PROJECT_ROOT_NAMESPACE": "team", "CI_COMMIT_SHA": SHA, "CI_COMMIT_BRANCH": "main",
            "CI_DEFAULT_BRANCH": "main", "CI_PROJECT_URL": "https://git.example.org/team/app",
            "PATCHWATCH_DISTRIBUTION_LICENSE": "MIT", "PATCHWATCH_URL": "https://patchwatch.example.org", **extra}


def assembled():
    bom = ci_sbom.assemble([source()], "team/app", SHA)
    ci.provenance(bom, {})
    ci_sbom.enrich(bom, environment(Path(".")), Path(".").resolve())
    return bom


class Assembly(unittest.TestCase):
    def test_source_root_leaves_nested_components_and_completeness_survive(self):
        raw = source()
        raw["components"][0]["components"] = [package("nested", name="nested")]
        raw["dependencies"].append({"ref": "nested", "dependsOn": []})
        raw["compositions"][0]["dependencies"].append("nested")
        before = deepcopy(raw)
        bom = ci_sbom.assemble([raw], "project", SHA)
        self.assertEqual(raw, before)
        by_name = {c["name"]: c["bom-ref"] for c in bom["components"]}
        root = bom["metadata"]["component"]["bom-ref"]
        graph = {d["ref"]: set(d["dependsOn"]) for d in bom["dependencies"]}
        self.assertEqual(graph[root], {by_name["source"]})
        self.assertEqual(graph[by_name["source"]], {by_name["demo"]})
        self.assertEqual(graph[by_name["demo"]], {by_name["nested"]})
        self.assertEqual(graph[by_name["nested"]], set())
        self.assertEqual(bom["compositions"][0]["aggregate"], "complete")
        self.assertEqual(set(bom["compositions"][0]["dependencies"]), set(by_name.values()))

    def test_distinct_instances_and_colliding_refs_in_different_scans_are_retained(self):
        first, second = source(), source()
        second["components"][0]["manufacturer"] = {"url": ["https://other.example.org"]}
        second["components"][0]["hashes"] = [{"alg": "SHA-512", "content": "b" * 128}]
        bom = ci_sbom.assemble([first, second], "project", SHA)
        self.assertEqual(len(bom["components"]), 4)
        self.assertEqual(len({c["bom-ref"] for c in bom["components"]}), 4)
        first_refs = {c["bom-ref"] for c in bom["components"][:2]}
        second_refs = {c["bom-ref"] for c in bom["components"][2:]}
        self.assertTrue(first_refs.isdisjoint(second_refs))

    def test_unknown_dependencies_are_not_reported_as_known_leaves(self):
        bom = ci_sbom.assemble([{"components": [package()]}], "project", SHA)
        ref = bom["components"][0]["bom-ref"]
        self.assertFalse(any(d["ref"] == ref for d in bom["dependencies"]))
        self.assertTrue(any(c["aggregate"] == "unknown" and ref in c["dependencies"] for c in bom["compositions"]))

    def test_physical_data_is_preserved_and_sensitive_scanner_data_is_excluded(self):
        file = package(type="file", hashes=[{"alg": "SHA-512", "content": "a" * 128}],
                       externalReferences=[{"type": "distribution", "url": "https://example.org/demo"}],
                       properties=[{"name": "bsi:component:filename", "value": "demo.py"},
                                   {"name": "syft:metadata:environment", "value": "SECRET"}],
                       description="SECRET", evidence={"identity": {"field": "name"}})
        bom = ci_sbom.assemble([{"components": [file], "vulnerabilities": [{"id": "CVE-example"}]}], "project", SHA)
        item = bom["components"][0]
        self.assertEqual(item["hashes"], file["hashes"])
        self.assertEqual(item["manufacturer"], file["manufacturer"])
        self.assertEqual(item["externalReferences"], file["externalReferences"])
        self.assertEqual(item["properties"][0]["value"], "demo.py")
        self.assertNotIn("SECRET", json.dumps(bom))
        self.assertNotIn("vulnerabilities", bom)

    def test_duplicate_and_unresolved_source_refs_are_rejected(self):
        raw = source()
        raw["components"].append(package())
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ci_sbom.assemble([raw], "project", SHA)
        raw = source()
        raw["dependencies"][0]["dependsOn"].append("missing")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            ci_sbom.assemble([raw], "project", SHA)

    def test_auxiliary_refs_and_additional_identifiers_survive_multiple_sources(self):
        raw = source()
        raw["components"][0]["manufacturer"]["bom-ref"] = "organization"
        raw["components"][0]["swhid"] = ["swh:1:dir:" + "a" * 40]
        bom = ci_sbom.assemble([raw, deepcopy(raw)], "project", SHA)
        ci.provenance(bom, {})
        ci_sbom.enrich(bom, environment(Path(".")), Path(".").resolve())
        self.assertEqual(ci_sbom.findings(bom), [])
        first, second = bom["components"][1], bom["components"][3]
        self.assertNotEqual(first["manufacturer"]["bom-ref"], second["manufacturer"]["bom-ref"])
        self.assertEqual(first["swhid"], raw["components"][0]["swhid"])


class Validation(unittest.TestCase):
    def test_valid_logical_bom_passes_with_offline_schema_validation(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            self.assertEqual(ci_sbom.findings(assembled()), [])

    def test_document_and_primary_component_are_checked(self):
        bom = assembled()
        del bom["metadata"]["timestamp"]
        del bom["metadata"]["manufacturer"]
        root = bom["metadata"]["component"]
        del root["manufacturer"]
        del root["licenses"]
        root["version"] = ""
        messages = " ".join(i["message"] for i in ci_sbom.findings(bom))
        for word in ("SBOM creator", "timestamp", "Component creator", "version", "distribution licences"):
            self.assertIn(word, messages)

    def test_declared_licence_is_not_promoted_to_distribution_licence(self):
        bom = assembled()
        bom["components"][0]["licenses"][0]["acknowledgement"] = "declared"
        self.assertTrue(any("distribution licences" in f["message"] for f in ci_sbom.findings(bom)))

    def test_licence_identifiers_expressions_and_exceptions(self):
        for expression in ("MIT", "Apache-2.0 AND (MIT OR BSD-3-Clause)",
                           "GPL-2.0-only WITH Classpath-exception-2.0", "LicenseRef-scancode-proprietary"):
            with self.subTest(expression=expression):
                self.assertTrue(ci_sbom.valid_expression(expression))
        for expression in ("MIT OR", "MIT BSD-3-Clause", "(MIT", "MIT AND ()", "Unknown-License",
                           "MIT WITH not-an-exception", "MIT AND OR BSD-3-Clause", "MIT; rm -rf /", ""):
            with self.subTest(expression=expression):
                self.assertFalse(ci_sbom.valid_expression(expression))

    def test_schema_errors_completeness_and_dangling_refs(self):
        bom = assembled()
        bom["components"][0]["manufacturer"] = []
        self.assertTrue(all(f["rule"] == "4" for f in ci_sbom.findings(bom)))
        bom = assembled()
        bom["compositions"] = []
        bom["dependencies"][0]["dependsOn"].append("missing")
        messages = " ".join(i["message"] for i in ci_sbom.findings(bom))
        self.assertIn("completeness", messages)
        self.assertIn("Unresolved", messages)

    def test_physical_fields_and_sha512_are_required(self):
        bom = assembled()
        file = bom["components"][1]
        file["type"] = "file"
        file["hashes"] = [{"alg": "SHA-256", "content": "a" * 64}]
        self.assertEqual(len(ci_sbom.findings(bom)), 5)  # filename, three flags, SHA-512
        file["properties"] = [{"name": "bsi:component:filename", "value": "demo.py"}] + [
            {"name": "bsi:component:" + key, "value": value} for key, value in
            (("executable", "executable"), ("archive", "no archive"), ("structured", "unstructured"))]
        file["externalReferences"] = [{"type": "distribution", "url": "https://example.org/demo.py",
                                       "hashes": [{"alg": "SHA-512", "content": "b" * 128}]}]
        self.assertEqual(ci_sbom.findings(bom), [])
        file["properties"].append({"name": "bsi:component:archive", "value": "no archive"})
        self.assertTrue(any("archive" in f["message"] for f in ci_sbom.findings(bom)))

    def test_first_external_dependency_needs_identification_not_distribution_fields(self):
        bom = assembled()
        item = bom["components"][1]
        del item["licenses"]
        item["properties"] = [{"name": "patchwatch:bsi:scope", "value": "identified"}]
        self.assertEqual(ci_sbom.findings(bom), [])
        del item["manufacturer"]
        self.assertTrue(any("creator" in f["message"] for f in ci_sbom.findings(bom)))


class Enrichment(unittest.TestCase):
    def test_artifact_hash_mtime_flags_and_original_licences(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            artifact = root / "demo.py"
            artifact.write_bytes(b"print('example')\n")
            os.utime(artifact, (1700000000, 1700000000))
            bom = assembled()
            file = bom["components"][1]
            file["type"] = "file"
            del file["version"]
            file["licenses"] = [{"expression": "MIT", "acknowledgement": "declared"}]
            config = {"components": {file["bom-ref"]: {
                "artifact": "demo.py", "licenses": LICENSES,
                "externalReferences": [{"type": "distribution", "url": "https://example.org/demo.py"}],
                "properties": [{"name": "bsi:component:" + key, "value": value} for key, value in
                               (("executable", "executable"), ("archive", "no archive"), ("structured", "unstructured"))]}}}
            (root / "metadata.json").write_text(json.dumps(config))
            ci_sbom.enrich(bom, {"PATCHWATCH_BSI_METADATA": "metadata.json"}, root)
            digest = hashlib.sha512(artifact.read_bytes()).hexdigest()
            self.assertEqual(file["hashes"], [{"alg": "SHA-512", "content": digest}])
            self.assertEqual(file["externalReferences"][0]["hashes"][0]["content"], digest)
            self.assertEqual(file["version"], "2023-11-14T22:13:20+00:00")
            self.assertTrue(any(p["name"] == "patchwatch:bsi:original-licenses" for p in file["properties"]))
            self.assertEqual(ci_sbom.findings(bom), [])

    def test_enrichment_cannot_escape_checkout_or_silently_ignore_selectors(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory).resolve()
            secret = Path(outside) / "secret"
            secret.write_text("secret")
            (root / "link").symlink_to(secret)
            for filename in (str(secret), "link"):
                with self.assertRaisesRegex(ValueError, "inside CI_PROJECT_DIR"):
                    ci_sbom.enrich(assembled(), {"PATCHWATCH_BSI_METADATA": filename}, root)
            (root / "metadata.json").write_text(json.dumps({"components": {"pkg:npm/missing@1": {"version": "1"}}}))
            with self.assertRaisesRegex(ValueError, "does not match"):
                ci_sbom.enrich(assembled(), {"PATCHWATCH_BSI_METADATA": "metadata.json"}, root)

    def test_creators_are_not_inferred_from_supplier(self):
        bom = assembled()
        item = bom["components"][1]
        del item["manufacturer"]
        item["supplier"] = CREATOR
        ci_sbom.enrich(bom, {"CI_PROJECT_URL": "https://example.org"}, Path(".").resolve())
        self.assertNotIn("manufacturer", item)
        self.assertTrue(any("creator" in f["message"] for f in ci_sbom.findings(bom)))

    def test_explicit_author_contact_is_mapped_as_creator(self):
        raw = package()
        del raw["manufacturer"]
        raw["authors"] = [{"name": "Creator", "email": "creator@example.org"}]
        result = ci_sbom.assemble([{"components": [raw]}], "project", SHA)
        self.assertEqual(result["components"][0]["manufacturer"]["contact"], raw["authors"])

    def test_file_timestamp_never_reads_host_paths_for_container_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            file = root / "local"
            file.write_text("host content")
            bom = {"components": [{"type": "file", "name": "/local"}]}
            ci_sbom.file_metadata(bom, root)
            self.assertNotIn("version", bom["components"][0])
            ci_sbom.file_metadata(bom, root, root)
            self.assertIn("version", bom["components"][0])


class Pipeline(unittest.TestCase):
    def test_upload_is_blocked_before_network_and_diagnostics_are_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "key"}), \
                    patch("patchwatch.ci.pipeline.scan", return_value=[{"components": [package(manufacturer={})]}]), \
                    patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                with self.assertRaisesRegex(ValueError, "upload refused"):
                    ci.run(environment(root))
            upload.assert_not_called()
            report = json.loads((root / "patchwatch-bsi-report.json").read_text())
            self.assertFalse(report["checksPassed"])
            self.assertEqual(report["mode"], "enforce")
            self.assertTrue((root / "patchwatch-sbom.json").exists())

    def test_complete_logical_inventory_uploads_exact_saved_document(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {"PATCHWATCH_UPLOAD_KEY": "key"}, clear=True), \
                    patch("patchwatch.ci.pipeline.scan", return_value=[source()]), \
                    patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                self.assertEqual(ci.run(environment(root)), 0)
            uploaded = upload.call_args.args[3]
            self.assertEqual(uploaded, json.loads((root / "patchwatch-sbom.json").read_text()))
            self.assertTrue(uploaded["metadata"]["component"]["version"].startswith(SHA + "."))
            self.assertEqual(upload.call_args.args[2]["projectVersion"], "main")
            self.assertTrue(json.loads((root / "patchwatch-bsi-report.json").read_text())["checksPassed"])

    def test_inventory_change_changes_snapshot_even_for_unchanged_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            versions = []
            for version in ("1", "2"):
                raw = source()
                raw["components"][0]["version"] = version
                with patch("patchwatch.ci.pipeline.scan", return_value=[raw]):
                    ci.run(environment(root), dry_run=True)
                versions.append(json.loads((root / "patchwatch-sbom.json").read_text())["metadata"]["component"]["version"])
            self.assertNotEqual(*versions)

    def test_explicit_report_mode_allows_inventory_but_never_malformed_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bom = assembled()
            del bom["metadata"]["manufacturer"]
            self.assertTrue(ci_sbom.check_and_write(bom, {"PATCHWATCH_BSI_MODE": "report"}, root))
            bom["components"][0]["manufacturer"] = []
            with self.assertRaisesRegex(ValueError, "upload refused"):
                ci_sbom.check_and_write(bom, {"PATCHWATCH_BSI_MODE": "report"}, root)

    def test_dry_run_uses_same_gate_without_upload_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("patchwatch.ci.pipeline.scan", return_value=[{"components": [package(licenses=[])]}]), \
                    patch("patchwatch.ci.pipeline.upload_and_wait") as upload:
                with self.assertRaisesRegex(ValueError, "upload refused"):
                    ci.run(environment(Path(directory)), dry_run=True)
                upload.assert_not_called()

    def test_mr_worker_rechecks_untrusted_producer_artifacts(self):
        from test_mr import FakeGitLab, FakeDTrack
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            worker = mr.Worker(FakeGitLab(), FakeDTrack(), "https://dt.example.org", "key", 123, "scan", output=Path(directory))
            with patch("patchwatch.ci.mr.upload_and_wait") as upload:
                with self.assertRaisesRegex(ValueError, "upload refused"):
                    worker.upload_version(source(), "mr-42", "source:gitlab-mr", SHA, "test")
                upload.assert_not_called()

    def test_mr_worker_preserves_complete_producer_metadata(self):
        from test_mr import FakeGitLab, FakeDTrack
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"PATCHWATCH_DISTRIBUTION_LICENSE": "MIT"}, clear=True):
            dt = FakeDTrack()
            worker = mr.Worker(FakeGitLab(), dt, "https://dt.example.org", "key", 123, "scan", output=Path(directory))
            with patch("patchwatch.ci.mr.upload_and_wait", side_effect=dt.register) as upload:
                worker.upload_version(assembled(), "mr-42", "source:gitlab-mr", SHA, "test")
            uploaded = upload.call_args.args[3]
            self.assertEqual(ci_sbom.findings(uploaded), [])
            self.assertEqual(uploaded["metadata"]["component"]["version"], SHA)
            self.assertEqual(uploaded["components"][2]["manufacturer"], CREATOR)


if __name__ == "__main__":
    unittest.main()
