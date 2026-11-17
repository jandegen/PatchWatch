# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent


def third_party_images():
    text = (ROOT / "ci/components.yml").read_text()
    return {m for m in re.findall(r"^\s+images: (\S+)$", text, re.M) if "$" not in m}


class Components(unittest.TestCase):
    def test_scanned_third_party_images_match_compose(self):
        compose = {m for m in re.findall(r"^\s+image: ['\"]?([^\s'\"$]+)", (ROOT / "compose.yaml").read_text(), re.M)
                   if "patchwatch" not in m}
        self.assertEqual(third_party_images(), compose,
                         "ci/components.yml and compose.yaml must list the same third-party images")

    def test_dtrack_chart_tag_matches_scanned_images(self):
        tags = set(re.findall(r"^\s+tag: ['\"]?([0-9][^\s'\"]*)", (ROOT / "deploy/environments/dtrack.yaml").read_text(), re.M))
        self.assertEqual(len(tags), 1, "API server and frontend must use the same tag")
        tag = tags.pop()
        for image in third_party_images():
            if "/dependencytrack/" in image:
                self.assertTrue(image.endswith(":" + tag), f"{image} differs from chart tag {tag}")

    def test_every_component_has_a_unique_job_and_project(self):
        text = (ROOT / "ci/components.yml").read_text()
        for key in ("job_name", "component"):
            values = re.findall(rf"^\s+{key}: (\S+)$", text, re.M)
            self.assertTrue(values)
            self.assertEqual(len(values), len(set(values)), key + " must be unique")

    def test_mr_scans_cover_the_same_images_as_release_scans(self):
        from patchwatch.core.services import compose_services
        release = dict(re.findall(
            r"      job_name: sbom-([^\n]+)\n(?:(?!  - local:).)*?      images: ([^\n]+)",
            (ROOT / "ci/components.yml").read_text(), re.S))
        scans = (ROOT / "ci/mr-components.yml").read_text()
        selectors = dict(re.findall(
            r"      job_name: mr-sbom-([^\n]+)\n(?:(?!  - local:).)*?      compose_images: ([^\n]+)", scans, re.S))
        actual = {}
        for component, selector in selectors.items():
            filename, service = selector.rsplit(":", 1)
            actual[component] = dict(compose_services((ROOT / filename).read_text()))[service]
        self.assertEqual(actual, {c: image for c, image in release.items() if "$" not in image})
        builds = dict(re.findall(
            r"      job_name: mr-sbom-([^\n]+)\n(?:(?!  - local:).)*?      dockerfiles: ([^\n]+)", scans, re.S))
        self.assertEqual(set(builds), {c for c, image in release.items() if "$" in image})
        self.assertTrue(all((ROOT / filename).is_file() for filename in builds.values()))

    def test_worker_matches_every_mr_producer(self):
        producers = re.findall(r"      job_name: (mr-sbom-[^\n]+)",
                               (ROOT / "ci/mr-components.yml").read_text())
        worker = (ROOT / "ci/mr-feedback.yml").read_text()
        consumers = re.findall(r"      scan_job: ([^\n]+)", worker)
        self.assertCountEqual(producers, consumers)
        components = re.findall(r"      component: ([^\n]+)", worker)
        self.assertCountEqual(consumers, ["mr-sbom-" + c for c in components])
        self.assertEqual(len(set(components)), len(components))
        self.assertIn("local: ci/mr-feedback.yml", (ROOT / ".gitlab-ci.yml").read_text())
        self.assertEqual(worker.count("image: $[[ inputs.image ]]"), len(consumers))

    def test_worker_requires_protected_default_branch_and_explicit_feedback_run(self):
        worker = (ROOT / "ci-templates/mr-feedback.yml").read_text()
        rules = re.findall(r"    - if: '([^'\n]+)'", worker)
        self.assertEqual(len(rules), 2)
        for rule in rules:
            self.assertIn('$CI_COMMIT_REF_PROTECTED == "true"', rule)
            self.assertIn('$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH', rule)
            self.assertIn('$PATCHWATCH_MR_FEEDBACK == "true"', rule)
            self.assertNotIn('merge_request_event', rule)
        self.assertIn('GIT_STRATEGY: empty', worker)

    def test_agent_is_not_a_separate_inventory(self):
        # stdlib only: nothing to inventory; see docs/usage/ci-integration.md
        self.assertNotIn("component: agent", (ROOT / "ci/components.yml").read_text())


if __name__ == "__main__":
    unittest.main()
