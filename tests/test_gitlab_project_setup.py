# SPDX-License-Identifier: Apache-2.0
"""scripts/setup-gitlab-project.sh against a fake curl that simulates GitLab and PatchWatch."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

try:
    import yaml  # optional: extra validation when PyYAML is installed (Alpine: py3-yaml)
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "setup-gitlab-project.sh"
FAKE = ROOT / "tests" / "fake_gitlab_curl.py"
spec = importlib.util.spec_from_file_location("packaging_build", ROOT / "packaging" / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)

GITLAB = "https://gitlab.example.com"
RELEASE = "https://example.test/rel"
IMAGE = "ghcr.io/acme/patchwatch/ci:v9.9.9"
TOKEN, UPLOAD, READ = "glpat-SECRETTOKEN", "UPLOADSECRET99", "READSECRET99"
SECRETS = (TOKEN, UPLOAD, READ)
BASE_ARGS = ["--gitlab-url", GITLAB, "--project", "acme/shop", "--patchwatch-url", "https://patchwatch.example.org",
             "--release-url", RELEASE]
AUTOMATIC = BASE_ARGS + ["--yes"]
INCLUDE = "  - local: .gitlab/patchwatch/patchwatch.yml"


def parse_generated(text):
    """The restricted YAML the script generates: ``include`` entries with ``local`` and flat ``inputs``."""
    entries, inputs = [], None
    for line in text.splitlines():
        if not line.strip() or line.startswith("#") or line == "include:":
            continue
        if line.startswith("  - local: "):
            inputs = {}
            entries.append({"local": line[len("  - local: "):], "inputs": inputs})
        elif line == "    inputs:":
            continue
        elif line.startswith("      "):
            key, _, value = line.strip().partition(": ")
            if value.startswith("'"):
                value = value[1:-1].replace("''", "'")
            else:
                value = {"true": True, "false": False}.get(value, value)
            inputs[key] = value
        else:
            raise AssertionError("unexpected line in generated YAML: " + line)
    return {"include": entries}


def check_yaml(text):
    if yaml is not None:
        return yaml.safe_load(text)


class Result:
    def __init__(self, process, world):
        self.code, self.out, self.err = process.returncode, process.stdout, process.stderr
        self.world = world

    @property
    def text(self):
        return self.out + self.err


class World:
    def __init__(self, test):
        self.dir = Path(tempfile.mkdtemp())
        test.addCleanup(shutil.rmtree, self.dir, True)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        curl = self.bin / "curl"
        curl.write_text(f"#!{sys.executable}\n" + FAKE.read_text())
        curl.chmod(curl.stat().st_mode | stat.S_IEXEC)
        self.state_path = self.dir / "state.json"
        archive = build.build_templates(self.dir / build.TEMPLATES_NAME, IMAGE)
        self.archive = archive
        sums = self.dir / "SHA256SUMS"
        sums.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {build.TEMPLATES_NAME}\n")
        self.state = {
            "gitlab_token": TOKEN, "version": "17.5.1", "protected": True,
            "project": {"id": 42, "path_with_namespace": "acme/shop", "web_url": GITLAB + "/acme/shop",
                        "default_branch": "main", "visibility": "private",
                        "permissions": {"project_access": {"access_level": 40}, "group_access": None}},
            "tree": ["README.md", "package.json", "Dockerfile"], "files": {}, "branches": {}, "variables": [],
            "patchwatch_keys": {UPLOAD: 200, READ: 200, "BADKEY": 401},
            "downloads": {f"{RELEASE}/{build.TEMPLATES_NAME}": str(archive), f"{RELEASE}/SHA256SUMS": str(sums)},
        }
        self.sums = sums

    def run(self, args, stdin="", env=None, path=None, shell="sh", token=TOKEN, upload=UPLOAD, read=None):
        self.state_path.write_text(json.dumps(self.state))
        (self.dir / "state.json.calls").write_text("")
        environment = {"PATH": path or f"{self.bin}:{os.environ['PATH']}", "FAKE_STATE": str(self.state_path),
                       "HOME": str(self.dir), "TMPDIR": str(self.dir)}
        if token:
            environment["GITLAB_TOKEN"] = token
        if upload:
            environment["PATCHWATCH_UPLOAD_KEY"] = upload
        if read:
            environment["PATCHWATCH_READ_KEY"] = read
        environment.update(env or {})
        shell = shell.split()
        shell[0] = shutil.which(shell[0])
        process = subprocess.run(shell + [str(SCRIPT)] + args, input=stdin, capture_output=True, text=True,
                                 env=environment, timeout=60)
        self.state = json.loads(self.state_path.read_text())
        return Result(process, self)

    @property
    def calls(self):
        return [json.loads(line) for line in (self.dir / "state.json.calls").read_text().splitlines()]

    def writes(self):
        return [c for c in self.calls if c["method"] != "GET" and c["url"].startswith(GITLAB)]

    def committed(self):
        commits = self.state.get("commits", [])
        return {a["file_path"]: a for c in commits for a in c["actions"]}

    def config(self):
        content = self.committed()[".gitlab/patchwatch/patchwatch.yml"]["content"]
        check_yaml(content)
        return parse_generated(content)

    def variable(self, key):
        return next((v for v in self.state["variables"] if v["key"] == key), None)


class Base(unittest.TestCase):
    def setUp(self):
        self.world = World(self)

    def assertNoSecrets(self, result):
        for secret in SECRETS:
            self.assertNotIn(secret, result.text)
            for call in self.world.calls:
                self.assertNotIn(secret, json.dumps(call["argv"]), "secret on a command line")

    def assertUntouched(self):
        self.assertEqual(self.world.writes(), [], "no write must have reached GitLab")


class Prerequisites(Base):
    def test_missing_jq_stops_before_any_request(self):
        restricted = self.world.dir / "restricted"
        restricted.mkdir()
        for tool in ("curl", "tar", "awk", "sed", "grep", "sha256sum", "tr", "cat", "mktemp", "rm", "date", "wc",
                     "sort", "head", "tail", "basename", "cp", "mv", "cmp", "diff", "stty", "uname", "id"):
            found = shutil.which(tool, path=f"{self.world.bin}:{os.environ['PATH']}")
            if found:
                (restricted / tool).symlink_to(found)
        result = self.world.run(AUTOMATIC, path=str(restricted))
        self.assertEqual(result.code, 1)
        self.assertIn("'jq' is missing", result.err)
        self.assertIn("sudo apt install", result.err)
        self.assertIn("brew install", result.err)
        self.assertIn("Nothing has been changed", result.err)
        self.assertEqual(self.world.calls, [])

    def test_help_and_unknown_option(self):
        self.assertIn("Usage:", self.world.run(["--help"]).out)
        result = self.world.run(["--bogus"])
        self.assertEqual(result.code, 2)
        self.assertIn("unknown option", result.err)

    def test_http_gitlab_url_is_refused(self):
        result = self.world.run(["--gitlab-url", "http://gitlab.example.com", "--project", "a/b", "--yes"])
        self.assertEqual(result.code, 1)
        self.assertIn("must start with https://", result.err)

    def test_no_token_without_terminal_is_an_error(self):
        result = self.world.run(AUTOMATIC, token=None)
        self.assertEqual(result.code, 1)
        self.assertIn("GITLAB_TOKEN is not set", result.err)
        self.assertUntouched()


class SingleInventory(Base):
    def test_happy_path_creates_variables_commit_and_merge_request(self):
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 0, result.text)
        self.assertNoSecrets(result)
        # variables
        url, key = self.world.variable("PATCHWATCH_URL"), self.world.variable("PATCHWATCH_UPLOAD_KEY")
        self.assertEqual(url["value"], "https://patchwatch.example.org")
        self.assertFalse(url["protected"] or url["masked"])
        self.assertEqual((key["value"], key["protected"], key["masked"]), (UPLOAD, True, True))
        self.assertIsNone(self.world.variable("PATCHWATCH_READ_KEY"))
        # commit
        files = self.world.committed()
        self.assertEqual(set(files), {".gitlab/patchwatch/sbom.yml", ".gitlab/patchwatch/patchwatch.yml", ".gitlab-ci.yml"})
        self.assertEqual({f["action"] for f in files.values()}, {"create"})
        self.assertEqual(files[".gitlab/patchwatch/sbom.yml"]["content"], (ROOT / "ci-templates/sbom.yml").read_text())
        self.assertEqual(files[".gitlab-ci.yml"]["content"], f"include:\n{INCLUDE}\n")
        self.assertEqual(self.world.state["commits"][0]["start_branch"], "main")
        self.assertEqual(self.world.state["commits"][0]["branch"], "patchwatch/setup")
        # generated configuration
        include = self.world.config()["include"]
        self.assertEqual(len(include), 1)
        inputs = include[0]["inputs"]
        self.assertEqual(include[0]["local"], ".gitlab/patchwatch/sbom.yml")
        self.assertEqual((inputs["stage"], inputs["image"], inputs["bsi_mode"], inputs["detect_services"]),
                         ("test", IMAGE, "report", True))
        self.assertNotIn("component", inputs)
        # merge request and summary
        self.assertEqual(self.world.state["merge_requests"][0]["target_branch"], "main")
        self.assertIn("/-/merge_requests/1", result.out)
        for heading in ("What the script did", "What you need to do now", "If something goes wrong"):
            self.assertIn(heading, result.out)
        self.assertIn("Review and merge the merge request", result.out)
        self.assertIn("acme/shop", result.out)
        for number in range(1, 9):
            self.assertIn(f"[{number}/8]", result.out)

    def test_read_key_adds_variable_and_fail_on(self):
        result = self.world.run(AUTOMATIC + ["--fail-on", "warn"], read=READ)
        self.assertEqual(result.code, 0, result.text)
        self.assertNoSecrets(result)
        self.assertEqual(self.world.variable("PATCHWATCH_READ_KEY")["masked"], True)
        self.assertEqual(self.world.config()["include"][0]["inputs"]["fail_on"], "warn")

    def test_fail_on_without_read_key_is_refused(self):
        result = self.world.run(AUTOMATIC + ["--fail-on", "fail"])
        self.assertEqual(result.code, 1)
        self.assertIn("needs a read key", result.err)
        self.assertUntouched()

    def test_scan_images_services_branches_and_team(self):
        result = self.world.run(AUTOMATIC + [
            "--scan-image", "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA", "--service", "api", "--service", "worker",
            "--team", "platform", "--environment", "production", "--branch", "release", "--image-stage", "scan",
            "--bsi-mode", "enforce", "--no-detect-services"])
        self.assertEqual(result.code, 0, result.text)
        inputs = self.world.config()["include"][0]["inputs"]
        self.assertEqual(inputs["images"], "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA")
        self.assertEqual((inputs["services"], inputs["team"], inputs["environment"]), ("api worker", "platform", "production"))
        self.assertEqual((inputs["stage"], inputs["bsi_mode"], inputs["detect_services"]), ("scan", "enforce", False))
        self.assertEqual(inputs["branches"], "release")
        self.assertIn('$CI_COMMIT_BRANCH == "release"', inputs["run_if"])

    def test_invalid_values_are_rejected(self):
        for args, message in ((["--team", "Bad Team"], "Invalid team"), (["--service", "a;c"], "Invalid service"),
                              (["--bsi-mode", "strict"], "BSI mode must be"), (["--branch", "x;y"], "Invalid branch"),
                              (["--scan-image", "x'y"], "Invalid image")):
            with self.subTest(args=args):
                result = self.world.run(AUTOMATIC + args)
                self.assertEqual(result.code, 1)
                self.assertIn(message, result.err)
                self.assertUntouched()

    def test_values_with_blanks_are_refused_instead_of_split(self):
        for option in ("--branch", "--service", "--scan-image", "--component"):
            with self.subTest(option=option):
                result = self.world.run(AUTOMATIC + [option, "x y"])
                self.assertEqual(result.code, 2)
                self.assertIn("without blanks", result.err)
                self.assertEqual(self.world.calls, [])

    def test_posix_shells(self):
        for shell in ("dash", "busybox sh", "bash"):
            if not shutil.which(shell.split()[0]):
                continue
            with self.subTest(shell=shell):
                world = World(self)
                result = world.run(AUTOMATIC, shell=shell)
                self.assertEqual(result.code, 0, result.text)
                self.assertEqual(len(world.state["merge_requests"]), 1)


class Components(Base):
    def test_components_generate_parent_and_one_job_each(self):
        result = self.world.run(AUTOMATIC + ["--component", "api=services/api", "--component", "web=web",
                                             "--service", "db"])
        self.assertEqual(result.code, 0, result.text)
        include = self.world.config()["include"]
        jobs = {i["inputs"]["job_name"]: i["inputs"] for i in include}
        self.assertEqual(set(jobs), {"patchwatch-sbom-parent", "patchwatch-sbom-api", "patchwatch-sbom-web"})
        self.assertEqual(include[0]["inputs"]["job_name"], "patchwatch-sbom-parent")
        parent = jobs["patchwatch-sbom-parent"]
        self.assertEqual((parent["mode"], parent["stage"], parent["services"]), ("parent", ".pre", "db"))
        api = jobs["patchwatch-sbom-api"]
        self.assertEqual((api["component"], api["scan_paths"], api["stage"], api["detect_services"]),
                         ("api", "services/api", "test", False))
        for path in ("acme/shop/api", "acme/shop/web", "acme/shop (parent)"):
            self.assertIn(path, result.out)

    def test_reserved_and_invalid_component_names(self):
        for value, message in (("services=svc", "reserved"), ("Bad=x", "Invalid component name"), ("noequals", "NAME=PATH"),
                               ("a=../x", "Invalid component path"), ("a=x", None)):
            with self.subTest(value=value):
                result = self.world.run(AUTOMATIC + ["--component", value])
                if message:
                    self.assertEqual(result.code, 1)
                    self.assertIn(message, result.err)
                    self.assertUntouched()
                else:
                    self.assertEqual(result.code, 0, result.text)

    def test_duplicate_component_names(self):
        result = self.world.run(AUTOMATIC + ["--component", "a=x", "--component", "a=y"])
        self.assertEqual(result.code, 1)
        self.assertIn("given twice", result.err)

    def test_component_with_image_uses_image_stage(self):
        result = self.world.run(AUTOMATIC + ["--component", "api=api", "--image-stage", "scan"])
        self.assertEqual(result.code, 0, result.text)
        jobs = {i["inputs"]["job_name"]: i["inputs"] for i in self.world.config()["include"]}
        self.assertEqual(jobs["patchwatch-sbom-api"]["stage"], "test")  # no image configured, so no image stage

    def test_interactive_discovery_of_components(self):
        self.world.state["tree"] = ["services/api/package.json", "services/web/package.json", "docs/readme.md",
                                    "node_modules/x/package.json"]
        answers = ["",            # read key
                   "2",           # structure: components
                   "y", "",       # services/api accepted, default name api
                   "y", "worker", # services/web accepted, renamed
                   "",            # no manual component
                   "", "", "", "", "", "",  # service names, team, environment, bsi mode, branches, stage
                   "", "", ""]    # continue, variables, commit
        result = self.world.run(BASE_ARGS, stdin="\n".join(answers) + "\n")
        self.assertEqual(result.code, 0, result.text)
        self.assertIn("2 candidate component folder(s)", result.out)
        jobs = {i["inputs"]["job_name"] for i in self.world.config()["include"]}
        self.assertEqual(jobs, {"patchwatch-sbom-parent", "patchwatch-sbom-api", "patchwatch-sbom-worker"})

    def test_interactive_rejects_reserved_name_and_asks_again(self):
        self.world.state["tree"] = ["a/package.json", "b/package.json"]
        answers = ["", "2", "y", "services", "x", "n", "", "", "", "", "", "", "", "", "", ""]
        result = self.world.run(BASE_ARGS, stdin="\n".join(answers) + "\n")
        self.assertEqual(result.code, 0, result.text)
        self.assertIn('"services" is reserved', result.out)
        jobs = {i["inputs"]["job_name"] for i in self.world.config()["include"]}
        self.assertEqual(jobs, {"patchwatch-sbom-parent", "patchwatch-sbom-x"})


class Interactive(Base):
    def test_all_defaults_by_pressing_enter(self):
        result = self.world.run(BASE_ARGS, stdin="\n" * 20)
        self.assertEqual(result.code, 0, result.text)
        self.assertEqual(len(self.world.state["merge_requests"]), 1)
        self.assertIn("What happens now:", result.out)
        self.assertIn("Continue with this configuration? [Y/n]", result.out)
        self.assertNoSecrets(result)

    def test_secrets_are_asked_for_when_missing(self):
        result = self.world.run(BASE_ARGS, stdin=f"{TOKEN}\n{UPLOAD}\n" + "\n" * 20, token=None, upload=None)
        self.assertEqual(result.code, 0, result.text)
        self.assertIn("personal_access_tokens", result.out)
        self.assertEqual(self.world.variable("PATCHWATCH_UPLOAD_KEY")["value"], UPLOAD)
        self.assertNoSecrets(result)

    def test_declining_the_configuration_writes_nothing(self):
        answers = [""] * 9 + ["n"]
        result = self.world.run(BASE_ARGS, stdin="\n".join(answers) + "\n")
        self.assertEqual(result.code, 1)
        self.assertIn("Stopped at your request", result.err)
        self.assertUntouched()

    def test_declining_the_commit_keeps_variables_only(self):
        answers = [""] * 11 + ["n"]
        result = self.world.run(BASE_ARGS, stdin="\n".join(answers) + "\n")
        self.assertEqual(result.code, 1)
        self.assertEqual(self.world.state.get("commits"), None)
        self.assertIsNotNone(self.world.variable("PATCHWATCH_URL"))

    def test_running_out_of_input_is_a_clear_error(self):
        result = self.world.run(BASE_ARGS, stdin="")
        self.assertEqual(result.code, 1)
        self.assertIn("No more input available", result.err)
        self.assertUntouched()

    def test_invalid_answers_are_asked_again(self):
        answers = [""] * 11 + ["maybe", "y"]
        result = self.world.run(BASE_ARGS, stdin="\n".join(answers) + "\n" + "\n" * 5)
        self.assertEqual(result.code, 0, result.text)
        self.assertIn("Please answer y or n.", result.out)


class Variables(Base):
    def existing(self, key, value, protected, masked, type="env_var"):
        self.world.state["variables"].append({"key": key, "value": value, "protected": protected, "masked": masked,
                                              "variable_type": type, "environment_scope": "*", "raw": True})

    def test_correct_variables_are_kept(self):
        self.existing("PATCHWATCH_URL", "https://patchwatch.example.org", False, False)
        self.existing("PATCHWATCH_UPLOAD_KEY", UPLOAD, True, True)
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 0, result.text)
        self.assertEqual([w for w in self.world.writes() if "/variables" in w["url"]], [])
        self.assertIn("already correct, kept", result.out)

    def test_existing_key_is_reused_without_asking(self):
        self.existing("PATCHWATCH_UPLOAD_KEY", UPLOAD, True, True)
        result = self.world.run(AUTOMATIC, upload=None)
        self.assertEqual(result.code, 0, result.text)
        self.assertIn("already stored", result.out)
        self.assertNoSecrets(result)

    def test_wrong_flags_are_corrected(self):
        self.existing("PATCHWATCH_UPLOAD_KEY", UPLOAD, False, False)
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 0, result.text)
        key = self.world.variable("PATCHWATCH_UPLOAD_KEY")
        self.assertEqual((key["protected"], key["masked"], key["value"]), (True, True, UPLOAD))
        self.assertIn("[fixed]", result.out)
        self.assertTrue(any(w["method"] == "PUT" for w in self.world.writes()))

    def test_different_value_is_kept_unless_forced(self):
        self.existing("PATCHWATCH_URL", "https://old.example.org", False, False)
        result = self.world.run(AUTOMATIC)
        self.assertEqual(self.world.variable("PATCHWATCH_URL")["value"], "https://old.example.org")
        self.assertIn("--force", result.out)
        forced = self.world.run(AUTOMATIC + ["--force"])
        self.assertEqual(forced.code, 0, forced.text)
        self.assertEqual(self.world.variable("PATCHWATCH_URL")["value"], "https://patchwatch.example.org")

    def test_existing_url_is_the_default_answer(self):
        self.existing("PATCHWATCH_URL", "https://patchwatch.example.org", False, False)
        args = [a for a in BASE_ARGS if a not in ("--patchwatch-url", "https://patchwatch.example.org")]
        result = self.world.run(args, stdin="\n" * 20)
        self.assertEqual(result.code, 0, result.text)
        self.assertIn("PatchWatch URL (https://...) [https://patchwatch.example.org]", result.out)

    def test_ca_certificate_becomes_a_file_variable(self):
        cert = self.world.dir / "ca.pem"
        cert.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
        result = self.world.run(AUTOMATIC + ["--ca-cert-file", str(cert)])
        self.assertEqual(result.code, 0, result.text)
        variable = self.world.variable("PATCHWATCH_CA_CERT")
        self.assertEqual(variable["variable_type"], "file")
        self.assertIn("BEGIN CERTIFICATE", variable["value"])
        probe = [c for c in self.world.calls if "/api/v1/project" in c["url"]][0]
        self.assertIn("--cacert", probe["argv"])

    def test_group_scope(self):
        result = self.world.run(AUTOMATIC + ["--group", "acme"])
        self.assertEqual(result.code, 0, result.text)
        self.assertEqual({v["key"] for v in self.world.state["group_variables"]},
                         {"PATCHWATCH_URL", "PATCHWATCH_UPLOAD_KEY"})
        self.assertEqual(self.world.state["variables"], [])
        self.assertIn("group acme", result.out)


class ProjectChecks(Base):
    def test_unprotected_branch_is_protected(self):
        self.world.state["protected"] = False
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 0, result.text)
        self.assertTrue(self.world.state["protected"])
        self.assertIn("protected the branch main", result.out)

    def test_declining_protection_warns_and_continues(self):
        self.world.state["protected"] = False
        answers = ["n"] + [""] * 20  # the protection question comes first
        result = self.world.run(BASE_ARGS, stdin="\n".join(answers) + "\n")
        self.assertEqual(result.code, 0, result.text)
        self.assertFalse(self.world.state["protected"])
        self.assertIn("NOT DONE: protect the branch", result.out)

    def test_not_a_maintainer(self):
        self.world.state["project"]["permissions"]["project_access"]["access_level"] = 30
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 1)
        self.assertIn("Maintainer", result.err)
        self.assertUntouched()

    def test_group_access_counts(self):
        self.world.state["project"]["permissions"] = {"project_access": None, "group_access": {"access_level": 50}}
        self.assertEqual(self.world.run(AUTOMATIC).code, 0)

    def test_old_gitlab_stops_with_yes(self):
        self.world.state["version"] = "16.11.2"
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 1)
        self.assertIn("17.0", result.text)
        self.assertUntouched()

    def test_unknown_project_and_bad_token(self):
        result = self.world.run(["--gitlab-url", GITLAB, "--project", "nope/missing", "--yes"])
        self.assertEqual(result.code, 1)
        self.assertIn("was not found", result.err)
        result = self.world.run(AUTOMATIC, token="wrong")
        self.assertEqual(result.code, 1)
        self.assertIn("rejected the token", result.err)

    def test_project_given_as_url(self):
        args = ["--project", GITLAB + "/acme/shop.git", "--patchwatch-url", "https://patchwatch.example.org",
                "--release-url", RELEASE, "--yes"]
        result = self.world.run(args)
        self.assertEqual(result.code, 0, result.text)

    def test_empty_repository(self):
        self.world.state["project"]["default_branch"] = None
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 1)
        self.assertIn("repository is empty", result.err)


class PatchWatchChecks(Base):
    def test_rejected_upload_key(self):
        result = self.world.run(AUTOMATIC, upload="BADKEY")
        self.assertEqual(result.code, 1)
        self.assertIn("rejected the upload key", result.err)
        self.assertIn("ci_upload_key", result.err)
        self.assertUntouched()

    def test_unreachable_server(self):
        self.world.state["patchwatch_down"] = True
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 1)
        self.assertIn("Cannot reach", result.err)
        self.assertIn("--ca-cert-file", result.err)
        self.assertUntouched()

    def test_http_url_is_refused(self):
        args = [a if a != "https://patchwatch.example.org" else "http://patchwatch.example.org" for a in AUTOMATIC]
        result = self.world.run(args)
        self.assertEqual(result.code, 1)
        self.assertIn("must start with https://", result.err)

    def test_invalid_read_key(self):
        result = self.world.run(AUTOMATIC, read="BADKEY")
        self.assertEqual(result.code, 1)
        self.assertIn("read key was not accepted", result.err)
        self.assertUntouched()


class Templates(Base):
    def test_checksum_mismatch_aborts(self):
        self.world.sums.write_text("0" * 64 + f"  {build.TEMPLATES_NAME}\n")
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 1)
        self.assertIn("Checksum mismatch", result.err)
        self.assertUntouched()

    def test_missing_release(self):
        result = self.world.run(AUTOMATIC[:-1] + ["--yes"], env={})
        self.assertEqual(self.world.run(["--gitlab-url", GITLAB, "--project", "acme/shop", "--patchwatch-url",
                                         "https://patchwatch.example.org", "--release-url", "https://example.test/none",
                                         "--yes"]).code, 1)
        self.assertEqual(result.code, 0)

    def test_unfilled_release_placeholder(self):
        args = [a for a in AUTOMATIC if a not in ("--release-url", RELEASE)]
        result = self.world.run(args)
        self.assertEqual(result.code, 1)
        self.assertIn("does not know where to download", result.err)
        self.assertUntouched()

    def test_local_archive_is_not_verified_and_says_so(self):
        args = [a for a in AUTOMATIC if a not in ("--release-url", RELEASE)] + ["--templates-archive", str(self.world.archive)]
        result = self.world.run(args)
        self.assertEqual(result.code, 0, result.text)
        self.assertIn("checksum is NOT verified", result.out)

    def test_job_image_comes_from_the_archive_or_option(self):
        self.world.run(AUTOMATIC)
        self.assertEqual(self.world.config()["include"][0]["inputs"]["image"], IMAGE)
        world = World(self)
        world.run(AUTOMATIC + ["--job-image", "registry.example.org/ci:v1"])
        self.assertEqual(world.config()["include"][0]["inputs"]["image"], "registry.example.org/ci:v1")

    def test_archive_without_image_asks_for_it(self):
        archive = build.build_templates(self.world.dir / "noimage" / build.TEMPLATES_NAME)
        self.world.sums.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {build.TEMPLATES_NAME}\n")
        self.world.state["downloads"][f"{RELEASE}/{build.TEMPLATES_NAME}"] = str(archive)
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 1)
        self.assertIn("No CI job image known", result.err)
        interactive = self.world.run(BASE_ARGS, stdin="\n" * 9 + "ghcr.io/acme/x/ci:v1\n" + "\n" * 10)
        self.assertEqual(interactive.code, 0, interactive.text)
        self.assertEqual(self.world.config()["include"][0]["inputs"]["image"], "ghcr.io/acme/x/ci:v1")


class ReleaseSubstitution(Base):
    def test_release_pipeline_fills_in_download_location_and_version(self):
        pipeline = (ROOT / "ci" / "release.yml").read_text()
        for placeholder in ("@RELEASE_BASE@", "@VERSION@", "setup-gitlab-project.sh", "patchwatch-ci-templates.tar.gz"):
            self.assertIn(placeholder, pipeline)
        base = "https://github.com/acme/patchwatch/releases/download/v9.9.9"
        script = self.world.dir / "released.sh"
        script.write_text(SCRIPT.read_text().replace("@RELEASE_BASE@", base).replace("@VERSION@", "9.9.9"))
        self.assertNotIn("@RELEASE_BASE@", script.read_text())
        self.world.state["downloads"] = {base + "/" + name: path for name, path in (
            (build.TEMPLATES_NAME, str(self.world.archive)), ("SHA256SUMS", str(self.world.sums)))}
        args = [a for a in AUTOMATIC if a not in ("--release-url", RELEASE)]
        self.world.state_path.write_text(json.dumps(self.world.state))
        (self.world.dir / "state.json.calls").write_text("")
        environment = {"PATH": f"{self.world.bin}:{os.environ['PATH']}", "FAKE_STATE": str(self.world.state_path),
                       "GITLAB_TOKEN": TOKEN, "PATCHWATCH_UPLOAD_KEY": UPLOAD, "TMPDIR": str(self.world.dir)}
        process = subprocess.run(["sh", str(script)] + args, capture_output=True, text=True, env=environment, timeout=60)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn("(9.9.9)", process.stdout)
        self.assertIn(f"Source: {base}", process.stdout)

    def test_unreleased_script_keeps_its_placeholders(self):
        self.assertIn("'@RELEASE_BASE@'", SCRIPT.read_text())


class GitlabCiFile(Base):
    def test_existing_file_without_include_is_extended(self):
        original = "stages:\n  - build\n  - test\n\nbuild:\n  script: make\n"
        self.world.state["files"][".gitlab-ci.yml"] = original
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 0, result.text)
        action = self.world.committed()[".gitlab-ci.yml"]
        self.assertEqual(action["action"], "update")
        self.assertTrue(action["content"].startswith(original))
        self.assertTrue(action["content"].endswith(f"include:\n{INCLUDE}\n"))
        check_yaml(action["content"])

    def test_existing_include_section_is_left_alone(self):
        self.world.state["files"][".gitlab-ci.yml"] = "include:\n  - template: Jobs/SAST.gitlab-ci.yml\n"
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 0, result.text)
        self.assertNotIn(".gitlab-ci.yml", self.world.committed())
        self.assertIn("already has an include: section", result.out)
        self.assertIn(INCLUDE.strip(), result.out)
        self.assertIn("TODO: add", result.out)

    def test_already_included_is_skipped(self):
        self.world.state["files"][".gitlab-ci.yml"] = f"include:\n{INCLUDE}\n"
        result = self.world.run(AUTOMATIC)
        self.assertNotIn(".gitlab-ci.yml", self.world.committed())
        self.assertIn("already includes", result.out)

    def test_custom_stages_are_detected(self):
        self.world.state["files"][".gitlab-ci.yml"] = "stages: [compile, verify, ship]\njob:\n  script: x\n"
        result = self.world.run(AUTOMATIC)
        self.assertIn("compile verify ship", result.out)
        self.assertEqual(self.world.config()["include"][0]["inputs"]["stage"], "compile")
        world = World(self)
        world.state["files"][".gitlab-ci.yml"] = "stages:\n- build\n- test # tests\n- deploy\n"
        result = world.run(AUTOMATIC)
        self.assertIn("build test deploy", result.out)
        self.assertEqual(world.config()["include"][0]["inputs"]["stage"], "test")

    def test_unknown_stage_warns(self):
        self.world.state["files"][".gitlab-ci.yml"] = "stages: [a, b]\n"
        result = self.world.run(AUTOMATIC + ["--component-stage", "zzz"])
        self.assertIn('Stage "zzz" is not in the stages', result.out)


class MergeRequest(Base):
    def test_lint_errors_prevent_the_merge_request(self):
        self.world.state.update(lint_valid=False, lint_errors=["jobs:patchwatch-sbom stage is not defined"])
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 1)
        self.assertIn("CI lint reports errors", result.out)
        self.assertIn("stage is not defined", result.out)
        self.assertIn("no merge request was opened", result.err)
        self.assertNotIn("merge_requests", self.world.state)
        self.assertIn("patchwatch/setup", self.world.state["branches"])

    def test_existing_branch_gets_a_new_name(self):
        self.world.state["branches"]["patchwatch/setup"] = {}
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 0, result.text)
        self.assertRegex(self.world.state["commits"][0]["branch"], r"^patchwatch/setup-\d{14}$")
        self.assertIn("already exists", result.out)

    def test_custom_branch_name(self):
        self.world.run(AUTOMATIC + ["--branch-name", "chore/patchwatch"])
        self.assertEqual(self.world.state["commits"][0]["branch"], "chore/patchwatch")

    def test_nothing_to_do_when_everything_is_current(self):
        first = self.world.run(AUTOMATIC)
        self.assertEqual(first.code, 0, first.text)
        self.world.state["files"] = {path: action["content"] for path, action in self.world.committed().items()}
        self.world.state.update(commits=[], branches={}, merge_requests=[])
        result = self.world.run(AUTOMATIC)
        self.assertEqual(result.code, 0, result.text)
        self.assertIn("Nothing to commit", result.out)
        self.assertUntouched()

    def test_commit_never_targets_the_default_branch(self):
        self.world.run(AUTOMATIC)
        commit_calls = [c for c in self.world.calls if c["url"].endswith("/repository/commits")]
        self.assertEqual(len(commit_calls), 1)
        self.assertNotEqual(json.loads(commit_calls[0]["body"])["branch"], "main")


class DryRun(Base):
    def test_dry_run_writes_nothing(self):
        self.world.state["protected"] = False
        result = self.world.run(AUTOMATIC + ["--dry-run", "--component", "api=api"], read=READ)
        self.assertEqual(result.code, 0, result.text)
        self.assertUntouched()
        self.assertIn("[dry run]", result.out)
        self.assertIn("Run the script again without --dry-run", result.out)
        self.assertIn("patchwatch-sbom-api", result.out)
        self.assertNoSecrets(result)


class UpdateAndReconfigure(Base):
    def setup_previous(self, **options):
        args = AUTOMATIC + [item for pair in options.items() for item in (f"--{pair[0].replace('_', '-')}", pair[1])]
        first = self.world.run(args)
        self.assertEqual(first.code, 0, first.text)
        self.world.state["files"] = {path: action["content"] for path, action in self.world.committed().items()}
        self.world.state.update(commits=[], branches={}, merge_requests=[])
        return first

    def test_update_keeps_the_configuration_and_refreshes_the_template(self):
        self.setup_previous(team="platform", bsi_mode="enforce")
        self.world.state["files"][".gitlab/patchwatch/sbom.yml"] = "# old template\n"
        result = self.world.run(["--yes", "--update"] + [a for a in AUTOMATIC if a != "--yes"])
        self.assertEqual(result.code, 0, result.text)
        files = self.world.committed()
        self.assertEqual(files[".gitlab/patchwatch/sbom.yml"]["action"], "update")
        self.assertIn("old template", result.out)
        # the generated configuration is identical to the earlier one, so only the template is committed
        self.assertNotIn(".gitlab/patchwatch/patchwatch.yml", files)
        self.assertIn("patchwatch.yml: unchanged", result.out)
        self.assertEqual([w for w in self.world.writes() if "/variables" in w["url"]], [])
        self.assertIn("Update PatchWatch CI templates", self.world.state["commits"][0]["commit_message"])

    def test_update_keeps_disabled_service_detection_and_components(self):
        self.setup_previous(component="api=api")
        self.world.state["files"][".gitlab/patchwatch/patchwatch.yml"] = \
            self.world.state["files"][".gitlab/patchwatch/patchwatch.yml"].replace('"detect_services":true', '"detect_services":false')
        self.world.state["files"][".gitlab/patchwatch/sbom.yml"] = "# old\n"
        result = self.world.run(AUTOMATIC + ["--update"])
        self.assertEqual(result.code, 0, result.text)
        jobs = {i["inputs"]["job_name"]: i["inputs"] for i in self.world.config()["include"]}
        self.assertIn("patchwatch-sbom-api", jobs)
        self.assertIs(jobs["patchwatch-sbom-parent"]["detect_services"], False)

    def test_update_without_previous_setup(self):
        result = self.world.run(AUTOMATIC + ["--update"])
        self.assertEqual(result.code, 1)
        self.assertIn("needs an earlier setup", result.err)
        self.assertUntouched()

    def test_reconfigure_uses_previous_answers_as_defaults(self):
        self.setup_previous(team="platform", environment="production")
        result = self.world.run(AUTOMATIC + ["--reconfigure"])
        self.assertEqual(result.code, 0, result.text)
        self.assertIn("Found an earlier PatchWatch setup", result.out)
        # --yes takes the previous answers as defaults, so nothing changes
        self.assertIn("Nothing to commit", result.out)
        changed = self.world.run(AUTOMATIC + ["--reconfigure", "--team", "other"])
        self.assertEqual(self.world.config()["include"][0]["inputs"]["team"], "other")
        self.assertEqual(self.world.config()["include"][0]["inputs"]["environment"], "production")


class Hygiene(Base):
    def test_no_secret_anywhere_across_scenarios(self):
        for extra in ([], ["--dry-run"], ["--component", "a=a"], ["--force"]):
            with self.subTest(extra=extra):
                world = World(self)
                result = world.run(AUTOMATIC + extra, read=READ)
                self.assertEqual(result.code, 0, result.text)
                for secret in SECRETS:
                    self.assertNotIn(secret, result.text)
                    for call in world.calls:
                        self.assertNotIn(secret, json.dumps(call["argv"]))
                        self.assertNotIn(secret, json.dumps(call["url"]))
                tokens = [h for c in world.calls for h in c["headers"] if h.startswith("PRIVATE-TOKEN")]
                self.assertTrue(tokens)

    def test_temporary_files_are_removed(self):
        before = set(os.listdir(self.world.dir))
        self.world.run(AUTOMATIC)
        leftovers = [n for n in set(os.listdir(self.world.dir)) - before if n.startswith("patchwatch-setup.")]
        self.assertEqual(leftovers, [])
        failing = self.world.run(AUTOMATIC, upload="BADKEY")
        self.assertEqual(failing.code, 1)
        leftovers = [n for n in os.listdir(self.world.dir) if n.startswith("patchwatch-setup.")]
        self.assertEqual(leftovers, [])

    def test_script_is_posix_and_executable(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        self.assertEqual(SCRIPT.read_text().splitlines()[0], "#!/bin/sh")
        self.assertNotRegex(SCRIPT.read_text(), r"\[\[ ")  # bash test syntax; POSIX classes like [[:space:]] are fine
        for shell in ("dash", "busybox"):
            if shutil.which(shell):
                args = [shell] + (["sh"] if shell == "busybox" else []) + ["-n", str(SCRIPT)]
                self.assertEqual(subprocess.run(args).returncode, 0)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        result = subprocess.run(["shellcheck", "--shell=sh", "--severity=warning", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
