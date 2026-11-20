# SPDX-License-Identifier: Apache-2.0
"""Fake ``curl`` for tests/test_gitlab_project_setup.py: a tiny GitLab and PatchWatch API.

The test writes the world to ``$FAKE_STATE`` (a JSON file); this program answers one curl call from it,
applies writes back to it and appends every call (arguments, request body, headers from the -K file) to
``$FAKE_STATE.calls`` so the tests can assert on what was sent.
"""
import json
import os
import re
import sys
from urllib.parse import parse_qs, unquote, urlsplit

STATE_PATH = os.environ["FAKE_STATE"]
state = json.load(open(STATE_PATH))
argv = sys.argv[1:]

method, out, fmt, data, config, headers, url = "GET", None, None, None, None, [], None
i = 0
while i < len(argv):
    a = argv[i]
    if a in ("-X",):
        method = argv[i + 1]; i += 2
    elif a == "-o":
        out = argv[i + 1]; i += 2
    elif a == "-w":
        fmt = argv[i + 1]; i += 2
    elif a == "-K":
        config = argv[i + 1]; i += 2
    elif a == "-H":
        headers.append(argv[i + 1]); i += 2
    elif a == "--data-binary":
        data = argv[i + 1]; i += 2
    elif a in ("--max-time", "--cacert"):
        i += 2
    elif a.startswith("-"):
        i += 1
    else:
        url = a; i += 1

config_headers = []
if config:
    config_headers = re.findall(r'header = "([^"]*)"', open(config).read())
body = None
if data and data.startswith("@"):
    body = open(data[1:]).read()
with open(STATE_PATH + ".calls", "a") as log:
    log.write(json.dumps({"method": method, "url": url, "argv": argv, "body": body, "headers": config_headers}) + "\n")


def finish(status, content="", binary=None):
    if out and out != "/dev/null":
        with open(out, "wb") as stream:
            stream.write(binary if binary is not None else (content if isinstance(content, bytes) else
                         (content if isinstance(content, str) else json.dumps(content)).encode()))
    if fmt:
        sys.stdout.write(fmt.replace("%{http_code}", str(status)))
    json.dump(state, open(STATE_PATH, "w"))
    sys.exit(0)


def fail_f(status):  # curl -f: exit 22 on HTTP errors
    sys.stderr.write(f"curl: (22) The requested URL returned error: {status}\n")
    json.dump(state, open(STATE_PATH, "w"))
    sys.exit(22)


parts = urlsplit(url)
query = parse_qs(parts.query)
path = parts.path
token_ok = any(h == "PRIVATE-TOKEN: " + state["gitlab_token"] for h in config_headers)

# --- downloads (no authentication) ---------------------------------------------------------------
if url in state.get("downloads", {}):
    finish(200, binary=open(state["downloads"][url], "rb").read())
if "/releases/download/" in url:
    fail_f(404)

# --- PatchWatch ----------------------------------------------------------------------------------
if path == "/api/v1/project":
    key = next((h.split(": ", 1)[1] for h in config_headers if h.startswith("X-Api-Key")), "")
    if state.get("patchwatch_down"):
        sys.stderr.write("curl: (6) Could not resolve host\n"); sys.exit(6)
    finish(state["patchwatch_keys"].get(key, 401), [])

# --- GitLab --------------------------------------------------------------------------------------
if not path.startswith("/api/v4/"):
    fail_f(404)
if not token_ok:
    finish(401, {"message": "401 Unauthorized"})
api = path[len("/api/v4/"):]
project = state["project"]
pid = str(project["id"])


def respond_page(items):
    page = int(query.get("page", ["1"])[0])
    per = int(query.get("per_page", ["100"])[0])
    finish(200, items[(page - 1) * per:page * per])


def branch_files(branch):
    return state["branches"].get(branch, state["files"] if branch == project["default_branch"] else None)


if api == "user":
    finish(200, {"username": "tester"})
if api == "version":
    finish(200 if state.get("version") else 404, {"version": state.get("version")})
if api.startswith("groups/") and not api.endswith("/variables"):
    finish(200, {"id": 7, "full_path": "acme"})
m = re.fullmatch(r"(projects|groups)/([^/]+)/variables(?:/([^/]+))?", api)
if m:
    scope = "group_variables" if m.group(1) == "groups" else "variables"
    variables = state.setdefault(scope, [])
    if method == "GET":
        respond_page(variables)
    new = json.loads(body)
    if method == "POST":
        if any(v["key"] == new["key"] for v in variables):
            finish(400, {"message": {"key": ["has already been taken"]}})
        if new["masked"] and len(new["value"]) < 8:
            finish(400, {"message": "value is invalid: masked variable needs at least 8 characters"})
        variables.append(new)
        finish(201, new)
    if method == "PUT":
        for index, v in enumerate(variables):
            if v["key"] == unquote(m.group(3)):
                variables[index] = new
                finish(200, new)
        finish(404, {"message": "404 Variable Not Found"})
if api in (f"projects/{project['path_with_namespace'].replace('/', '%2F')}", f"projects/{pid}") or \
        api == "projects/" + project["path_with_namespace"].replace("/", "%2F"):
    finish(200, project)
if api.startswith("projects/%s/" % pid):
    rest = api[len("projects/%s/" % pid):]
    if rest.startswith("repository/branches/"):
        name = unquote(rest.split("/", 2)[2])
        if name == project["default_branch"]:
            finish(200, {"name": name, "protected": state["protected"]})
        if name in state["branches"]:
            finish(200, {"name": name, "protected": False})
        finish(404, {"message": "404 Branch Not Found"})
    if rest == "protected_branches" and method == "POST":
        state["protected"] = True
        finish(201, {"name": query["name"][0]})
    if rest == "repository/tree":
        respond_page([{"path": p, "type": "blob"} for p in state["tree"]])
    m = re.fullmatch(r"repository/files/(.+)/raw", rest)
    if m:
        files = branch_files(query.get("ref", [project["default_branch"]])[0]) or {}
        name = unquote(m.group(1))
        if name in files:
            finish(200, files[name])
        finish(404, {"message": "404 File Not Found"})
    if rest == "repository/commits" and method == "POST":
        commit = json.loads(body)
        if commit["branch"] in state["branches"]:
            finish(400, {"message": "A branch with this name already exists"})
        files = dict(branch_files(commit["start_branch"]))
        for action in commit["actions"]:
            if action["action"] == "create" and action["file_path"] in files:
                finish(400, {"message": "A file with this name already exists"})
            if action["action"] == "update" and action["file_path"] not in files:
                finish(400, {"message": "A file with this name doesn't exist"})
            files[action["file_path"]] = action["content"]
        state["branches"][commit["branch"]] = files
        state.setdefault("commits", []).append(commit)
        finish(201, {"id": "abc123"})
    if rest == "ci/lint":
        finish(200, {"valid": state.get("lint_valid", True), "errors": state.get("lint_errors", []), "warnings": []})
    if rest == "merge_requests" and method == "POST":
        state.setdefault("merge_requests", []).append(json.loads(body))
        finish(201, {"web_url": project["web_url"] + "/-/merge_requests/1"})
finish(404, {"message": "404 Not found: " + api})
