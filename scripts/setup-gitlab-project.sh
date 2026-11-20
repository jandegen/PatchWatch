#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Interactive setup: connect a GitLab project to PatchWatch (SBOM upload from GitLab CI).
#
# Needs only a POSIX shell, curl, jq, tar and sha256sum (or shasum). It talks to the GitLab REST API with
# a personal access token (scope "api"), never prints secrets and never passes them as arguments.
# Every step explains what it does first and asks before it writes anything. Run with --help for options.
# shellcheck disable=SC2016  # '$CI_...' strings are GitLab CI variables that must stay literal
set -eu
umask 077

SCRIPT_VERSION='@VERSION@'
RELEASE_BASE='@RELEASE_BASE@'  # replaced at release time: https://github.com/<owner>/<repo>/releases/download/vX.Y.Z
ARCHIVE_NAME=patchwatch-ci-templates.tar.gz
SETUP_DIR=.gitlab/patchwatch
STEPS=8
STEP=0

usage() {
  cat <<'EOF'
Usage: setup-gitlab-project.sh [options]

Connects a GitLab project to PatchWatch. The script asks for whatever you do not pass as an option.
It opens a merge request that adds the CI configuration; it never pushes to the default branch.

Connection
  --gitlab-url URL        GitLab instance (default: https://gitlab.com, or taken from --project URL)
  --project PATH|ID|URL   Project, e.g. group/project
  --group PATH|ID         Store the CI/CD variables on this group instead of the project
  --patchwatch-url URL    PatchWatch server (https), e.g. https://patchwatch.example.org
  --ca-cert-file FILE     CA certificate if the PatchWatch server uses an internal CA

What to inventory
  --component NAME=PATH   One inventory per component (repeatable); implies a monorepo layout
  --no-components         One inventory for the whole repository
  --service NAME          Additional service name (repeatable)
  --no-detect-services    Do not read services from Compose files
  --scan-image REF        Container image to scan (repeatable, single-inventory layout)
  --team NAME             Owning team (alert routing); default: top-level GitLab group
  --environment NAME      Environment tag, e.g. production
  --bsi-mode MODE         report (default) or enforce
  --branch NAME           Additional branch that may upload (repeatable)
  --fail-on LEVEL         none (default), warn or fail; needs a read key
  --job-image REF         CI job image (default: the image named in the templates archive)
  --component-stage NAME  Stage of the inventory jobs (default: test)
  --image-stage NAME      Stage of jobs that scan images (default: same as above)

Behaviour
  --yes                   Do not ask; take the default of every question
  --dry-run               Read from GitLab and PatchWatch, show the plan, write nothing
  --force                 Overwrite variables that already exist with the values you give
  --update                Refresh the vendored template and keep the previous configuration
  --reconfigure           Ask the inventory questions again, using the previous answers as defaults
  --branch-name NAME      Branch for the merge request (default: patchwatch/setup)
  --release-url URL       Where the templates archive and SHA256SUMS are downloaded from
  --templates-archive F   Use a local archive instead (checksum is NOT verified)
  --help                  Show this help

Environment (secrets are never accepted as arguments)
  GITLAB_TOKEN            Personal access token with scope "api"
  PATCHWATCH_UPLOAD_KEY   Upload key of the PatchWatch team ci-upload
  PATCHWATCH_READ_KEY     Optional read key (result summary, fail_on, delta report)
EOF
}

# -- options ---------------------------------------------------------------------------------------
GITLAB_URL=${GITLAB_URL:-}
PROJECT=
GROUP=
PATCHWATCH_URL=${PATCHWATCH_URL:-}
CA_CERT_FILE=${PATCHWATCH_CA_CERT_FILE:-}
COMPONENT_FLAGS=
NO_COMPONENTS=0
SERVICE_FLAGS=
DETECT_SERVICES=
SCAN_IMAGE_FLAGS=
TEAM=
ENVIRONMENT=
BSI_MODE=
BRANCH_FLAGS=
FAIL_ON=
JOB_IMAGE=
COMPONENT_STAGE=
IMAGE_STAGE=
YES=0
DRY_RUN=0
FORCE=0
UPDATE=0
RECONFIGURE=0
BRANCH_NAME=patchwatch/setup
TEMPLATES_ARCHIVE=
UPLOAD_KEY=${PATCHWATCH_UPLOAD_KEY:-}
READ_KEY=${PATCHWATCH_READ_KEY:-}
unset PATCHWATCH_UPLOAD_KEY PATCHWATCH_READ_KEY

while [ $# -gt 0 ]; do
  case $1 in
    --help|-h) usage; exit 0 ;;
    --yes) YES=1; shift; continue ;;
    --dry-run) DRY_RUN=1; shift; continue ;;
    --force) FORCE=1; shift; continue ;;
    --update) UPDATE=1; shift; continue ;;
    --reconfigure) RECONFIGURE=1; shift; continue ;;
    --no-components) NO_COMPONENTS=1; shift; continue ;;
    --no-detect-services) DETECT_SERVICES=false; shift; continue ;;
  esac
  case $1 in
    --gitlab-url|--project|--group|--patchwatch-url|--ca-cert-file|--component|--service|--scan-image|--team|--environment|\
    --bsi-mode|--branch|--fail-on|--job-image|--component-stage|--image-stage|--branch-name|--release-url|--templates-archive) ;;
    *) printf 'Error: unknown option %s (see --help)\n' "$1" >&2; exit 2 ;;
  esac
  if [ $# -lt 2 ]; then printf 'Error: option %s needs a value (see --help)\n' "$1" >&2; exit 2; fi
  case $1 in
    --component|--service|--scan-image|--branch)  # repeatable, one value each: no blanks (they would be split silently)
      case $2 in *[[:space:]]*) printf 'Error: %s takes one value without blanks (got: "%s"); repeat the option instead\n' "$1" "$2" >&2; exit 2 ;; esac ;;
  esac
  case $1 in
    --gitlab-url) GITLAB_URL=$2 ;;
    --project) PROJECT=$2 ;;
    --group) GROUP=$2 ;;
    --patchwatch-url) PATCHWATCH_URL=$2 ;;
    --ca-cert-file) CA_CERT_FILE=$2 ;;
    --component) COMPONENT_FLAGS="$COMPONENT_FLAGS$2
" ;;
    --service) SERVICE_FLAGS="$SERVICE_FLAGS $2" ;;
    --scan-image) SCAN_IMAGE_FLAGS="$SCAN_IMAGE_FLAGS $2" ;;
    --team) TEAM=$2 ;;
    --environment) ENVIRONMENT=$2 ;;
    --bsi-mode) BSI_MODE=$2 ;;
    --branch) BRANCH_FLAGS="$BRANCH_FLAGS $2" ;;
    --fail-on) FAIL_ON=$2 ;;
    --job-image) JOB_IMAGE=$2 ;;
    --component-stage) COMPONENT_STAGE=$2 ;;
    --image-stage) IMAGE_STAGE=$2 ;;
    --branch-name) BRANCH_NAME=$2 ;;
    --release-url) RELEASE_BASE=$2 ;;
    --templates-archive) TEMPLATES_ARCHIVE=$2 ;;
    *) printf 'Error: unknown option %s (see --help)\n' "$1" >&2; exit 2 ;;
  esac
  shift 2
done

# -- output helpers --------------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m')
  GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); RESET=$(printf '\033[0m')
else
  BOLD=; DIM=; RED=; GREEN=; YELLOW=; RESET=
fi
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
  *[Uu][Tt][Ff]*8*) if [ -t 1 ]; then S_OK='✔'; S_KEPT='•'; S_FIXED='!'; S_FAIL='✘'; else S_OK='[ok]'; S_KEPT='[kept]'; S_FIXED='[fixed]'; S_FAIL='[failed]'; fi ;;
  *) S_OK='[ok]'; S_KEPT='[kept]'; S_FIXED='[fixed]'; S_FAIL='[failed]' ;;
esac

TMP=
STTY_OLD=
cleanup() {
  [ -z "$STTY_OLD" ] || stty "$STTY_OLD" 2>/dev/null || true
  [ -z "$TMP" ] || rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

say() { printf '%s\n' "$*"; }
blank() { printf '\n'; }
step() { STEP=$((STEP + 1)); printf '\n%s[%s/%s] %s%s\n' "$BOLD" "$STEP" "$STEPS" "$1" "$RESET"; }
explain() {
  printf '%sWhat happens now:%s\n' "$DIM" "$RESET"
  for _line in "$@"; do printf '  %s%s%s\n' "$DIM" "$_line" "$RESET"; done
}
good() { printf '  %s%s%s %s\n' "$GREEN" "$S_OK" "$RESET" "$*"; }
kept() { printf '  %s %s\n' "$S_KEPT" "$*"; }
fixed() { printf '  %s%s%s %s\n' "$YELLOW" "$S_FIXED" "$RESET" "$*"; }
warn() { printf '  %sWarning:%s %s\n' "$YELLOW" "$RESET" "$*"; }
note() { printf '  %s\n' "$*"; }
record() { printf '%s\n' "$*" >>"$TMP/summary"; }
die() {
  printf '\n%s%s Error:%s %s\n' "$RED" "$S_FAIL" "$RESET" "$1" >&2
  shift
  for _line in "$@"; do printf '  %s\n' "$_line" >&2; done
  exit 1
}

read_line() {
  IFS= read -r REPLY || [ -n "$REPLY" ] || {
    [ -z "$STTY_OLD" ] || { stty "$STTY_OLD" 2>/dev/null || true; STTY_OLD=; }
    die "No more input available." "Run the script in a terminal, or pass the missing values as options (see --help)."
  }
}
# ask PROMPT DEFAULT -> REPLY
ask() {
  if [ "$YES" = 1 ]; then REPLY=$2; return 0; fi
  if [ -n "$2" ]; then printf '  %s [%s]: ' "$1" "$2"; else printf '  %s: ' "$1"; fi
  read_line
  [ -n "$REPLY" ] || REPLY=$2
}
# ask_secret PROMPT -> REPLY (hidden when reading from a terminal)
ask_secret() {
  printf '  %s: ' "$1"
  if [ -t 0 ]; then
    STTY_OLD=$(stty -g)
    stty -echo
    read_line
    stty "$STTY_OLD"; STTY_OLD=
    printf '\n'
  else
    read_line
  fi
}
# confirm QUESTION DEFAULT(y|n): returns 0 for yes
confirm() {
  if [ "$YES" = 1 ]; then
    if [ "$2" = y ]; then note "$1 -> yes (--yes)"; return 0; fi
    note "$1 -> no (--yes)"; return 1
  fi
  while :; do
    if [ "$2" = y ]; then printf '  %s [Y/n]: ' "$1"; else printf '  %s [y/N]: ' "$1"; fi
    read_line
    case $(printf '%s' "$REPLY" | tr '[:upper:]' '[:lower:]') in
      '') if [ "$2" = y ]; then return 0; else return 1; fi ;;
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) note "Please answer y or n." ;;
    esac
  done
}
write_gate() { # write_gate DESCRIPTION: returns 1 (and says so) in dry-run mode
  if [ "$DRY_RUN" = 1 ]; then note "[dry run] would $1"; return 1; fi
  return 0
}

# -- generic helpers -------------------------------------------------------------------------------
urlenc() { jq -rn --arg v "$1" '$v|@uri'; }
yq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"; }
valid() { # valid KIND VALUE
  case $1 in
    name) printf '%s' "$2" | grep -Eq '^[a-z0-9][a-z0-9._-]*$' ;;
    path) printf '%s' "$2" | grep -Eq '^[A-Za-z0-9._/-]+$' && ! printf '%s' "$2" | grep -Eq '(^|/)\.\.(/|$)' ;;
    word) printf '%s' "$2" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$' ;;
    imageref) printf '%s' "$2" | grep -Eq '^[A-Za-z0-9$][A-Za-z0-9._/:@${}-]*$' ;;
    branch) printf '%s' "$2" | grep -Eq '^[A-Za-z0-9._/-]+$' ;;
    stage) printf '%s' "$2" | grep -Eq '^[A-Za-z.][A-Za-z0-9._-]*$' ;;
  esac
}
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
words_of() { printf '%s' "$1" | tr -s ' \n' ' ' | sed 's/^ //; s/ $//'; }

# -- API wrappers ----------------------------------------------------------------------------------
BODY=
HTTP_STATUS=
# api METHOD PATH [JSONFILE]: HTTP_STATUS and BODY are set; only transport errors are fatal.
api() {
  _m=$1; _p=$2; _d=${3:-}
  set -- -sS --max-time 60 -K "$TMP/gitlab.cfg" -X "$_m" -o "$BODY" -w '%{http_code}'
  [ -z "$_d" ] || set -- "$@" -H 'Content-Type: application/json' --data-binary "@$_d"
  HTTP_STATUS=$(curl "$@" "$GITLAB_URL/api/v4/$_p" 2>"$TMP/curl.err") || {
    die "Cannot reach $GITLAB_URL ($(tr '\n' ' ' <"$TMP/curl.err"))." "Check the URL, your network and proxy settings."
  }
  case $HTTP_STATUS in
    2??) return 0 ;;
    *) return 1 ;;
  esac
}
api_message() { jq -r 'if type=="object" then (.message // .error // .error_description // empty) | if type=="string" then . else tojson end else empty end' "$BODY" 2>/dev/null || true; }
# api_must METHOD PATH [JSONFILE] WHAT: fatal unless 2xx
api_must() {
  _what=$4
  api "$1" "$2" "${3:-}" || die "GitLab refused to $_what (HTTP $HTTP_STATUS): $(api_message)" \
    "Your token needs the scope \"api\" and the Maintainer role in the project."
}
json_file() { # json_file NAME -> path of a fresh file in TMP
  printf '%s/%s' "$TMP" "$1"
}

# =================================================================================================
TMP=$(mktemp -d "${TMPDIR:-/tmp}/patchwatch-setup.XXXXXX")
BODY="$TMP/body.json"
: >"$TMP/summary"

blank
printf '%sPatchWatch setup for GitLab projects%s' "$BOLD" "$RESET"
case $SCRIPT_VERSION in @*) blank ;; *) printf ' (%s)\n' "$SCRIPT_VERSION" ;; esac
cat <<EOF

This script connects a GitLab project to PatchWatch. In 8 steps it will:
   1. check that the tools it needs are installed
   2. log in to GitLab with your access token
   3. check the project (your role, the default branch)
   4. check your PatchWatch server and upload key
   5. download and verify the CI templates
   6. ask what to inventory (repository, components, services, images)
   7. store the CI/CD variables in GitLab
   8. open a merge request with the CI configuration

It does not install anything, does not change the PatchWatch server and does not push to your
default branch. Every step that writes something asks first.
EOF
[ "$DRY_RUN" != 1 ] || say "
${YELLOW}Dry run:${RESET} nothing will be written. You see exactly what the script would do."

# -- 1. prerequisites ------------------------------------------------------------------------------
step "Check prerequisites"
explain "Checks for curl, jq, tar and a SHA-256 tool. Nothing is changed."
MISSING=
for _tool in curl jq tar awk sed grep; do
  command -v "$_tool" >/dev/null 2>&1 || MISSING="$MISSING $_tool"
done
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || MISSING="$MISSING sha256sum"
if [ -n "$MISSING" ]; then
  _hint=
  if command -v apt-get >/dev/null 2>&1; then _hint='sudo apt install'
  elif command -v dnf >/dev/null 2>&1; then _hint='sudo dnf install'
  elif command -v apk >/dev/null 2>&1; then _hint='apk add'
  elif command -v brew >/dev/null 2>&1; then _hint='brew install'
  fi
  {
    for _tool in $MISSING; do
      case $_tool in
        jq) printf "Error: 'jq' is missing (needed to read GitLab responses).\n" ;;
        *) printf "Error: '%s' is missing.\n" "$_tool" ;;
      esac
    done
    [ -z "$_hint" ] || printf 'Install it with: %s%s\n' "$_hint" "$MISSING"
    printf 'Install it:\n'
    printf '  Debian/Ubuntu:  sudo apt install%s\n' "$MISSING"
    printf '  Fedora/RHEL:    sudo dnf install%s\n' "$MISSING"
    printf '  Alpine:         apk add%s\n' "$MISSING"
    printf '  macOS:          brew install%s\n' "$MISSING"
    case $MISSING in *jq*) printf '  Windows:        winget install jqlang.jq\n' ;; esac
    printf 'Then run this script again. Nothing has been changed.\n'
  } >&2
  exit 1
fi
good "curl, jq, tar and checksum tool found"

# -- 2. GitLab access ------------------------------------------------------------------------------
step "Log in to GitLab"
explain "Asks for the GitLab URL, the project and a personal access token, then calls GET /user to check the token." \
        "The token is used only for this run. It is kept in a private temporary file, never shown and never put on a command line."

if [ -z "$PROJECT" ]; then ask "Project (group/project or URL)" ""; PROJECT=$REPLY; fi
[ -n "$PROJECT" ] || die "No project given." "Pass --project group/project."
case $PROJECT in
  http://*|https://*)
    _rest=${PROJECT#*://}; _host=${_rest%%/*}
    _path=${_rest#*/}; _path=${_path%%/-/*}; _path=${_path%.git}; _path=${_path%/}
    [ -n "$GITLAB_URL" ] || GITLAB_URL=${PROJECT%%://*}://$_host
    PROJECT=$_path ;;
esac
if [ -z "$GITLAB_URL" ]; then ask "GitLab URL" "https://gitlab.com"; GITLAB_URL=$REPLY; fi
GITLAB_URL=${GITLAB_URL%/}
case $GITLAB_URL in
  https://?*) ;;
  *) die "The GitLab URL must start with https:// (got: $GITLAB_URL)." "The token would be sent unencrypted otherwise." ;;
esac

TOKEN=${GITLAB_TOKEN:-}
unset GITLAB_TOKEN
if [ -z "$TOKEN" ]; then
  say
  note "No GITLAB_TOKEN in the environment. Create a token (scope \"api\", short expiry) here:"
  note "  $GITLAB_URL/-/user_settings/personal_access_tokens"
  note "  (older GitLab versions: $GITLAB_URL/-/profile/personal_access_tokens)"
  [ "$YES" != 1 ] || die "GITLAB_TOKEN is not set." "Export GITLAB_TOKEN and run again."
  ask_secret "GitLab access token"
  TOKEN=$REPLY
fi
[ -n "$TOKEN" ] || die "No token given."
printf 'header = "PRIVATE-TOKEN: %s"\n' "$TOKEN" >"$TMP/gitlab.cfg"
unset TOKEN

if ! api GET user; then
  case $HTTP_STATUS in
    401) die "GitLab rejected the token (HTTP 401)." "Check that it is valid, not expired, and has the scope \"api\"." ;;
    *) die "GitLab answered HTTP $HTTP_STATUS on $GITLAB_URL/api/v4/user: $(api_message)" "Is $GITLAB_URL the right instance?" ;;
  esac
fi
USERNAME=$(jq -r '.username // "?"' "$BODY")
good "Logged in as $USERNAME on $GITLAB_URL"

# -- 3. project ------------------------------------------------------------------------------------
step "Check the project"
explain "Reads the project, your role and the default branch. Jobs use protected variables, so the default branch must" \
        "be protected. If it is not, the script offers to protect it. Nothing is written without your confirmation."

case $PROJECT in
  *[!0-9]*) PROJECT_REF=$(urlenc "$PROJECT") ;;
  *) PROJECT_REF=$PROJECT ;;
esac
if ! api GET "projects/$PROJECT_REF"; then
  case $HTTP_STATUS in
    404) die "Project \"$PROJECT\" was not found, or your token cannot see it." "Use the full path (group/subgroup/project) or the numeric project ID." ;;
    *) die "Could not read the project (HTTP $HTTP_STATUS): $(api_message)" ;;
  esac
fi
PROJECT_ID=$(jq -r '.id' "$BODY")
PROJECT_PATH=$(jq -r '.path_with_namespace' "$BODY")
WEB_URL=$(jq -r '.web_url' "$BODY")
DEFAULT_BRANCH=$(jq -r '.default_branch // empty' "$BODY")
ACCESS=$(jq -r '[.permissions.project_access.access_level, .permissions.group_access.access_level] | map(select(. != null)) | max // 0' "$BODY")
VISIBILITY=$(jq -r '.visibility' "$BODY")
good "Project: $PROJECT_PATH ($VISIBILITY), default branch: ${DEFAULT_BRANCH:-none}"
[ -n "$DEFAULT_BRANCH" ] || die "The repository is empty." "Create an initial commit on the default branch, then run the script again."
[ "$ACCESS" -ge 40 ] || die "You need the Maintainer role in $PROJECT_PATH (you have access level $ACCESS)." \
  "Ask a maintainer to run this script or to raise your role."
good "Your role: Maintainer or higher"
PROJECT_REF=$PROJECT_ID

if api GET version; then
  GITLAB_VERSION=$(jq -r '.version // ""' "$BODY")
  _major=${GITLAB_VERSION%%.*}
  case $_major in
    ''|*[!0-9]*) kept "GitLab version unknown, skipping the version check" ;;
    *)
      if [ "$_major" -lt 17 ]; then
        warn "GitLab $GITLAB_VERSION is older than 17.0. The CI templates use spec:inputs, which needs 17.0 or newer."
        confirm "Continue anyway?" n || die "Stopped. Upgrade GitLab or use a newer instance." "Nothing has been changed."
      else
        good "GitLab $GITLAB_VERSION supports the CI templates"
      fi ;;
  esac
fi

BRANCH_REF=$(urlenc "$DEFAULT_BRANCH")
BRANCH_PROTECTED=0
if api GET "projects/$PROJECT_ID/repository/branches/$BRANCH_REF"; then
  [ "$(jq -r '.protected' "$BODY")" = true ] && BRANCH_PROTECTED=1
fi
if [ "$BRANCH_PROTECTED" = 1 ]; then
  good "Default branch $DEFAULT_BRANCH is protected"
else
  warn "The default branch $DEFAULT_BRANCH is not protected. The upload key is a protected variable and would not be available to its jobs."
  if confirm "Protect $DEFAULT_BRANCH now?" y; then
    if write_gate "protect branch $DEFAULT_BRANCH"; then
      api_must POST "projects/$PROJECT_ID/protected_branches?name=$BRANCH_REF" "" "protect the branch"
      fixed "Protected branch $DEFAULT_BRANCH"
      record "protected the branch $DEFAULT_BRANCH"
    fi
  else
    warn "Continuing without protection: the SBOM jobs will not find PATCHWATCH_UPLOAD_KEY until you protect the branch."
    record "NOT DONE: protect the branch $DEFAULT_BRANCH (Settings > Repository > Protected branches)"
  fi
fi

# -- 4. PatchWatch server --------------------------------------------------------------------------
step "Check the PatchWatch server"
explain "Asks for the PatchWatch URL and the upload key (the operator has them: secret ci_upload_key), then makes one" \
        "read-only request to the server to test both. The server is not changed." \
        "The key is stored in GitLab as a masked, protected variable in step 7."

VARS_PATH="projects/$PROJECT_ID/variables"
VARS_SCOPE="project $PROJECT_PATH"
if [ -n "$GROUP" ]; then
  case $GROUP in *[!0-9]*) _g=$(urlenc "$GROUP") ;; *) _g=$GROUP ;; esac
  api GET "groups/$_g" || die "Group \"$GROUP\" was not found or is not visible to your token (HTTP $HTTP_STATUS)."
  VARS_PATH="groups/$(jq -r '.id' "$BODY")/variables"
  VARS_SCOPE="group $(jq -r '.full_path' "$BODY")"
fi
: >"$TMP/vars.json"
echo '[]' >"$TMP/vars.json"
_page=1
while :; do
  api_must GET "$VARS_PATH?per_page=100&page=$_page" "" "list the CI/CD variables of the $VARS_SCOPE"
  jq -s '.[0] + .[1]' "$TMP/vars.json" "$BODY" >"$TMP/vars.next" && mv "$TMP/vars.next" "$TMP/vars.json"
  [ "$(jq 'length' "$BODY")" -ge 100 ] || break
  _page=$((_page + 1))
done
# var_field KEY FIELD: field of the variable KEY (environment scope *), empty if missing
var_field() {
  jq -r --arg k "$1" --arg f "$2" '[.[] | select(.key == $k and .environment_scope == "*")][0] | if . == null then "" else (.[$f] | if . == null then "" else tostring end) end' "$TMP/vars.json"
}
var_exists() { [ "$(jq --arg k "$1" '[.[] | select(.key == $k and .environment_scope == "*")] | length' "$TMP/vars.json")" -gt 0 ]; }

if [ -z "$PATCHWATCH_URL" ] && var_exists PATCHWATCH_URL; then PATCHWATCH_URL_DEFAULT=$(var_field PATCHWATCH_URL value); else PATCHWATCH_URL_DEFAULT=; fi
if [ -z "$PATCHWATCH_URL" ]; then
  ask "PatchWatch URL (https://...)" "$PATCHWATCH_URL_DEFAULT"; PATCHWATCH_URL=$REPLY
fi
PATCHWATCH_URL=${PATCHWATCH_URL%/}
case $PATCHWATCH_URL in
  https://?*) ;;
  '') die "No PatchWatch URL given." "Pass --patchwatch-url https://patchwatch.example.org." ;;
  *) die "The PatchWatch URL must start with https:// (got: $PATCHWATCH_URL)." "Plain HTTP is rejected by the CI job as well." ;;
esac

CA_CERT_CONTENT=
if [ -n "$CA_CERT_FILE" ]; then
  [ -r "$CA_CERT_FILE" ] || die "Cannot read the CA certificate file $CA_CERT_FILE."
  CA_CERT_CONTENT=$(cat "$CA_CERT_FILE")
  case $CA_CERT_CONTENT in *"BEGIN CERTIFICATE"*) ;; *) die "$CA_CERT_FILE is not a PEM certificate." ;; esac
fi

KEY_FROM_VARIABLE=0
if [ -z "$UPLOAD_KEY" ]; then
  if var_exists PATCHWATCH_UPLOAD_KEY && [ "$FORCE" != 1 ]; then
    UPLOAD_KEY=$(var_field PATCHWATCH_UPLOAD_KEY value)
    KEY_FROM_VARIABLE=1
    note "Using the upload key that is already stored in the variable PATCHWATCH_UPLOAD_KEY."
  else
    [ "$YES" != 1 ] || die "PATCHWATCH_UPLOAD_KEY is not set." "Export PATCHWATCH_UPLOAD_KEY (the ci_upload_key secret) and run again."
    ask_secret "PatchWatch upload key (input hidden)"
    UPLOAD_KEY=$REPLY
  fi
fi
[ -n "$UPLOAD_KEY" ] || die "No upload key given."

# probe_key KEY WHAT: one read-only request against the server
probe_key() {
  printf 'header = "X-Api-Key: %s"\n' "$1" >"$TMP/patchwatch.cfg"
  set -- -sS --max-time 30 -K "$TMP/patchwatch.cfg" -o /dev/null -w '%{http_code}'
  [ -z "$CA_CERT_FILE" ] || set -- "$@" --cacert "$CA_CERT_FILE"
  PROBE_STATUS=$(curl "$@" "$PATCHWATCH_URL/api/v1/project?pageSize=1" 2>"$TMP/probe.err") || PROBE_STATUS=000
}
probe_key "$UPLOAD_KEY"
case $PROBE_STATUS in
  200) good "PatchWatch at $PATCHWATCH_URL is reachable and accepts the upload key" ;;
  401|403) die "The PatchWatch server rejected the upload key (HTTP $PROBE_STATUS)." \
    "Use the key of the team ci-upload: kubectl -n patchwatch get secret patchwatch-provisioning -o jsonpath='{.data.ci_upload_key}' | base64 -d" \
    "(Compose: cat .secrets/ci_upload_key). Ask your PatchWatch operator if you do not have it." ;;
  000) die "Cannot reach $PATCHWATCH_URL ($(tr '\n' ' ' <"$TMP/probe.err"))." \
    "Check the URL and your network. For an internal CA pass --ca-cert-file ca.pem." ;;
  *) warn "The server answered HTTP $PROBE_STATUS to the test request."
     confirm "Continue anyway?" n || die "Stopped. Check $PATCHWATCH_URL and try again." "Nothing has been changed." ;;
esac

if [ -z "$READ_KEY" ] && var_exists PATCHWATCH_READ_KEY && [ "$FORCE" != 1 ]; then
  READ_KEY=$(var_field PATCHWATCH_READ_KEY value)
  note "Using the read key that is already stored in the variable PATCHWATCH_READ_KEY."
elif [ -z "$READ_KEY" ] && [ "$YES" != 1 ]; then
  note "Optional: a read key (monitor_key) lets jobs show findings and enables fail_on and the delta report."
  note "It sees the whole portfolio, so only add it if you want those features. Press Enter to skip."
  ask_secret "PatchWatch read key (optional, input hidden)"
  READ_KEY=$REPLY
fi
if [ -n "$READ_KEY" ]; then
  probe_key "$READ_KEY"
  case $PROBE_STATUS in
    200) good "The read key is accepted" ;;
    *) die "The read key was not accepted (HTTP $PROBE_STATUS)." "Use the monitor_key secret, or leave the read key empty." ;;
  esac
fi

# -- 5. templates ----------------------------------------------------------------------------------
step "Download the CI templates"
explain "Downloads $ARCHIVE_NAME and SHA256SUMS from the PatchWatch release, verifies the checksum and unpacks it" \
        "into a temporary directory. No GitLab token is sent. Nothing is written to your project yet."
TPL="$TMP/templates"
mkdir "$TPL"
if [ -n "$TEMPLATES_ARCHIVE" ]; then
  [ -r "$TEMPLATES_ARCHIVE" ] || die "Cannot read $TEMPLATES_ARCHIVE."
  cp "$TEMPLATES_ARCHIVE" "$TMP/$ARCHIVE_NAME"
  warn "Using a local archive, the checksum is NOT verified."
else
  case $RELEASE_BASE in
    @*|'') die "This copy of the script does not know where to download the templates." \
      "Use the script from the PatchWatch release page, or pass --release-url or --templates-archive." ;;
  esac
  note "Source: $RELEASE_BASE"
  curl -fsSL --max-time 120 -o "$TMP/$ARCHIVE_NAME" "$RELEASE_BASE/$ARCHIVE_NAME" 2>"$TMP/dl.err" \
    || die "Download of $ARCHIVE_NAME failed: $(tr '\n' ' ' <"$TMP/dl.err")" "Check $RELEASE_BASE in a browser."
  curl -fsSL --max-time 60 -o "$TMP/SHA256SUMS" "$RELEASE_BASE/SHA256SUMS" 2>"$TMP/dl.err" \
    || die "Download of SHA256SUMS failed: $(tr '\n' ' ' <"$TMP/dl.err")"
  _expected=$(awk -v n="$ARCHIVE_NAME" '$2 == n || $2 == "*" n {print $1; exit}' "$TMP/SHA256SUMS")
  [ -n "$_expected" ] || die "SHA256SUMS does not list $ARCHIVE_NAME." "The release may be incomplete. Nothing has been changed."
  [ "$(sha256_of "$TMP/$ARCHIVE_NAME")" = "$_expected" ] \
    || die "Checksum mismatch for $ARCHIVE_NAME." "The download is damaged or has been tampered with. Nothing has been changed."
  good "Checksum verified"
fi
tar -tzf "$TMP/$ARCHIVE_NAME" >"$TMP/archive.list" 2>/dev/null || die "$ARCHIVE_NAME is not a valid archive."
if grep -Eq '(^/|(^|/)\.\.(/|$))' "$TMP/archive.list"; then die "The archive contains unsafe paths. Nothing has been changed."; fi
tar -xzf "$TMP/$ARCHIVE_NAME" -C "$TPL"
[ -f "$TPL/ci-templates/sbom.yml" ] && [ -f "$TPL/VERSION" ] || die "The archive does not contain ci-templates/sbom.yml and VERSION."
TEMPLATE_VERSION=$(tr -d '\n' <"$TPL/VERSION")
ARCHIVE_IMAGE=
[ ! -f "$TPL/IMAGE" ] || ARCHIVE_IMAGE=$(tr -d '\n' <"$TPL/IMAGE")
good "PatchWatch CI templates $TEMPLATE_VERSION"

# -- repository facts (read only): tree, existing configuration ------------------------------------
: >"$TMP/tree"
TREE_OK=1
_page=1
while [ "$_page" -le 20 ]; do
  if api GET "projects/$PROJECT_ID/repository/tree?recursive=true&per_page=100&page=$_page&ref=$BRANCH_REF"; then
    jq -r '.[] | select(.type == "blob") | .path' "$BODY" >>"$TMP/tree"
    [ "$(jq 'length' "$BODY")" -ge 100 ] || break
  else
    TREE_OK=0; break
  fi
  _page=$((_page + 1))
done
grep -Ev '(^|/)(node_modules|vendor|third_party|\.git)/|^\.gitlab/patchwatch/' "$TMP/tree" >"$TMP/tree.f" || true
# repo_file PATH OUT: raw file from the default branch
repo_file() {
  _r="projects/$PROJECT_ID/repository/files/$(urlenc "$1")/raw?ref=$BRANCH_REF"
  if api GET "$_r"; then cp "$BODY" "$2"; return 0; fi
  return 1
}
CI_FILE_EXISTS=0
STAGES=
repo_file .gitlab-ci.yml "$TMP/ci.existing" && CI_FILE_EXISTS=1
PREV_FILE="$SETUP_DIR/patchwatch.yml"
PREV_JSON=
if repo_file "$PREV_FILE" "$TMP/prev.yml"; then
  PREV_JSON=$(sed -n 's/^# patchwatch-setup: //p' "$TMP/prev.yml" | head -n 1)
  printf '%s' "$PREV_JSON" | jq -e . >/dev/null 2>&1 || PREV_JSON=
fi
prev() { if [ -n "$PREV_JSON" ]; then printf '%s' "$PREV_JSON" | jq -r "$1 // empty"; fi; }
if [ -n "$PREV_JSON" ]; then
  note "Found an earlier PatchWatch setup in this project ($PREV_FILE, templates $(prev .version))."
  if [ "$UPDATE" != 1 ] && [ "$RECONFIGURE" = 1 ]; then note "Reconfiguring: your previous answers are offered as defaults."; fi
elif [ "$UPDATE" = 1 ]; then
  die "--update needs an earlier setup, but $PREV_FILE does not exist on $DEFAULT_BRANCH." \
    "Run the script without --update first (and merge its merge request)."
fi

# -- 6. choices ------------------------------------------------------------------------------------
step "Choose what to inventory"
if [ "$UPDATE" = 1 ]; then
  explain "--update keeps the configuration of the earlier setup and only refreshes the vendored template."
else
  explain "Looks at the file names in your repository (no file contents) and asks how the project should appear in" \
          "PatchWatch: one inventory for everything, or one per component (monorepo), plus services and images." \
          "Nothing is written in this step; you see the result before it is committed."
fi

# detection ----------------------------------------------------------------------------------------
MANIFEST_RE='(^|/)(package\.json|pyproject\.toml|requirements\.txt|go\.mod|pom\.xml|build\.gradle(\.kts)?|Cargo\.toml|composer\.json|Gemfile|Pipfile)$'
DOCKER_RE='(^|/)(Dockerfile(\.[^/]*)?|[^/]*\.Dockerfile)$'
COMPOSE_RE='(^|/)(docker-)?compose([.-][^/]*)?\.ya?ml$'
grep -E "$COMPOSE_RE" "$TMP/tree.f" >"$TMP/compose.list" || true
grep -E "$DOCKER_RE" "$TMP/tree.f" >"$TMP/docker.list" || true
grep -E "$MANIFEST_RE" "$TMP/tree.f" >"$TMP/manifest.list" || true
cat "$TMP/manifest.list" "$TMP/docker.list" | sed -n 's|/[^/]*$||p' | awk -F/ 'NF <= 3' | sort -u >"$TMP/candidates"
N_COMPOSE=$(wc -l <"$TMP/compose.list" | tr -d ' ')
N_DOCKER=$(wc -l <"$TMP/docker.list" | tr -d ' ')
N_MANIFEST=$(wc -l <"$TMP/manifest.list" | tr -d ' ')
N_CAND=$(wc -l <"$TMP/candidates" | tr -d ' ')
if [ "$TREE_OK" = 1 ]; then
  note "Found $N_MANIFEST dependency manifest(s), $N_DOCKER Dockerfile(s) and $N_COMPOSE Compose file(s); $N_CAND candidate component folder(s)."
else
  warn "Could not read the repository tree, so nothing can be suggested. You can still enter everything by hand."
fi

if [ "$UPDATE" = 1 ]; then
  STRUCTURE=$(prev .structure)
  COMPONENTS=$(printf '%s' "$PREV_JSON" | jq -r '.components[]? | [.name, .path, (.bsi // ""), (.images // "")] | join("|")')
  SERVICES=$(prev .services)
  DETECT_SERVICES=$(printf '%s' "$PREV_JSON" | jq -r '.detect_services | if . == null then "" else tostring end')
  SCAN_IMAGES=$(prev .images); TEAM=$(prev .team); ENVIRONMENT=$(prev .environment)
  BSI_MODE=$(prev .bsi_mode); BRANCHES=$(prev .branches); FAIL_ON=$(prev .fail_on)
  BSI_FILE=$(prev .bsi)
  COMPONENT_STAGE=$(prev .stage); IMAGE_STAGE=$(prev .image_stage)
  [ -n "$JOB_IMAGE" ] || JOB_IMAGE=${ARCHIVE_IMAGE:-$(prev .image)}
  [ -n "$DETECT_SERVICES" ] || DETECT_SERVICES=true
else
  STRUCTURE=
  COMPONENTS=
  SERVICES=$(words_of "$SERVICE_FLAGS")
  SCAN_IMAGES=$(words_of "$SCAN_IMAGE_FLAGS")
  BRANCHES=$(words_of "$BRANCH_FLAGS")
  BSI_FILE=
  P_STRUCTURE=$(prev .structure)
  # --- structure and components
  if [ -n "$COMPONENT_FLAGS" ]; then
    STRUCTURE=components
    for _c in $COMPONENT_FLAGS; do
      _n=${_c%%=*}; _p=${_c#*=}
      [ "$_n" != "$_c" ] || die "--component needs NAME=PATH (got: $_c)."
      valid name "$_n" || die "Invalid component name \"$_n\"." "Use lowercase letters, digits, '.', '_' and '-'."
      [ "$_n" != services ] || die "The component name \"services\" is reserved for the service inventory."
      valid path "$_p" || die "Invalid component path \"$_p\"."
      printf '%s' "$COMPONENTS" | grep -q "^$_n|" && die "Component \"$_n\" is given twice."
      COMPONENTS="$COMPONENTS$_n|${_p%/}||
"
    done
  elif [ "$NO_COMPONENTS" = 1 ]; then
    STRUCTURE=single
  elif [ "$YES" = 1 ]; then
    STRUCTURE=${P_STRUCTURE:-single}
    if [ "$STRUCTURE" = components ]; then
      COMPONENTS=$(printf '%s' "$PREV_JSON" | jq -r '.components[]? | [.name, .path, (.bsi // ""), (.images // "")] | join("|")')
    fi
  else
    _default=1
    [ "$N_CAND" -lt 2 ] || _default=2
    [ "$P_STRUCTURE" != components ] || _default=2
    [ "$P_STRUCTURE" != single ] || _default=1
    blank
    note "How should this repository appear in PatchWatch?"
    note "  1) One inventory for the whole repository (one project in PatchWatch)"
    note "  2) One inventory per component (a parent project with one child per component; for monorepos)"
    ask "Choose 1 or 2" "$_default"
    case $REPLY in 2) STRUCTURE=components ;; *) STRUCTURE=single ;; esac
    if [ "$STRUCTURE" = components ]; then
      if [ "$P_STRUCTURE" = components ] && confirm "Keep the components of the earlier setup?" y; then
        COMPONENTS=$(printf '%s' "$PREV_JSON" | jq -r '.components[]? | [.name, .path, (.bsi // ""), (.images // "")] | join("|")')
      else
        note "A component is a folder that gets its own inventory. Component names become part of the project name."
        while read -r _dir <&3; do
          [ -n "$_dir" ] || continue
          confirm "Add a component for the folder \"$_dir\"?" y || continue
          _default_name=$(basename "$_dir" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g; s/^[^a-z0-9]*//')
          while :; do
            ask "  Component name for $_dir" "$_default_name"
            if ! valid name "$REPLY"; then note "  Use lowercase letters, digits, '.', '_' and '-', starting with a letter or digit."
            elif [ "$REPLY" = services ]; then note "  \"services\" is reserved for the service inventory."
            elif printf '%s' "$COMPONENTS" | grep -q "^$REPLY|"; then note "  That name is already used."
            else break; fi
          done
          COMPONENTS="$COMPONENTS$REPLY|$_dir||
"
        done 3<"$TMP/candidates"
        while :; do
          ask "Add another component by hand as name=path (Enter to finish)" ""
          [ -n "$REPLY" ] || break
          _n=${REPLY%%=*}; _p=${REPLY#*=}
          if [ "$_n" = "$REPLY" ] || ! valid name "$_n" || [ "$_n" = services ] || ! valid path "$_p"; then
            note "  Use name=path, e.g. api=services/api (lowercase name, not \"services\")."; continue
          fi
          printf '%s' "$COMPONENTS" | grep -q "^$_n|" && { note "  That name is already used."; continue; }
          COMPONENTS="$COMPONENTS$_n|${_p%/}||
"
        done
      fi
    fi
  fi
  [ "$STRUCTURE" != components ] || [ -n "$(printf '%s' "$COMPONENTS" | tr -d '\n ')" ] \
    || die "No component was chosen." "Run again and choose a folder, or pass --component name=path / --no-components."

  # --- BSI metadata and images per component (only where files hint at them)
  find_bsi() { # find_bsi PATH
    if [ "$1" = . ]; then grep -Ei '^[^/]*bsi[^/]*\.json$' "$TMP/tree.f" | head -n 1
    else grep -Ei "^$1/[^/]*bsi[^/]*\.json\$" "$TMP/tree.f" | head -n 1; fi
  }
  if [ "$STRUCTURE" = components ]; then
    _new=
    while IFS='|' read -r _n _p _b _i <&3; do
      [ -n "$_n" ] || continue
      _f=$(find_bsi "$_p" || true)
      if [ -n "$_f" ] && [ -z "$_b" ] && confirm "Use $_f as BSI metadata for component $_n?" y; then _b=$_f; fi
      if grep -Eq "^$_p/" "$TMP/docker.list" 2>/dev/null && [ -z "$_i" ] && [ "$YES" != 1 ]; then
        note "Component $_n has a Dockerfile. If your pipeline builds and pushes its image, the image can be scanned too."
        ask "  Image of $_n to scan (e.g. \$CI_REGISTRY_IMAGE/$_n:\$CI_COMMIT_SHORT_SHA, Enter for none)" ""
        if [ -n "$REPLY" ] && valid imageref "$REPLY"; then _i=$REPLY; elif [ -n "$REPLY" ]; then note "  Not a valid image reference, skipped."; fi
      fi
      _new="$_new$_n|$_p|$_b|$_i
"
    done 3<<EOF
$COMPONENTS
EOF
    COMPONENTS=$_new
  else
    _f=$(find_bsi . || true)
    if [ -n "$_f" ] && confirm "Use $_f as BSI metadata?" y; then BSI_FILE=$_f; fi
  fi

  # --- services
  if [ -z "$DETECT_SERVICES" ]; then
    if [ "$N_COMPOSE" -gt 0 ]; then
      blank
      note "Services are read statically from Compose files (name and image only, no proof that they run). Found:"
      sed 's/^/    /' "$TMP/compose.list"
      if confirm "List the services of these Compose files in PatchWatch?" y; then DETECT_SERVICES=true; else DETECT_SERVICES=false; fi
    else
      DETECT_SERVICES=true
    fi
  fi
  if [ -z "$SERVICES" ] && [ "$YES" != 1 ]; then
    ask "Additional service names, space-separated (Enter for none)" "$(prev .services)"
    SERVICES=$(words_of "$REPLY")
  elif [ -z "$SERVICES" ]; then
    SERVICES=$(prev .services)
  fi

  # --- images (single layout)
  if [ "$STRUCTURE" = single ] && [ -z "$SCAN_IMAGES" ] && [ "$YES" != 1 ]; then
    _hint=
    [ "$N_DOCKER" -eq 0 ] || _hint='$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA'
    if [ "$N_DOCKER" -gt 0 ]; then
      note "The repository has $N_DOCKER Dockerfile(s). If your pipeline builds and pushes an image before the scan stage, it can be scanned too."
    fi
    ask "Images to scan, space-separated (Enter for none)" "$(prev .images)"
    SCAN_IMAGES=$(words_of "$REPLY")
    [ -z "$SCAN_IMAGES" ] || [ -n "$_hint" ] || true
  elif [ "$STRUCTURE" = single ] && [ -z "$SCAN_IMAGES" ]; then
    SCAN_IMAGES=$(prev .images)
  fi

  # --- team, environment, BSI mode, branches, fail_on
  [ -n "$TEAM" ] || { ask "Owning team (routes alerts; Enter uses the top-level GitLab group)" "$(prev .team)"; TEAM=$REPLY; }
  [ -n "$ENVIRONMENT" ] || { ask "Environment tag, e.g. production (Enter for none)" "$(prev .environment)"; ENVIRONMENT=$REPLY; }
  if [ -z "$BSI_MODE" ]; then
    note "BSI mode: \"report\" uploads even when mandatory BSI fields are missing. \"enforce\" refuses such uploads and fails the job."
    note "Start with report and switch to enforce once the BSI metadata is complete (docs/usage/bsi-sbom.md)."
    ask "BSI mode (report or enforce)" "$(prev .bsi_mode)"; BSI_MODE=${REPLY:-report}
  fi
  if [ -z "$BRANCHES" ] && [ "$YES" != 1 ]; then
    ask "Branches besides $DEFAULT_BRANCH and tags that may upload, space-separated (Enter for none)" "$(prev .branches)"
    BRANCHES=$(words_of "$REPLY")
  elif [ -z "$BRANCHES" ]; then BRANCHES=$(prev .branches); fi
  if [ -n "$READ_KEY" ]; then
    if [ -z "$FAIL_ON" ]; then
      note "fail_on: fail the job when the project has policy violations (none, warn or fail)."
      ask "fail_on" "$(prev .fail_on)"; FAIL_ON=${REPLY:-none}
    fi
  else
    if [ -n "$FAIL_ON" ] && [ "$FAIL_ON" != none ]; then die "--fail-on $FAIL_ON needs a read key (PATCHWATCH_READ_KEY)."; fi
    FAIL_ON=none
  fi

  # --- stages and job image
  if [ "$CI_FILE_EXISTS" = 1 ]; then
    cat >"$TMP/stages.awk" <<'AWK'
/^stages:[ \t]*\[/ { sub(/^stages:[ \t]*\[/, ""); sub(/\].*$/, ""); gsub(/['"]/, ""); gsub(/[ ,]+/, " "); print; exit }
/^stages:[ \t]*$/ { inblock = 1; next }
inblock && /^[ \t]*-[ \t]*/ { s = $0; sub(/^[ \t]*-[ \t]*/, "", s); sub(/[ \t]*#.*$/, "", s); gsub(/['"]/, "", s); out = out s " "; next }
inblock && /^[^ \t#-]/ { exit }
END { if (out != "") print out }
AWK
    STAGES=$(awk -f "$TMP/stages.awk" "$TMP/ci.existing" | sed 's/ *$//')
  else
    STAGES=
  fi
  _first_stage='test'
  if [ -n "$STAGES" ]; then
    note "Your .gitlab-ci.yml defines the stages: $STAGES"
    case " $STAGES " in *" test "*) _first_stage='test' ;; *) _first_stage=${STAGES%% *} ;; esac
  fi
  note "The parent job runs in the built-in stage .pre. The inventory jobs need a stage of your pipeline."
  [ -n "$COMPONENT_STAGE" ] || { ask "Stage of the inventory jobs" "${_first_stage}"; COMPONENT_STAGE=$REPLY; }
  _needs_image_stage=0
  [ -z "$SCAN_IMAGES" ] || _needs_image_stage=1
  printf '%s' "$COMPONENTS" | awk -F'|' 'NF > 3 && $4 != "" {f = 1} END {exit !f}' && _needs_image_stage=1
  if [ "$_needs_image_stage" = 1 ]; then
    [ -n "$IMAGE_STAGE" ] || { note "Jobs that scan images must run after the stage that builds and pushes them."; ask "Stage of the jobs that scan images" "$COMPONENT_STAGE"; IMAGE_STAGE=$REPLY; }
  fi
  [ -n "$IMAGE_STAGE" ] || IMAGE_STAGE=$COMPONENT_STAGE
  if [ -z "$JOB_IMAGE" ]; then
    if [ -n "$ARCHIVE_IMAGE" ]; then JOB_IMAGE=$ARCHIVE_IMAGE
    else
      note "The jobs run in the PatchWatch CI image (Syft and the PatchWatch CI module)."
      ask "CI job image (ghcr.io/<owner>/<repo>/ci:vX.Y.Z)" "$(prev .image)"; JOB_IMAGE=$REPLY
    fi
  fi
fi

# validation of everything that ends up in YAML ----------------------------------------------------
case $BSI_MODE in report|enforce) ;; *) die "BSI mode must be report or enforce (got: $BSI_MODE)." ;; esac
case $FAIL_ON in none|warn|fail) ;; *) die "fail_on must be none, warn or fail (got: $FAIL_ON)." ;; esac
case $DETECT_SERVICES in true|false) ;; *) die "Internal error: detect_services is \"$DETECT_SERVICES\"." ;; esac
[ -z "$TEAM" ] || valid name "$TEAM" || die "Invalid team \"$TEAM\"." "Use lowercase letters, digits, '.', '_' and '-'."
[ -z "$ENVIRONMENT" ] || valid name "$ENVIRONMENT" || die "Invalid environment \"$ENVIRONMENT\"." "Use lowercase letters, digits, '.', '_' and '-'."
for _s in $SERVICES; do valid word "$_s" || die "Invalid service name \"$_s\"." "Use letters, digits, '.', '_' and '-'."; done
for _i in $SCAN_IMAGES; do valid imageref "$_i" || die "Invalid image reference \"$_i\"."; done
for _b in $BRANCHES; do valid branch "$_b" || die "Invalid branch name \"$_b\"."; done
valid stage "$COMPONENT_STAGE" || die "Invalid stage \"$COMPONENT_STAGE\"."
valid stage "$IMAGE_STAGE" || die "Invalid stage \"$IMAGE_STAGE\"."
[ -n "$JOB_IMAGE" ] || die "No CI job image known." "Pass --job-image ghcr.io/<owner>/<repo>/ci:vX.Y.Z."
valid imageref "$JOB_IMAGE" || die "Invalid job image \"$JOB_IMAGE\"."
[ -z "$BSI_FILE" ] || valid path "$BSI_FILE" || die "Invalid BSI metadata path \"$BSI_FILE\"."
printf '%s\n' "$COMPONENTS" | while IFS='|' read -r _n _p _b _i; do
  [ -n "$_n" ] || continue
  valid name "$_n" && valid path "$_p" && { [ -z "$_b" ] || valid path "$_b"; } && { [ -z "$_i" ] || valid imageref "$_i"; } || exit 1
done || die "A component in the configuration is invalid (name, path, BSI file or image)."
if [ -n "$STAGES" ]; then
  for _s in $COMPONENT_STAGE $IMAGE_STAGE; do
    case " $STAGES .pre .post " in *" $_s "*) ;; *) warn "Stage \"$_s\" is not in the stages of your .gitlab-ci.yml ($STAGES). The pipeline would be invalid; the check in step 8 will tell." ;; esac
  done
fi

# generation ---------------------------------------------------------------------------------------
emit() { # emit KEY VALUE: quoted input, skipped when empty
  [ -z "$2" ] || printf '      %s: %s\n' "$1" "$(yq "$2")"
}
emit_bool() { printf '      %s: %s\n' "$1" "$2"; }
run_if_expr() {
  if [ -z "$BRANCHES" ]; then return 0; fi
  _expr='$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  for _b in $BRANCHES; do _expr="$_expr || \$CI_COMMIT_BRANCH == \"$_b\""; done
  printf '$CI_COMMIT_TAG || ($CI_COMMIT_BRANCH && (%s))' "$_expr"
}
TEMPLATE_LOCAL="$SETUP_DIR/sbom.yml"
generate_config() {
  _header=$(jq -nc \
    --arg version "$TEMPLATE_VERSION" --arg structure "$STRUCTURE" --arg services "$SERVICES" \
    --arg detect "$DETECT_SERVICES" --arg images "$SCAN_IMAGES" --arg team "$TEAM" --arg environment "$ENVIRONMENT" \
    --arg bsi_mode "$BSI_MODE" --arg branches "$BRANCHES" --arg fail_on "$FAIL_ON" --arg bsi "$BSI_FILE" \
    --arg stage "$COMPONENT_STAGE" --arg image_stage "$IMAGE_STAGE" --arg image "$JOB_IMAGE" \
    --arg components "$COMPONENTS" \
    '{version: $version, structure: $structure, services: $services, detect_services: ($detect == "true"), images: $images,
      team: $team, environment: $environment, bsi_mode: $bsi_mode, branches: $branches, fail_on: $fail_on, bsi: $bsi,
      stage: $stage, image_stage: $image_stage, image: $image,
      components: [$components | split("\n")[] | select(length > 0) | split("|") | {name: .[0], path: .[1], bsi: .[2], images: .[3]}]}')
  _run_if=$(run_if_expr)
  printf '# SPDX-License-Identifier: Apache-2.0\n'
  printf '# Generated by setup-gitlab-project.sh for PatchWatch %s. Do not edit by hand:\n' "$TEMPLATE_VERSION"
  printf '# run the script again (--reconfigure to change answers, --update to refresh the template).\n'
  printf '# patchwatch-setup: %s\n' "$_header"
  printf 'include:\n'
  if [ "$STRUCTURE" = components ]; then
    printf '  - local: %s\n    inputs:\n' "$TEMPLATE_LOCAL"
    printf '      job_name: patchwatch-sbom-parent\n      stage: .pre\n'
    emit image "$JOB_IMAGE"
    printf '      mode: parent\n'
    emit team "$TEAM"; emit environment "$ENVIRONMENT"
    emit services "$SERVICES"
    emit_bool detect_services "$DETECT_SERVICES"
    emit run_if "$_run_if"
    printf '%s\n' "$COMPONENTS" | while IFS='|' read -r _n _p _b _i; do
      [ -n "$_n" ] || continue
      printf '  - local: %s\n    inputs:\n' "$TEMPLATE_LOCAL"
      printf '      job_name: %s\n' "patchwatch-sbom-$_n"
      if [ -n "$_i" ]; then emit stage "$IMAGE_STAGE"; else emit stage "$COMPONENT_STAGE"; fi
      emit image "$JOB_IMAGE"
      emit component "$_n"
      emit scan_paths "$_p"
      emit images "$_i"
      emit_bool detect_services false
      emit team "$TEAM"; emit environment "$ENVIRONMENT"
      printf '      bsi_mode: %s\n' "$BSI_MODE"
      emit bsi_metadata "$_b"
      emit branches "$BRANCHES"
      emit run_if "$_run_if"
      [ "$FAIL_ON" = none ] || emit fail_on "$FAIL_ON"
    done
  else
    printf '  - local: %s\n    inputs:\n' "$TEMPLATE_LOCAL"
    if [ -n "$SCAN_IMAGES" ]; then emit stage "$IMAGE_STAGE"; else emit stage "$COMPONENT_STAGE"; fi
    emit image "$JOB_IMAGE"
    emit team "$TEAM"; emit environment "$ENVIRONMENT"
    emit images "$SCAN_IMAGES"
    emit services "$SERVICES"
    emit_bool detect_services "$DETECT_SERVICES"
    printf '      bsi_mode: %s\n' "$BSI_MODE"
    emit bsi_metadata "$BSI_FILE"
    emit branches "$BRANCHES"
    emit run_if "$_run_if"
    [ "$FAIL_ON" = none ] || emit fail_on "$FAIL_ON"
  fi
}
generate_config >"$TMP/patchwatch.yml"
cp "$TPL/ci-templates/sbom.yml" "$TMP/sbom.yml"

# the .gitlab-ci.yml change
INCLUDE_LINE="  - local: $SETUP_DIR/patchwatch.yml"
CI_ACTION=skip
CI_MANUAL=0
if [ "$CI_FILE_EXISTS" = 0 ]; then
  CI_ACTION=create
  printf 'include:\n%s\n' "$INCLUDE_LINE" >"$TMP/ci.new"
elif grep -Eq "local:[[:space:]]*['\"]?/?$SETUP_DIR/patchwatch\.yml" "$TMP/ci.existing"; then
  CI_ACTION=skip
elif grep -Eq '^include:' "$TMP/ci.existing"; then
  CI_ACTION=manual; CI_MANUAL=1
else
  CI_ACTION=update
  { cat "$TMP/ci.existing"; [ -z "$(tail -c1 "$TMP/ci.existing")" ] || printf '\n'; printf '\ninclude:\n%s\n' "$INCLUDE_LINE"; } >"$TMP/ci.new"
fi

blank
note "Plan"
if [ "$STRUCTURE" = components ]; then
  note "  Layout: one inventory per component below the parent project $PROJECT_PATH"
  printf '%s\n' "$COMPONENTS" | while IFS='|' read -r _n _p _b _i; do
    [ -n "$_n" ] || continue
    printf '    job patchwatch-sbom-%s  stage %s  scans %s  ->  PatchWatch project %s/%s\n' "$_n" "$( [ -n "$_i" ] && printf '%s' "$IMAGE_STAGE" || printf '%s' "$COMPONENT_STAGE")" "$_p" "$PROJECT_PATH" "$_n"
  done
  printf '    job patchwatch-sbom-parent  stage .pre  creates the parent project %s (and %s/services)\n' "$PROJECT_PATH" "$PROJECT_PATH"
else
  printf '  Layout: one inventory  ->  PatchWatch project %s\n' "$PROJECT_PATH"
  printf '    job patchwatch-sbom  stage %s  scans the whole repository%s\n' "$( [ -n "$SCAN_IMAGES" ] && printf '%s' "$IMAGE_STAGE" || printf '%s' "$COMPONENT_STAGE")" "$( [ -n "$SCAN_IMAGES" ] && printf ' and the images %s' "$SCAN_IMAGES")"
fi
note "  Services: Compose detection $DETECT_SERVICES${SERVICES:+, plus $SERVICES}"
note "  Runs on: the default branch ($DEFAULT_BRANCH) and tags${BRANCHES:+, plus the branches $BRANCHES}"
note "  BSI mode: $BSI_MODE; team: ${TEAM:-top-level GitLab group}; environment: ${ENVIRONMENT:-none}; fail_on: $FAIL_ON"
note "  Job image: $JOB_IMAGE"
blank
note "Generated $SETUP_DIR/patchwatch.yml:"
sed 's/^/    | /' "$TMP/patchwatch.yml"
if [ "$UPDATE" != 1 ] && [ "$YES" != 1 ]; then
  blank
  confirm "Continue with this configuration?" y || die "Stopped at your request." "Nothing has been written."
fi

# -- 7. variables ----------------------------------------------------------------------------------
step "Store the CI/CD variables"
if [ "$UPDATE" = 1 ]; then
  explain "--update does not touch the CI/CD variables."
  kept "variables unchanged (--update)"
else
  explain "Creates the variables PATCHWATCH_URL and PATCHWATCH_UPLOAD_KEY (and PATCHWATCH_READ_KEY / PATCHWATCH_CA_CERT if given)" \
          "in the $VARS_SCOPE. Keys are masked and protected. A variable that already exists with the right settings is kept." \
          "Values are never shown."
  # set_var KEY VALUE PROTECTED MASKED TYPE
  set_var() {
    _k=$1; _v=$2; _prot=$3; _mask=$4; _type=$5
    _state=missing
    if var_exists "$_k"; then
      _cur_prot=$(var_field "$_k" protected); _cur_mask=$(var_field "$_k" masked); _cur_type=$(var_field "$_k" variable_type)
      _cur_val=$(var_field "$_k" value)
      if [ "$_cur_prot" != "$_prot" ] || [ "$_cur_mask" != "$_mask" ] || [ "$_cur_type" != "$_type" ]; then _state=flags
      elif [ "$_cur_val" != "$_v" ] && [ "$FORCE" = 1 ]; then _state=value
      elif [ "$_cur_val" != "$_v" ]; then _state=differs
      else _state=ok; fi
    fi
    case $_state in
      ok) kept "$_k: already correct, kept" ;;
      differs) kept "$_k: exists with a different value, kept (use --force to overwrite)"
               record "kept the existing value of $_k, which differs from the one you gave" ;;
      *)
        if write_gate "set the variable $_k ($_state)"; then
          printf '%s' "$_v" >"$TMP/value"
          jq -n --arg k "$_k" --rawfile v "$TMP/value" --argjson p "$_prot" --argjson m "$_mask" --arg t "$_type" \
            '{key: $k, value: $v, protected: $p, masked: $m, variable_type: $t, raw: true, environment_scope: "*"}' >"$TMP/var.json"
          if [ "$_state" = missing ]; then
            api_must POST "$VARS_PATH" "$TMP/var.json" "create the variable $_k"
            good "$_k created"; record "created the variable $_k"
          else
            api_must PUT "$VARS_PATH/$_k?filter%5Benvironment_scope%5D=*" "$TMP/var.json" "update the variable $_k"
            fixed "$_k updated ($_state)"; record "updated the variable $_k"
          fi
          rm -f "$TMP/value" "$TMP/var.json"
        fi ;;
    esac
  }
  if confirm "Write the variables to the $VARS_SCOPE?" y; then
    set_var PATCHWATCH_URL "$PATCHWATCH_URL" false false env_var
    if [ "$KEY_FROM_VARIABLE" = 1 ]; then kept "PATCHWATCH_UPLOAD_KEY: kept the stored key"
      _cp=$(var_field PATCHWATCH_UPLOAD_KEY protected); _cm=$(var_field PATCHWATCH_UPLOAD_KEY masked)
      if [ "$_cp" != true ] || [ "$_cm" != true ]; then set_var PATCHWATCH_UPLOAD_KEY "$UPLOAD_KEY" true true env_var; fi
    else set_var PATCHWATCH_UPLOAD_KEY "$UPLOAD_KEY" true true env_var; fi
    [ -z "$READ_KEY" ] || set_var PATCHWATCH_READ_KEY "$READ_KEY" true true env_var
    [ -z "$CA_CERT_CONTENT" ] || set_var PATCHWATCH_CA_CERT "$CA_CERT_CONTENT" false false file
  else
    warn "Variables not written. The jobs cannot upload until PATCHWATCH_URL and PATCHWATCH_UPLOAD_KEY exist."
    record "NOT DONE: create the CI/CD variables PATCHWATCH_URL and PATCHWATCH_UPLOAD_KEY (protected, masked) in $VARS_SCOPE"
  fi
fi
UPLOAD_KEY=; READ_KEY=

# -- 8. merge request ------------------------------------------------------------------------------
step "Create the merge request"
explain "Commits the CI configuration to a new branch, validates it with GitLab's CI lint and opens a merge request." \
        "Nothing is committed to $DEFAULT_BRANCH. You review and merge the request yourself."

# classify each file against the default branch
ACTIONS="$TMP/actions.json"
echo '[]' >"$ACTIONS"
CHANGES=0
add_action() { # add_action PATH LOCALFILE
  _ap=$1; _af=$2
  if repo_file "$_ap" "$TMP/remote.tmp"; then
    if cmp -s "$TMP/remote.tmp" "$_af"; then kept "$_ap: unchanged"; return 0; fi
    _act=update
    if [ "$_ap" = "$SETUP_DIR/sbom.yml" ]; then
      note "$_ap differs from the template $TEMPLATE_VERSION. Changes:"
      diff -u "$TMP/remote.tmp" "$_af" | sed 's/^/    /' | head -n 40 || true
    fi
  else _act=create; fi
  jq --arg a "$_act" --arg p "$_ap" --rawfile c "$_af" '. + [{action: $a, file_path: $p, content: $c}]' "$ACTIONS" >"$ACTIONS.next" && mv "$ACTIONS.next" "$ACTIONS"
  CHANGES=$((CHANGES + 1))
  note "$_act  $_ap"
}
add_action "$SETUP_DIR/sbom.yml" "$TMP/sbom.yml"
add_action "$SETUP_DIR/patchwatch.yml" "$TMP/patchwatch.yml"
case $CI_ACTION in
  create|update) add_action .gitlab-ci.yml "$TMP/ci.new" ;;
  skip) kept ".gitlab-ci.yml: already includes $SETUP_DIR/patchwatch.yml" ;;
  manual)
    warn ".gitlab-ci.yml already has an include: section, which the script does not rewrite."
    note "Add this line to that list yourself (in the merge request or afterwards):"
    note "$INCLUDE_LINE"
    record "TODO: add \"$INCLUDE_LINE\" to the include: list of .gitlab-ci.yml"
    ;;
esac

MR_URL=
LINT_NOTE=
if [ "$CHANGES" = 0 ]; then
  good "Nothing to commit: the project is already up to date"
  record "no changes were necessary"
elif write_gate "create the branch $BRANCH_NAME, commit $CHANGES file(s) and open a merge request"; then
  confirm "Commit $CHANGES file(s) to a new branch and open a merge request?" y || die "Stopped at your request." "Variables may already have been written in step 7."
  _branch=$BRANCH_NAME
  if api GET "projects/$PROJECT_ID/repository/branches/$(urlenc "$_branch")"; then
    _branch="$BRANCH_NAME-$(date +%Y%m%d%H%M%S)"
    warn "The branch $BRANCH_NAME already exists; using $_branch instead."
  fi
  if [ "$UPDATE" = 1 ]; then _msg="Update PatchWatch CI templates to $TEMPLATE_VERSION"; else _msg="Add PatchWatch SBOM jobs"; fi
  jq -n --arg b "$_branch" --arg s "$DEFAULT_BRANCH" --arg m "$_msg" --slurpfile a "$ACTIONS" \
    '{branch: $b, start_branch: $s, commit_message: $m, actions: $a[0]}' >"$TMP/commit.json"
  api_must POST "projects/$PROJECT_ID/repository/commits" "$TMP/commit.json" "commit to the new branch"
  good "Committed to branch $_branch"
  record "committed $CHANGES file(s) to the branch $_branch"
  LINT_OK=1
  if api GET "projects/$PROJECT_ID/ci/lint?content_ref=$(urlenc "$_branch")"; then
    if [ "$(jq -r '.valid' "$BODY")" = true ]; then
      good "GitLab CI lint: the configuration is valid"
    else
      LINT_OK=0
      printf '  %s CI lint reports errors:\n' "$S_FAIL"
      jq -r '.errors[]? | "    - " + .' "$BODY"
    fi
  else
    LINT_NOTE="GitLab could not validate the configuration automatically (HTTP $HTTP_STATUS). Check it in the pipeline editor."
    warn "$LINT_NOTE"
  fi
  if [ "$LINT_OK" = 0 ]; then
    record "NOT DONE: merge request. The branch $_branch has errors; fix them there or delete it, then run again"
    die "The generated configuration is invalid, so no merge request was opened." \
      "The branch $_branch contains the files; open it in $WEB_URL/-/tree/$_branch to inspect them." \
      "Run the script again with --reconfigure after fixing the cause (often the stage names)."
  fi
  jq -n --arg s "$_branch" --arg t "$DEFAULT_BRANCH" --arg title "$_msg" --arg d "Generated by setup-gitlab-project.sh (PatchWatch $TEMPLATE_VERSION).

Adds the SBOM jobs that upload this project's inventory to PatchWatch. After merging, the jobs run on $DEFAULT_BRANCH and on tags.
The CI/CD variables PATCHWATCH_URL and PATCHWATCH_UPLOAD_KEY must exist in the project or its group." \
    '{source_branch: $s, target_branch: $t, title: $title, description: $d, remove_source_branch: true}' >"$TMP/mr.json"
  api_must POST "projects/$PROJECT_ID/merge_requests" "$TMP/mr.json" "open the merge request"
  MR_URL=$(jq -r '.web_url' "$BODY")
  good "Merge request opened: $MR_URL"
  record "opened the merge request $MR_URL"
fi

# -- summary ---------------------------------------------------------------------------------------
DOCS_URL=
case $RELEASE_BASE in https://github.com/*/releases/download/*) DOCS_URL="${RELEASE_BASE%%/releases/download/*}/blob/main/docs/usage/ci-integration.md" ;; esac

printf '\n%s== Summary ==%s\n\n' "$BOLD" "$RESET"
printf '%sWhat the script did%s\n' "$BOLD" "$RESET"
if [ -s "$TMP/summary" ]; then sed 's/^/  - /' "$TMP/summary"; else note "- nothing was written"; fi
[ "$DRY_RUN" != 1 ] || note "- dry run: nothing was written at all"

printf '\n%sWhat you need to do now%s\n' "$BOLD" "$RESET"
_n=1
if [ "$DRY_RUN" = 1 ]; then
  note "$_n. Run the script again without --dry-run to apply the plan above."; _n=$((_n + 1))
fi
if [ -n "$MR_URL" ]; then
  note "$_n. Review and merge the merge request: $MR_URL"; _n=$((_n + 1))
  note "$_n. After the merge, wait for the pipeline on $DEFAULT_BRANCH ($WEB_URL/-/pipelines)."
  note "   The job(s) named patchwatch-sbom* must be green."; _n=$((_n + 1))
fi
if [ "$CI_MANUAL" = 1 ]; then
  note "$_n. Add this line to the include: list in .gitlab-ci.yml: $INCLUDE_LINE"; _n=$((_n + 1))
fi
if [ "$DRY_RUN" != 1 ]; then
  if [ "$STRUCTURE" = components ]; then
    note "$_n. Open PatchWatch ($PATCHWATCH_URL) and check these projects appear:"
    note "   $PROJECT_PATH (parent), $PROJECT_PATH/services (if services were found)"
    printf '%s\n' "$COMPONENTS" | while IFS='|' read -r _cn _cp _cb _ci; do [ -z "$_cn" ] || note "   $PROJECT_PATH/$_cn"; done
  else
    note "$_n. Open PatchWatch ($PATCHWATCH_URL) and check that the project $PROJECT_PATH appears."
  fi
  _n=$((_n + 1))
  note "$_n. Revoke the GitLab access token if you created it only for this script:"
  note "   $GITLAB_URL/-/user_settings/personal_access_tokens"; _n=$((_n + 1))
  if [ "$BSI_MODE" = report ]; then
    note "$_n. Optional: complete the BSI metadata, then run again with --reconfigure and choose --bsi-mode enforce."
    [ -z "$DOCS_URL" ] || note "   Documentation: $DOCS_URL"
  fi
fi

printf '\n%sIf something goes wrong%s\n' "$BOLD" "$RESET"
note "- Job says the upload key or URL is missing: the variables are protected, so the branch or tag must be protected too."
note "- 404 \"parent not found\": the parent job did not run first; check the stage of patchwatch-sbom-parent (.pre)."
note "- The runner cannot pull the job image: make the ghcr.io package of the image public, or mirror it."
note "- The pipeline is invalid: run the script again with --reconfigure and pick stages that exist in your .gitlab-ci.yml."
[ -z "$DOCS_URL" ] || note "- Full documentation and troubleshooting: $DOCS_URL"
blank
