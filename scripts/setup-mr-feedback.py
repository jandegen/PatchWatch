#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision same-project MR feedback using the existing glab login; never prints keys.

Run after merging the templates with --activate. Without that flag, prepare a disabled
schedule so provisioning before merge cannot accidentally run the old default-branch CI.
"""
import argparse
from datetime import date, timedelta
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import quote, urlsplit

SCOPE = "patchwatch-mr-feedback"
SCHEDULE = "PatchWatch MR findings"


def api(endpoint, payload=None, method=None, hostname=None):
    args = ["glab", "api", endpoint]
    if hostname:
        args += ["--hostname", hostname]
    if method:
        args += ["--method", method]
    if payload is None:
        result = subprocess.run(args, check=True, capture_output=True, text=True)
    else:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as stream:
            json.dump(payload, stream)
            stream.flush()
            result = subprocess.run(args + ["--input", stream.name, "--header", "Content-Type: application/json"],
                                    check=True, capture_output=True, text=True)
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except ValueError:
        return result.stdout


def provision(project, call, *, activate=False, ca_cert=None):
    info = call(f"projects/{project}")
    branch = info['default_branch']
    if not call(f"projects/{project}/repository/branches/" + quote(branch, safe='')).get('protected'):
        raise ValueError("Protect the default branch before configuring MR credentials")
    variables = []
    page = 1
    while True:
        batch = call(f"projects/{project}/variables?per_page=100&page={page}")
        variables.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    available = {v['key']: v for v in variables if v.get('environment_scope', '*') in ('*', SCOPE)}
    for name in ('PATCHWATCH_URL', 'PATCHWATCH_UPLOAD_KEY', 'PATCHWATCH_READ_KEY'):
        if name not in available or not available[name].get('value'):
            raise ValueError(f"Configure {name} in the project before running setup")
        if name.endswith('_KEY') and not available[name].get('protected'):
            raise ValueError(f"{name} must be protected")
    if activate:
        config = call(f"projects/{project}/repository/files/.gitlab-ci.yml/raw?ref=" + quote(branch, safe=''))
        if not isinstance(config, str) or 'mr-feedback.yml' not in config:
            raise ValueError("Merge the MR feedback include on the default branch before activating the schedule")
    # Prevent protected variables being passed to any MR pipeline, including protected sources.
    call(f"projects/{project}", {'protect_merge_request_pipelines': False}, 'PUT')

    def variable(key, value, masked=False, file=False):
        existing = available.get(key)
        if existing:
            if not existing.get('protected'):
                raise ValueError(f"Existing {key} must be protected")
            return
        call(f"projects/{project}/variables", {'key': key, 'value': value, 'protected': True,
             'masked': masked, 'raw': True, 'environment_scope': SCOPE,
             'variable_type': 'file' if file else 'env_var'}, 'POST')
        print(f"Configured protected {key} (scope {SCOPE})")

    origin = urlsplit(info['web_url'])
    variable('PATCHWATCH_GITLAB_URL', f"{origin.scheme}://{origin.netloc}")
    if 'PATCHWATCH_GITLAB_TOKEN' not in available:
        access = call(f"projects/{project}/access_tokens", {'name': 'patchwatch-mr-feedback',
                      'scopes': ['api'], 'access_level': 30,
                      'expires_at': (date.today() + timedelta(days=90)).isoformat()}, 'POST')
        try:
            variable('PATCHWATCH_GITLAB_TOKEN', access['token'], masked=True)
        except Exception:
            call(f"projects/{project}/access_tokens/{access['id']}", method='DELETE')
            raise
        print(f"Project bot created (Developer, api); expires {access['expires_at']}")
    elif not available['PATCHWATCH_GITLAB_TOKEN'].get('protected'):
        raise ValueError('Existing PATCHWATCH_GITLAB_TOKEN must be protected')
    if ca_cert:
        variable('PATCHWATCH_CA_CERT', ca_cert, file=True)
    schedules = call(f"projects/{project}/pipeline_schedules?per_page=100")
    existing = next((s for s in schedules if s['description'] == SCHEDULE), None)
    payload = {'description': SCHEDULE, 'ref': branch, 'cron': '*/5 * * * *',
               'cron_timezone': 'UTC', 'active': activate}
    if existing:
        schedule = call(f"projects/{project}/pipeline_schedules/{existing['id']}", payload, 'PUT')
    else:
        schedule = call(f"projects/{project}/pipeline_schedules", payload, 'POST')
    endpoint = f"projects/{project}/pipeline_schedules/{schedule['id']}"
    detail = call(endpoint)
    present = any(v['key'] == 'PATCHWATCH_MR_FEEDBACK' for v in detail.get('variables', []))
    call(endpoint + '/variables' + ('/PATCHWATCH_MR_FEEDBACK' if present else ''),
         {'key': 'PATCHWATCH_MR_FEEDBACK', 'value': 'true'}, 'PUT' if present else 'POST')
    print(f"Schedule {schedule['id']}: {'active' if activate else 'prepared, disabled until merge'} (every five minutes on {branch})")
    return schedule


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=int, default=120)
    parser.add_argument('--hostname')
    parser.add_argument('--ca-cert', type=Path, help='Public CA bundle installed as a protected file variable')
    parser.add_argument('--activate', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        def call(endpoint, payload=None, method=None):
            return api(endpoint, payload, method, args.hostname)
        provision(args.project, call, activate=args.activate,
                  ca_cert=args.ca_cert.read_text() if args.ca_cert else None)
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'MR feedback setup failed ({type(error).__name__}); check protected variables and GitLab access\n')


if __name__ == '__main__':
    main()
