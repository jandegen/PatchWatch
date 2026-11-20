#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Configure the GitHub mirror of the release pipeline (ci/release.yml: mirror-github, release-github-images, release-github).

Uses the existing glab login. First reports which of the protected CI/CD variables GITHUB_MIRROR_URL,
GITHUB_MIRROR_TOKEN (masked), MIRROR_FORBIDDEN_PATTERNS and GITHUB_GHCR_TOKEN (masked, optional: classic PAT
with write:packages, without it the images are not published) already exist and are protected/masked.
Only missing or wrongly flagged variables are asked for and written; a correct variable is kept as it is
unless --force is given. Tokens are read from the environment (GITHUB_MIRROR_TOKEN, GITHUB_GHCR_TOKEN) or a
hidden prompt, never from an argument, and are never printed. New tokens are checked against GitHub first
(--skip-check disables that). Finally the tags v* are protected. Creating the GitHub repository and the tokens
(see docs/operations/release.md) stays a manual step; GitHub has no API for it.
"""
import argparse
from getpass import getpass
import json
import os
import re
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

URL_PATTERN = re.compile(r'^https://github\.com/([\w.-]+/[\w.-]+)\.git$')
TAG_PROTECTION = 'v*'
MAINTAINER = 40
VARIABLES = {'GITHUB_MIRROR_URL': False, 'GITHUB_MIRROR_TOKEN': True,
             'MIRROR_FORBIDDEN_PATTERNS': False, 'GITHUB_GHCR_TOKEN': True}  # name: masked
OPTIONAL = {'GITHUB_GHCR_TOKEN'}


def api(endpoint, payload=None, method=None, hostname=None):
    args = ['glab', 'api', endpoint]
    if hostname:
        args += ['--hostname', hostname]
    if method:
        args += ['--method', method]
    if payload is None:
        result = subprocess.run(args, check=True, capture_output=True, text=True)
    else:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as stream:
            json.dump(payload, stream)
            stream.flush()
            result = subprocess.run(args + ['--input', stream.name, '--header', 'Content-Type: application/json'],
                                    check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def github_get(url, token):
    """(status, headers, json) of an authenticated GitHub API GET."""
    request = Request(url, headers={'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json',
                                    'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with urlopen(request, timeout=30) as response:
            return response.status, response.headers, json.load(response)
    except HTTPError as error:
        return error.code, error.headers, None
    except URLError:
        raise ValueError('GitHub is not reachable (use --skip-check to skip the token check)')


def validate_url(url):
    if not URL_PATTERN.match(url or ''):
        raise ValueError('URL must look like https://github.com/<owner>/<repo>.git')


def validate_token(token, name):
    if not token or re.search(r'\s', token) or len(token) < 8:
        raise ValueError(f'{name} must be at least 8 characters without whitespace (required for masking)')


def validate_patterns(patterns):
    if not patterns.strip():
        raise ValueError('MIRROR_FORBIDDEN_PATTERNS must not be empty (the mirror job refuses to run without it)')
    try:
        re.compile(patterns)
    except re.error as error:
        raise ValueError(f'MIRROR_FORBIDDEN_PATTERNS is not a valid regex: {error}')


def check_mirror_token(url, token, get=github_get):
    status, _, repo = get(f'https://api.github.com/repos/{URL_PATTERN.match(url).group(1)}', token)
    if status != 200:
        raise ValueError(f'GITHUB_MIRROR_TOKEN cannot access the repository (HTTP {status}): check the repository '
                         'name and that the token covers it')
    if not (repo.get('permissions') or {}).get('push'):
        raise ValueError('GITHUB_MIRROR_TOKEN has no write access (needs Contents: Read and write)')


def check_ghcr_token(token, get=github_get):
    status, headers, _ = get('https://api.github.com/user', token)
    if status != 200:
        raise ValueError(f'GITHUB_GHCR_TOKEN is not valid (HTTP {status})')
    scopes = [item.strip() for item in (headers.get('X-OAuth-Scopes') or '').split(',')]
    if 'write:packages' not in scopes:
        raise ValueError('GITHUB_GHCR_TOKEN needs a classic token with the scope write:packages '
                         '(fine-grained tokens do not work with ghcr.io)')


def fetch_variables(project, call):
    existing = {}
    page = 1
    while True:
        batch = call(f'projects/{quote(str(project), safe="")}/variables?per_page=100&page={page}')
        existing.update({v['key']: v for v in batch if v.get('environment_scope', '*') == '*'})
        if len(batch) < 100:
            return existing
        page += 1


def state(existing, key):
    """'missing', 'ok' or 'flags' (present but not protected, or a token that is not masked)."""
    variable = existing.get(key)
    if variable is None:
        return 'missing'
    if not variable.get('protected') or (VARIABLES[key] and not variable.get('masked')):
        return 'flags'
    return 'ok'


def report(existing):
    labels = {'missing': 'missing' , 'ok': 'set', 'flags': 'set, but not protected/masked'}
    for key in VARIABLES:
        suffix = ' (optional)' if key in OPTIONAL and key not in existing else ''
        print(f'  {key}: {labels[state(existing, key)]}{suffix}')
    return {key: state(existing, key) for key in VARIABLES}


def write(project, call, existing, wanted, *, dry_run=False):
    project = quote(str(project), safe='')
    for key, value in wanted.items():
        masked = VARIABLES[key]
        payload = {'key': key, 'value': value, 'protected': True, 'masked': masked, 'raw': True,
                   'environment_scope': '*', 'variable_type': 'env_var'}
        action = 'update' if key in existing else 'create'
        print(f'{action} protected variable {key}{" (masked)" if masked else ""}')
        if dry_run:
            continue
        if key in existing:
            call(f'projects/{project}/variables/{key}?filter[environment_scope]=*', payload, 'PUT')
        else:
            call(f'projects/{project}/variables', payload, 'POST')
    tags = call(f'projects/{project}/protected_tags?per_page=100')
    if any(t['name'] == TAG_PROTECTION for t in tags):
        print(f'tag protection {TAG_PROTECTION} already present')
    else:
        print(f'protect tags {TAG_PROTECTION} (create: Maintainers)')
        if not dry_run:
            call(f'projects/{project}/protected_tags',
                 {'name': TAG_PROTECTION, 'create_access_level': MAINTAINER}, 'POST')


def plan(existing, states, args, ask, ask_secret):
    """Values to write: only missing or wrongly flagged variables, everything with --force."""
    wanted = {}
    for key, masked in VARIABLES.items():
        if states[key] == 'ok' and not args.force:
            continue
        if not masked:
            current = existing.get(key, {}).get('value')
            if states[key] == 'flags' and not args.force and current:
                wanted[key] = current  # only the flags are wrong: keep the value
            elif key == 'GITHUB_MIRROR_URL':
                wanted[key] = args.url or ask('GitHub repository URL (https://github.com/<owner>/<repo>.git): ')
            else:
                wanted[key] = args.patterns or ask('Forbidden patterns (extended regex, e.g. example\\.internal|meinuser): ')
        elif key == 'GITHUB_MIRROR_TOKEN':
            wanted[key] = os.environ.get(key) or ask_secret('GitHub token (fine-grained, Contents: write): ')
        else:
            value = os.environ.get(key) or ask_secret('ghcr.io token (classic PAT, write:packages; empty = do not publish images): ')
            if value:
                wanted[key] = value
    return wanted


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--project', default='120', help='GitLab project id or path (default: 120)')
    parser.add_argument('--hostname', help='GitLab host if it differs from the glab default')
    parser.add_argument('--url', default=os.environ.get('GITHUB_MIRROR_URL'),
                        help='https://github.com/<owner>/<repo>.git (or env GITHUB_MIRROR_URL)')
    parser.add_argument('--patterns', default=os.environ.get('MIRROR_FORBIDDEN_PATTERNS'),
                        help='Extended regex of installation-specific strings (or env MIRROR_FORBIDDEN_PATTERNS)')
    parser.add_argument('--force', action='store_true', help='ask for and overwrite variables that are already correct')
    parser.add_argument('--skip-check', action='store_true', help='do not test new tokens against GitHub')
    parser.add_argument('--dry-run', action='store_true', help='validate and show the plan without changing anything')
    args = parser.parse_args()
    os.umask(0o077)
    tty = sys.stdin.isatty()
    ask = input if tty else (lambda prompt: '')
    ask_secret = getpass if tty else (lambda prompt: '')

    def call(endpoint, payload=None, method=None):
        return api(endpoint, payload, method, args.hostname)

    try:
        print('Current project variables:')
        existing = fetch_variables(args.project, call)
        states = report(existing)
        wanted = plan(existing, states, args, ask, ask_secret)
        if not wanted:
            print('All variables are set; nothing to ask (use --force to overwrite).')
        if 'GITHUB_MIRROR_URL' in wanted:
            validate_url(wanted['GITHUB_MIRROR_URL'])
        if 'MIRROR_FORBIDDEN_PATTERNS' in wanted:
            validate_patterns(wanted['MIRROR_FORBIDDEN_PATTERNS'])
        for key in ('GITHUB_MIRROR_TOKEN', 'GITHUB_GHCR_TOKEN'):
            if key in wanted:
                validate_token(wanted[key], key)
        if states['GITHUB_MIRROR_URL'] != 'ok' and 'GITHUB_MIRROR_URL' not in wanted:
            raise ValueError('GITHUB_MIRROR_URL is required')
        if not args.skip_check:
            url = wanted.get('GITHUB_MIRROR_URL') or existing.get('GITHUB_MIRROR_URL', {}).get('value')
            if 'GITHUB_MIRROR_TOKEN' in wanted:
                if not URL_PATTERN.match(url or ''):
                    raise ValueError('cannot check the token without a valid GITHUB_MIRROR_URL')
                check_mirror_token(url, wanted['GITHUB_MIRROR_TOKEN'])
                print('GITHUB_MIRROR_TOKEN: write access to the repository confirmed')
            if 'GITHUB_GHCR_TOKEN' in wanted:
                check_ghcr_token(wanted['GITHUB_GHCR_TOKEN'])
                print('GITHUB_GHCR_TOKEN: scope write:packages confirmed')
        for key in ('GITHUB_MIRROR_TOKEN', 'MIRROR_FORBIDDEN_PATTERNS'):
            if key not in wanted and states[key] == 'missing':
                raise ValueError(f'{key} is required')
        write(args.project, call, existing, wanted, dry_run=args.dry_run)
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Release mirror setup failed ({type(error).__name__}'
                       f'{": " + str(error) if isinstance(error, ValueError) else ""}); check glab login and permissions\n')
    if states['GITHUB_GHCR_TOKEN'] == 'missing' and 'GITHUB_GHCR_TOKEN' not in wanted:
        print('Note: without GITHUB_GHCR_TOKEN the images are not published to ghcr.io.')
    print('Done. Test with a tag vX.Y.Z; see docs/operations/release.md.')


if __name__ == '__main__':
    main()
