#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish release assets as a GitHub Release (ci/release.yml, job release-github).

Standard library only. Before anything is uploaded, every file is copied to a staging directory, the
given --rewrite substitutions are applied to JSON files (internal registry names in the SBOM become the
public ghcr.io names) and the result is scanned, including the members of zip, tar and ar archives
(.pyz, .deb), against MIRROR_FORBIDDEN_PATTERNS. A hit aborts the job without touching GitHub.

Environment: GITHUB_MIRROR_TOKEN (Contents: write), MIRROR_FORBIDDEN_PATTERNS (extended regex).
The release is created for an existing tag; a re-run replaces assets of the same name.
"""
import argparse
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tempfile
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
import zipfile

URL_PATTERN = re.compile(r'^https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?$')
API = 'https://api.github.com'
UPLOADS = 'https://uploads.github.com'
MAX_DEPTH = 4


def repository(url):
    match = URL_PATTERN.match(url or '')
    if not match:
        raise ValueError('URL must look like https://github.com/<owner>/<repo>.git')
    return match.group(1)


def ar_members(data):
    """Members of a Unix ar archive (.deb) as (name, bytes)."""
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        size = int(header[48:58])
        offset += 60
        yield header[:16].decode('ascii', 'replace').strip(), data[offset:offset + size]
        offset += size + size % 2


def members(data):
    """Nested contents of an archive, or an empty list for a plain file."""
    if data.startswith(b'!<arch>\n'):
        return list(ar_members(data))
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return [(i.filename, archive.read(i)) for i in archive.infolist() if not i.is_dir()]
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            return [(m.name, archive.extractfile(m).read()) for m in archive if m.isfile()]
    except (tarfile.TarError, EOFError, OSError):
        return []


def scan(name, data, pattern, depth=0):
    """Names of files (nested as a/b) whose content or name matches the pattern."""
    hits = [name] if pattern.search(name.encode()) or pattern.search(data) else []
    if depth < MAX_DEPTH:
        for inner, content in members(data):
            hits += scan(f'{name}/{inner}', content, pattern, depth + 1)
    return hits


def stage(files, rewrites, directory):
    staged = []
    for source in files:
        target = Path(directory) / Path(source).name
        if target.suffix == '.json':
            text = Path(source).read_text()
            for old, new in rewrites:
                text = text.replace(old, new)
            json.loads(text)
            target.write_text(text)
        else:
            shutil.copyfile(source, target)
        staged.append(target)
    return staged


class GitHub:
    def __init__(self, repo, token):
        self.repo, self.token = repo, token

    def call(self, url, payload=None, method=None, data=None, content_type='application/json'):
        body = data if data is not None else (json.dumps(payload).encode() if payload is not None else None)
        request = Request(url, data=body, method=method or ('POST' if body is not None else 'GET'), headers={
            'Authorization': f'Bearer {self.token}', 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': content_type})
        with urlopen(request, timeout=300) as response:
            raw = response.read()
        return json.loads(raw) if raw else None

    def release(self, tag, name, notes):
        try:
            return self.call(f'{API}/repos/{self.repo}/releases/tags/{quote(tag)}')
        except HTTPError as error:
            if error.code != 404:
                raise
        return self.call(f'{API}/repos/{self.repo}/releases',
                         {'tag_name': tag, 'name': name, 'body': notes, 'draft': False, 'prerelease': False})

    def upload(self, release, path):
        for asset in release.get('assets', []):
            if asset['name'] == path.name:
                self.call(f'{API}/repos/{self.repo}/releases/assets/{asset["id"]}', method='DELETE')
        self.call(f'{UPLOADS}/repos/{self.repo}/releases/{release["id"]}/assets?name={quote(path.name)}',
                  data=path.read_bytes(), content_type='application/octet-stream')


def publish(client, tag, name, notes, staged):
    release = client.release(tag, name, notes)
    for path in staged:
        print(f'upload {path.name}')
        client.upload(release, path)
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', default=os.environ.get('GITHUB_MIRROR_URL'))
    parser.add_argument('--tag', required=True)
    parser.add_argument('--name')
    parser.add_argument('--notes', default='')
    parser.add_argument('--rewrite', action='append', default=[], metavar='OLD=NEW')
    parser.add_argument('files', nargs='+')
    args = parser.parse_args()
    patterns = os.environ.get('MIRROR_FORBIDDEN_PATTERNS', '')
    token = os.environ.get('GITHUB_MIRROR_TOKEN', '')
    if not patterns.strip() or not token:
        parser.exit(1, 'MIRROR_FORBIDDEN_PATTERNS and GITHUB_MIRROR_TOKEN are required\n')
    try:
        repo = repository(args.url)
        pattern = re.compile(patterns.encode(), re.IGNORECASE)
        rewrites = [tuple(item.split('=', 1)) for item in args.rewrite]
        with tempfile.TemporaryDirectory() as directory:
            staged = stage(args.files, rewrites, directory)
            hits = [hit for path in staged for hit in scan(path.name, path.read_bytes(), pattern)]
            if hits:
                parser.exit(1, 'Installation-specific data found, refusing to publish: ' + ', '.join(hits) + '\n')
            release = publish(GitHub(repo, token), args.tag, args.name or args.tag, args.notes, staged)
    except (OSError, ValueError, KeyError, re.error) as error:
        parser.exit(1, f'GitHub release failed ({type(error).__name__})\n')
    print(f'Release: {release.get("html_url", "")}')


if __name__ == '__main__':
    sys.exit(main())
