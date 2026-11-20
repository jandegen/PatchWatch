# SPDX-License-Identifier: Apache-2.0
import io
import json
from pathlib import Path
import re
import runpy
import tarfile
import tempfile
import unittest
import zipfile

module = runpy.run_path(str(Path(__file__).resolve().parent.parent / 'scripts/publish-github-release.py'))
PATTERN = re.compile(rb'internal\.example|meinuser', re.I)


def ar(name, content):
    return b'!<arch>\n' + name.ljust(16).encode() + b'0'.ljust(12) + b'0'.ljust(6) * 2 + b'100644'.ljust(8) \
        + str(len(content)).ljust(10).encode() + b'`\n' + content + (b'\n' if len(content) % 2 else b'')


class Scan(unittest.TestCase):
    def test_repository_from_url(self):
        self.assertEqual(module['repository']('https://github.com/acme/patchwatch.git'), 'acme/patchwatch')
        with self.assertRaises(ValueError):
            module['repository']('https://gitlab.internal.example/acme/patchwatch.git')

    def test_plain_file(self):
        self.assertEqual(module['scan']('a.txt', b'host gitlab.internal.example', PATTERN), ['a.txt'])
        self.assertEqual(module['scan']('a.txt', b'clean', PATTERN), [])

    def test_nested_archives(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('pkg/mod.py', 'URL = "https://internal.example"')
        self.assertEqual(module['scan']('agent.pyz', archive.getvalue(), PATTERN), ['agent.pyz/pkg/mod.py'])
        tar = io.BytesIO()
        with tarfile.open(fileobj=tar, mode='w:gz') as t:
            info = tarfile.TarInfo('usr/x')
            payload = b'owner meinuser'
            info.size = len(payload)
            t.addfile(info, io.BytesIO(payload))
        deb = ar('data.tar.gz', tar.getvalue())
        self.assertEqual(module['scan']('a.deb', deb, PATTERN), ['a.deb/data.tar.gz/usr/x'])

    def test_stage_rewrites_json_only(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as target:
            sbom = Path(source) / 'sbom.json'
            sbom.write_text(json.dumps({'image': 'registry.internal.example/g/p/bridge:1'}))
            other = Path(source) / 'SHA256SUMS'
            other.write_text('registry.internal.example')
            staged = module['stage']([sbom, other], [('registry.internal.example/g/p', 'ghcr.io/acme/patchwatch')], target)
            self.assertEqual(json.loads(staged[0].read_text())['image'], 'ghcr.io/acme/patchwatch/bridge:1')
            self.assertEqual(staged[1].read_text(), 'registry.internal.example')


class FakeClient:
    def __init__(self, assets=()):
        self.calls = []
        self.assets = list(assets)

    def release(self, tag, name, notes):
        self.calls.append(('release', tag))
        return {'id': 7, 'assets': self.assets, 'html_url': 'u'}

    def upload(self, release, path):
        self.calls.append(('upload', path.name))


class Publish(unittest.TestCase):
    def test_uploads_every_file_to_the_release(self):
        client = FakeClient()
        module['publish'](client, 'v1.0.0', 'n', '', [Path('/x/a.deb'), Path('/x/SHA256SUMS')])
        self.assertEqual(client.calls, [('release', 'v1.0.0'), ('upload', 'a.deb'), ('upload', 'SHA256SUMS')])

    def test_rerun_replaces_existing_asset(self):
        calls = []
        github = module['GitHub']('acme/patchwatch', 't')
        github.call = lambda url, payload=None, method=None, data=None, content_type=None: calls.append((method, url))
        with tempfile.NamedTemporaryFile(suffix='.deb') as f:
            module['GitHub'].upload(github, {'id': 7, 'assets': [{'name': Path(f.name).name, 'id': 3}]}, Path(f.name))
        self.assertEqual([m for m, _ in calls], ['DELETE', None])
        self.assertIn('/releases/assets/3', calls[0][1])
        self.assertIn('/releases/7/assets?name=', calls[1][1])


if __name__ == '__main__':
    unittest.main()
