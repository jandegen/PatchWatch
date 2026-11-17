# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from patchwatch.agent.extensions import MAX_METADATA, collect, reconcile
from patchwatch.core.sbom import sanitize


class ExtensionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.home = Path(self.folder.name)
        self.config = {'extension_homes': [str(self.home)]}

    def write(self, relative, data):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))
        return path

    def archive(self, relative, member, data):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr(member, data)
        return path

    def vscode(self, relative='.vscode/extensions/pub.tool-1/package.json', version='1'):
        return self.write(relative, {'publisher': 'Pub', 'name': 'Tool', 'version': version,
                                    'engines': {'vscode': '*'}, 'license': 'MIT',
                                    'description': 'PRIVATE CONTENT', 'scripts': {'install': 'DO NOT EXECUTE'}})

    def test_linux_and_macos_profiles_merge_without_losing_versions_or_locations(self):
        for system in ('Linux', 'Darwin'):
            with self.subTest(system=system), patch('patchwatch.agent.extensions.platform.system', return_value=system):
                self.vscode()
                self.vscode('.cursor/extensions/pub.tool-1/package.json')
                self.vscode('.vscode/extensions/pub.tool-2/package.json', '2')
                for base in ('.config/google-chrome/Default', '.config/BraveSoftware/Brave-Browser/Profile 1',
                             'Library/Application Support/Google/Chrome/Default'):
                    self.write(base + '/Extensions/abcdefghijklmnop/1/manifest.json',
                               {'name': '__MSG_private__', 'version': '1', 'manifest_version': 3,
                                'permissions': ['PRIVATE PERMISSION']})
                result = sanitize([collect(self.config)], 'host')
                self.assertEqual(len(result['components']), 3)
                items = {(c['group'], c['version']): c for c in result['components']}
                self.assertEqual(len(items['vscode', '1']['properties']), 2)
                self.assertEqual(len(items['chromium-extension', '1']['properties']), 3)
                self.assertNotIn('PRIVATE', json.dumps(result))
                self.assertNotIn('DO NOT EXECUTE', json.dumps(result))
                self.assertNotIn('__MSG_', json.dumps(result))

    def test_firefox_xpi_unpacked_and_jetbrains_jars(self):
        manifest = {'version': '2', 'browser_specific_settings': {'gecko': {'id': 'addon@example.org'}}}
        self.archive('.mozilla/firefox/one/extensions/addon@example.org.xpi', 'manifest.json', json.dumps(manifest))
        self.write('Library/Application Support/Firefox/Profiles/two/extensions/addon@example.org/manifest.json', manifest)
        xml = '<idea-plugin><id>org.example.plugin</id><name>Display name</name><version>3</version></idea-plugin>'
        self.archive('.local/share/JetBrains/Idea2026/plugins/example/lib/plugin.jar', 'META-INF/plugin.xml', xml)
        self.archive('.local/share/JetBrains/Idea2026/plugins/example/lib/dependency.jar', 'some-library', 'unrelated')
        self.archive('Library/Application Support/JetBrains/PyCharm2026/plugins/example/lib/plugin.jar', 'META-INF/plugin.xml', xml)
        result = sanitize([collect(self.config)], 'host')['components']
        self.assertEqual(len(result), 2)
        self.assertEqual({c['group'] for c in result}, {'firefox-extension', 'jetbrains-plugin'})
        self.assertTrue(all(len(c['properties']) == 2 for c in result))
        self.assertIn('addon%40example.org', next(c['purl'] for c in result if c['group'] == 'firefox-extension'))

    def test_syft_manifest_duplicates_merge_and_nested_libraries_and_edges_survive(self):
        manifest = self.vscode()
        extensions = collect(self.config)
        for location in (str(manifest), '.vscode/extensions/pub.tool-1/package.json',
                         '/.vscode/extensions/pub.tool-1/package.json', str(manifest.parent)):
            with self.subTest(location=location):
                parent = {'type': 'library', 'name': 'Tool', 'version': '1', 'purl': 'pkg:npm/Tool@1',
                          'bom-ref': 'extension', 'properties': [{'name': 'syft:location:0:path', 'value': location}]}
                dependency = {'type': 'library', 'name': 'Tool', 'version': '1', 'purl': 'pkg:npm/Tool@1',
                              'bom-ref': 'dependency', 'properties': [{'name': 'syft:location:0:path',
                              'value': str(manifest.parent / 'node_modules/Tool/package.json')}]}
                bom = {'components': [parent, dependency], 'dependencies': [{'ref': 'extension', 'dependsOn': ['dependency']}]}
                reconcile(bom, extensions, self.home)
                result = sanitize([bom, extensions, bom], 'host')
                self.assertEqual(len(result['components']), 2)
                by_group = {c.get('group'): c['bom-ref'] for c in result['components']}
                self.assertIn({'ref': by_group['vscode'], 'dependsOn': [by_group[None]]}, result['dependencies'])

    def test_invalid_oversized_and_broken_metadata_do_not_abort_other_extensions(self):
        self.vscode()
        self.write('.cursor/extensions/invalid/package.json', {'name': 'no-publisher', 'version': '1', 'engines': {'vscode': '*'}})
        broken = self.write('.vscode/extensions/broken/package.json', {})
        broken.write_text('{broken')
        self.archive('.mozilla/firefox/one/extensions/large.xpi', 'manifest.json', ' ' * (MAX_METADATA + 1))
        self.archive('.local/share/JetBrains/Idea/plugins/evil/lib/plugin.jar', 'META-INF/plugin.xml',
                     '<!DOCTYPE idea-plugin [<!ENTITY e "private">]><idea-plugin><id>&e;</id></idea-plugin>')
        with self.assertWarns(RuntimeWarning):
            result = collect(self.config)
        self.assertEqual(len(result['components']), 1)

    def test_opt_out_empty_homes_and_invalid_configuration(self):
        self.vscode()
        self.assertEqual(collect({**self.config, 'scan_extensions': False}), {'components': []})
        self.assertEqual(collect({'extension_homes': []}), {'components': []})
        for homes in ('/home/alice', [42], ['relative']):
            with self.subTest(homes=homes), self.assertRaises(ValueError):
                collect({'extension_homes': homes})

    def test_duplicate_homes_and_symlinked_installations_are_read_once(self):
        self.vscode()
        (self.home / '.cursor').symlink_to(self.home / '.vscode', target_is_directory=True)
        result = collect({'extension_homes': [str(self.home), str(self.home)]})
        self.assertEqual(len(result['components']), 1)

    def test_agent_merges_extension_with_syft_and_supports_extension_only_inventory(self):
        from patchwatch.agent import run
        manifest = self.vscode()
        key = self.home / 'api-key'
        key.write_text('test-key')
        key.chmod(0o600)
        config = {**self.config, 'host_id': 'asset-1', 'hostname': 'host',
                  'url': 'https://example.org', 'api_key_file': str(key),
                  'lock_file': str(self.home / 'agent.lock')}

        def scan(args, **kwargs):
            output = next(arg.split('=', 1)[1] for arg in args if arg.startswith('cyclonedx-json='))
            Path(output).write_text(json.dumps({'components': [
                {'type': 'library', 'name': 'Tool', 'version': '1', 'purl': 'pkg:npm/Tool@1',
                 'properties': [{'name': 'syft:location:0:path', 'value': str(manifest)}]}]}))

        for roots in ([str(self.home)], []):
            with self.subTest(roots=roots), patch('patchwatch.agent.scanner.subprocess.run', side_effect=scan) as scanner, \
                    patch('patchwatch.agent.runner.upload_and_wait') as upload:
                run({**config, 'roots': roots})
                self.assertEqual(scanner.call_count, len(roots))
                bom = upload.call_args.args[3]
                self.assertEqual(len(bom['components']), 1)
                self.assertEqual(bom['components'][0]['purl'], 'pkg:generic/vscode/pub.tool@1')
                self.assertNotIn('test-key', json.dumps(bom))

    def test_system_and_user_scope_home_discovery(self):
        from types import SimpleNamespace
        from patchwatch.agent.extensions import _homes
        accounts = [SimpleNamespace(pw_uid=0, pw_dir='/root'), SimpleNamespace(pw_uid=501, pw_dir='/Users/mac'),
                    SimpleNamespace(pw_uid=1000, pw_dir='/home/linux'), SimpleNamespace(pw_uid=65534, pw_dir='/nonexistent')]
        with patch('patchwatch.agent.extensions.os.geteuid', return_value=0), patch('patchwatch.agent.extensions.pwd.getpwall', return_value=accounts):
            with patch('patchwatch.agent.extensions.platform.system', return_value='Linux'):
                self.assertEqual(_homes({}), [Path('/home/linux')])
            with patch('patchwatch.agent.extensions.platform.system', return_value='Darwin'):
                self.assertEqual(_homes({}), [Path('/Users/mac'), Path('/home/linux')])
        with patch('patchwatch.agent.extensions.os.geteuid', return_value=1000), patch('patchwatch.agent.extensions.Path.home', return_value=self.home):
            self.assertEqual(_homes({}), [self.home])
