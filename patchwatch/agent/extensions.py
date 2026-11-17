# SPDX-License-Identifier: Apache-2.0
"""Read installed extension metadata without executing editors or browsers."""
import json
import os
from pathlib import Path
import platform
import pwd
from urllib.parse import quote
import warnings
import xml.etree.ElementTree as ET
import zipfile

MAX_METADATA = 2 * 1024 * 1024


def _read(path, member=None):
    if member is None:
        with path.open('rb') as stream:
            data = stream.read(MAX_METADATA + 1)
    else:
        with zipfile.ZipFile(path) as archive:
            if archive.getinfo(member).file_size > MAX_METADATA:
                raise ValueError('Extension metadata too large')
            with archive.open(member) as stream:
                data = stream.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise ValueError('Extension metadata too large')
    return data


def _json(path, member=None):
    data = json.loads(_read(path, member))
    if not isinstance(data, dict):
        raise ValueError('Extension metadata must be an object')
    return data


def _text(value):
    return isinstance(value, str) and 0 < len(value) <= 512 and not any(ord(c) < 32 for c in value)


def _component(ecosystem, identifier, version, path, license=None):
    if not _text(identifier) or not _text(version):
        raise ValueError('Missing extension identity or version')
    item = {'type': 'application', 'group': ecosystem, 'name': identifier, 'version': version,
            'purl': f'pkg:generic/{ecosystem}/{quote(identifier, safe="")}@{quote(version, safe="")}',
            'properties': [{'name': 'syft:location:0:path', 'value': str(path.resolve())}]}
    if _text(license):
        item['licenses'] = [{'license': {'name': license}}]
    return item


def _homes(config):
    if 'extension_homes' in config:
        values = config['extension_homes']
        if not isinstance(values, list) or any(not isinstance(v, str) or not Path(v).is_absolute() for v in values):
            raise ValueError('extension_homes must be a list of absolute home directories')
        return sorted({Path(v).resolve() for v in values})
    if os.geteuid() != 0:
        return [Path.home()]
    minimum = 500 if platform.system() == 'Darwin' else 1000
    return sorted({Path(entry.pw_dir).resolve() for entry in pwd.getpwall()
                   if entry.pw_uid >= minimum and entry.pw_uid != 65534 and Path(entry.pw_dir).is_absolute()
                   and entry.pw_dir not in ('/', '/nonexistent', '/var/empty')})


def _glob(base, pattern):
    # A missing/locked profile must not abort inventory for all other users.
    try:
        return sorted(base.glob(pattern))
    except OSError:
        warnings.warn('Extension directory unreadable; inventory may be incomplete', RuntimeWarning)
        return []


def _vscode(path):
    data = _json(path)
    if not isinstance(data.get('engines'), dict) or 'vscode' not in data['engines']:
        return None
    publisher, name = data.get('publisher'), data.get('name')
    if not _text(publisher) or not _text(name):
        raise ValueError('Invalid VS Code extension identity')
    return _component('vscode', (publisher + '.' + name).lower(), data.get('version'), path, data.get('license'))


def _chromium(path):
    data = _json(path)
    return _component('chromium-extension', path.parent.parent.name, data.get('version'), path)


def _firefox(path):
    data = _json(path, 'manifest.json') if path.suffix == '.xpi' else _json(path)
    settings = data.get('browser_specific_settings', data.get('applications', {}))
    identifier = settings.get('gecko', {}).get('id') if isinstance(settings, dict) else None
    # Firefox assigns IDs to signed extensions that do not declare one in the manifest.
    identifier = identifier or (path.stem if path.suffix == '.xpi' else path.parent.name)
    return _component('firefox-extension', identifier, data.get('version'), path)


def _jetbrains(path):
    data = _read(path, 'META-INF/plugin.xml') if path.suffix == '.jar' else _read(path)
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('Unsupported plugin XML declaration')
    root = ET.fromstring(data)
    if root.tag != 'idea-plugin':
        return None
    return _component('jetbrains-plugin', root.findtext('id') or root.findtext('name'), root.findtext('version'), path)


VSCODE = ('.vscode', '.vscode-insiders', '.vscode-oss', '.vscode-server', '.vscode-server-insiders',
          '.cursor', '.cursor-server', '.windsurf', '.windsurf-server')
LINUX_BROWSERS = ('.config/google-chrome*', '.config/chromium', '.config/BraveSoftware/Brave-Browser*',
                  '.config/microsoft-edge*', '.config/vivaldi',
                  'snap/chromium/common/chromium', '.var/app/org.chromium.Chromium/config/chromium',
                  '.var/app/com.google.Chrome/config/google-chrome')
MAC_BROWSERS = ('Library/Application Support/Google/Chrome*', 'Library/Application Support/Chromium',
                'Library/Application Support/BraveSoftware/Brave-Browser*',
                'Library/Application Support/Microsoft Edge*', 'Library/Application Support/Vivaldi')
FIREFOX = ('.mozilla/firefox', 'snap/firefox/common/.mozilla/firefox',
           '.var/app/org.mozilla.firefox/.mozilla/firefox', 'Library/Application Support/Firefox/Profiles')
JETBRAINS = ('.local/share/JetBrains/*/plugins', 'Library/Application Support/JetBrains/*/plugins')


def collect(config):
    """One manifest pass, independent of Syft roots; sanitize merges installations by identity."""
    if not config.get('scan_extensions', True):
        return {'components': []}
    if platform.system() not in ('Linux', 'Darwin'):
        return {'components': []}
    components, seen = [], set()

    def add(path, reader):
        try:
            resolved = path.resolve()
            if resolved in seen:
                return
            seen.add(resolved)
            item = reader(path)
            if item:
                components.append(item)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, ET.ParseError, zipfile.BadZipFile):
            # Do not include user paths or manifest content in logs.
            warnings.warn('Extension metadata unreadable or invalid; inventory may be incomplete', RuntimeWarning)

    for home in _homes(config):
        for editor in VSCODE:
            for manifest in _glob(home / editor, 'extensions/*/package.json'):
                add(manifest, _vscode)
        for pattern in LINUX_BROWSERS + MAC_BROWSERS:
            for browser in _glob(home, pattern):
                for manifest in _glob(browser, '*/Extensions/*/*/manifest.json'):
                    add(manifest, _chromium)
        for pattern in FIREFOX:
            for manifest in _glob(home / pattern, '*/extensions/*/manifest.json'):
                add(manifest, _firefox)
            for archive in _glob(home / pattern, '*/extensions/*.xpi'):
                add(archive, _firefox)
        for pattern in JETBRAINS:
            for plugins in _glob(home, pattern):
                for manifest in _glob(plugins, '*/META-INF/plugin.xml'):
                    add(manifest, _jetbrains)
                for archive in _glob(plugins, '*/lib/*.jar'):
                    # Most jars contain libraries, not the plugin descriptor.
                    try:
                        with zipfile.ZipFile(archive) as jar:
                            if 'META-INF/plugin.xml' not in jar.namelist():
                                continue
                    except (OSError, zipfile.BadZipFile):
                        continue
                    add(archive, _jetbrains)
    return {'components': components}


def reconcile(bom, extensions, scan_root):
    """Give Syft's record of the same manifest the extension identity, retaining its edges.

    Match exact locations, never names alone: nested npm/JAR dependencies remain packages.
    Syft paths can be absolute host paths or paths relative to its scan root.
    """
    locations = {}
    for item in extensions['components']:
        for prop in item['properties']:
            path = Path(prop['value'])
            locations[path] = item
            if path.name in ('package.json', 'manifest.json'):
                locations[path.parent] = item
    for source in bom.get('components', []):
        if source.get('type') == 'file':
            continue
        for prop in source.get('properties', []):
            key, value = prop.get('name', ''), prop.get('value')
            if not key.startswith('syft:location:') or not key.endswith(':path') or not isinstance(value, str):
                continue
            path = Path(value)
            candidates = [path.resolve()] if path.is_absolute() else []
            candidates.append((Path(scan_root) / value.lstrip('/')).resolve())
            match = next((locations[p] for p in candidates if p in locations), None)
            if match and source.get('version') == match['version']:
                for key in ('type', 'group', 'name', 'version', 'purl', 'cpe'):
                    source.pop(key, None)
                    if key in match:
                        source[key] = match[key]
                break
