# SPDX-License-Identifier: Apache-2.0
"""Tag schema (``key:value`` project tags) and host identity shared by uploads, registration and monitoring.

The agent needs :func:`hostname` and :func:`inventory_tags`; ``ci_tags`` and ``is_host_project`` belong to
the server side but live here because they define the same schema."""
import os
import platform
import re
import socket

MANAGED_TAG = 'managed-by:patchwatch'
ASSET_TAG = 'asset-type:workstation'
APPLICATION_TAG = 'asset-type:application'
RESERVED = {'managed-by', 'asset-type', 'asset-id', 'host', 'os', 'distro', 'agent-scope'}
ALIASES = {'agent': 'agent-scope', 'host-group': 'asset-group'}
TAG_VALUE = re.compile(r'[a-z0-9][a-z0-9._-]{0,127}\Z')


def hostname(value=None):
    """Normalized DNS hostname (lowercase, no trailing dot); ``None`` means this machine. Raises ``ValueError`` if invalid."""
    name = (socket.gethostname() if value is None else value).strip().rstrip('.').lower()
    label = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
    if not name or len(name)>253 or any(not label.fullmatch(part) for part in name.split('.')):
        raise ValueError('Invalid DNS hostname')
    return name


def canonical_tags(tags):
    """Validate ``key:value`` tags (aliases resolved, one value per key) and return them sorted."""
    if not isinstance(tags, list):
        raise ValueError('tags must be a list of key:value strings')
    values = {}
    for tag in tags:
        if not isinstance(tag, str):
            raise ValueError('Tags must be strings')
        key, separator, value = tag.strip().lower().partition(':')
        key = ALIASES.get(key, key)
        if not separator or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', key) or not TAG_VALUE.fullmatch(value):
            raise ValueError('Tags must use lowercase key:value names without spaces, commas or secrets')
        if key in values and values[key]!=value:
            raise ValueError('Only one value per tag key is supported')
        values[key] = value
    return sorted(key+':'+value for key,value in values.items())


def inventory_tags(config, name=None):
    """Canonical tags of a host project from an agent profile.

    Detected metadata (``host``, ``os``, ``distro``, ``agent-scope``, ``asset-id``) cannot be overridden by the
    profile's own ``tags``. Note: OS and distribution describe the machine this runs on."""
    name = hostname(config.get('hostname') if name is None else name)
    asset_id = str(config['host_id']).lower()
    if not TAG_VALUE.fullmatch(asset_id):
        raise ValueError('host_id must be a stable asset identifier')
    scope = config.get('agent_scope', 'system' if os.geteuid()==0 else 'user')
    if scope not in ('user','system'):
        raise ValueError('agent_scope must be user or system')
    values = {'managed-by':'patchwatch', 'asset-type':'workstation', 'asset-id':asset_id,
              'host':name, 'os':platform.system().lower(), 'agent-scope':scope}
    if values['os']=='linux':
        try: values['distro'] = platform.freedesktop_os_release()['ID'].lower()
        except (OSError,KeyError): pass
    for tag in canonical_tags(config.get('tags', [])):
        key,value=tag.split(':',1)
        if key in RESERVED and values.get(key)!=value:
            raise ValueError('Reserved inventory tags cannot override detected host metadata')
        values[key]=value
    return canonical_tags([key+':'+value for key,value in values.items()])


def ci_tags(project_id, team, environment=None):
    """Canonical tags for a GitLab CI project. Team and environment are never guessed here."""
    project_id = str(project_id).lower()
    if not project_id.isdigit():
        raise ValueError('GitLab project id must be numeric')
    values = ['managed-by:patchwatch', APPLICATION_TAG, 'source:gitlab-ci', 'gitlab-project-id:' + project_id,
              'team:' + str(team).strip().lower()]
    if environment:
        values.append('environment:' + str(environment).strip().lower())
    return canonical_tags(values)


def is_host_project(project):
    """Whether a Dependency-Track project represents a workstation (managed host tags or the old ``devhost-`` name)."""
    tags = {t['name'] if isinstance(t,dict) else t for t in (project.get('tags') or [])}
    return (MANAGED_TAG in tags and ASSET_TAG in tags) or project.get('name','').startswith('devhost-')
