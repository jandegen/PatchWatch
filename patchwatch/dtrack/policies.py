# SPDX-License-Identifier: Apache-2.0
"""Reconcile explicitly owned Dependency-Track policies from versioned JSON."""
import argparse
import json
import os
from decimal import Decimal, InvalidOperation
import re
from pathlib import Path
from urllib.parse import quote
from ..core.tags import canonical_tags

DEFAULT_FILE = Path(__file__).parent / 'data' / 'default-policies.json'
SUBJECTS = {'AGE', 'COORDINATES', 'CPE', 'LICENSE', 'LICENSE_GROUP', 'PACKAGE_URL',
            'SEVERITY', 'SWID_TAGID', 'VERSION', 'IS_INTERNAL', 'COMPONENT_HASH',
            'CWE', 'VULNERABILITY_ID', 'VERSION_DISTANCE', 'EPSS'}
OPERATORS = {'IS', 'IS_NOT', 'MATCHES', 'NO_MATCH', 'NUMERIC_GREATER_THAN',
             'NUMERIC_LESS_THAN', 'NUMERIC_EQUAL', 'NUMERIC_NOT_EQUAL',
             'NUMERIC_GREATER_THAN_OR_EQUAL', 'NUMERIC_LESSER_THAN_OR_EQUAL',
             'CONTAINS_ALL', 'CONTAINS_ANY'}


def load(path=None):
    """Read and validate the policy definitions (default: the packaged ``data/default-policies.json``). Only ``Patchwatch``-prefixed policies are allowed."""
    document = json.loads(Path(path or os.getenv('PATCHWATCH_POLICIES_FILE') or DEFAULT_FILE).read_text())
    if set(document) != {'policies'} or not isinstance(document['policies'], list):
        raise ValueError('Expected a policies array')
    names = set()
    for policy in document['policies']:
        if set(policy) != {'name', 'operator', 'violationState', 'scopeTags', 'conditions'}:
            raise ValueError('Unexpected or missing policy fields')
        name = policy['name']
        if not isinstance(name, str) or not name.startswith('Patchwatch ') or name in names:
            raise ValueError('Policies require unique Patchwatch-prefixed names')
        names.add(name)
        if policy['operator'] not in ('ANY', 'ALL') or policy['violationState'] not in ('INFO', 'WARN', 'FAIL'):
            raise ValueError('Invalid policy operator or violation state')
        tags = policy['scopeTags']
        if not isinstance(tags, list) or not tags or any(not isinstance(t, str) or not t.strip() for t in tags):
            raise ValueError('At least one scope tag is required; global scope is not implicit')
        if canonical_tags(tags) != sorted(set(tags)):
            raise ValueError('Scope tags must use canonical lowercase key:value names')
        if not isinstance(policy['conditions'], list) or not policy['conditions']:
            raise ValueError('At least one condition is required')
        for condition in policy['conditions']:
            if set(condition) != {'subject', 'operator', 'value'}:
                raise ValueError('Unexpected or missing condition fields')
            if condition['subject'] not in SUBJECTS or condition['operator'] not in OPERATORS:
                raise ValueError('Unknown condition subject or operator')
            if not isinstance(condition['value'], str) or not condition['value'].strip():
                raise ValueError('Condition value must be a nonempty string')
            if condition['subject'] in ('LICENSE', 'LICENSE_GROUP', 'SEVERITY') and condition['operator'] not in ('IS', 'IS_NOT'):
                raise ValueError('License and severity conditions require IS or IS_NOT')
            if condition['subject'] == 'SEVERITY' and condition['value'] not in ('UNASSIGNED', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
                raise ValueError('Severity must use an uppercase DTrack severity value')
            if condition['subject'] in ('EPSS', 'VERSION_DISTANCE') and not condition['operator'].startswith('NUMERIC_'):
                raise ValueError('EPSS and version distance require numeric operators')
            if condition['subject'] == 'EPSS':
                try: score = Decimal(condition['value'])
                except InvalidOperation: raise ValueError('EPSS requires a number') from None
                if not score.is_finite() or not 0 <= score <= 1:
                    raise ValueError('EPSS must be between zero and one')
            if condition['subject'] == 'VERSION_DISTANCE':
                distance = json.loads(condition['value'])
                if not isinstance(distance, dict) or not distance or set(distance) - {'epoch', 'major', 'minor', 'patch'}:
                    raise ValueError('Invalid version distance object')
                if any(not isinstance(v, str) or not re.fullmatch(r'\d+|\?', v) for v in distance.values()):
                    raise ValueError('Version distance values must be numeric strings or ?')

    return document['policies']


def load_license_groups(path=None):
    """Read and validate the license groups that PatchWatch owns (default: ``data/default-license-groups.json``)."""
    path = path or os.getenv('PATCHWATCH_LICENSE_GROUPS_FILE') or DEFAULT_FILE.with_name('default-license-groups.json')
    document = json.loads(Path(path).read_text())
    if set(document) != {'groups'} or not isinstance(document['groups'], list):
        raise ValueError('Expected a groups array')
    names = set()
    for group in document['groups']:
        if set(group) != {'name', 'licenses'} or not isinstance(group['name'], str) or not group['name'].startswith('Patchwatch '):
            raise ValueError('Only explicitly owned Patchwatch license groups can be managed')
        if group['name'] in names or not isinstance(group['licenses'], list) or not group['licenses']:
            raise ValueError('License groups require unique names and nonempty license lists')
        names.add(group['name'])
        if any(not isinstance(i, str) or not re.fullmatch(r'[A-Za-z0-9.+-]+', i) for i in group['licenses']):
            raise ValueError('Group licenses must be SPDX identifiers')
    return document['groups']


def sync(client, definitions, license_groups=()):
    # Resolve all external references before any policy changes. JSON uses portable SPDX
    # identifiers / group names; database UUIDs are resolved for this installation only.
    """Create or update the managed license groups and policies so that they match the definitions.

    External references (license groups, tags) are resolved before the first change is made, so an
    invalid definition leaves the instance untouched."""
    resolved = json.loads(json.dumps(definitions))
    group_references = {condition['value'] for p in resolved for condition in p['conditions']
                        if condition['subject'] == 'LICENSE_GROUP'}
    groups = {g['name']: g for g in client.all('licenseGroup')} if group_references or license_groups else {}
    managed_names = {g['name'] for g in license_groups}
    if group_references - set(groups) - managed_names:
        raise ValueError('Referenced license group does not exist')
    licenses = {}
    def license_uuid(identifier):
        if identifier not in licenses:
            licenses[identifier] = client.call('license/' + quote(identifier, safe=''))['uuid']
        return licenses[identifier]
    for policy in resolved:
        for condition in policy['conditions']:
            if condition['subject'] == 'LICENSE' and condition['value'] != 'unresolved':
                condition['value'] = license_uuid(condition['value'])
    # Complete all license lookups before changing any groups or policies.
    desired_groups = [(g['name'], {license_uuid(i) for i in g['licenses']}) for g in license_groups]
    for name, desired in desired_groups:
        group = groups.get(name)
        if group is None:
            group = client.call('licenseGroup', {'name': name}, 'PUT')
        group = client.call('licenseGroup/' + group['uuid'])
        existing_licenses = {i['uuid'] for i in group.get('licenses', [])}
        base = 'licenseGroup/' + group['uuid'] + '/license/'
        for identifier in sorted(desired - existing_licenses):
            client.call(base + identifier, method='POST')
        for identifier in sorted(existing_licenses - desired):
            client.call(base + identifier, method='DELETE')
        groups[name] = group
    for policy in resolved:
        for condition in policy['conditions']:
            if condition['subject'] == 'LICENSE_GROUP':
                condition['value'] = groups[condition['value']]['uuid']
    existing = {p['name']: p for p in client.all('policy')}
    for definition in resolved:
        policy = existing.get(definition['name'])
        if policy is None:
            policy = client.call('policy', {k: definition[k] for k in ('name', 'operator', 'violationState')}, 'PUT')
        policy = client.call('policy/' + policy['uuid'])
        policy.update({k: definition[k] for k in ('operator', 'violationState')})
        policy.update({'includeChildren': True, 'onlyLatestProjectVersion': False})
        client.call('policy', policy, 'POST')
        base = 'policy/' + policy['uuid']
        # Explicit project bindings would widen the tag scope. This module owns the
        # entire definition of the named policies, including all scope bindings.
        client.call('tag', definition['scopeTags'], 'PUT')
        old_tags = {t['name'] for t in policy.get('tags', [])}
        # v5 tags policies from the tag side: POST/DELETE /tag/{name}/policy with the policy UUIDs.
        for tag in sorted(set(definition['scopeTags']) - old_tags):
            client.call('tag/' + quote(tag, safe='') + '/policy', [policy['uuid']], 'POST')
        for tag in sorted(old_tags - set(definition['scopeTags'])):
            client.call('tag/' + quote(tag, safe='') + '/policy', [policy['uuid']], 'DELETE')
        for project in policy.get('projects', []):
            client.call(base + '/project/' + project['uuid'], method='DELETE')
        desired = {(c['subject'], c['operator'], c['value']) for c in definition['conditions']}
        kept = set()
        for condition in policy.get('policyConditions', []):
            key = (condition['subject'], condition['operator'], condition['value'])
            if key not in desired or key in kept:
                client.call('policy/condition/' + condition['uuid'], method='DELETE')
            else:
                kept.add(key)
        for subject, operator, value in sorted(desired - kept):
            client.call(base + '/condition', {'subject': subject, 'operator': operator, 'value': value}, 'PUT')


def main():
    """CLI: validate (``--check``) or apply the policy files."""
    from .client import admin_client
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file')
    parser.add_argument('--check', action='store_true', help='Validate JSON locally without API access')
    args = parser.parse_args()
    try:
        definitions = load(args.file)
        groups = load_license_groups()
        if not args.check:
            sync(admin_client(os.environ['DT_URL']), definitions, groups)
        print(f'{len(definitions)} policy definitions validated' + ('' if args.check else ' and applied'))
    except Exception as error:
        parser.exit(1, f'Policy setup failed ({type(error).__name__}); check definitions, references and API access\n')


if __name__ == '__main__':
    main()
