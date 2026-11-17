# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path
import tempfile
import unittest
from patchwatch.dtrack.policies import load, load_license_groups, sync
from patchwatch.dtrack.compliance import project_report, breaches


class PolicyAPI:
    def __init__(self):
        self.policies = {'owned': {'uuid': 'owned', 'name': 'Patchwatch severity High or Critical',
            'tags': [{'name': 'old-scope'}], 'projects': [{'uuid': 'old-project'}],
            'policyConditions': [{'uuid': 'stale', 'subject': 'SEVERITY', 'operator': 'IS', 'value': 'LOW'}]},
            'unowned': {'uuid': 'unowned', 'name': 'Administrator policy', 'policyConditions': []}}
        self.groups = {"baseline": {"uuid": "baseline", "name": "Patchwatch distribution baseline", "licenses": []},
                       "external": {"uuid": "external", "name": "Approved", "licenses": []}}
        self.mutations = []

    def all(self, path):
        if path == 'policy': return copy.deepcopy(list(self.policies.values()))
        if path == 'licenseGroup': return copy.deepcopy(list(self.groups.values()))
        raise AssertionError(path)

    def call(self, path, data=None, method=None):
        data = copy.deepcopy(data)
        if method: self.mutations.append((path, data, method))
        parts = path.split('/')
        if parts[0] == 'license': return {'uuid': 'local-'+parts[1].lower()}
        if path == 'tag': return []
        if path == 'licenseGroup':
            data.update(uuid='g'+str(len(self.groups)), licenses=[])
            self.groups[data['uuid']] = data
            return copy.deepcopy(data)
        if parts[0] == 'licenseGroup':
            group = self.groups[parts[1]]
            if len(parts) == 2: return copy.deepcopy(group)
            if method == 'POST': group['licenses'].append({'uuid': parts[3]})
            else: group['licenses'] = [i for i in group['licenses'] if i['uuid'] != parts[3]]
            return copy.deepcopy(group)

        if path == 'policy':
            if method == 'PUT':
                data.update(uuid='p'+str(len(self.policies)), tags=[], projects=[], policyConditions=[])
            self.policies[data['uuid']] = data
            return copy.deepcopy(data)
        if parts[0] == 'tag' and parts[2] == 'policy':
            # v5: tags are bound from the tag side with a list of policy UUIDs.
            name = parts[1].replace('%3A', ':')
            for uuid in data:
                policy = self.policies[uuid]
                if method == 'POST': policy['tags'].append({'name': name})
                else: policy['tags'] = [t for t in policy['tags'] if t['name'] != name]
            return None
        if len(parts) == 2: return copy.deepcopy(self.policies[parts[1]])
        if parts[1] == 'condition':
            for policy in self.policies.values():
                policy['policyConditions'] = [c for c in policy['policyConditions'] if c['uuid'] != parts[2]]
            return None
        policy = self.policies[parts[1]]
        if parts[2] == 'project': policy['projects'] = []
        elif parts[2] == 'condition':
            data['uuid'] = 'condition-'+str(len(self.mutations))
            policy['policyConditions'].append(data)
        else: raise AssertionError(path)
        return None


class PolicyTests(unittest.TestCase):
    def test_scope_and_stale_conditions_reconciled_without_touching_other_policies(self):
        api = PolicyAPI()
        untouched = copy.deepcopy(api.policies['unowned'])
        sync(api, load())
        owned = api.policies['owned']
        self.assertEqual(owned['tags'], [{'name': 'managed-by:patchwatch'}])
        self.assertEqual(owned['projects'], [])
        self.assertEqual({c['value'] for c in owned['policyConditions']}, {'HIGH', 'CRITICAL'})
        self.assertEqual(api.policies['unowned'], untouched)
        before = copy.deepcopy(api.policies)
        sync(api, load())
        self.assertEqual(api.policies, before)
        license_policy = next(p for p in api.policies.values() if 'unresolved' in p['name'])
        self.assertEqual(license_policy['violationState'], 'WARN')
        self.assertEqual(license_policy['policyConditions'][0]['value'], 'unresolved')

    def test_missing_license_group_fails_before_any_mutations(self):
        definitions = load()
        definitions[0]['conditions'] = [{'subject': 'LICENSE_GROUP', 'operator': 'IS', 'value': 'Missing'}]
        api = PolicyAPI()
        with self.assertRaises(ValueError): sync(api, definitions)
        self.assertEqual(api.mutations, [])

    def test_portable_spdx_id_resolved_to_installation_uuid(self):
        definitions = load()[:1]
        definitions[0]['conditions'] = [{'subject': 'LICENSE', 'operator': 'IS', 'value': 'MIT'}]
        api = PolicyAPI(); sync(api, definitions)
        self.assertEqual(api.policies['owned']['policyConditions'][0]['value'], 'local-mit')

    def test_invalid_definitions_rejected_locally(self):
        for edit in (lambda p: p.update(scopeTags=[]), lambda p: p.update(name='Other policy'),
                     lambda p: p.update(violationState='BLOCK'), lambda p: p.update(typo=True)):
            definitions = load(); edit(definitions[0])
            with tempfile.TemporaryDirectory() as folder:
                file = Path(folder)/'policies.json'; file.write_text(json.dumps({'policies': definitions}))
                with self.assertRaises(ValueError): load(file)

    def test_report_distinguishes_metadata_native_violations_and_conflicts(self):
        class API:
            def call(self, path):
                return {'metadata': {'component': {'bom-ref': 'root'}}, 'components': [
                    {'name': 'a', 'licenses': [{'license': {'id': 'MIT'}}]},
                    {'name': 'b', 'properties': [{'name': 'patchwatch:license-conflict', 'value': 'true'}]}],
                    'dependencies': [{'ref': 'root', 'dependsOn': ['a','b']}, {'ref': 'a', 'dependsOn': ['b']}]}
            def all(self, path):
                return [{'type': 'LICENSE', 'policyCondition': {'policy': {'name': 'Review', 'violationState': 'WARN'}}}]
        result = project_report(API(), {'uuid': 'p', 'name': 'host'})
        self.assertEqual(result['componentsWithLicenseMetadata'], 1)
        self.assertEqual(len(result['licenseConflicts']), 1)
        self.assertEqual(result['packageDependencyEdges'], 1)
        self.assertFalse(breaches({'projects': [result]}, 'fail'))
        self.assertTrue(breaches({'projects': [result]}, 'warn'))
        self.assertFalse(breaches({'projects': [result]}, 'none'))

    def test_managed_license_group_is_reconciled_without_modifying_external_groups(self):
        api = PolicyAPI()
        api.groups['baseline']['licenses'] = [{'uuid': 'obsolete'}]
        untouched = copy.deepcopy(api.groups['external'])
        sync(api, load(), load_license_groups())
        expected = {'local-'+i.lower() for i in load_license_groups()[0]['licenses']}
        self.assertEqual({i['uuid'] for i in api.groups['baseline']['licenses']}, expected)
        self.assertEqual(api.groups['external'], untouched)
        before = copy.deepcopy(api.groups)
        sync(api, load(), load_license_groups())
        self.assertEqual(api.groups, before)

    def test_new_group_is_created_and_license_references_checked_before_changes(self):
        api = PolicyAPI(); del api.groups['baseline']
        sync(api, load(), load_license_groups())
        self.assertTrue(any(g['name']=='Patchwatch distribution baseline' for g in api.groups.values()))

    def test_policy_scopes_and_blocked_package_match_boundaries(self):
        import re
        policies = {p['name']:p for p in load()}
        license_policy = policies['Patchwatch distribution license approval']
        self.assertEqual(license_policy['scopeTags'], ['policy-profile:distribution'])
        self.assertEqual(license_policy['violationState'], 'WARN')
        self.assertEqual(policies['Patchwatch direct dependency major version lag']['scopeTags'], ['source:gitlab-ci'])
        expression = policies['Patchwatch blocked xz upstream releases']['conditions'][0]['value']
        # DTrack's Matcher expands stars; use brace quantifiers so the expression is stable.
        self.assertNotIn('*', expression)
        for value in ('pkg:generic/xz@5.6.0', 'pkg:deb/debian/liblzma5@5.6.1-1?arch=amd64', 'pkg:rpm/fedora/xz-libs@5.6.0-2.fc40'):
            self.assertRegex(value, expression)
        for value in ('pkg:generic/xz@5.6.2', 'pkg:generic/other@5.6.0', 'pkg:deb/debian/xz-utils@5.6.1+really5.4.5'):
            self.assertIsNone(re.search(expression, value))

    def test_invalid_epss_and_distance_are_rejected_before_api_access(self):
        for subject, value in [('EPSS','10'), ('EPSS','NaN'), ('EPSS','-0.1'), ('VERSION_DISTANCE','1'), ('VERSION_DISTANCE','{"major":"invalid"}')]:
            definitions = load()
            definitions[0]['conditions'] = [{'subject':subject, 'operator':'NUMERIC_GREATER_THAN', 'value':value}]
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder)/'policies.json'; path.write_text(json.dumps({'policies':definitions}))
                with self.assertRaises(ValueError): load(path)
