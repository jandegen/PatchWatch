# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from patchwatch.dtrack.client import DependencyTrack
from patchwatch.dtrack.setup import Provisioner


class OidcConfigurationTests(unittest.TestCase):
    def test_no_mapping_file_preserves_existing_access(self):
        client = DependencyTrack('https://dtrack.example', {})
        config = Provisioner(client)
        with patch.dict(os.environ, {}, clear=True), patch.object(client, 'call') as call:
            config.oidc()
            call.assert_not_called()

    def test_repeated_setup_preserves_groups_and_does_not_issue_api_keys(self):
        client = DependencyTrack('https://dtrack.example', {})
        config = Provisioner(client)
        teams, groups, mappings = {}, {}, set()
        def call(path, data=None, method=None):
            if path.startswith('team?'):
                return list(teams.values())
            if path.startswith('oidc/group?'):
                return list(groups.values())
            if path == 'team':
                team = dict(data, uuid='team-' + data['name'], permissions=[])
                teams[data['name']] = team
                return team
            if path.startswith('permission/'):
                permission, team_id = path.split('/')[1::2]
                team = next(t for t in teams.values() if t['uuid'] == team_id)
                if method == 'POST':
                    team['permissions'].append({'name': permission})
                else:
                    team['permissions'] = [p for p in team['permissions'] if p['name'] != permission]
                return None
            if path == 'oidc/group':
                group = dict(data, uuid='group-' + data['name'])
                groups[data['name']] = group
                return group
            if path == 'oidc/mapping':
                mappings.add((data['team'], data['group']))
                return {}
            self.fail('Unexpected API call: ' + path)

        filename = Path(__file__).resolve().parent.parent / 'deploy/environments/oidc-teams.json'
        with patch.dict(os.environ, {'OIDC_TEAM_MAPPINGS_FILE': str(filename)}), patch.object(client, 'call', side_effect=call):
            config.oidc()
            # A follow-up deployment must remove accidentally added write permissions.
            teams['Patchwatch Viewers']['permissions'].append({'name': 'ACCESS_MANAGEMENT'})
            config.oidc()
        self.assertEqual(len(groups), 6)
        self.assertEqual(len(mappings), 6)
        self.assertEqual({p['name'] for p in teams['Patchwatch Viewers']['permissions']},
                         {'VIEW_PORTFOLIO', 'VIEW_VULNERABILITY', 'VIEW_POLICY_VIOLATION'})
        self.assertIn({'name': 'ACCESS_MANAGEMENT'}, teams['Patchwatch Administrators']['permissions'])
        for name, team in teams.items():
            if name == 'Patchwatch Administrators':
                continue
            permissions = {p['name'] for p in team['permissions']}
            self.assertTrue(permissions.isdisjoint({'ACCESS_MANAGEMENT', 'SECRET_MANAGEMENT',
                'SYSTEM_CONFIGURATION', 'PORTFOLIO_ACCESS_CONTROL_BYPASS',
                'PORTFOLIO_MANAGEMENT', 'PORTFOLIO_MANAGEMENT_DELETE',
                'POLICY_MANAGEMENT', 'POLICY_MANAGEMENT_DELETE', 'VULNERABILITY_MANAGEMENT'}), name)

    def test_invalid_mapping_does_not_partially_change_permissions(self):
        client = DependencyTrack('https://dtrack.example', {})
        config = Provisioner(client)
        with tempfile.TemporaryDirectory() as folder:
            filename = Path(folder) / 'mappings.json'
            filename.write_text(json.dumps([{'team': 'Admins', 'group': 'admins', 'permissions': ['ACCESS_MANAGEMENT']},
                                            {'team': 'Invalid', 'permissions': []}]))
            with patch.dict(os.environ, {'OIDC_TEAM_MAPPINGS_FILE': str(filename)}), patch.object(client, 'call') as call:
                with self.assertRaises(ValueError):
                    config.oidc()
                call.assert_not_called()
