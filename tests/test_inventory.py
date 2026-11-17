# SPDX-License-Identifier: Apache-2.0
import unittest
from unittest.mock import patch
from patchwatch.core.tags import canonical_tags, inventory_tags, hostname, is_host_project


class InventoryTests(unittest.TestCase):
    def test_hostnames_are_detected_and_validated(self):
        with patch('patchwatch.core.tags.socket.gethostname',return_value='Dev-Station'):
            self.assertEqual(hostname(),'dev-station')
        self.assertEqual(hostname('host.example.internal.'),'host.example.internal')
        for value in ['', 'host/name', '../host', 'host..name', 'host\nname', '-host']:
            with self.subTest(value=value), self.assertRaises(ValueError): hostname(value)

    def test_canonical_tags_do_not_invent_team_ownership(self):
        cfg={'host_id':'asset-1','agent_scope':'user','tags':[' Team:Platform ','team:platform','host-group:Developer-Workstations','agent:user']}
        with patch('patchwatch.core.tags.platform.system',return_value='Linux'), patch('patchwatch.core.tags.platform.freedesktop_os_release',return_value={'ID':'ubuntu'}):
            tags=inventory_tags(cfg,'dev-station')
        self.assertEqual(tags,sorted(set(tags)))
        self.assertIn('team:platform',tags)
        self.assertIn('asset-group:developer-workstations',tags)
        self.assertIn('managed-by:patchwatch',tags)
        self.assertIn('host:dev-station',tags)
        self.assertIn('distro:ubuntu',tags)
        self.assertFalse(any(t.startswith('team:') for t in inventory_tags({'host_id':'asset-1'},'dev-station')))

    def test_ambiguous_invalid_or_spoofed_tags_fail(self):
        for tags in [['team:one','team:two'],['plain'],['team:with space'],['team:x,y'],['url:https://secret'],['managed-by:other'],['host:other']]:
            with self.subTest(tags=tags), self.assertRaises(ValueError):
                inventory_tags({'host_id':'asset-1','tags':tags},'dev-station')

    def test_host_project_detection_survives_rename(self):
        self.assertTrue(is_host_project({'name':'dev-station','tags':[{'name':'managed-by:patchwatch'},{'name':'asset-type:workstation'}]}))
        self.assertTrue(is_host_project({'name':'devhost-legacy'}))
        self.assertFalse(is_host_project({'name':'app','tags':[{'name':'managed-by:patchwatch'}]}))
