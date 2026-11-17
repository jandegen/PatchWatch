# SPDX-License-Identifier: Apache-2.0
import unittest
from unittest.mock import Mock
import urllib.error
import uuid
from patchwatch.dtrack.register import register


def missing():
    return urllib.error.HTTPError('https://example',404,'Not found',{},None)


class RegisterTests(unittest.TestCase):
    def test_migrate_preserves_project_uuid_and_history(self):
        uid=str(uuid.uuid4())
        original={'uuid':uid,'name':'devhost-asset-1','version':'current','active':True,'isLatest':False,
                  'description':'keep me','metrics':{'findingsTotal':12},'tags':[{'name':'agent:user'}]}
        client=Mock()
        def call(path,data=None,method=None):
            if path.startswith('project/lookup?'):
                if 'devhost-' in path: return original
                raise missing()
            if path=='project' and method=='POST':
                self.assertEqual(data['uuid'],uid)
                self.assertEqual(data['description'],'keep me')
                self.assertEqual(data['metrics']['findingsTotal'],12)
                return data
            if path=='metrics/portfolio/refresh': return None
            self.fail(path)
        client.call.side_effect=call
        config,project=register({'host_id':'asset-1','hostname':'dev-station','agent_scope':'user'},client)
        self.assertEqual(config['project_uuid'],uid)
        self.assertEqual(project['name'],'dev-station')
        self.assertTrue(project['isLatest'])
        self.assertNotIn('agent:user',[t['name'] for t in project['tags']])

    def test_hostname_collision_never_merges_projects(self):
        client=Mock()
        client.call.side_effect=[{'uuid':'another-project'}, {'uuid':'original-project'}]
        with self.assertRaises(ValueError): register({'host_id':'asset-1','hostname':'dev-station'},client)
        self.assertFalse(any(c.args[0]=='project' for c in client.call.call_args_list))

    def test_uuid_target_preserves_identity_across_hostname_change(self):
        uid=str(uuid.uuid4()); client=Mock()
        def call(path,data=None,method=None):
            if path.startswith('project/lookup?'): raise missing()
            if path=='project/'+uid: return {'uuid':uid,'name':'old-name','version':'current'}
            if path=='project': return data
            return None
        client.call.side_effect=call
        cfg,project=register({'host_id':'asset-1','hostname':'new-name','project_uuid':uid},client)
        self.assertEqual(project['uuid'],uid)
        self.assertEqual(project['name'],'new-name')
