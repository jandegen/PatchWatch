# SPDX-License-Identifier: Apache-2.0
import contextlib
import io
from pathlib import Path
import runpy
import unittest

provision = runpy.run_path(str(Path(__file__).resolve().parent.parent / 'scripts/setup-mr-feedback.py'))['provision']


class GitLabSetup:
    def __init__(self):
        self.variables = [{'key': name, 'value': 'dtrack-secret' if name.endswith('_KEY') else 'https://dt.example',
                           'protected': True, 'environment_scope': '*'}
                          for name in ('PATCHWATCH_URL', 'PATCHWATCH_UPLOAD_KEY', 'PATCHWATCH_READ_KEY')]
        self.schedule = None
        self.writes = []
        self.config = 'include:\n  - local: ci/mr-feedback.yml\n'
        self.protected = True

    def call(self, endpoint, payload=None, method=None):
        if method:
            self.writes.append((endpoint, payload, method))
        if endpoint == 'projects/120':
            return {'default_branch': 'main', 'web_url': 'https://gitlab.example/team/app'}
        if '/repository/branches/' in endpoint:
            return {'protected': self.protected}
        if '/repository/files/' in endpoint:
            return self.config
        if '/variables?' in endpoint:
            return self.variables
        if endpoint == 'projects/120/variables':
            self.variables.append(payload)
            return payload
        if endpoint == 'projects/120/access_tokens':
            return {'id': 55, 'token': 'bot-secret', 'expires_at': '2027-02-13'}
        if endpoint.endswith('pipeline_schedules?per_page=100'):
            return [self.schedule] if self.schedule else []
        if endpoint.endswith('pipeline_schedules') or endpoint.endswith('pipeline_schedules/44'):
            if payload:
                self.schedule = {**(self.schedule or {'id': 44, 'variables': []}), **payload}
            return self.schedule
        if 'pipeline_schedules/44/variables' in endpoint:
            self.schedule['variables'] = [payload]
            return payload
        raise AssertionError(endpoint)


class Setup(unittest.TestCase):
    def setUp(self):
        self.gl = GitLabSetup()
        self.log = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.log))

    def test_provision_is_idempotent_and_does_not_activate_old_default_branch_ci(self):
        provision(120, self.gl.call, ca_cert='public CA')
        provision(120, self.gl.call)
        self.assertFalse(self.gl.schedule['active'])
        bots = [w for w in self.gl.writes if w[0].endswith('access_tokens')]
        self.assertEqual(len(bots), 1)
        self.assertEqual(bots[0][1]['access_level'], 30)
        self.assertIn(('projects/120', {'protect_merge_request_pipelines': False}, 'PUT'), self.gl.writes)
        token = next(v for v in self.gl.variables if v['key'] == 'PATCHWATCH_GITLAB_TOKEN')
        self.assertTrue(token['protected'])
        self.assertTrue(token['masked'])
        self.assertEqual(token['environment_scope'], 'patchwatch-mr-feedback')
        self.assertNotIn('bot-secret', self.log.getvalue())
        self.assertNotIn('dtrack-secret', self.log.getvalue())
        self.assertEqual(self.gl.schedule['variables'][0]['value'], 'true')

    def test_activation_requires_feedback_include_on_default_branch(self):
        self.gl.config = 'include: []'
        with self.assertRaisesRegex(ValueError, 'Merge the MR feedback include'):
            provision(120, self.gl.call, activate=True)
        self.assertFalse(self.gl.writes)

    def test_activation_sets_five_minute_schedule_on_default_branch(self):
        provision(120, self.gl.call, activate=True)
        self.assertTrue(self.gl.schedule['active'])
        self.assertEqual(self.gl.schedule['cron'], '*/5 * * * *')
        self.assertEqual(self.gl.schedule['ref'], 'main')

    def test_unprotected_branch_or_keys_prevent_creating_bot_credentials(self):
        self.gl.protected = False
        with self.assertRaisesRegex(ValueError, 'Protect the default branch'):
            provision(120, self.gl.call)
        self.assertFalse(self.gl.writes)
        self.gl.protected = True
        self.gl.variables[1]['protected'] = False
        with self.assertRaisesRegex(ValueError, 'must be protected'):
            provision(120, self.gl.call)
        self.assertFalse(self.gl.writes)
