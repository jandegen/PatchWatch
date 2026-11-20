# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

module = runpy.run_path(str(Path(__file__).resolve().parent.parent / 'scripts/setup-release-mirror.py'))
URL = 'https://github.com/acme/patchwatch.git'


def variable(key, value='x', protected=True, masked=None):
    return {'key': key, 'value': value, 'protected': protected,
            'masked': module['VARIABLES'][key] if masked is None else masked, 'environment_scope': '*'}


def args(**overrides):
    return SimpleNamespace(**{'force': False, 'url': None, 'patterns': None, **overrides})


class State(unittest.TestCase):
    def test_states(self):
        existing = {'GITHUB_MIRROR_URL': variable('GITHUB_MIRROR_URL'),
                    'GITHUB_MIRROR_TOKEN': variable('GITHUB_MIRROR_TOKEN', masked=False),
                    'MIRROR_FORBIDDEN_PATTERNS': variable('MIRROR_FORBIDDEN_PATTERNS', protected=False)}
        state = module['state']
        self.assertEqual([state(existing, k) for k in module['VARIABLES']], ['ok', 'flags', 'flags', 'missing'])


class Plan(unittest.TestCase):
    def run_plan(self, existing, **overrides):
        states = {key: module['state'](existing, key) for key in module['VARIABLES']}
        prompts = []

        def ask(prompt):
            prompts.append(prompt)
            return {'u': URL}.get('u') if 'repository URL' in prompt else 'pat\\.tern'

        def secret(prompt):
            prompts.append(prompt)
            return 'tokentoken' if 'GitHub token' in prompt else ''

        with patch.dict('os.environ', {}, clear=True):
            return module['plan'](existing, states, args(**overrides), ask, secret), prompts

    def test_everything_correct_asks_for_nothing(self):
        existing = {k: variable(k) for k in module['VARIABLES']}
        wanted, prompts = self.run_plan(existing)
        self.assertEqual((wanted, prompts), ({}, []))

    def test_force_asks_again(self):
        existing = {k: variable(k) for k in module['VARIABLES']}
        wanted, _ = self.run_plan(existing, force=True)
        self.assertEqual(set(wanted), {'GITHUB_MIRROR_URL', 'GITHUB_MIRROR_TOKEN', 'MIRROR_FORBIDDEN_PATTERNS'})

    def test_fresh_setup_asks_for_required_and_skips_empty_ghcr(self):
        wanted, _ = self.run_plan({})
        self.assertEqual(wanted, {'GITHUB_MIRROR_URL': URL, 'GITHUB_MIRROR_TOKEN': 'tokentoken',
                                  'MIRROR_FORBIDDEN_PATTERNS': 'pat\\.tern'})

    def test_wrong_flags_keep_the_existing_plain_value(self):
        existing = {k: variable(k) for k in module['VARIABLES']}
        existing['MIRROR_FORBIDDEN_PATTERNS'] = variable('MIRROR_FORBIDDEN_PATTERNS', 'keep\\.me', protected=False)
        wanted, prompts = self.run_plan(existing)
        self.assertEqual(wanted, {'MIRROR_FORBIDDEN_PATTERNS': 'keep\\.me'})
        self.assertEqual(prompts, [])


class Checks(unittest.TestCase):
    def test_mirror_token_needs_push_access(self):
        check = module['check_mirror_token']
        check(URL, 't', lambda url, token: (200, {}, {'permissions': {'push': True}}))
        with self.assertRaisesRegex(ValueError, 'write access'):
            check(URL, 't', lambda url, token: (200, {}, {'permissions': {'push': False}}))
        with self.assertRaisesRegex(ValueError, 'HTTP 404'):
            check(URL, 't', lambda url, token: (404, {}, None))

    def test_ghcr_token_needs_the_scope(self):
        check = module['check_ghcr_token']
        check('t', lambda url, token: (200, {'X-OAuth-Scopes': 'read:packages, write:packages'}, {}))
        with self.assertRaisesRegex(ValueError, 'classic'):
            check('t', lambda url, token: (200, {}, {}))
        with self.assertRaisesRegex(ValueError, 'HTTP 401'):
            check('t', lambda url, token: (401, {}, None))


class Write(unittest.TestCase):
    def test_creates_or_updates_and_protects_tags(self):
        calls = []

        def call(endpoint, payload=None, method=None):
            calls.append((method, endpoint))
            return [] if 'protected_tags?' in endpoint else None

        existing = {'GITHUB_MIRROR_URL': variable('GITHUB_MIRROR_URL')}
        with patch('builtins.print'):
            module['write'](7, call, existing, {'GITHUB_MIRROR_URL': URL, 'GITHUB_GHCR_TOKEN': 'ghp_12345678'})
        self.assertEqual([m for m, _ in calls], ['PUT', 'POST', None, 'POST'])

    def test_dry_run_writes_nothing(self):
        calls = []
        with patch('builtins.print'):
            module['write'](7, lambda e, p=None, m=None: calls.append(m) or [], {}, {'GITHUB_MIRROR_URL': URL},
                            dry_run=True)
        self.assertEqual(calls, [None])


if __name__ == '__main__':
    unittest.main()
