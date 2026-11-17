# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from patchwatch.dtrack.client import DependencyTrack
from patchwatch.dtrack.setup import Provisioner


class TrivyConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.client = DependencyTrack('https://dtrack.example', {})
        self.config = Provisioner(self.client)

    def test_no_requested_server_preserves_existing_configuration(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(self.client, 'extension') as update, \
                patch.object(self.client, 'secret') as store:
            self.config.trivy()
            update.assert_not_called()
            store.assert_not_called()

    def test_missing_token_does_not_partially_enable_analyzer(self):
        with patch.dict(os.environ, {'TRIVY_URL': 'https://trivy.example'}, clear=True), \
                patch.object(self.client, 'extension') as update, patch.object(self.client, 'secret') as store:
            with self.assertRaises(ValueError): self.config.trivy()
            update.assert_not_called()
            store.assert_not_called()

    def test_transport_and_option_validation_happen_before_updates(self):
        for settings in [
            {'TRIVY_URL': 'http://trivy.example', 'TRIVY_TOKEN': 'secret'},
            {'TRIVY_URL': 'https://user:password@trivy.example', 'TRIVY_TOKEN': 'secret'},
            {'TRIVY_URL': 'https://trivy.example', 'TRIVY_TOKEN': 'secret', 'TRIVY_IGNORE_UNFIXED': 'yes'},
        ]:
            with self.subTest(settings=list(settings)), patch.dict(os.environ, settings, clear=True), \
                    patch.object(self.client, 'extension') as update, patch.object(self.client, 'secret') as store:
                with self.assertRaises(ValueError): self.config.trivy()
                update.assert_not_called()
                store.assert_not_called()

    def test_token_goes_to_secret_store_and_extension_references_it_by_name(self):
        with tempfile.TemporaryDirectory() as folder:
            token = Path(folder)/'token'; token.write_text('file-token')
            settings = {'TRIVY_URL': 'http://trivy:4954', 'ALLOW_HTTP': 'true', 'TRIVY_TOKEN_FILE': str(token)}
            with patch.dict(os.environ, settings, clear=True), patch.object(self.client, 'secret', return_value='NAME') as store, \
                    patch.object(self.client, 'extension') as update:
                self.config.trivy()
                store.assert_called_once_with('PATCHWATCH_TRIVY_TOKEN', 'file-token')
                update.assert_called_once_with('vuln-analyzer', 'trivy', enabled=True, apiUrl='http://trivy:4954',
                                               apiToken='NAME', ignoreUnfixed=False, scanLibrary=True, scanOs=True)
