# SPDX-License-Identifier: Apache-2.0
import unittest
from patchwatch.core.quality import violations
from patchwatch.dtrack.compliance import breaches
from patchwatch.ci.pipeline import gate


class QualityTests(unittest.TestCase):
    def test_empty_inventory_fails_but_collection_container_is_exempt(self):
        self.assertEqual(violations({'components': []})[0]['state'], 'FAIL')
        self.assertEqual(violations({'components': []}, allow_empty=True), [])

    def test_missing_metadata_warns_and_participates_in_optional_gate(self):
        issues = violations({'components': [{'type':'library','name':'a'},
                                             {'type':'library','name':'b','version':'1','purl':'pkg:pypi/b@1'}]})
        result = {'unsuppressedViolations': [], 'qualityViolations': issues}
        self.assertEqual([i['count'] for i in issues], [1,1])
        self.assertTrue(gate(result, 'warn'))
        self.assertFalse(gate(result, 'fail'))
        self.assertFalse(gate(result, 'none'))

    def test_file_metadata_does_not_trigger_package_requirements(self):
        self.assertEqual(violations({'components':[{'type':'file','name':'file'}]}), [])
