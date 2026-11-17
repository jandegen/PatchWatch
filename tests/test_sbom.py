# SPDX-License-Identifier: Apache-2.0
"""Tests of the SBOM reduction shared by agent and CI."""
import json
import unittest

from patchwatch.core.sbom import sanitize


class SanitizeTests(unittest.TestCase):
    def test_privacy_and_deduplication(self):
        raw = {"metadata": {"user": "alice", "secret": "password"}, "components": [
            {"type": "library", "name": "example", "version": "1", "purl": "pkg:pypi/example@1",
             "description": "PRIVATE FILE CONTENTS", "properties": [
                 {"name": "syft:location:0:path", "value": "/opt/example"},
                 {"name": "syft:metadata:secrets", "value": "secret"}]},
            {"type": "file", "name": "private-file"}]}
        result = sanitize([raw, raw], "asset-123")
        self.assertEqual(len(result["components"]), 1)
        text = json.dumps(result)
        for forbidden in ("alice", "password", "PRIVATE", "secret", "private-file"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(result["components"][0]["properties"][0]["value"], "/opt/example")
        self.assertEqual(result["metadata"]["component"]["name"], "asset-123")

    def test_license_identifiers_survive_without_texts_or_urls(self):
        component={'type':'library','name':'example','version':'1','licenses':[
            {'license':{'id':'Apache-2.0','text':{'content':'PRIVATE LICENSE TEXT'},'url':'https://user:secret@example.org'}},
            {'license':{'name':'Vendor EULA','acknowledgement':'declared','licensing':{'licensor':{'name':'private-person'}}}}]}
        result=sanitize([{'components':[component]}],'host')['components'][0]
        self.assertEqual(result['licenses'],[{'license':{'acknowledgement':'declared','name':'Vendor EULA'}},{'license':{'id':'Apache-2.0'}}])
        serialized=json.dumps(result)
        for forbidden in ('PRIVATE','secret','private-person','url','licensor'):
            self.assertNotIn(forbidden,serialized)

    def test_license_data_is_not_part_of_component_identity(self):
        component={'type':'library','name':'pkg','version':'1','purl':'pkg:pypi/pkg@1'}
        licensed={**component,'licenses':[{'license':{'id':'MIT'}}]}
        before=sanitize([{'components':[component]}],'host')['components'][0]
        after=sanitize([{'components':[licensed,component]}],'host')['components']
        self.assertEqual(len(after),1)
        self.assertEqual(before['bom-ref'],after[0]['bom-ref'])
        self.assertEqual(after[0]['licenses'],[{'license':{'id':'MIT'}}])

    def test_license_expressions_preserve_and_or_semantics(self):
        expression='MIT OR (Apache-2.0 AND BSD-3-Clause)'
        component={'type':'library','name':'pkg','licenses':[{'expression':expression,'acknowledgement':'declared','bom-ref':'private-reference'}]}
        result=sanitize([{'components':[component]}],'host')['components'][0]
        self.assertEqual(result['licenses'],[{'expression':expression,'acknowledgement':'declared'}])

    def test_conflicting_expressions_are_marked_instead_of_combined(self):
        first={'type':'library','name':'pkg','licenses':[{'expression':'MIT OR Apache-2.0'}]}
        second={**first,'licenses':[{'expression':'GPL-3.0-only'}]}
        result=sanitize([{'components':[first,second]}],'host')['components'][0]
        self.assertEqual(result['licenses'],[{'expression':'MIT OR Apache-2.0'}])
        self.assertIn({'name':'patchwatch:license-conflict','value':'true'},result['properties'])

    def test_unknown_licenses_are_not_assigned_a_default(self):
        result=sanitize([{'components':[{'type':'library','name':'unknown','licenses':[{'license':{'text':{'content':'unknown'}}}]}]}],'host')
        self.assertNotIn('licenses',result['components'][0])

    def test_graph_references_survive_deduplication_and_source_collisions(self):
        a={'type':'library','name':'a','bom-ref':'same'}
        b={'type':'library','name':'b','bom-ref':'b'}
        c={'type':'library','name':'c','bom-ref':'same'}
        first={'components':[a,b,{'type':'file','name':'private','bom-ref':'file'}],
               'dependencies':[{'ref':'same','dependsOn':['b','file','missing']},
                               {'ref':'b','dependsOn':['same','b']}]}
        second={'components':[c,b], 'dependencies':[{'ref':'same','dependsOn':['b']}]}
        result=sanitize([first,second,first],'host','stable-id')
        refs={c['name']:c['bom-ref'] for c in result['components']}
        graph={d['ref']:d['dependsOn'] for d in result['dependencies']}
        root=result['metadata']['component']['bom-ref']
        self.assertIn(refs['c'],graph[root])
        self.assertLess(len(graph[root]),len(refs))
        self.assertEqual(graph[refs['a']],[refs['b']])
        self.assertEqual(graph[refs['b']],[refs['a']])
        self.assertEqual(graph[refs['c']],[refs['b']])
        self.assertNotIn('file',json.dumps(graph))
        self.assertEqual(root,sanitize([second],'renamed-host','stable-id')['metadata']['component']['bom-ref'])

    def test_inventory_without_scanner_dependencies_does_not_invent_edges(self):
        result=sanitize([{'components':[{'type':'library','name':'pkg'}]}],'host')
        root=result['metadata']['component']['bom-ref']
        self.assertEqual(result['dependencies'],[{'ref':root,'dependsOn':[]}])

    def test_large_inventory_does_not_become_thousands_of_direct_dependencies(self):
        packages=[{'type':'library','name':f'isolated-{i}'} for i in range(2000)]
        packages += [{'type':'library','name':'app','bom-ref':'app'},
                     {'type':'library','name':'dependency','bom-ref':'dependency'}]
        result=sanitize([{'components':packages,'dependencies':[{'ref':'app','dependsOn':['dependency']}]}],'host')
        self.assertEqual(len(result['components']),2002)
        root=result['metadata']['component']['bom-ref']
        direct=next(d['dependsOn'] for d in result['dependencies'] if d['ref']==root)
        self.assertEqual(len(direct),1)
        self.assertEqual(sum(len(d['dependsOn']) for d in result['dependencies']),2)


class DetectedServices(unittest.TestCase):
    def test_compose_services_reach_the_sbom_without_secrets(self):
        import tempfile
        from pathlib import Path
        from patchwatch.core.services import find_services
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "opt/app").mkdir(parents=True)
            (Path(folder) / "opt/app/docker-compose.yml").write_text(
                "services:\n  api:\n    image: ghcr.io/x/api:1.2@sha256:abc\n    environment:\n      PASSWORD: hunter2\n")
            bom = sanitize([{"components": []}], "host", services=find_services([folder]))
        self.assertEqual(bom["services"][0]["name"], "api")
        self.assertEqual(bom["services"][0]["version"], "1.2")
        self.assertNotIn("hunter2", str(bom))


if __name__ == "__main__":
    unittest.main()
