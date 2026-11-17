# SPDX-License-Identifier: Apache-2.0
import unittest

from patchwatch.dtrack import legacy


def entry(name, tags):
    return {"uuid": name, "name": name, "version": "v", "tags": [{"name": t} for t in tags]}


class Legacy(unittest.TestCase):
    def test_only_tagged_projects_below_a_mr_feedback_segment_are_selected(self):
        projects = [entry("g/p/mr-feedback/api", ["scan-purpose:mr-feedback"]),
                    entry("g/p/mr-feedback/api", []),                          # untagged: not ours
                    entry("g/p/api", ["scan-purpose:mr-feedback"]),            # current scheme
                    entry("mr-feedback", ["scan-purpose:mr-feedback"])]        # top-level name, not a segment below a path

        class Client:
            def all(self, path):
                return projects
        self.assertEqual([p["name"] for p in legacy.legacy_projects(Client())], ["g/p/mr-feedback/api"])
