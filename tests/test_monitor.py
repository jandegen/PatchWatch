# SPDX-License-Identifier: Apache-2.0
import unittest
from patchwatch.dtrack.monitor import stale_projects


class MonitorTests(unittest.TestCase):
    def test_stale_missing_never_uploaded_and_active_filter(self):
        now = 1_800_000_000
        projects = [
            {"name": "devhost-old", "version": "current", "lastBomImport": (now - 49*3600)*1000},
            {"name": "devhost-new", "version": "current", "lastBomImport": now*1000},
            {"name": "devhost-never", "version": "current"},
            {"name": "devhost-inactive", "version": "current", "active": False},
            {"name": "other-project", "version": "1"}]
        self.assertEqual(stale_projects(projects, 48, now, ["devhost-missing", "devhost-new"]),
                         ["devhost-missing", "devhost-never", "devhost-old"])

    def test_hostname_projects_are_monitored_by_tags(self):
        project={'name':'dev-station','version':'current','tags':[{'name':'managed-by:patchwatch'},{'name':'asset-type:workstation'}]}
        self.assertEqual(stale_projects([project],48,now=1_800_000_000),['dev-station'])

    def test_empty_dashboard_is_detected_after_aggregation_grace(self):
        from patchwatch.dtrack.monitor import portfolio_consistency
        project={'name':'dev-station','version':'current','lastBomImport':1_799_900_000_000,
                 'tags':[{'name':'managed-by:patchwatch'},{'name':'asset-type:workstation'}],
                 'metrics':{'components':100,'findingsTotal':12}}
        self.assertIsNotNone(portfolio_consistency([project],{'projects':0,'components':0,'findingsTotal':0},now=1_800_000_000))
        self.assertIsNone(portfolio_consistency([project],{'projects':1,'components':100,'findingsTotal':12},now=1_800_000_000))
        project['lastBomImport']=1_800_000_000_000
        self.assertIsNone(portfolio_consistency([project],{'projects':0},now=1_800_000_000))
