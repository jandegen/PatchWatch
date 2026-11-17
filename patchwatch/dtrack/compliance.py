# SPDX-License-Identifier: Apache-2.0
"""Read-only license coverage and policy violation report for managed projects."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from .client import DependencyTrack
from ..core.http import check_url, secret
from ..core.tags import MANAGED_TAG
from ..core.quality import violations as quality_violations


def project_report(client, project):
    """License and policy report of one project: component/license coverage, license conflicts, quality findings and unsuppressed violations."""
    identifier = project['uuid']
    bom = client.call('bom/cyclonedx/project/' + identifier)
    components = bom.get('components', [])
    conflicts = []
    for component in components:
        if any(p.get('name') == 'patchwatch:license-conflict' and p.get('value') == 'true'
               for p in component.get('properties', [])):
            conflicts.append({k: component[k] for k in ('name', 'version', 'purl', 'bom-ref') if k in component})
    violations = client.all('violation/project/' + identifier)
    counts = Counter()
    for violation in violations:
        policy = violation['policyCondition']['policy']
        counts[(violation['type'], policy['violationState'], policy['name'])] += 1
    dependencies = bom.get('dependencies', [])
    root = bom.get('metadata', {}).get('component', {}).get('bom-ref')
    return {'project': {k: project[k] for k in ('uuid', 'name', 'version') if k in project},
            'lastBomImport': project.get('lastBomImport'),
            'components': len(components),
            'componentsWithLicenseMetadata': sum(bool(c.get('licenses')) for c in components),
            'licenseConflicts': conflicts,
            'qualityViolations': quality_violations(bom, allow_empty=str(project.get('collectionLogic', '')).startswith('AGGREGATE_')),
            'graphEdges': sum(len(d.get('dependsOn', [])) for d in dependencies),
            'packageDependencyEdges': sum(len(d.get('dependsOn', [])) for d in dependencies if d.get('ref') != root),
            'unsuppressedViolations': [{'type': t, 'state': s, 'policy': p, 'count': n}
                                      for (t, s, p), n in sorted(counts.items())]}


def report(client):
    """Report of all active projects that carry the managed-by tag."""
    projects = [p for p in client.all('project') if p.get('active', True)
                and any(t.get('name') == MANAGED_TAG for t in p.get('tags', []))]
    return {'generatedAt': datetime.now(timezone.utc).isoformat(),
            'scopeTag': MANAGED_TAG, 'projects': [project_report(client, p) for p in projects]}


def breaches(result, threshold):
    """Whether ``result`` violates the threshold: ``none`` never, ``fail`` on FAIL states, ``warn`` on WARN or FAIL (including license conflicts)."""
    states = {'none': set(), 'fail': {'FAIL'}, 'warn': {'WARN', 'FAIL'}}[threshold]
    return any((p['licenseConflicts'] and 'WARN' in states)
               or any(v['state'] in states and v['count'] for v in p['unsuppressedViolations'] + p.get('qualityViolations', []))
               for p in result['projects'])


def main():
    """CLI: write the report and exit 2 when ``--fail-on`` is exceeded."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='compliance-report.json')
    parser.add_argument('--fail-on', choices=('none', 'warn', 'fail'), default='none')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        url = check_url(os.environ['DT_URL'], os.getenv('ALLOW_HTTP') == 'true')
        key = secret('DT_API_KEY')
        if not key:
            raise ValueError('DT_API_KEY(_FILE) is required; VIEW_PORTFOLIO and VIEW_POLICY_VIOLATION required')
        result = report(DependencyTrack(url, {'X-Api-Key': key}))
        Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
        print(f"Compliance report: {len(result['projects'])} managed projects")
        if breaches(result, args.fail_on):
            parser.exit(2, 'Compliance threshold exceeded; see report\n')
    except Exception as error:
        parser.exit(1, f'Compliance report failed ({type(error).__name__}); check API access\n')


if __name__ == '__main__':
    main()
