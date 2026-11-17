# SPDX-License-Identifier: Apache-2.0
"""SBOM completeness checks; findings never imply that an unobserved package is safe."""


def violations(bom, allow_empty=False):
    """Operational findings for SBOM completeness: empty inventory (FAIL) and packages without version or purl (WARN). ``allow_empty`` is for aggregating parents."""
    components = bom.get('components', [])
    if not components:
        return [] if allow_empty else [{'type': 'OPERATIONAL', 'state': 'FAIL',
                                       'policy': 'Patchwatch nonempty inventory', 'count': 1}]
    versioned = [c for c in components if c.get('type', 'library') in
                 ('library', 'application', 'framework', 'operating-system', 'container')]
    counts = {
        'Patchwatch package version metadata': sum(not str(c.get('version') or '').strip()
                                                   or str(c.get('version')).upper() in ('UNKNOWN', 'NOASSERTION') for c in versioned),
        'Patchwatch package URL metadata': sum(not str(c.get('purl') or '').startswith('pkg:') for c in versioned),
    }
    return [{'type': 'OPERATIONAL', 'state': 'WARN', 'policy': name, 'count': count}
            for name, count in counts.items() if count]
