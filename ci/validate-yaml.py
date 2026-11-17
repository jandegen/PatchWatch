#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reject duplicate YAML keys, including accidentally concatenated Helm release documents.

CI tooling only: requires PyYAML (Alpine package py3-yaml).
"""
import sys
from pathlib import Path
import yaml


class StrictLoader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    values = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in values:
            raise ValueError(f'Duplicate YAML key {key!r} at line {key_node.start_mark.line+1}')
        values[key] = loader.construct_object(value_node, deep=deep)
    return values


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
for filename in sys.argv[1:]:
    items = [d for d in yaml.load_all(Path(filename).read_text(), Loader=StrictLoader) if d is not None]
    for item in items:
        if not isinstance(item, dict) or not all(k in item for k in ('apiVersion','kind','metadata')):
            raise ValueError(f'{filename}: incomplete Kubernetes manifest')
    print(f'{filename}: {len(items)} documents, no duplicate keys')
