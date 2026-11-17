# SPDX-License-Identifier: Apache-2.0
"""Register or rename a host with administrative credentials, preserving project UUID and findings."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import urllib.error
import uuid
from urllib.parse import urlencode
from .client import admin_client
from ..core.tags import hostname, inventory_tags


def register(config, client):
    """Create or update the project of a host with administrative rights; returns ``(config with project_uuid, project)``.

    An existing project keeps its UUID and findings. Hostname collisions with a different project are
    refused instead of merged."""
    name = hostname(config.get('hostname'))
    tags = inventory_tags(config, name)
    def lookup(candidate):
        try: return client.call('project/lookup?'+urlencode({'name':candidate,'version':'current'}))
        except urllib.error.HTTPError as error:
            if error.code!=404: raise
            error.close()
            return None
    target = lookup(name)
    if config.get('project_uuid'):
        project = client.call('project/'+str(uuid.UUID(config['project_uuid'])))
    else:
        project = lookup('devhost-'+config['host_id'])
        if project is None and target:
            existing_tags = {t['name'] for t in target.get('tags',[])}
            if 'asset-id:'+str(config['host_id']).lower() not in existing_tags:
                raise ValueError('Hostname already belongs to another project; explicitly provide its project_uuid to migrate it')
            project = target
    if project is not None and target and project['uuid']!=target['uuid']:
        raise ValueError('Hostname collision: projects must not be merged automatically')
    if project is None:
        project = client.call('project', {'name':name,'version':'current','active':True,
                              'isLatest':True,'classifier':'DEVICE','tags':[{'name':t} for t in tags]}, 'PUT')
    else:
        project = dict(project)
        project.update({'name':name,'version':'current','active':True,'isLatest':True,
                        'classifier':'DEVICE','tags':[{'name':t} for t in tags]})
        project = client.call('project', project, 'POST')
    expected = set(tags)
    actual = {t['name'] for t in project.get('tags',[])}
    if project.get('name')!=name or actual!=expected or not project.get('isLatest'):
        raise RuntimeError('Host registration was not applied as requested')
    client.call('metrics/portfolio/refresh')
    return {**config, 'project_uuid':project['uuid']}, project


def main():
    """CLI: register this host and store only the project UUID in the agent profile."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',default='/etc/patchwatch/agent.json')
    parser.add_argument('--hostname',help='Override automatic hostname detection, e.g. when provisioning a remote host')
    parser.add_argument('--project-uuid',help='Explicit existing project UUID to migrate without losing findings')
    args=parser.parse_args()
    os.umask(0o077)
    path=Path(args.config)
    config=json.loads(path.read_text())
    if args.hostname: config['hostname']=args.hostname
    if args.project_uuid: config['project_uuid']=args.project_uuid
    client=admin_client(os.getenv('DT_URL',config['url']))
    config,project=register(config,client)
    # Credentials stay in the operator environment; only the project UUID is written to agent config.
    with tempfile.NamedTemporaryFile('w',dir=path.parent,delete=False) as stream:
        temp=Path(stream.name)
        json.dump(config,stream,indent=2); stream.write('\n')
    try: os.replace(temp,path)
    finally: temp.unlink(missing_ok=True)
    print(json.dumps({'project':project['name'],'uuid':project['uuid'],'tags':[t['name'] for t in project['tags']]},indent=2))


if __name__=='__main__': main()
