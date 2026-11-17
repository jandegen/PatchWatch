#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify a real Dependency-Track -> Trivy scan using synthetic package coordinates.

Requires DT_URL and DT_ADMIN_PASSWORD(_FILE), or DT_ADMIN_API_KEY(_FILE).
Creates a unique test project and removes it afterwards. No vulnerable software is installed.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid
from urllib.parse import urlencode
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from patchwatch.core.sbom import multipart
from patchwatch.core.http import check_url, request, secret


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args()
    url = check_url(os.environ['DT_URL'], os.getenv('ALLOW_HTTP') == 'true')
    if secret('DT_ADMIN_API_KEY'):
        headers = {'X-Api-Key': secret('DT_ADMIN_API_KEY')}
    else:
        token, _ = request(url+'/api/v1/user/login', urlencode({'username': 'admin', 'password': secret('DT_ADMIN_PASSWORD')}).encode(), {'Content-Type': 'application/x-www-form-urlencoded'}, 'POST')
        headers = {'Authorization': 'Bearer '+token}
    def call(path, method=None):
        return request(url+'/api/v1/'+path, headers=headers, method=method)[0]
    config = call('configProperty')
    assert any(x['propertyName']=='trivy.enabled' and x['propertyValue']=='true' for x in config), 'Trivy analyzer is not enabled'
    name = 'patchwatch-trivy-smoke-'+uuid.uuid4().hex[:12]
    # Maven coordinates only; there is no log4j binary on this machine or in the project.
    bom = {'bomFormat':'CycloneDX','specVersion':'1.6','version':1,
           'components':[{'type':'library','group':'org.apache.logging.log4j','name':'log4j-core',
                          'version':'2.14.1','purl':'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'}]}
    body, content_type = multipart({'autoCreate':'true','projectName':name,'projectVersion':'smoke'},bom)
    project_id = None
    try:
        request(url+'/api/v1/bom',body,{**headers,'Content-Type':content_type},'POST')
        deadline = time.monotonic()+args.timeout
        while time.monotonic()<deadline:
            if not project_id:
                try:
                    project = call('project/lookup?'+urlencode({'name':name,'version':'smoke'}))
                    project_id = project['uuid']
                except Exception:
                    time.sleep(2)
                    continue
            findings = call('finding/project/'+project_id)
            for finding in findings:
                vulnerability = finding.get('vulnerability', {})
                attribution = finding.get('attribution', {})
                if vulnerability.get('vulnId')=='CVE-2021-44228' and attribution.get('analyzerIdentity')=='TRIVY_ANALYZER':
                    print('Native Trivy integration verified: CVE-2021-44228 attributed to TRIVY_ANALYZER')
                    return
            time.sleep(3)
        raise RuntimeError('Expected Trivy finding was not received within the polling budget')
    finally:
        if project_id:
            call('project/'+project_id, 'DELETE')
            print('Synthetic test project removed')


if __name__ == '__main__':
    main()
