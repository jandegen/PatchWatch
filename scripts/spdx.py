#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproducible SPDX-2.3 inventory of this project's source plus declared runtime dependencies."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "patchwatch.spdx.json"


def document():
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    files = []
    sha1s = []
    for name in sorted(set(names)):
        path = ROOT / name
        if not name or name == DEST.name or not path.is_file():
            continue
        content = path.read_bytes()
        sha1 = hashlib.sha1(content).hexdigest()
        sha1s.append(sha1)
        files.append({"SPDXID": "SPDXRef-File-" + hashlib.sha256(name.encode()).hexdigest()[:24],
                      "fileName": "./" + name, "checksums": [{"algorithm": "SHA1", "checksumValue": sha1},
                      {"algorithm": "SHA256", "checksumValue": hashlib.sha256(content).hexdigest()}],
                      "licenseConcluded": "Apache-2.0", "licenseInfoInFiles": ["Apache-2.0"],
                      "copyrightText": "NOASSERTION"})
    verification = hashlib.sha1("".join(sorted(sha1s)).encode()).hexdigest()
    packages = [{"name": "patchwatch", "SPDXID": "SPDXRef-Patchwatch", "versionInfo": "1.0.10",
                 "downloadLocation": "NOASSERTION",
                 "filesAnalyzed": True, "packageVerificationCode": {"packageVerificationCodeValue": verification,
                 "packageVerificationCodeExcludedFiles": ["./patchwatch.spdx.json"]},
                 "licenseConcluded": "Apache-2.0", "licenseDeclared": "Apache-2.0", "copyrightText": "NOASSERTION",
                 "primaryPackagePurpose": "APPLICATION", "licenseInfoFromFiles": ["Apache-2.0"]}]
    dependencies = [
        ("Trivy", "0.76.2", "Apache-2.0", "https://github.com/aquasecurity/trivy/releases/tag/v0.76.2"),
        ("DockerCLI", "29.9.3", "Apache-2.0", "https://github.com/docker/cli/releases/tag/v29.9.3"),
        ("Syft", "1.57.1", "Apache-2.0", "https://github.com/anchore/syft/releases/tag/v1.57.1"),
        ("DependencyTrack", "5.2.1", "Apache-2.0", "https://github.com/DependencyTrack/dependency-track/releases/tag/5.2.1"),
        ("DependencyTrackFrontend", "5.2.1", "Apache-2.0", "https://github.com/DependencyTrack/frontend/releases/tag/5.2.1"),
        ("DependencyTrackHelmChart", "2.9.0", "Apache-2.0", "https://github.com/DependencyTrack/helm-charts/releases/tag/dependency-track-2.9.0"),
        ("PostgreSQL", "17.7", "PostgreSQL", "https://www.postgresql.org/ftp/source/v17.7/"),
        ("Python", "3.14.0", "Python-2.0", "https://www.python.org/downloads/release/python-3140/"),
        ("NginxUnprivileged", "1.28.0-alpine", "Apache-2.0", "https://github.com/nginx/docker-nginx-unprivileged")]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Patchwatch"}]
    for name, version, license_id, location in dependencies:
        ref = "SPDXRef-" + name
        packages.append({"name": name, "SPDXID": ref, "versionInfo": version, "downloadLocation": location,
                         "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": license_id,
                         "copyrightText": "NOASSERTION", "comment": "Declared deployment dependency; transitive dependencies and container OS layers are not analyzed by this source inventory."})
        relationships.append({"spdxElementId": "SPDXRef-Patchwatch", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": ref})
    relationships += [{"spdxElementId": "SPDXRef-Patchwatch", "relationshipType": "CONTAINS", "relatedSpdxElement": f["SPDXID"]} for f in files]
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "patchwatch-1.0.10", "documentNamespace": "https://spdx.org/spdxdocs/patchwatch-1.0.10-" + verification,
            "creationInfo": {"created": "2026-11-13T00:00:00Z", "creators": ["Tool: patchwatch-spdx-0.1.0"], "licenseListVersion": "3.26.0"},
            "packages": packages, "files": files, "relationships": relationships}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(document(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not DEST.exists() or DEST.read_text() != encoded:
            sys.exit("SPDX inventory is stale; run python3 scripts/spdx.py and commit patchwatch.spdx.json")
        print("SPDX source checksums verified")
    else:
        DEST.write_text(encoded)
        print("Wrote patchwatch.spdx.json")


if __name__ == "__main__":
    main()
