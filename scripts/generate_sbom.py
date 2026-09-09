#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from datetime import datetime, timezone

def calculate_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def main():
    p = argparse.ArgumentParser(description="Generate SPDX 2.3 SBOM and SLSA Provenance")
    p.add_argument('--artifact', required=True, help="Path to binary artifact")
    p.add_argument('--name', required=True, help="Package name")
    p.add_argument('--version', required=True, help="Version string")
    p.add_argument('--output', required=True, help="Output SPDX JSON file")
    p.add_argument('--provenance', help="Output SLSA provenance JSON file")
    p.add_argument('--checksums', help="Output SHA-256 checksum manifest file")
    a = p.parse_args()

    sha = calculate_sha256(a.artifact)
    filename = os.path.basename(a.artifact)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

    doc = {
        'spdxVersion': 'SPDX-2.3',
        'dataLicense': 'CC0-1.0',
        'SPDXID': 'SPDXRef-DOCUMENT',
        'name': f'{a.name}-{a.version}',
        'documentNamespace': f'https://github.com/domehahn/{a.name}/sbom/{a.version}/{sha}',
        'creationInfo': {
            'created': now,
            'creators': ['Tool: project-release-sbomgen-2.0']
        },
        'packages': [{
            'name': a.name,
            'SPDXID': 'SPDXRef-Package',
            'versionInfo': a.version,
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False,
            'checksums': [{'algorithm': 'SHA256', 'checksumValue': sha}],
            'supplier': 'Organization: Open Source Project',
            'licenseConcluded': 'MIT',
            'licenseDeclared': 'MIT',
            'copyrightText': 'NOASSERTION'
        }],
        'relationships': [{
            'spdxElementId': 'SPDXRef-DOCUMENT',
            'relationshipType': 'DESCRIBES',
            'relatedSpdxElement': 'SPDXRef-Package'
        }]
    }

    with open(a.output, 'w') as f:
        json.dump(doc, f, indent=2)
        f.write('\n')
    print(f"Generated SBOM: {a.output}")

    if a.provenance:
        prov = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": filename,
                    "digest": {"sha256": sha}
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://github.com/domehahn/skrun@v1",
                    "externalParameters": {
                        "repository": "https://github.com/domehahn/skrun",
                        "ref": f"refs/tags/v{a.version}"
                    },
                    "internalParameters": {
                        "builder": "go build -trimpath -ldflags '-s -w'"
                    }
                },
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/domehahn/skrun/builders/release"
                    },
                    "metadata": {
                        "invocationId": f"build-{sha[:16]}",
                        "startedOn": now,
                        "finishedOn": now
                    }
                }
            }
        }
        with open(a.provenance, 'w') as f:
            json.dump(prov, f, indent=2)
            f.write('\n')
        print(f"Generated Provenance: {a.provenance}")

    if a.checksums:
        with open(a.checksums, 'w') as f:
            f.write(f"{sha}  {filename}\n")
        print(f"Generated Checksums: {a.checksums}")

if __name__ == '__main__':
    main()
