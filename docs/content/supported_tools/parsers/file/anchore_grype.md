---
title: "Anchore Grype"
toc_hide: true
---
### File Types
DefectDojo parser accepts a .json file.

Anchore Grype JSON files are created using the Grype CLI, using the '--output=json' option.  See: https://github.com/anchore/grype

**Example:**
{{< highlight bash >}}
grype yourApp/example-page --output=json=example_vulns.json
{{< /highlight >}}

It's possible to instruct Anchore to organize all findings by CVE (vs GHSA, RHSA, etc) using the `--by-cve` parameter.
Considerations:
- Using `--by-cve` could lead to more, or different Findings being created as some advisories fix multiple CVEs at once.
- We recommend you consistently choose whether to use this flag or not in your report generation.  Mixing reports generated with `--by-cve` and without (via Reimport, for example) can lead to unpredictable results, such as mismatched Hash Codes.

### Acceptable JSON Format
All properties are expected as strings and are required by the parser.

~~~
{
    "matches": [
            {
                "vulnerability": {
                    "id": "example-id",
                    "dataSource": "https://example.org/.../example-id",
                    "namespace": "exampleName",
                    "severity": "exampleSeverity",
                    "urls": [
                        "https://example.org/.../example-id",
                        ...
                    ],
                    "cvss": [],
                    "fix": {
                        "versions": [],
                        "state": "not-fixed"
                    },
                    "advisories": []
                },
                "relatedVulnerabilities": [
                        {
                            "id": "first-related-example-id",
                            "dataSource": "https://example.org/.../related-example-id",
                            "namespace": "first-related-exampleName",
                            "severity": "first-related-exampleSeverity",
                            "urls": [
                                "https://example.org/.../related-example-id",
                                ...
                            ],
                            "description": "first-example-description",
                            "cvss": [
                                {
                                    "version": "2.0",
                                    "vector": "AV:L/AC:L/Au:N/C:N/I:P/A:N",
                                    "metrics": {
                                        "baseScore": 2.1,
                                        "exploitabilityScore": 3.9,
                                        "impactScore": 2.9
                                    },
                                    "vendorMetadata": {}
                                }
                            ]
                        },
                    ...
                ],
                "matchDetails": [
                    {
                        "matcher": "example-matcher",
                        "searchedBy": {
                            "distro": {
                                "type": "example-distrotype",
                                "version": "10"
                            },
                            "namespace": "exampleName",
                            "package": {
                                "name": "example-package",
                                "version": "1.17-3+deb10u3"
                            }
                        },
                        "found": {
                            "versionConstraint": "none (deb)"
                        }
                    }
                ],
                "artifact": {
                        "name": "example-artifact",
                        "version": "example-artifact-version",
                        "type": "example-type",
                        "locations": [
                            {
                                "path": ".../examplePath/",
                                "layerID": "exampleLayerID"
                            },
                            {
                                "path": ".../examplePath-2/",
                                "layerID": "exampleLayerID"
                            },
                        ...
                    ],
                    "language": "",
                    "licenses": [
                        "GPL-2"
                    ],
                    "cpes": [
                        "example-cpe",
                        ...
                    ],
                    "purl": "pkg:deb/debian/libgssapi-krb5-2@1.17-3+deb10u3?arch=amd64",
                    "metadata": {
                        "Source": "krb5"
                    }
                }
            },
        ...
    ],
    "source": {
        "type": "image",
        "target": {
            "userInput": "vulnerable-image:latest",
            "imageID": "sha256:ce9898fd214aef9c994a42624b09056bdce3ff4a8e3f68dc242d967b80fcbeee",
            "manifestDigest": "sha256:9d8825ab20ac86b40eb71495bece1608a302fb180384740697a28c2b0a5a0fc6",
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "tags": [
                "vulnerable-image:latest"
            ],
            "imageSize": 707381791,
            "layers": [
                    {
                        "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                        "digest": "sha256:d000633a56813933cb0ac5ee3246cf7a4c0205db6290018a169d7cb096581046",
                        "size": 69238554
                    },
                ...
            ],
            "manifest": "exampleManifestString==",
            "config": "exampleConfigString",
            "repoDigests": []
        }
    },
    "distro": {
        "name": "debian",
        "version": "10",
        "idLike": ""
    },
    "descriptor": {
        "name": "grype",
        "version": "0.28.0",
        "configuration": {
            "configPath": "",
            "output": "json",
            "file": "",
            "output-template-file": "",
            "quiet": false,
            "check-for-app-update": true,
            "only-fixed": false,
            "scope": "Squashed",
            "log": {
                "structured": false,
                "level": "",
                "file": ""
            },
            "db": {
                "cache-dir": "/home/user/.cache/grype/db",
                "update-url": "https://toolbox-data.anchore.io/grype/databases/listing.json",
                "ca-cert": "",
                "auto-update": true,
                "validate-by-hash-on-start": false
            },
            "dev": {
                "profile-cpu": false,
                "profile-mem": false
            },
            "fail-on-severity": "",
            "registry": {
                "insecure-skip-tls-verify": false,
                "insecure-use-http": false,
                "auth": []
            },
            "ignore": null,
            "exclude": []
        },
        "db": {
            "built": "2021-12-24T08:14:02Z",
            "schemaVersion": 3,
            "location": "/home/user/.cache/grype/db/3",
            "checksum": "sha256:6c4777e1acea787e5335ccee6b5e4562cd1767b9cca138c07e0802efb2a74162",
            "error": null
        }
    }
}
~~~

### Sample Scan Data
Sample Grype scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/anchore_grype).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component name
- component version

### Anchore Grype Detailed

Both scan types accept the same JSON report format. The difference is in how Findings are deduplicated:

- **`Anchore Grype`** — Aggregates all matches for the same CVE, component name, and version into a single Finding, regardless of file path. Deduplication is based on hashcode fields (`title`, `severity`, `component_name`, `component_version`).
- **`Anchore Grype detailed`** — Creates a separate Finding for each unique file path. Deduplication is based on `unique_id_from_tool`, composed as `{vuln_id}|{component_name}|{component_version}|{file_path}`.

A typical case is a package installed at multiple paths in a container image (e.g., /usr/lib/x86_64-linux-gnu/libc.so.6 and /lib/x86_64-linux-gnu/libc.so.6) — the same CVE would produce one Finding in default mode and two in detailed mode.

**Field mapping:**

| Finding Field | Grype JSON Source |
|---|---|
| `title` | `{vulnerability.id} in {artifact.name}:{artifact.version}` |
| `severity` | `vulnerability.severity` (mapped: `Unknown`/`Negligible` → `Info`) |
| `description` | `vulnerability.namespace`, `vulnerability.description`, `matchDetails[].matcher`, `artifact.purl` |
| `component_name` | `artifact.name` |
| `component_version` | `artifact.version` |
| `file_path` | `artifact.locations[0].path` |
| `vuln_id_from_tool` | `vulnerability.id` |
| `unique_id_from_tool` | `vuln_id\|component_name\|component_version\|file_path` (detailed mode only) |
| `references` | `vulnerability.dataSource`, `vulnerability.urls`, `relatedVulnerabilities[0].dataSource`, `relatedVulnerabilities[0].urls` |
| `mitigation` | `vulnerability.fix.versions` |
| `fix_available` | `true` if `vulnerability.fix.versions` is non-empty |
| `fix_version` | `vulnerability.fix.versions[0]` (or comma-joined if multiple) |
| `cvssv3` | `vulnerability.cvss` or `relatedVulnerabilities[0].cvss` |
| `epss_score` / `epss_percentile` | `vulnerability.epss` or `relatedVulnerabilities[0].epss` |
