---
title: "Anchore Grype"
toc_hide: true
---
### File Types
DefectDojo parser accepts a .json file.

Anchore Grype JSON files are created using the Grype CLI, using the '-o json' option.  See: https://github.com/anchore/grype

**Example:**
{{< highlight bash >}}
grype yourApp/example-page -o json > example_vulns.json
{{< /highlight >}}


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
Sample Grype scans can be found at https://github.com/DefectDojo/sample-scan-files/tree/master/anchore_grype .