---
title: "Anchore-Engine"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json file.

Using the [Anchore CLI](https://docs.anchore.com/current/docs/using/cli_usage/images/inspecting_image_content/) is the most reliable way to generate an Anchore report which DefectDojo can parse. When generating a report with the Anchore CLI, please use the following command to ensure complete data: `anchore-cli --json image vuln <image:tag> all`

### Acceptable JSON Format
All properties are strings and are required by the parser.

~~~

{
    "imageDigest": "sha256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "vulnerabilities": [
        {
            "feed": "example-feed",
            "feed_group": "example-feed-group",
            "fix": "1.2.4",
            "package": "example-package",
            "package_cpe": "cpe:2.3:a:*:example:1.2.3:*:*:*:*:*:*:*",
            "package_name": "example-package-name",
            "package_path": "path/to/package",
            "package_type": "dpkg",
            "package_version": "1.2.3",
            "severity": "Medium",
            "url": "https://example.com/cve/CVE-2011-3389",
            "vuln": "CVE-2011-3389"
        },
      ...
    ],
    "vulnerability_type": "os"
}
~~~

### Sample Scan Data
Sample Anchore-Engine scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/anchore_engine).