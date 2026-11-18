---
title: "Early Light"
toc_hide: true
---
### File Types
[Early Light](https://github.com/DefectDojo/earlylight) is DefectDojo's open source emerging-vulnerability scanner. Each detector targets one newly disclosed vulnerability and checks filesystems, container images, source trees or live hosts for it.

This parser imports the JSON report. Generate it with:

```
earlylight scan fs --format json --output earlylight.json /path/to/dir
earlylight scan image --format json --output earlylight.json php:8.3.0-cli
earlylight scan repo --format json --output earlylight.json /path/to/source
earlylight scan host --format json --output earlylight.json example.com:443
```

Flags go before the paths, image references or hosts. One report can hold several targets (for example several images scanned in one run), and the parser imports the findings of all of them.

### Which findings are imported
Early Light gives every finding a verdict:

- **vulnerable**: imported, tagged `earlylight`.
- **unknown**: imported, tagged `earlylight` and `needs-review`. The description starts with the reason Early Light could not settle it.
- **fixed**, **inactive** and **managed**: Early Light cleared these, so they are not imported.

A report with no vulnerable or unknown findings imports no findings.

### Field Mapping Details
- **title**: `<detector>/<kind>: <message>`, for example `php2shell/php-runtime-web: PHP 8.3.0 (cgi-fcgi)`.
- **vuln_id_from_tool**: `<detector>/<kind>`, for example `brotli/bundled-decoder`.
- **vulnerability_ids**: the CVE IDs listed on the finding itself (`cves[].id`). The detector's own CVE list is not copied, so a finding with no CVEs of its own, such as an eMudhra certificate trust finding, has none.
- **description**: the verdict or the needs-review reason, the message, the target (image reference, host or path, with its type, digest and platform), the path and line, the detection method, the detector, every fact, and the verdict of each CVE with its reason.
- **mitigation**: the finding's `fix`. `fix_available` is set when there is one.
- **references**: the detector's advisory links.
- **file_path** and **line**: the finding's `path` and `line` (the line is set only for findings in source files).
- **component_name** and **component_version**: from the facts when present: `product` and `version` (a program or library carrying the Brotli decoder), `package` and `current` (a dependency that bundles it), the installing OS package (`package`), or `php` and `php_version`.
- **cwe**: the first CWE of the kind, from the detector catalog.
- **static_finding** / **dynamic_finding**: host scans are dynamic, all other scans are static.

### Severity
1. If the finding states its own severity (`critical`, `high`, `medium` or `low`), that is used. php2shell findings do this. The values `review` and `none` that php2shell also writes are not severities and fall through to the next rule.
2. Otherwise the severity of the kind is used. The JSON report does not carry it, so the parser keeps a table built from the detector catalog (`earlylight detectors --format json`): a CVSS-style score of 9 or more is Critical, 7 or more High, 4 or more Medium, anything lower Low. A kind without a score uses its level: error is High, warning is Medium, note is Info.

| Kind | Severity |
|------|----------|
| `brotli/decoder-library`, `brotli/bundled-decoder`, `brotli/node-pin`, `brotli/dotnet-pin`, `brotli/bun-pin`, `brotli/dependency` | Critical (9.2) |
| `brotli/go-port` | Medium (5.3) |
| `brotli/not-checked` | Info (note) |
| `emudhra/compromised-key`, `emudhra/path-root`, `emudhra/weak-key`, `emudhra/issued-by-compromised-ca` | High (error) |
| `emudhra/unpatched-go` | Medium (warning) |
| `php2shell/php-runtime-web`, `php2shell/php-image` | Critical (9.2) |
| `php2shell/php-runtime-cli` | High (7.5) |

3. A kind the parser does not know yet (from a detector released after it) is High when vulnerable and Medium when unknown.

### Deduplication
The "Early Light Scan" scan type uses the `unique_id_from_tool` [deduplication algorithm](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/). The parser sets `unique_id_from_tool` to a SHA-256 of the detector, the kind, the target type, the target, the path, and the certificate (`spki_sha256`, `cert_sha256`) or image reference (`image`) facts when present. It does not include line numbers or wording, so the same finding keeps its ID across scans. Findings that would still be identical in one report are told apart by their order.

### Sample Scan Data
Sample scan data for testing purposes can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/earlylight).

### Link To Tool
- [Early Light](https://github.com/DefectDojo/earlylight)
