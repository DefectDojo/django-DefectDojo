---
title: 'Generic Findings Import'
toc_hide: true
aliases:
  - "/en/connecting_your_tools/parsers/file/generic/"
---

Generic Findings Import can be used to import any report in CSV or JSON format.

### Choosing CSV or JSON

DefectDojo picks the format from the file name:

- A file whose name ends in `.csv` (any case) is read as CSV.
- Every other file is read as JSON, whatever its extension.

JSON supports far more fields than CSV (components, SAST data, tags, endpoint objects, attached files, report metadata). Use JSON when you can.

## CSV format

### File rules

- The first row is a header row naming the columns. Column order does not matter.
- Column names are case-sensitive and must match the names below exactly. `Title` works, `title` does not.
- Values are separated by commas. Wrap a value in double quotes if it contains a comma or a line break, and write a literal double quote as two double quotes (`""`).
- Save the file as UTF-8 without a byte order mark (BOM). Some spreadsheet tools add a BOM by default ("CSV UTF-8" in Excel). The BOM becomes part of the first column name, so DefectDojo no longer recognizes that column and the import fails.
- Each row is one finding. Rows with the same `Severity`, `Title` and `Description` are merged into a single finding: their `Url` values are combined, their vulnerability IDs and CWEs are combined, and the finding's occurrence count goes up by one for each extra row. Use this to report one issue found at several URLs.
- Columns not listed below are ignored.

### Required columns

`Date`, `Title`, `Description` and `Severity` must be present in the header, and every row needs a value for `Date`. A file missing one of these columns fails to import.

### Supported columns

| Column | Data type | Example values | Notes |
|---|---|---|---|
| `Date` | Date | `2024-05-01`, `05/01/2024`, `2024-05-01T10:00:00Z` | **Required.** Parsed with [dateutil](https://dateutil.readthedocs.io/en/stable/parser.html), so most common formats work. Ambiguous dates such as `05/01/2024` are read month first (May 1). Any time of day is dropped. |
| `Title` | String (max 511 characters) | `SQL Injection in login form` | **Required.** |
| `Description` | String | `User input reaches the query unescaped.` | **Required.** Can span several lines when enclosed in double quotes. |
| `Severity` | One of `Critical`, `High`, `Medium`, `Low`, `Info` | `High` | **Required.** Case-sensitive. Any other value, including `high` or `Informational`, is imported as `Info` without an error. |
| `CweId` | Integer | `89` | A whole number. An empty cell leaves the CWE unset. `CWE-89` or any other non-numeric value fails the import; use `CweIds` for labels. |
| `CweIds` | List of CWEs | `"79, CWE-89 352"` | Several CWEs for one finding, separated by commas, spaces or line breaks. `79` and `CWE-79` are both accepted and duplicates are dropped. If `CweId` is empty or absent, the first entry becomes the primary CWE. |
| `CVE` | String | `CVE-2024-3094` | Added to the finding's vulnerability IDs. |
| `Vulnerability Id` | String | `GHSA-5mrr-rgp6-x4gr` | One extra vulnerability ID, added after `CVE`. Note the space in the column name. |
| `Url` | String (URL or host) | `https://app.example.com/login`, `app.example.com:8443` | One endpoint per row. The scheme is optional. To attach several URLs to one finding, repeat the row (see the merge rule above). |
| `Mitigation` | String | `Use parameterized queries.` | Can span several lines when enclosed in double quotes. |
| `Impact` | String | `An attacker can read the users table.` | Can span several lines when enclosed in double quotes. |
| `References` | String | `https://owasp.org/Top10/` | Can span several lines when enclosed in double quotes. |
| `Active` | Boolean (see below) | `TRUE`, `FALSE` | If the column is absent, findings are active. If the column is present, an empty cell makes the finding inactive. |
| `Verified` | Boolean (see below) | `TRUE`, `FALSE` | Defaults to false. |
| `FalsePositive` | Boolean (see below) | `TRUE`, `FALSE` | Defaults to false. |
| `Duplicate` | Boolean (see below) | `TRUE`, `FALSE` | Defaults to false. |
| `IsMitigated` | Boolean (see below) | `TRUE`, `FALSE` | Defaults to false. |
| `MitigatedDate` | Date and time | `2024-05-20`, `2024-05-20T14:30:00Z` | Parsed with dateutil. An empty cell leaves the field unset. |
| `epss_score` | Decimal number, 0 to 1 | `0.97283` | The finding's [EPSS score](https://www.first.org/epss/). An empty cell leaves the field unset. |
| `epss_percentile` | Decimal number, 0 to 1 | `0.99971` | The finding's [EPSS percentile](https://www.first.org/epss/articles/prob_percentile_bins). An empty cell leaves the field unset. |
| `CVSSV3` | String (CVSS v3 vector) | `CVSS:3.1/AV:N/AC:L/…` | Must include the `CVSS:3.0/` or `CVSS:3.1/` prefix; a vector without it is ignored. See the example CSV for a full vector. The CVSS v3 score is calculated from the vector. |
| `CVSSV3_score` | Decimal number, 0 to 10 | `9.8` | If `CVSSV3` holds a valid vector, the score calculated from the vector replaces this value. An empty cell leaves the field unset. |
| `CVSSV4` | String (CVSS v4 vector) | `CVSS:4.0/AV:N/AC:L/…` | Must include the `CVSS:4.0/` prefix; a vector without it is ignored. See the example JSON for a full vector. |
| `CVSSV4_score` | Decimal number, 0 to 10 | `9.3` | If `CVSSV4` holds a valid vector, the score calculated from the vector replaces this value. An empty cell leaves the field unset. |
| `known_exploited` | Boolean (see below) | `TRUE`, `FALSE` | Listed in the Known Exploited Vulnerabilities catalog. Defaults to false. |
| `ransomware_used` | Boolean (see below) | `TRUE`, `FALSE` | Known to be used in ransomware campaigns. Defaults to false. |
| `fix_available` | Boolean (see below) | `TRUE`, `FALSE` | A fix exists. An empty cell leaves it unset (unknown). |
| `fix_version` | String (max 100 characters) | `2.4.1` | Version that contains the fix. |
| `kev_date` | Date | `2024-03-29` | Date the vulnerability was added to the Known Exploited Vulnerabilities catalog. Parsed with dateutil. An empty cell leaves the field unset. |

#### Boolean values in CSV

`Active`, `Verified`, `FalsePositive`, `Duplicate`, `IsMitigated`, `known_exploited`, `ransomware_used` and `fix_available` are true when the value starts with `t` or `T` (`TRUE`, `True`, `true`, `t`). Every other value is false, including `yes` and `1`. An empty cell is false for the first five columns; for `known_exploited`, `ransomware_used` and `fix_available` it leaves the field at its default (false, false, and unknown).

An empty cell in the numeric and date columns (`CweId`, `epss_score`, `epss_percentile`, `CVSSV3_score`, `CVSSV4_score`, `MitigatedDate`, `kev_date`) leaves that field unset, so rows can mix filled and empty cells. A value that is not a number or date, such as `N/A`, still fails the import.

### Example CSV

```csv
Date,Title,CweId,Url,Severity,Description,Mitigation,References,Active,Verified,CVE,CVSSV3
2024-05-01,SQL Injection in login form,89,https://app.example.com/login,High,"The username parameter is concatenated into a SQL query.
An attacker can bypass authentication.",Use parameterized queries.,https://owasp.org/Top10/A03_2021-Injection/,TRUE,FALSE,,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
2024-05-01,SQL Injection in login form,89,https://app.example.com/admin/login,High,"The username parameter is concatenated into a SQL query.
An attacker can bypass authentication.",Use parameterized queries.,https://owasp.org/Top10/A03_2021-Injection/,TRUE,FALSE,,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
2024-05-02,Outdated xz-utils package,506,build.example.com,Critical,xz-utils 5.6.0 contains a backdoor.,Upgrade to 5.6.2 or later.,https://nvd.nist.gov/vuln/detail/CVE-2024-3094,TRUE,TRUE,CVE-2024-3094,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

The first two rows share a severity, title and description, so they import as one finding with two endpoints and an occurrence count of 2.

## JSON format

A JSON report is an object with a `findings` array and, optionally, report-level metadata.

### Report-level fields

| Field | Data type | Example | Notes |
|---|---|---|---|
| `findings` | List of finding objects | `[{...}, {...}]` | The findings to import. If omitted, the report imports with no findings. |
| `type` | String | `"Tool1"` | Sets the Test Type name. See [Test Type naming](#test-type-naming). |
| `name` | String | `"Nightly scan"` | Accepted but not used. It does not rename the Test or the Test Type. |
| `version` | String | `"1.2.0"` | Stored as the Test's version. |
| `description` | String | `"Weekly authenticated scan"` | Stored as the Test's description. |
| `static_tool` | Boolean | `true` | Sets the Test Type's Static Tool flag. See [Test Type metadata](#test-type-metadata). |
| `dynamic_tool` | Boolean | `false` | Sets the Test Type's Dynamic Tool flag. See [Test Type metadata](#test-type-metadata). |
| `soc` | Boolean | `true` | DefectDojo Pro only. Labels the Test Type as SOC rather than AppSec. Ignored by the open-source edition. See [Test Type metadata](#test-type-metadata). |

### Test Type metadata

`static_tool`, `dynamic_tool` and `soc` describe the tool, not the report, so they are stored on the **Test Type** rather than on the Test. A CSV import never sets them.

- **They apply to every Test of that Test Type.** A Test Type is shared across all Products, so the flags are instance-wide for that tool. Each import that includes a flag overwrites it, and the last import wins.
- **An omitted flag keeps its current value.** `null` is treated the same as omitting the key. To clear a flag, send `false`.
- **Set `type` before you set these flags.** A report without `type` imports into the built-in `Generic Findings Import` Test Type, so its flags change that Test Type for every generic import on the instance, including CSV imports. Give each tool its own `type` so its flags stay with that tool.
- **Send JSON booleans.** `true` and `false` work. A quoted `"false"` is rejected and the whole import fails with a 400 error.

What the flags drive:

| Flag | Effect |
|---|---|
| `static_tool`, `dynamic_tool` | Stored on the Test Type and returned by the `/api/v2/test_types/` API. In DefectDojo Pro you can also filter Test Types and build reports on them, and a Test Type with `static_tool` set counts as static analysis evidence for compliance obligations. They do not change the static or dynamic flag on individual findings; set `static_finding` and `dynamic_finding` for that. |
| `soc` | DefectDojo Pro only. Findings from a Test Type with `soc` set are grouped as SOC rather than AppSec, for example in Priority Insights. |

### Finding fields

Every finding must have `title`, `severity` and `description`. A finding with a key that is not in this table stops the import with a `Not allowed fields are present` error naming the key, so check spelling carefully (for example `false_p`, not `false_positive`).

| Field | Data type | Example | Notes |
|---|---|---|---|
| `title` | String (max 511 characters) | `"SQL Injection in login form"` | **Required.** |
| `severity` | One of `Critical`, `High`, `Medium`, `Low`, `Info` | `"High"` | **Required.** Not case-sensitive: `"high"` and `"HIGH"` become `High`. `"Informational"`, `"info"` and `"None"` become `Info`. Any other value stops the import with an error. |
| `description` | String | `"Line one\n\nLine two"` | **Required.** Use `\n` for line breaks. |
| `date` | Date | `"2024-05-01"`, `"05/01/2024"`, `"2024-05-01T10:00:00Z"` | Parsed with [dateutil](https://dateutil.readthedocs.io/en/stable/parser.html), so most formats work. Ambiguous dates are read month first. Any time of day is dropped. Defaults to the day of the import. |
| `cwe` | Integer | `89`, `"89"` | Only a number is accepted. `"CWE-89"` is not a number and is silently dropped, so use `cwes` if your tool emits labels. |
| `cwes` | List of CWEs | `["CWE-79", 89]` | Several CWEs for one finding. Items may be numbers or `CWE-<n>` labels. If `cwe` is not set, the first entry becomes the primary CWE. |
| `cve` | String (max 50 characters) | `"CVE-2024-3094"` | Added as the first vulnerability ID. |
| `vulnerability_ids` | List of strings, or a single string | `["GHSA-5mrr-rgp6-x4gr", "OSV-2021-1234"]` | Added after `cve`. |
| `epss_score` | Decimal number, 0 to 1 | `0.97283` | |
| `epss_percentile` | Decimal number, 0 to 1 | `0.99971` | |
| `cvssv3` | String (CVSS v3 vector) | `"CVSS:3.1/AV:N/AC:L/…"` | Include the `CVSS:3.x/` prefix; the example JSON below has a full vector. An invalid vector is dropped with a warning in the logs. |
| `cvssv3_score` | Decimal number, 0 to 10 | `9.8` | If `cvssv3` holds a valid vector, the score calculated from the vector replaces this value. |
| `cvssv4` | String (CVSS v4 vector) | `"CVSS:4.0/AV:N/AC:L/…"` | Include the `CVSS:4.0/` prefix; the example JSON below has a full vector. An invalid vector is dropped with a warning in the logs. |
| `cvssv4_score` | Decimal number, 0 to 10 | `9.3` | If `cvssv4` holds a valid vector, the score calculated from the vector replaces this value. |
| `mitigation` | String | `"Use parameterized queries."` | |
| `impact` | String | `"An attacker can read the users table."` | |
| `steps_to_reproduce` | String | `"1. Open /login\n2. Submit the form"` | |
| `severity_justification` | String | `"Reachable without authentication."` | |
| `references` | String | `"https://owasp.org/Top10/"` | A single string. Put several references on separate lines with `\n`. |
| `active` | Boolean | `true` | Defaults to `true`. |
| `verified` | Boolean | `false` | Defaults to `false`. |
| `false_p` | Boolean | `false` | False positive. Defaults to `false`. |
| `out_of_scope` | Boolean | `false` | Defaults to `false`. |
| `risk_accepted` | Boolean | `false` | Defaults to `false`. |
| `under_review` | Boolean | `false` | Defaults to `false`. |
| `is_mitigated` | Boolean | `true` | Defaults to `false`. |
| `mitigated` | Date and time | `"2024-05-20"`, `"2024-05-20T14:30:00Z"` | When the finding was mitigated. Parsed with dateutil. |
| `thread_id` | Integer | `42` | |
| `numerical_severity` | String | `"S1"` | Accepted but ignored. DefectDojo always derives it from `severity`. |
| `param` | String | `"username"` | The vulnerable parameter. |
| `payload` | String | `"' OR 1=1 --"` | |
| `line` | Integer | `42`, `"42"` | Line number in `file_path`. |
| `file_path` | String (max 4000 characters) | `"src/auth/login.py"` | Setting this marks a new finding as static (see `static_finding`). |
| `component_name` | String (max 500 characters) | `"xz-utils"` | |
| `component_version` | String (max 100 characters) | `"5.6.0"` | |
| `static_finding` | Boolean | `true` | Defaults to `false`. When `file_path` is set, DefectDojo marks a new finding as static regardless of this value. |
| `dynamic_finding` | Boolean | `false` | Defaults to `true`. When `file_path` is set, DefectDojo can override this value for a new finding. |
| `scanner_confidence` | Integer | `3` | Confidence reported by the tool. |
| `unique_id_from_tool` | String (max 500 characters) | `"a1b2c3d4"` | The tool's identifier for this finding. If the same value appears on more than one finding in a report, it is removed from all of them and those findings are deduplicated by hash code instead. |
| `vuln_id_from_tool` | String (max 500 characters) | `"django.sqli"` | The tool's rule or check ID. |
| `sast_source_object` | String (max 500 characters) | `"request.GET['username']"` | Where tainted data enters. |
| `sast_sink_object` | String (max 500 characters) | `"cursor.execute"` | Where tainted data is used. |
| `sast_source_line` | Integer | `12` | |
| `sast_source_file_path` | String (max 4000 characters) | `"src/auth/views.py"` | |
| `nb_occurences` | Integer | `3` | Number of times the finding occurred. Note the spelling (one `r`). |
| `publish_date` | Date, `YYYY-MM-DD` only | `"2024-03-29"` | Date the vulnerability was published. Other formats, including a date with a time, stop the import. |
| `service` | String (max 200 characters) | `"payments-api"` | |
| `planned_remediation_date` | Date, `YYYY-MM-DD` only | `"2024-06-30"` | Other formats, including a date with a time, stop the import. |
| `planned_remediation_version` | String (max 99 characters) | `"2.5.0"` | |
| `effort_for_fixing` | String | `"Low"` | Intended values are `High`, `Medium` and `Low`. |
| `kev_date` | Date, `YYYY-MM-DD` only | `"2024-03-29"` | Date the vulnerability was added to the Known Exploited Vulnerabilities catalog. Other formats, including a date with a time, stop the import. |
| `known_exploited` | Boolean | `true` | Listed in the Known Exploited Vulnerabilities catalog. Defaults to `false`. |
| `ransomware_used` | Boolean | `false` | Known to be used in ransomware campaigns. Defaults to `false`. |
| `fix_available` | Boolean | `true` | A fix exists. |
| `fix_version` | String (max 100 characters) | `"5.6.2"` | Version that contains the fix. |
| `tags` | List of strings | `["security", "pci"]` | |
| `endpoints` | List of strings or objects | see [Endpoints](#endpoints) | |
| `files` | List of objects | see [Attached files](#attached-files) | |

#### Value rules

- **Booleans** must be JSON `true` or `false`, not quoted strings. The parser does not convert `"true"` or `"false"`, and a quoted lowercase value such as `"false"` stops the import when the finding is saved.
- **Numbers** (`cwe`, `line`, `thread_id`, `nb_occurences`, `scanner_confidence`, `sast_source_line`, `epss_score`, `epss_percentile`, `cvssv3_score`, `cvssv4_score`) may be given as a number or a quoted number (`42` or `"42"`). A value that holds no number, such as `"N/A"` for a line number the tool could not determine, is ignored and the field keeps its default. `true` and `false` are not treated as numbers.
- **Dates**: `date` and `mitigated` accept most formats. `publish_date`, `planned_remediation_date` and `kev_date` accept only `YYYY-MM-DD` (or `YYYYMMDD`).

#### Endpoints

`endpoints` is a list. Each item is either a string or an object.

- A string is a URL or a host. The scheme is optional: `"https://app.example.com:8443/login?next=1"`, `"app.example.com"`.
- An object names the URL parts. Supported keys: `protocol` (string), `host` (string), `port` (integer), `path` (string), `query` (string), `fragment` (string).

```JSON
"endpoints": [
    "app.example.com",
    "https://app.example.com:8443/login?next=1",
    {
        "protocol": "https",
        "host": "api.example.com",
        "port": 443,
        "path": "v1/users"
    }
]
```

#### Attached files

`files` is a list of objects, each with a `title` (string) and `data` (the file's contents, Base64-encoded). The files are attached to the finding.

The `title` must end in an extension the instance allows for uploads. By default these are `.txt`, `.pdf`, `.json`, `.xml`, `.csv`, `.yml`, `.png`, `.jpeg`, `.sarif`, `.xlsx`, `.doc`, `.html`, `.js`, `.nessus`, `.zip` and `.fpr`; administrators can change the list with the `DD_FILE_UPLOAD_TYPES` setting. A title with another extension (including `.jpg`) or no extension stops the import.

```JSON
"files": [
    {
        "title": "login-screenshot.png",
        "data": "iVBORw0KGgoAAAANSUhEUgAABWgAAAK0CAIAAAARSkPJAAAAA3N<...>TkSuQmCC"
    }
]
```

### Example JSON

```JSON
{
    "name": "Nightly scan",
    "type": "Tool1",
    "version": "1.2.0",
    "description": "Authenticated scan of the staging environment",
    "findings": [
        {
            "title": "SQL Injection in login form",
            "description": "The username parameter is concatenated into a SQL query.\n\nAn attacker can bypass authentication.",
            "severity": "High",
            "date": "2024-05-01",
            "cwe": 89,
            "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvssv4": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "mitigation": "Use parameterized queries.",
            "references": "https://owasp.org/Top10/A03_2021-Injection/",
            "param": "username",
            "payload": "' OR 1=1 --",
            "active": true,
            "verified": false,
            "unique_id_from_tool": "tool1-4f2a9c",
            "endpoints": [
                "https://app.example.com/login",
                {
                    "protocol": "https",
                    "host": "app.example.com",
                    "path": "admin/login"
                }
            ],
            "tags": ["security", "pci"]
        },
        {
            "title": "Hard-coded credentials",
            "description": "A database password is committed to source control.",
            "severity": "critical",
            "cwes": ["CWE-798", "CWE-259"],
            "file_path": "src/settings.py",
            "line": 42,
            "static_finding": true,
            "dynamic_finding": false,
            "vuln_id_from_tool": "generic.secrets.password",
            "effort_for_fixing": "Low"
        },
        {
            "title": "Backdoor in xz-utils",
            "description": "xz-utils 5.6.0 and 5.6.1 contain malicious code.",
            "severity": "Critical",
            "cve": "CVE-2024-3094",
            "vulnerability_ids": ["GHSA-rxwq-x6h5-x525"],
            "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "epss_score": 0.85,
            "epss_percentile": 0.99,
            "component_name": "xz-utils",
            "component_version": "5.6.0",
            "fix_available": true,
            "fix_version": "5.6.2",
            "known_exploited": true,
            "kev_date": "2024-04-01",
            "publish_date": "2024-03-29"
        },
        {
            "title": "Reflected XSS in search",
            "description": "The q parameter is echoed without encoding.",
            "severity": "Medium",
            "date": "2024-01-04T11:02:11Z",
            "cwe": 79,
            "is_mitigated": true,
            "mitigated": "2024-01-24T11:02:11Z",
            "endpoints": ["app.example.com/search"]
        }
    ]
}
```

### Test Type naming

The Test Type for a JSON import comes from the report's `type` field. A CSV import always uses the Test Type `Generic Findings Import`.

| `type` value | Resulting Test Type |
|---|---|
| omitted, empty, or `"Generic Findings Import"` | `Generic Findings Import` |
| `"Tool1"` | `Tool1 Scan (Generic Findings Import)` |
| `"Tool1 (Generic Findings Import)"` | `Tool1 (Generic Findings Import)` (used as-is, so the suffix is never doubled) |

Each distinct `type` creates its own Test Type. Because deduplication settings are looked up by Test Type name, you can set custom `HASHCODE_FIELDS_PER_SCANNER` or `DEDUPLICATION_ALGORITHM_PER_PARSER` entries for a generic tool by using the resulting name as the key, for example `Tool1 Scan (Generic Findings Import)`.

When you reimport into an existing Test, the report's `type` has to resolve to that Test's Test Type (or to plain `Generic Findings Import`). Otherwise the reimport is rejected with a `Test type mismatch` error.

### Sample Scan Data

Sample Generic Findings Import scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/generic).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
