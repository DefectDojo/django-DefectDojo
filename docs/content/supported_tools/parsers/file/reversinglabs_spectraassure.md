---
title: "ReversingLabs Spectra Assure"
toc_hide: true
---

# ReversingLabs Spectra Assure Parser

The Spectra Assure platform is a set of [ReversingLabs](https://www.reversinglabs.com/) solutions
primarily designed for software assurance and software supply chain security use-cases.
Spectra Assure products analyze compiled software packages,
their components and third-party dependencies to detect exposures,
reduce vulnerabilities, and eliminate threats before reaching production.

Every Spectra Assure analysis (software scan) produces a set of reports
and the overall CI status (pass or fail) for the analyzed software package.
The reports are created in multiple different formats,
with different level of detail and scope of information about the analysis results.
The official documentation describes all
[supported report formats](https://docs.secure.software/concepts/analysis-reports)
 in Spectra Assure.

**The primary purpose of this parser is extracting known vulnerabilities (CVEs/GHSA) that are present in the `components` and `dependencies` sections of the `rl-json` report.**

It also reports failing **secrets** and **threats** (malware) policy violations.


### File Types

The parser accepts only `report.rl.json` files
(the Spectra Assure [rl-json report](https://docs.secure.software/concepts/analysis-reports#rl-json)).

You can find instructions for exporting the `rl-json` report in the documentation of the Spectra Assure product you're using.

- [Spectra Assure CLI](https://docs.secure.software/cli/commands/report).
- [Spectra Assure Portal](https://docs.secure.software/api-reference/#tag/Version/operation/getVersionReport).
- [docker:rl-scanner](https://hub.docker.com/r/reversinglabs/rl-scanner).
- [docker:rl-scanner-cloud](https://hub.docker.com/r/reversinglabs/rl-scanner-cloud).


### Total Fields in Reversinglabs Spectra Assure rl-json

For the specification of the `rl-json` report, consult the official Spectra Assure documentation:

- [rl-json report schema](https://docs.secure.software/cli/rl-json-schema)
- [Analysis reports: rl-json](https://docs.secure.software/concepts/analysis-reports#rl-json).


### Field Mapping Details

The parser creates two kinds of findings:

- **Vulnerability findings**: one per active vulnerability (CVE or GHSA) on a component,
  or on a dependency found inside a component. Only the `active` vulnerabilities are imported.
- **Policy violation findings**: one per component referenced by a failing `threats` or `secrets` policy violation.

The finding date is the scan date (the report `timestamp`); a report without a valid `timestamp` is rejected.


#### Title

##### Vulnerability on a component

`<vulnerability id> on component: purl: <component purl> (sha256 <first 8 characters>)`

Without a purl, `purl: <purl>` is replaced by `<name> version <version>`; an empty name or version is left out.

##### Vulnerability on a dependency

`<vulnerability id> on dependency: purl: <dependency purl> (sha256 <first 8 characters>)`

Without a purl, `purl: <purl>` is replaced by `<dependency name> version <dependency version>`; an empty part is left out.
The sha256 is that of the component the dependency was found in.

##### Policy violation

`<violation description> (<category>) on <component name> (sha256 <first 8 characters>)`

The short sha256 is there because one name can stand for several different binaries:
an installer may ship a build per language, all with the same name and the same install path.
Without it those findings would be identical rows in the findings list.


#### Description

Every description starts with the title as a heading.

##### Vulnerabilities

The vulnerability summary, followed by the component the vulnerability was found in:
its purl (without a purl, `item: <name> <version>`), the path and the full sha256.
The full sha256 is included because a file scan may have multiple components with the same name and version,
but with different hashes; typically this happens with multi-language Windows installer packages.

When the same binary (same sha256) sits at more than one path in one report, the finding is reported once:
the number of occurrences is incremented and each extra path is added as an `- also at: <path>` line.

##### Policy violations

- `threats`: the threat name from the component classification, e.g. `Threat name: Win32.Trojan.Example`.
- `secrets`: for each secret detected on the component (service, timestamp, exposed)
  and each piece of evidence (liveness, file offset, line number, canary), as a fenced block.
  When the report holds no secret detail for that rule and component, the description has the title only.


#### Severity

Vulnerability findings: from the CVSS base score.

| CVSS v3.x / v4.0 | CVSS v2   | Severity |
|------------------|-----------|----------|
| 9.0 - 10.0       |           | Critical |
| 7.0 - 8.9        | 7.0 - 10  | High     |
| 4.0 - 6.9        | 4.0 - 6.9 | Medium   |
| 0.1 - 3.9        | 0 - 3.9   | Low      |
| 0 or no score    |           | Info     |

The base score is stored in `CVSSv3 score` or `CVSSv4 score`, depending on the CVSS version; a v2 score is not stored.

Policy violation findings: the severity of the violation in the report; an unknown severity becomes `Info`.


#### Other fields

- `Vulnerability Id` and `vuln_id_from_tool`: the CVE or GHSA id. For policy violations there is no vulnerability id
  and `vuln_id_from_tool` is `<category>-<rule_id>`, e.g. `secrets-SQ34304`.
- `Component Name` / `Component Version`: the component; for a vulnerable dependency, the dependency.
  The version is the one in the report, except that `Generic` (Spectra Assure's version for a file without a version
  of its own) on a component without a purl is no version: it is left out of the field, the title and the description.
- `File Path`: the path of the component in the scanned package.
- Tags and impact: the exploit information of the vulnerability, as `Fix Available`, `Exploit Exists`,
  `Exploited by Malware` and `Patching Mandated`. `Patching Mandated` also sets `Known Exploited`.
  The exploit states `UNPROVEN` ("CVE Discovered" in the Portal) and `TRIAGED` give no tag and no impact line.
- All findings are static findings.


##### Notes

- No endpoints are created.
- With `V3_FEATURE_LOCATIONS` enabled, each vulnerability finding whose package has a purl gets one `dependency` location
  naming the vulnerable package (for a vulnerable dependency, the dependency itself, not the component containing it)
  and the path of the component it was found in. Policy violation findings carry no package, so they get no location.
- Deduplication uses the `hash_code` algorithm on `unique_id_from_tool`, `component_name` and `component_version`.
  `unique_id_from_tool` is the vulnerability id (or `<category>-<rule_id>` for a policy violation) plus the sha256 of the
  component file it was found in, e.g. `CVE-2016-9840/sha256:0c0d54b2...`. A different sha256 is a different binary,
  so it is a different finding, even under the same name and path. Without a sha256 the component path is used.
- Earlier versions of this parser deduplicated on a sha256 of the title. Findings imported with an earlier version
  will not match findings imported with this version.


### Sample Scan Data or Unit Tests

- [Sample Scan Data Folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/reversinglabs_spectraassure)


### Link To Tool

- [Spectra Assure Cli](https://docs.secure.software/cli/)
- [Spectra Assure Portal](https://docs.secure.software/portal/)
- [docker:rl-scanner](https://docs.secure.software/cli/integrations/docker-image)
- [docker:rl-scanner-cloud](https://docs.secure.software/portal/docker-image)
