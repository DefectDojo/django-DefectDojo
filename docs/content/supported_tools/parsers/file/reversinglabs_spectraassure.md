---
title: "ReversingLabs Spectra Assure"
toc_hide: true
---

# ReversingLabs Spectra Assure Parser

The Spectra Assure platform is a set of [ReversingLabs](https://www.reversinglabs.com/) solutions primarily designed for software assurance and software supply chain security use-cases.
Spectra Assure products analyze compiled software packages, their components and third-party dependencies to detect exposures, reduce vulnerabilities, and eliminate threats before reaching production.

Every Spectra Assure analysis (software scan) produces a set of reports and the overall CI status (pass or fail) for the analyzed software package.
The reports are created in multiple different formats, with different level of detail and scope of information about the analysis results.
The official documentation describes all [supported report formats](https://docs.secure.software/concepts/analysis-reports) in Spectra Assure.

**The primary purpose of this parser is extracting known vulnerabilities (CVEs) that are present in the `components` and `dependencies` sections of the `rl-json` report.**

### File Types

The parser accepts only `report.rl.json` files (the Spectra Assure [rl-json report](https://docs.secure.software/concepts/analysis-reports#rl-json)).

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

#### Title

##### Component

For a component, the title includes:

- the CVE
- the type: `Component`
- the `purl` of the `Component` if present; otherwise name and version


##### Dependency

For a dependency, the title includes:

- the CVE
- the type: `Dependency`
- the `purl` of the `Dependency` if present; otherwise name and version

#### Description

##### Component

For a component, the description repeats the information from the [title](#title) and includes the SHA256 hash of the component.

The SHA256 is included because sometimes a file scan may have multiple items with the same name and version, but with different hashes.
Typically this happens with multi-language Windows installer packages.


##### Dependency

For a dependency, the description repeats the information from the [title](#title) and includes the component path, `component-name` and `component-hash`.
For duplicates, the description includes an additional line showing the title and component of each duplicate.

#### Vulnerabilities

For vulnerabilities, the following information is retrieved:

- the CVE unique ID
- CVSS version
- CVSS base score

From the CVSS base score, we map the severity into:

- Info
- Low
- Medium
- High
- Critical

If no mapping is matched, the default severity is `Info`.

##### Notes

- Currently, no endpoints are created.
- Deduplication is done with sha256 if the title.
- On detecting a duplicate dependency, we increment the number of occurrences. Components have no duplicates, so the number of occurrences is always 1.
- We extract the scan date, the Spectra Assure scanner version, and set a static scanner name.

### Sample Scan Data or Unit Tests

- [Sample Scan Data Folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/reversinglabs_spectraassure)

### Link To Tool

- [Spectra Assure Cli](https://docs.secure.software/cli/)
- [Spectra Assure Portal](https://docs.secure.software/portal/)
- [docker:rl-scanner](https://docs.secure.software/cli/integrations/docker-image)
- [docker:rl-scanner-cloud](https://docs.secure.software/portal/docker-image)
