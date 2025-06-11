---
title: "ReversingLabs Spectra Assure"
toc_hide: true
---

# ReversingLabs SpectraAssure Parser

### File Types

The parser accepts only `report.rl.json` files.
You can find instructions how to export the `rl-json` report from the cli and portal scanners.

- [Spectra Assure Cli](https://docs.secure.software/cli/).
- [Spectra Assure Portal](https://docs.secure.software/portal/).
- [docker:rl-scanner](https://hub.docker.com/r/reversinglabs/rl-scanner).
- [docker:rl-scanner-cloud](https://hub.docker.com/r/reversinglabs/rl-scanner-cloud).


### Total Fields in Reversinglabs Spectra Assure rl-json

For the specification of the rl-json report, see the documentation at:

- [rl-json-schema](https://docs.secure.software/cli/rl-json-schema)
- [analysis-reports:rl-json](https://docs.secure.software/concepts/analysis-reports#rl-json).


### Field Mapping Details

#### Title

##### Component

For a Components, the title shows:

- the CVE.
- the type: `Component`.
- the `purl` of the `Component` if present, otherwise name and version.


##### Dependency

The title shows the:

- the CVE.
- the type: `Dependecy`.
- the `purl` of the `Dependency` if present, otherwise name and version.

#### Description

##### Component

For a component we repeat the title, but add the sha256.

The sha256 is added as sometimes a file scan my have multiple items with the same name and version
but with a different hash.
Typically this happens with Windows intstall packages with multiple languages.


##### Dependency

For a dependency we repeat the title and then add the component_name, the component path and the component_hash.
For duplicates we add one additional line to the description for each duplicate, showing its title and component.

#### Vulnerabilities

From the vulnerability data in the rl-json file, we fetch:

- the CVE unique id
- cvss version
- cvss.basescore

From the cvss.basescore we map the severity into:

- Info
- Low
- Medium
- High
- Critical

##### Notes

- Currently no endpoints are created
- Deduplication is done with the `unique-id-from-tool` field.
    - for component: `<component sha256>:<cve>`
    - for dependencies: `<component sha256>:<cve>:<dependency purl>`
- On detecting a duplicate `dependency` we increment the number of occurrences.<br/>
`Components` have no duplicates so the nr of occurrences is always 1.
- The default severity if no mapping is matched is `Info`.
- We extract the scan date and the scanner version and set a static scanner-name.

### Sample Scan Data or Unit Tests

- [Sample Scan Data Folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/reversinglabs_spectraassure)

### Link To Tool

- [Spectra Assure Cli](https://docs.secure.software/cli/)
- [Spectra Assure Portal](https://docs.secure.software/portal/)
- [docker:rl-scanner](https://docs.secure.software/cli/integrations/docker-image)
- [docker:rl-scanner-cloud](https://docs.secure.software/portal/docker-image)
