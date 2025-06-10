# ReversingLabs SpectraAssure Parser

## File Types

The parser accepts only `report.rl.json` files.
You can find instructions how to export the `rl-json` report from the cli and portal scanners.

- [Spectra Assure Cli](https://docs.secure.software/cli/).
- [Spectra Assure Portal](https://docs.secure.software/portal/).
- [docker:rl-scanner](https://hub.docker.com/r/reversinglabs/rl-scanner).
- [docker:rl-scanner-cloud](https://hub.docker.com/r/reversinglabs/rl-scanner-cloud).


## Relevant Fields in report.rl.json

The format of the `rl-json` report is shown in:

- [analysis-reports:rl-json](https://docs.secure.software/concepts/analysis-reports#rl-json).

The RlJsonInfo module is the principal parser vor the `report.rl.json` data.
The primary focus is on extracting vulnerabilities (CVE) that occur on rl-json `components` and rl-json `dependencies`. All items without vulnerabilities are currently ignored.

All data is stored only once in the rl-json file and it uses references to map relevant related data:

        Component -> Vulnerabilities
        Component -> Dependencies -> Vulnerabilities

During the parsing we follow the references and add each item to a individual `CveInfoNode` record that has the vulnerablity and the component and the dependency data.

The `CveInfoNode` basically maps almost directly to the `DefectDojo Finding`.

The `title` and `description` are build using the collected data.

### Title

#### Component

For a Components, the title shows:

- the CVE.
- the type: `Component`.
- the `purl` of the `Component` if present, otherwise name and version.
- the component-name.
- the component-sha256.

The sha256 is added as sometimes a file scan my have multiple items with the same name and version but with a different hash.
Typically this happens with multi language windows installeres.

#### Dependency

The title shows the:

- the CVE.
- the type: `Dependecy`.
- the `purl` of the `Dependency` if present, otherwise name and version.

### Description

#### Component

For a component we repeat the title.

#### Dependency

For a dependency we repeat the title and then add the component_name and component_hash.
For duplicates we add one additional line to the description for each duplicate, showing its title and component.

### Vulnerabilities

From the vulnerability we fetch:

- the CVE unique id
- cvss version
- cvss.basescore

From the cvss.basescore we map the severity into:

- Info
- Low
- Medium
- High
- Critical

### Other

We extract the scan date and the scanner version and set a static scanner-name.

## Field Mapping Details


- Currently no endpoints are created

- On detecting a duplicate `dependency` we increment the number of occurrences.
`Components` have no duplicates so the nr of occurrences is always 1.

- Deduplication is done only on Dependencies and we use the title (cve + dependency_name and version) + the `component-path` as the hash_key to detect duplicates.

- The default severity if no mapping is matched is `Info`.

## Sample Scan Data or Unit Tests

- [Sample Scan Data Folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/reversinglabs_spectraassure)

## Link To Tools

- [Spectra Assure Cli](https://docs.secure.software/cli/)
- [Spectra Assure Portal](https://docs.secure.software/portal/)
- [docker:rl-scanner](https://docs.secure.software/cli/integrations/docker-image)
- [docker:rl-scanner-cloud](https://docs.secure.software/portal/docker-image)
