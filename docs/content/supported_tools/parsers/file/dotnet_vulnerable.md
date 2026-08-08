---
title: "Dotnet Vulnerable Packages"
toc_hide: true
---

Import the JSON report of `dotnet list package --vulnerable`, which checks restored NuGet
packages against the GitHub Advisory Database.

### File Types

JSON, as written by the .NET SDK. Generated with **.NET SDK 8.0.423**:

```
dotnet restore
dotnet list package --vulnerable --include-transitive --format json > dotnet_vulnerable.json
```

**Pass `--include-transitive`.** A vulnerable package is very often pulled in by another dependency
rather than referenced directly, and only `transitivePackages` names those. Both lists are walked.
Transitive entries carry no `requestedVersion`, and their mitigation says so — telling someone to
"upgrade" a package that is not in their project file is not actionable, so the finding names the real
options instead.

Severity comes from the NuGet advisory (`Critical`/`High`/`Moderate`/`Low`).

**The report carries no advisory identifier**, only `advisoryurl`. The GHSA id is parsed out of that
URL, and is the only public identifier available — there is no CVE field.

A project with nothing vulnerable omits the `frameworks` key entirely rather than reporting an empty
list. A package reported under several target frameworks of one project is a single finding.

### Sample Scan Data

Sample Dotnet Vulnerable Packages scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dotnet_vulnerable).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- component_name
- component_version
- vuln_id_from_tool
