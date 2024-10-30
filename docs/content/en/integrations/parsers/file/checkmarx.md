---
title: "Checkmarx"
toc_hide: true
---
- `Checkmarx Scan`, `Checkmarx Scan detailed`: XML report from Checkmarx SAST (source code analysis)
- `Checkmarx OSA`: json report from Checkmarx Open Source Analysis (dependencies analysis)

To generate the OSA report using Checkmarx CLI:
`./runCxConsole.sh OsaScan -v -CxServer <...> -CxToken <..> -projectName <...>  -enableOsa -OsaLocationPath <lib_folder> -OsaJson <output_folder>`

That will generate three files, two of which are needed for defectdojo. Build the file for defectdojo with the jq utility:
`jq -s . CxOSAVulnerabilities.json CxOSALibraries.json`

Data for SAST, SCA and KICS are supported.

### Sample Scan Data
Sample Checkmarx scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/checkmarx).