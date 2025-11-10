---
title: "Trivy"
toc_hide: true
---
JSON report of [trivy scanner](https://github.com/aquasecurity/trivy).

The [status](https://trivy.dev/latest/docs/configuration/filtering/) field in Trivy is mapped to the Defect Dojo status flags in the following way:

| Trivy Status         | Active | Verified | Mitigated | Remarks                                                                                                         |
|----------------------|--------|----------|-----------|-----------------------------------------------------------------------------------------------------------------|
| unknown              | True   | False    | False     | use default value for active which is usually True                                                              |
| not_affected         | False  | True     | True      | false positive is the most appropriate status for not affected as out of scope might be interpreted as something else |
| affected             | True   | True     | False     | standard case                                                                                                   |
| fixed                | True   | True     | False     | fixed in this context means that there is a fix available by patching/updating/upgrading the package but it's still active and verified |
| under_investigation  | True   | False    | False     | no status flag in Defect Dojo to capture this, but verified is False                                            |
| will_not_fix         | True   | True     | False     | no different from affected as Defect Dojo doesn't have a flag to capture will_not_fix by OS/Package Vendor; we can't set active to False as the user needs to risk accept this finding |
| fix_deferred         | True   | True     | False     | no different from affected as Defect Dojo doesn't have a flag to capture will_not_fix by OS/Package Vendor; we can't set active to False as the user needs to (temporarily) risk accept this finding |
| end_of_life          | True   | True     | False     | no different from affected as Defect Dojo doesn't have a flag to capture will_not_fix by OS/Package Vendor; we can't set active to False as the user needs to (temporarily) risk accept

The status field contains the status as assigned by the OS/Package vendor such as Red Hat, Debian, etc.
It is recommended to assess the appropriate action in your Product's context.
If you want to exclude certain status from being imported into Defect Dojo, please [filter them in the export from Trivy](https://trivy.dev/latest/docs/configuration/filtering/)

### Sample Scan Data
Sample Trivy scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/trivy).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- vulnerability ids
- cwe
- description

### Field fix_available
In case a mitigation is available, then field 'fix_available' is set to True. 