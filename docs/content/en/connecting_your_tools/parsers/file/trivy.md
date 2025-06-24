---
title: "Trivy"
toc_hide: true
---
JSON report of [trivy scanner](https://github.com/aquasecurity/trivy).

The status field in Trivy is mapped to the Defect Dojo status flags in the following way:

| Trivy Status         | Active | Verified | Mitigated | False Positive | Remarks                                                                                                         |
|----------------------|--------|----------|-----------|---------------|-----------------------------------------------------------------------------------------------------------------|
| unknown              | True   | False    | False     |               | use default value for active which is usually True                                                              |
| not_affected         | False  | True     | True      | True          | false positive is the most appropriate status for not affected as out of scope might be interpreted as something else |
| affected             | True   | True     | False     |               | standard case                                                                                                   |
| fixed                | True   | True     | False     |               | fixed in this context means that there is a fix available by patching/updating/upgrading the package but it's still active and verified |
| under_investigation  | True   | False    | False     |               | no status flag in Defect Dojo to capture this, but verified is False                                            |
| will_not_fix         | True   | True     | False     |               | no different from affected as Defect Dojo doesn't have a flag to capture will_not_fix by OS/Package Vendor; we can't set active to False as the user needs to risk accept this finding |
| fix_deferred         | True   | True     | False     |               | no different from affected as Defect Dojo doesn't have a flag to capture will_not_fix by OS/Package Vendor; we can't set active to False as the user needs to (temporarily) risk accept this finding |
| end_of_life          | True   | True     | False     |               | no different from affected as Defect Dojo doesn't have a flag to capture will_not_fix by OS/Package Vendor; we can't set active to False as the user needs to (temporarily) risk accept

The status field contains the status as assigned by the OS/Package vendor such as Red Hat, Debian, etc.
As s Defect Dojo user you still have to asses the appropiate action in your product context.

### Sample Scan Data
Sample Trivy scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/trivy).