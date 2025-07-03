---
title: "Mayhem SARIF Reports"
toc_hide: true
---
Import for Mayhem generated SARIF reports. In general, the exiting
SARIF report consumer should work, and for general cases does. However,
since Mayhem is A. DAST and B. includes fuzzed data in the content of
the report, a Mayhem-specific SARIF consumer is added.
See more below: 
[Mayhem SARIF Report (API)](https://docs.mayhem.security/api-testing/tutorials/identifying-api-issues/bug-reporting/#sarif-reports).
[Mayhem SARIF Report (CI)](https://docs.mayhem.security/integrations/ci-integrations/github/#analyzing-sarif-reports).


#### Parity with Existing SARIF Consumer

The current implementation is mostly lifted from the existing SARIF parser support. As such, it will also aggregate all the findings in the SARIF file in one single report, and it also supports fingerprint deduplication.

### Sample Scan Data
Sample Mayhem SARIF reports can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/mayhem).