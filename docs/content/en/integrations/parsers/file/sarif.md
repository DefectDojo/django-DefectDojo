---
title: "SARIF"
toc_hide: true
---
OASIS Static Analysis Results Interchange Format (SARIF). SARIF is
supported by many tools. More details about the format here:
<https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif>

{{% alert title="Information" color="info" %}}
SARIF parser customizes the Test_Type with data from the report.
For example, a report with `Dockle` as a driver name will produce a Test with a Test_Type named `Dockle Scan (SARIF)`
{{% /alert %}}

{{% alert title="Warning" color="warning" %}}
Current implementation is limited and will aggregate all the findings in the SARIF file in one single report.
{{% /alert %}}

##### Support for de-duplication (fingerprinting)

SARIF parser take into account data for fingerprinting. It's base on `fingerprints` and `partialFingerprints` properties.
It's possible to activate de-duplication based on this data by customizing settings.

```Python
# in your settings.py file
DEDUPLICATION_ALGORITHM_PER_PARSER["SARIF"] = DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE
```
