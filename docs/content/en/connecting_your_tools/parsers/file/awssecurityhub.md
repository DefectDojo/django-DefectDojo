---
title: "AWS Security Hub"
toc_hide: true
---
### File Types
This DefectDojo parser accepts JSON files from AWS Security Hub. The JSON reports can be created from the [AWS Security Hub CLI](https://docs.aws.amazon.com/cli/latest/reference/securityhub/get-findings.html) using the following command: `aws securityhub get-findings`.

AWS Security Hub integrates with multiple AWS Tools. Thus, you can retrieve findings from various AWS sources through AWS Security Hub. This parser is able to handle the following findings retrieved over AWS Security Hub:
- AWS Security Hub Compliance Checks 
- AWS Security Hub GuardDuty
- AWS Security Hub Inspector

### Example Commands to retrieve JSON output
- AWS Security Hub Compliance Checks: <br>`aws securityhub get-findings --filters ComplianceStatus="[{Comparison=EQUALS,Value=FAILED}]" | jq "." > output.json`
- AWS Security Hub GuardDuty: <br>`aws securityhub get-findings --filters ProductName="[{Value=GuardDuty,Comparison=EQUALS}]" | jq "." > output.json`
- AWS Security Hub Inspector: <br>`aws securityhub get-findings --filters ProductName="[{Value=Inspector,Comparison=EQUALS}]" | jq "." > output.json`

### Important note
AWS Security Hub Parser does import the affected service ARNs as hosts to DefectDojo. However, as ARNs contain invalid digits for hosts, the ARN is changed slightly. ":", " " & "/" are replaced by "_".

### Sample Scan Data
Sample scan data for testing purposes can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/awssecurityhub).