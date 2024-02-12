---
title: "AWS Security Hub"
toc_hide: true
---
### File Types
This DefectDojo parser accepts JSON files from AWS Security Hub. The JSON reports can be created from the [AWS Security Hub CLI](https://docs.aws.amazon.com/cli/latest/reference/securityhub/get-findings.html) using the following command: `aws securityhub get-findings`.

AWS Security Hub integrates with multiple AWS Tools. Thus, you can retrieve findings from various AWS sources through AWS Security Hub. This parser is able to handle the following findings retrieved over AWS Security Hub:
- AWS Security Hub Compliance Checks 
- AWS Inspector
- AWS GuardDuty

### Acceptable JSON Format
Parser expects a .json file, with an array of Findings contained within a single JSON object.  All properties are strings and are required by the parser.

### Sample Scan Data
Sample scan data for testing purposes can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/awssecurityhub).