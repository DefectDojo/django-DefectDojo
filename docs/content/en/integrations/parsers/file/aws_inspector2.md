---
title: "AWS Inspector2 Scanner"
toc_hide: true
---

### File Types
AWS Inspector2 report can be imported in json format. Inspector2 name comes from API calls to "modern" Inspector API - `aws inspector2` as opposite to Classic Inspector (previous version of the service), this is an example of how such report can be generated: `aws inspector2 list-findings --filter-criteria '{"resourceId":[{"comparison":"EQUALS","value":"i-instance_id_here"}]}' --region us-east-1 > inspector2_findings.json`


This parser can help to get findings in a delegated admin account for AWS Inspector or in a standalone AWS account. The parser is developed mostly for a scenario where findings are obtained for a specific resource like an ECR image or an instance, and uploaded to a test in a DefectDojo engagement that represents a branch from a git repository.


A minimal valid json file with no findings:

```json
{
    "findings": []
}
```

Detailed API response format can be obtained [here](https://docs.aws.amazon.com/inspector/v2/APIReference/API_Finding.html)

### Sample Scan Data
Sample AWS Inspector2 findings can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/aws_inspector2).
