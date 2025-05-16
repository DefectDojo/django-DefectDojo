---
title: "AnchoreCTL Policies Report"
toc_hide: true
---
AnchoreCTLs JSON policies report format. Both legacy list-based format and new evaluation-based format are supported.

## Usage

To generate a policy report that can be imported into DefectDojo:

```bash
# Evaluate policies and output to JSON format
anchorectl policy evaluate -o json > policy_report.json
```

In DefectDojo, select "AnchoreCTL Policies Report" as the scan type when uploading the file.

### Format Support

The parser supports both:
- Legacy format (list of objects at the root level)
- New format from `anchorectl policy evaluate -o json` (object with evaluations array)

### Sample Scan Data
Sample AnchoreCTL Policies Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/anchorectl_policies).