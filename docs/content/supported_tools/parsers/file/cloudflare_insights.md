---
title: "Cloudflare Insights"
toc_hide: true
---

Import Cloudflare Insights findings using the **CSV export** or via api the **JSON output** provided by Cloudflare.

### Sample Scan Data
Sample Cloudflare Insights files can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cloudflare_insights).

### Supported Fields
The parser supports the following CSV columns:

- `severity`
- `issue_class`
- `subject`
- `issue_type`
- `status`
- `insight` *(optional)*
- `detection_method` *(optional)*
- `risk` *(optional)*
- `recommended_action`
