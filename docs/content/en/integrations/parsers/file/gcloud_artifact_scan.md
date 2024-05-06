---
title: "Google Cloud Artifact Vulnerability Scan"
toc_hide: true
---
Google Cloud has a Artifact Registry that you can enable security scans https://cloud.google.com/artifact-registry/docs/analysis
Once a scan is completed, results can be pulled via API/gcloud https://cloud.google.com/artifact-analysis/docs/metadata-storage and exported to JSON

### File Types
DefectDojo parser accepts Google Cloud Artifact Vulnerability Scan data as a .json file.

### Sample Scan Data
Sample reports can be found at https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/gcloud_artifact_scan